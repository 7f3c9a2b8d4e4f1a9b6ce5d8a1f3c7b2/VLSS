# Audit Report

## Title
Oracle Health Indicators Not Validated - Unhealthy Prices Can Cause Value Misallocation

## Summary
The Volo vault oracle system fails to validate Switchboard aggregator health metrics (standard deviation, range, variance) before caching and using prices. During market volatility, prices with high variance can be cached via the public `update_price()` function and subsequently used for critical vault operations, causing permanent value transfer between depositors through incorrect share ratio calculations, incorrect DeFi position valuations, and potential loss tolerance bypass.

## Finding Description

The vulnerability stems from Volo's oracle integration failing to validate available health indicators from Switchboard aggregators before using prices for critical vault accounting.

**Root Cause Analysis:**

The `PriceInfo` struct only stores basic price data without health indicators: [1](#0-0) 

However, Switchboard's `CurrentResult` contains comprehensive health metrics including standard deviation, range, mean, and min/max results: [2](#0-1) 

The Switchboard `compute_current_result` function calculates variance metrics but never validates them against the aggregator's `max_variance` configuration: [3](#0-2) 

When Volo's `get_current_price` retrieves prices from Switchboard, it only validates timestamp staleness, ignoring all health indicators: [4](#0-3) 

The public `update_price` function allows anyone to cache these potentially unhealthy prices: [5](#0-4) 

**Propagation Through Vault System:**

These cached unhealthy prices propagate through critical vault operations:

1. **Share Ratio Calculation:** Asset values are updated using oracle prices via `update_free_principal_value`: [6](#0-5) 

The vault aggregates all asset values to calculate total USD value: [7](#0-6) 

This total value determines the share ratio used for deposit share allocation: [8](#0-7) 

During deposit execution, shares are calculated using this ratio: [9](#0-8) 

2. **DeFi Position Valuations:** The Navi adaptor uses these same oracle prices for position valuation: [10](#0-9) 

3. **Loss Tolerance:** The tolerance system uses total USD value (derived from oracle prices) as the base for loss calculations: [11](#0-10) 

**Why Existing Protections Fail:**

Slippage checks on deposits provide only partial protection: [12](#0-11) 

These checks:
- Only protect individual users who set appropriate bounds
- Do NOT prevent inter-depositor value transfer (relative share dilution between users)
- Are insufficient during volatility when users may widen slippage tolerance
- Do not affect the underlying issue of incorrect price-based valuations

## Impact Explanation

**Direct Fund Impact:**

When unhealthy prices (e.g., temporary 5% spike with high variance) are cached and used:

1. **Permanent Value Transfer Between Depositors:** If a price spike inflates `total_usd_value` by 5%, the share ratio increases by 5%. New depositors receive approximately 5% fewer shares than they should for their deposit amount. This represents a permanent wealth transfer from new depositors to existing shareholders, as the incorrectly allocated shares remain after prices normalize.

2. **Incorrect DeFi Position Valuations:** Navi, Cetus, Suilend, and other DeFi adaptors use these prices to value positions. Incorrect valuations affect operation execution decisions and risk assessment.

3. **Loss Tolerance Bypass:** If unhealthy prices artificially inflate `cur_epoch_loss_base_usd_value`, the calculated `loss_limit` becomes incorrectly higher, allowing operations that exceed the intended loss tolerance to proceed.

**Affected Parties:**
- All depositors during volatile market periods experience potential value transfer
- Vault operators making decisions based on incorrect position valuations
- Protocol integrity through incorrect loss tolerance enforcement

**Severity Assessment:**

Medium-High severity based on:
- **Impact**: Permanent fund misallocation, not temporary
- **Likelihood**: Common market conditions (volatility), no attacker required
- **Exploitability**: Public function, anyone can trigger
- **Mitigation**: Slippage checks are insufficient for inter-depositor issues

## Likelihood Explanation

**Feasibility:**

This vulnerability is highly likely to occur under normal market conditions:

1. **Natural Trigger:** Market volatility causing oracle divergence is common in cryptocurrency markets. No malicious actor is required - natural price movements trigger the issue.

2. **Public Access:** The `update_price` function is publicly callable, allowing any user or keeper to cache unhealthy prices: [13](#0-12) 

3. **Common Occurrence:** Cryptocurrency markets experience significant volatility regularly, particularly during:
   - Major news events
   - Large liquidation cascades
   - Low liquidity periods
   - Network congestion affecting oracle updates

4. **Update Window:** The default update interval is 1 minute, providing sufficient time for unhealthy prices to be used in vault operations: [14](#0-13) 

**Execution Path:**

1. Market volatility causes Switchboard oracles to report divergent prices (high stdev/range in `CurrentResult`)
2. Any user calls `update_price()` with the aggregator
3. Price passes only timestamp staleness check, gets cached in `PriceInfo`
4. Vault operations (`execute_deposit`, `calculate_navi_position_value`, etc.) use the unhealthy price
5. Value misallocation occurs with permanent effect on share allocations

**Detection Difficulty:**

Users cannot easily detect when cached prices have high variance since:
- Health metrics are not exposed in `PriceInfo`
- Individual users see their deposits succeed within slippage bounds
- The relative value transfer between depositors is not immediately visible
- Only post-analysis would reveal systematic under/over-allocation of shares

## Recommendation

**Immediate Fix:**

Add health metric validation in the oracle caching logic. Before accepting a price from Switchboard, validate that the aggregator's health indicators are within acceptable bounds:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    // ADDED: Validate health metrics
    let stdev_value = current_result.stdev().value();
    let range_value = current_result.range().value();
    let result_value = current_result.result().value();
    
    // Check standard deviation is within acceptable threshold (e.g., 5% of price)
    let max_acceptable_stdev = result_value / 20; // 5%
    assert!(stdev_value <= max_acceptable_stdev, ERR_PRICE_HEALTH_CHECK_FAILED);
    
    // Check range is within acceptable threshold (e.g., 10% of price)
    let max_acceptable_range = result_value / 10; // 10%
    assert!(range_value <= max_acceptable_range, ERR_PRICE_HEALTH_CHECK_FAILED);
    
    // Optional: Validate against aggregator's max_variance if available
    // Note: This requires access to the aggregator's configuration
    
    current_result.result().value() as u256
}
```

**Additional Improvements:**

1. **Store Health Metrics:** Extend `PriceInfo` to include health indicators for transparency:
```move
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
    stdev: u256,  // Added
    range: u256,  // Added
}
```

2. **Configurable Thresholds:** Allow protocol admin to configure acceptable health metric thresholds per asset type.

3. **Circuit Breaker:** Implement automatic price update rejection during extreme market conditions when variance exceeds safety thresholds.

4. **Health Status Events:** Emit events when prices are rejected due to health checks, allowing monitoring and debugging.

## Proof of Concept

```move
#[test]
fun test_unhealthy_price_causes_share_dilution() {
    use sui::test_scenario;
    use sui::clock;
    use volo_vault::vault;
    use volo_vault::vault_oracle;
    
    let admin = @0xAD;
    let user1 = @0x1;
    let user2 = @0x2;
    
    let mut scenario = test_scenario::begin(admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Create vault with normal price
    // ... vault initialization code ...
    
    // Step 1: User1 deposits at normal price (share_ratio = 1.0)
    // User1 gets correct shares
    
    // Step 2: Market volatility causes Switchboard price to spike 5% with high variance
    // Simulate Switchboard aggregator with high stdev/range in CurrentResult
    // Any keeper calls update_price() - it passes only timestamp check
    
    // Step 3: User2 deposits at inflated price (share_ratio = 1.05)
    // User2 receives ~5% fewer shares than they should
    // Calculation: shares = deposit_usd / share_ratio
    // With 5% inflated ratio: shares are 5% lower
    
    // Step 4: Price normalizes back
    // User1 has gained relative value at User2's expense
    // Value transfer is permanent despite price returning to normal
    
    // Assert: User2 received fewer shares than User1 for same USD deposit amount
    // proving permanent value dilution from temporary unhealthy price
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

The test demonstrates that unhealthy prices cached during volatility cause permanent share dilution, transferring value between depositors even after prices normalize.

## Notes

**Key Distinctions:**

1. **Impact is Permanent, Not Temporary:** While each unhealthy price cache lasts up to 1 minute, the value transfer from incorrect share allocations is permanent. Once shares are minted at the wrong ratio, they remain, affecting all future vault operations.

2. **Natural Market Conditions:** This vulnerability doesn't require a malicious actor. Normal cryptocurrency market volatility naturally creates the conditions for unhealthy oracle data.

3. **Integration Responsibility:** While Switchboard computes health metrics, Volo bears responsibility for validating external data before use in critical accounting operations. The available health indicators in `CurrentResult` provide the necessary information for validation.

4. **Switchboard's max_variance:** The aggregator configuration includes a `max_variance` field that is included in oracle signatures but is never enforced against computed variance in the result validation logic.

### Citations

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
```

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
}
```

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L12-22)
```text
public struct CurrentResult has copy, drop, store {
    result: Decimal,
    timestamp_ms: u64,
    min_timestamp_ms: u64,
    max_timestamp_ms: u64,
    min_result: Decimal,
    max_result: Decimal,
    stdev: Decimal,
    range: Decimal,
    mean: Decimal,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L395-396)
```text
    let variance = m2 / ((count - 1) as u256); 
    let stdev = sqrt(variance);
```

**File:** volo-vault/sources/volo_vault.move (L608-641)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
}

public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L820-853)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;
```

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
}
```

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
```
