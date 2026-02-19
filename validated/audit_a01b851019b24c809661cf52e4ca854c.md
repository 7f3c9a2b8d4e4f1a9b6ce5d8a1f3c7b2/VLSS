# Audit Report

## Title
Oracle Health Indicators Not Validated - Unhealthy Prices Can Cause Value Misallocation

## Summary
The Volo oracle system does not validate Switchboard aggregator health metrics (standard deviation, range, variance) before caching and using prices. The Switchboard `compute_current_result` function calculates variance but never enforces the configured `max_variance` threshold, allowing unhealthy prices to be cached and used for critical vault operations. This causes incorrect share ratios and value transfer between depositors during market volatility.

## Finding Description

The vulnerability exists across three layers:

**Layer 1: PriceInfo lacks health indicators**

The `PriceInfo` struct only stores basic price data without health indicators. [1](#0-0) 

**Layer 2: Switchboard computes but never validates variance**

Switchboard's `CurrentResult` contains comprehensive health metrics including stdev, range, mean, and min/max results. [2](#0-1) 

The `compute_current_result` function calculates variance using Welford's online algorithm and computes standard deviation and range. [3](#0-2) 

However, the aggregator's `max_variance` configuration field is never validated against the computed variance. [4](#0-3) 

**Layer 3: Volo caches unhealthy prices**

The `get_current_price` function retrieves prices from Switchboard aggregators but only validates timestamp staleness, not health metrics. [5](#0-4) 

The public `update_price` function then caches these potentially unhealthy prices without any health validation. [6](#0-5) 

**Impact on critical calculations:**

These cached prices directly affect share ratio calculations. The share ratio is computed as `total_usd_value / total_shares`, where total_usd_value is aggregated from individual asset prices. [7](#0-6) 

During deposit execution, user shares are calculated as `new_usd_value_deposited / share_ratio_before`. If the share ratio is inflated by unhealthy prices, new depositors receive fewer shares than they should. [8](#0-7) 

DeFi position valuations are also affected, as the Navi adaptor uses `get_asset_price` to calculate position values. [9](#0-8) 

Loss tolerance calculations can be affected when unhealthy prices inflate `cur_epoch_loss_base_usd_value`, the baseline for loss limit calculations. [10](#0-9) 

## Impact Explanation

**Direct Value Transfer:**
- During market volatility when oracle sources diverge, prices with high variance can be cached and used for share ratio calculations
- If a price spike with 5% variance inflates total_usd_value by 5%, new depositors receive 5% fewer shares than they should
- This effectively transfers value from new depositors to existing shareholders
- The transfer persists until the next price update (up to 1 minute based on default `update_interval`)

**Affected Parties:**
- All depositors (new and existing) during volatile market periods
- Vault operators making rebalancing decisions based on incorrect valuations
- Protocol integrity via incorrect loss tolerance enforcement

**Severity: Medium**
1. Requires specific market conditions (volatility causing oracle divergence) rather than direct attacker control
2. Impact is temporary (up to 1 minute per price update)
3. Partial mitigation exists via slippage checks on user deposits/withdrawals
4. However, no protection exists for inter-depositor value transfer or operator actions without slippage bounds [11](#0-10) 

## Likelihood Explanation

**High Likelihood:**
- Market volatility causing oracle divergence occurs regularly in cryptocurrency markets
- No attacker capabilities required - natural market conditions trigger the issue
- `update_price` is publicly callable, allowing anyone to cache unhealthy prices
- The default update interval is 1 minute, providing a window for exploitation [12](#0-11) 

**Execution Path:**
1. Market volatility causes Switchboard oracle sources to report divergent prices
2. `compute_current_result` calculates high variance but does not reject the result
3. Any user calls `update_price()` with the aggregator
4. Price passes only timestamp staleness check and gets cached
5. Vault operations (deposits, position valuations) use the unhealthy price
6. Value misallocation occurs until next price update

**Constraints:**
While slippage checks provide some protection for individual deposits/withdrawals, they do not prevent inter-depositor value transfer via incorrect share ratios, incorrect DeFi position valuations, or operator actions without slippage bounds.

## Recommendation

**Option 1: Enforce max_variance in Switchboard**

Modify `compute_current_result` to validate the computed variance against the aggregator's `max_variance` configuration:

```move
fun compute_current_result(aggregator: &Aggregator, now_ms: u64): Option<CurrentResult> {
    // ... existing variance calculation code ...
    
    let variance = m2 / ((count - 1) as u256);
    
    // Add validation against max_variance
    assert!(variance <= (aggregator.max_variance as u256), ERROR_VARIANCE_TOO_HIGH);
    
    let stdev = sqrt(variance);
    // ... rest of function ...
}
```

**Option 2: Add health validation in Volo oracle**

Add validation of health metrics when retrieving prices from Switchboard:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    // Add health validation
    let stdev = current_result.stdev();
    let range = current_result.range();
    // Define acceptable thresholds and validate
    assert!(stdev.value() < MAX_ACCEPTABLE_STDEV, ERR_UNHEALTHY_PRICE);
    
    current_result.result().value() as u256
}
```

**Recommended approach:** Implement Option 1 as it enforces the intended behavior at the source (Switchboard), preventing unhealthy results from being created in the first place. This provides defense-in-depth protection for all consumers of Switchboard prices.

## Proof of Concept

The vulnerability can be demonstrated by examining the code flow:

1. **Setup**: A Switchboard aggregator is configured with `max_variance = 100` (representing acceptable variance threshold)

2. **Market volatility**: Oracle sources report divergent prices (e.g., $100, $105, $110, $95) resulting in high variance > 100

3. **Switchboard accepts unhealthy result**: The `compute_current_result` function calculates variance but never checks it against `max_variance`, returning the median price

4. **Volo caches unhealthy price**: Anyone calls `vault_oracle::update_price()` which calls `get_current_price()` that only validates timestamps, caching the unhealthy price in `PriceInfo`

5. **Value misallocation**: During `execute_deposit`, the inflated price increases `total_usd_value`, which inflates `share_ratio_before`, causing fewer shares to be minted to the new depositor

The core issue is visible in the Switchboard code where variance is computed but the `max_variance` field (defined in the Aggregator struct and configurable) is never referenced or enforced during result computation.

### Citations

**File:** volo-vault/sources/oracle.move (L10-12)
```text
// ---------------------  Constants  ---------------------//
const VERSION: u64 = 2;
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L338-412)
```text
fun compute_current_result(aggregator: &Aggregator, now_ms: u64): Option<CurrentResult> {
    let update_state = &aggregator.update_state;
    let updates = &update_state.results;
    let mut update_indices = update_state.valid_update_indices(aggregator.max_staleness_seconds * 1000, now_ms);

    // if there are not enough valid updates, return
    if (update_indices.length() < aggregator.min_sample_size) {
        return option::none()
    };

    // if there's only 1 index, return the result
    if (update_indices.length() == 1) {
        let (result, timestamp_ms) = update_state.median_result(&mut update_indices);
        return option::some(CurrentResult {
            min_timestamp_ms: updates[update_indices[0]].timestamp_ms,
            max_timestamp_ms: updates[update_indices[0]].timestamp_ms,
            min_result: result,
            max_result: result,
            range: decimal::zero(),
            result,
            stdev: decimal::zero(),
            mean: result,
            timestamp_ms,
        })
    };

    let mut sum: u128 = 0;
    let mut min_result = decimal::max_value();
    let mut max_result = decimal::zero();
    let mut min_timestamp_ms = u64::max_value!();
    let mut max_timestamp_ms = 0;
    let mut mean: u128 = 0;
    let mut mean_neg: bool = false;
    let mut m2: u256 = 0;
    let mut m2_neg: bool = false;
    let mut count: u128 = 0;

    vector::do_ref!(&update_indices, |idx| {
        let update = &updates[*idx];
        let value = update.result.value();
        let value_neg = update.result.neg();
        count = count + 1;

        // Welford's online algorithm
        let (delta, delta_neg) = sub_i128(value, value_neg, mean, mean_neg);
        (mean, mean_neg) = add_i128(mean, mean_neg, delta / count, delta_neg);
        let (delta2, delta2_neg) = sub_i128(value, value_neg, mean, mean_neg);

        (m2, m2_neg) = add_i256(m2, m2_neg, (delta as u256) * (delta2 as u256), delta_neg != delta2_neg);

        sum = sum + value;
        min_result = decimal::min(&min_result, &update.result);
        max_result = decimal::max(&max_result, &update.result);
        min_timestamp_ms = u64::min(min_timestamp_ms, update.timestamp_ms);
        max_timestamp_ms = u64::max(max_timestamp_ms, update.timestamp_ms);
    });

    let variance = m2 / ((count - 1) as u256); 
    let stdev = sqrt(variance);
    let range = max_result.sub(&min_result);
    let (result, timestamp_ms) = update_state.median_result(&mut update_indices);
    
    // update the current result
    option::some(CurrentResult {
        min_timestamp_ms,
        max_timestamp_ms,
        min_result,
        max_result,
        range,
        result,
        stdev: decimal::new(stdev, false),
        mean: decimal::new(mean, false),
        timestamp_ms,
    })
}
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

**File:** volo-vault/sources/volo_vault.move (L806-872)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
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

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
```

**File:** volo-vault/sources/volo_vault.move (L874-892)
```text
public(package) fun deposit_by_operator<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    coin: Coin<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_normal();

    let deposit_amount = coin.value();

    self.free_principal.join(coin.into_balance());
    update_free_principal_value(self, config, clock);

    emit(OperatorDeposited {
        vault_id: self.vault_id(),
        amount: deposit_amount,
    });
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
