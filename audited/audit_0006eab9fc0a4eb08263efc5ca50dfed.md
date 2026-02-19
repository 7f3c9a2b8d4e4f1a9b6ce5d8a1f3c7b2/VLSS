### Title
Oracle Health Indicators Not Validated - Unhealthy Prices Can Cause Value Misallocation

### Summary
The `PriceInfo` struct lacks health indicator fields and the oracle system does not validate Switchboard aggregator health metrics (stdev, range, variance) before caching and using prices. During market volatility or oracle divergence, prices with high variance can be cached and used for critical vault operations, causing incorrect share ratios, DeFi position valuations, and potential value transfer between depositors.

### Finding Description

The root cause is that `PriceInfo` only stores basic price data without health indicators: [1](#0-0) 

While Switchboard's `CurrentResult` contains comprehensive health metrics (stdev, range, min/max results, mean): [2](#0-1) 

These health indicators are computed but never validated. The `compute_current_result` function calculates variance metrics: [3](#0-2) 

However, the aggregator's `max_variance` configuration is not enforced against the computed variance. When `get_current_price` retrieves prices, it only validates timestamp staleness: [4](#0-3) 

The public `update_price` function then caches these potentially unhealthy prices: [5](#0-4) 

These cached prices are subsequently used for critical calculations including share ratios: [6](#0-5) 

And DeFi position valuations in adaptors like Navi: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**
- Incorrect share ratios cause value transfer between depositors. If a price spike with high variance inflates total_usd_value by 5%, new depositors receive 5% fewer shares than they should, effectively transferring value to existing shareholders.
- DeFi position valuations (Navi, Cetus, Suilend) become incorrect, affecting operation decisions and loss tolerance calculations.

**Custody/Receipt Integrity:**
- Receipt share allocations become incorrect when based on unhealthy prices, affecting all future deposit/withdraw operations for those users.

**Security Integrity Impact:**
- Loss tolerance checks can be bypassed if unhealthy prices artificially inflate `cur_epoch_loss_base_usd_value`: [8](#0-7) 

**Who is affected:**
- All depositors (both existing and new) during volatile market periods
- Vault operators making rebalancing decisions
- Protocol integrity via incorrect loss tolerance enforcement

**Severity Justification:**
Medium severity because:
1. Requires specific market conditions (high volatility) rather than direct attacker control
2. Impact is temporary (up to 1 minute per price update)
3. Partial mitigation exists via slippage checks on user deposits/withdrawals
4. However, no protection for inter-depositor value transfer or operator actions

### Likelihood Explanation

**Feasibility:**
- Market volatility causing oracle divergence occurs regularly in crypto markets
- No attacker capabilities required - natural market conditions trigger the issue
- `update_price` is publicly callable, allowing anyone to cache the unhealthy price
- Attack window is up to 1 minute (the `update_interval` default): [9](#0-8) 

**Execution Practicality:**
1. Market volatility causes Switchboard oracles to diverge (high stdev/range in CurrentResult)
2. Any user calls `update_price()` with the aggregator
3. Price passes only timestamp staleness check, gets cached
4. Vault operations use the unhealthy price for share ratio and valuation calculations
5. Value misallocation occurs until next price update

**Detection/Constraints:**
- While slippage checks provide some protection for individual deposits/withdrawals, they do not prevent:
  - Inter-depositor value transfer via incorrect share ratios
  - Incorrect DeFi position valuations
  - Loss tolerance bypass
  - Operator deposit actions without slippage bounds: [10](#0-9) 

**Probability:**
Medium-High during volatile market conditions, which are common in cryptocurrency markets. The vulnerability is exploitable without malicious intent, simply through normal market dynamics.

### Recommendation

**Code-level Mitigation:**

1. **Extend PriceInfo struct** to include health indicators:
```move
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
    stdev: u256,        // Add: standard deviation
    range: u256,        // Add: price range (max - min)
    is_healthy: bool,   // Add: health flag
}
```

2. **Add health validation in get_current_price**:
```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): (u256, bool) {
    config.check_version();
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    // Existing staleness check
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    // Add: Health validation
    let max_variance = aggregator.max_variance();
    let stdev = current_result.stdev().value();
    let range = current_result.range().value();
    let price = current_result.result().value() as u256;
    
    // Check if variance is acceptable
    let variance_ratio = (stdev * 10000) / price; // Basis points
    let is_healthy = variance_ratio <= max_variance;
    
    (price, is_healthy)
}
```

3. **Update PriceInfo storage** to cache health indicators and add validation gate:
```move
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();
    let now = clock.timestamp_ms();
    let (current_price, is_healthy) = get_current_price(config, clock, aggregator);
    
    // Only cache if healthy, or emit warning event if forced update
    assert!(is_healthy, ERR_UNHEALTHY_PRICE);
    
    // Update with health indicators...
}
```

4. **Add configuration for maximum acceptable variance/stdev thresholds** per asset type in `OracleConfig`.

**Invariant Checks:**
- Assert health indicators are within acceptable bounds before using prices for critical operations
- Add monitoring/alerts when prices are unhealthy
- Consider rejecting or flagging operations during periods of high oracle variance

**Test Cases:**
- Test vault operations with Switchboard aggregator having high stdev/range
- Verify share ratio calculations remain accurate during simulated oracle divergence
- Test that unhealthy prices are rejected before being cached
- Verify loss tolerance checks work correctly with health-validated prices

### Proof of Concept

**Initial State:**
- Vault has 1000 shares, $100,000 total USD value (share ratio = $100/share)
- User A holds all 1000 shares
- Switchboard aggregator for principal asset normally reports $100 with low variance

**Attack Sequence:**

1. **Market Volatility Occurs:**
   - Oracle sources diverge significantly
   - Switchboard CurrentResult: price = $105, stdev = $10, range = $20
   - High variance indicates unhealthy/unreliable price

2. **Anyone Calls update_price:**
   ```
   update_price(oracle_config, aggregator, clock, "PrincipalCoin")
   ```
   - `get_current_price` only checks timestamp (passes)
   - Ignores high stdev/range
   - Caches price = $105

3. **User B Deposits $10,000:**
   ```
   deposit(vault, $10,000, expected_shares=95)  // Based on ~$105 price
   ```
   - Vault recalculates with inflated price
   - Total USD value = $105,000 (incorrect, should be $100,000)
   - User B receives ~95 shares
   - **Actual fair allocation should be 100 shares**

4. **Price Corrects:**
   - Next update: price returns to $100
   - Total value now $110,000 with 1095 shares
   - Share ratio = $100.46/share

**Result:**
- User A's 1000 shares now worth $100,460 (gain of $460)
- User B's 95 shares now worth $9,540 (loss of $460)
- **$460 value transferred from User B to User A** due to unhealthy price being used

**Success Condition:**
The vulnerability is confirmed because unhealthy prices with high variance are accepted and cached without validation, enabling value misallocation during normal market volatility.

**Notes:**

The vulnerability is particularly concerning because:
1. It requires no malicious actor - normal market volatility is sufficient
2. The public nature of `update_price` means anyone can trigger the caching of unhealthy prices
3. Slippage protection is insufficient as it doesn't prevent inter-depositor value transfer via incorrect share ratios
4. The 1-minute caching window provides an exploitable timeframe during which multiple operations can be affected
5. DeFi position valuations and loss tolerance calculations are also impacted without any slippage protection

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L395-411)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L608-624)
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```
