### Title
Oracle Failure Causes Complete Health Calculation DoS, Blocking Critical Withdrawals and Liquidations

### Summary
The health calculation for Navi lending positions fails entirely if any single collateral or loan asset has an invalid oracle price (stale or zero). This blocks withdrawals, borrows, and most critically, liquidations, potentially leading to protocol insolvency when underwater positions cannot be liquidated due to unrelated oracle failures.

### Finding Description

In `dynamic_user_health_collateral_value`, the function loops through all user collateral assets and calls `dynamic_user_collateral_value` for each asset without error handling: [1](#0-0) 

This function chain leads to `calculator::calculate_value`, which retrieves the oracle price and asserts it is valid: [2](#0-1) 

The oracle price is considered invalid if either the price is zero or the timestamp is stale (exceeds `update_interval`): [3](#0-2) 

Since Move has no try-catch mechanism, when the assertion fails, the entire transaction aborts. The health calculation does not skip the problematic asset—it completely fails.

This health calculation is used in critical operations:
- **Withdrawals**: `execute_withdraw` checks health via `is_health` [4](#0-3) 

- **Borrows**: `execute_borrow` checks health via `user_health_factor` [5](#0-4) 

- **Liquidations**: `execute_liquidate` checks health via `is_health` [6](#0-5) 

The health factor calculation aggregates all collateral values via `user_health_collateral_value`, which also loops through all assets with the same oracle dependency: [7](#0-6) 

### Impact Explanation

**Withdrawal DoS**: Users with multiple collateral assets cannot withdraw ANY asset if even one unrelated asset has an invalid oracle. For example, a user with SUI, USDC, and ETH collateral cannot withdraw SUI if the ETH oracle goes stale, even though SUI and USDC oracles are healthy.

**Liquidation Failure**: Most critically, liquidators cannot liquidate underwater positions if the target user has any asset with an invalid oracle. This creates systemic risk:
- Underwater positions accumulate bad debt
- Protocol becomes insolvent as losses exceed reserves
- Healthy users bear the losses

**Borrow DoS**: Users cannot take new borrows if any of their existing collateral assets has an invalid oracle.

Oracle failures are realistic:
- Network congestion delays price updates beyond `update_interval`
- Oracle keeper transactions fail due to gas spikes
- Extreme market conditions cause prices to hit zero
- Oracle infrastructure downtime

Even a brief oracle outage for a single asset creates protocol-wide DoS for all users holding that asset.

### Likelihood Explanation

**No Attacker Required**: This is a natural failure mode, not requiring any malicious action. Oracle staleness happens regularly in production systems.

**Common Preconditions**: Many lending users have multiple collateral assets to diversify risk. The more assets supported, the higher the probability that at least one oracle fails at any given time.

**Execution Path**: 
1. User has collateral in assets [A, B, C] on Navi
2. Asset C oracle becomes stale (timestamp exceeds `update_interval`)
3. User attempts to withdraw asset A via `withdraw_with_account_cap`
4. Health check calls `user_health_collateral_value`
5. Loop processes asset A (succeeds), asset B (succeeds), asset C (assertion fails)
6. Transaction aborts, withdrawal blocked

The same path applies to liquidations, where the liquidator's transaction fails when trying to liquidate any user with a stale oracle asset.

**Realistic Frequency**: Given typical oracle update intervals (e.g., 60 seconds) and network variability, brief periods of staleness occur regularly. A single missed update blocks all operations for affected users.

### Recommendation

Implement graceful degradation by skipping assets with invalid oracles rather than aborting the entire calculation:

```move
// In dynamic_user_health_collateral_value and similar functions
while (i < len) {
    let asset_t = vector::borrow(&c, i);
    let estimate_value_t = 0;
    if (asset == *asset_t) {
        estimate_value_t = estimate_value;
    };
    
    // Get oracle validity first
    let oracle_id = storage::get_oracle_id(storage, *asset_t);
    let (is_valid, _, _) = oracle::get_token_price(clock, oracle, oracle_id);
    
    // Only include asset if oracle is valid
    if (is_valid) {
        let collateral_value = dynamic_user_collateral_value(
            clock, oracle, storage, *asset_t, user, estimate_value_t, is_increase
        );
        value = value + collateral_value;
    };
    // Otherwise skip this asset (conservative: excludes from collateral)
    
    i = i + 1;
};
```

**Alternative**: Maintain a separate "oracle health" flag per asset and only include assets with healthy oracles in health calculations. This is conservative—it reduces collateral value, making liquidations more likely but preventing DoS.

**Invariant to Add**: Document that health calculations must be resilient to individual oracle failures to maintain protocol availability.

**Test Cases**:
1. User with 3 collateral assets, one oracle stale → withdrawal of other assets should succeed
2. Underwater user with 1 stale oracle asset → liquidation should still proceed based on valid assets
3. All user oracles stale → operations should fail (no valid health data)

### Proof of Concept

**Initial State**:
- User holds collateral: 100 SUI, 1000 USDC, 1 ETH on Navi
- User has borrowed: 500 USDC
- User is healthy with 200% collateralization
- Oracle `update_interval` is 60 seconds

**Attack Sequence**:
1. ETH oracle last updated at timestamp T
2. Current timestamp is T + 61 seconds (ETH oracle now stale)
3. SUI and USDC oracles are current and valid
4. User attempts to withdraw 50 SUI (safe withdrawal, would maintain 180% collateralization)

**Expected Result**: Withdrawal succeeds, user receives 50 SUI, health factor remains > 1.0

**Actual Result**: 
- `execute_withdraw` calls `is_health`
- `is_health` calls `user_health_factor`
- `user_health_factor` calls `user_health_collateral_value`
- Loop processes: SUI (✓), USDC (✓), ETH (✗ assertion fails)
- Transaction aborts with error: `invalid_price()`
- User cannot withdraw, funds are locked

**Liquidation DoS**:
1. User becomes underwater (health factor = 0.8) due to market movement
2. ETH oracle goes stale (same as above)
3. Liquidator attempts to liquidate, repaying USDC debt to seize SUI collateral
4. `execute_liquidate` checks `is_health` to verify user is unhealthy
5. Same failure: ETH oracle invalid → transaction aborts
6. Position cannot be liquidated, accumulates bad debt
7. Protocol insolvency risk increases

**Notes**

The vulnerability exists identically in both `lending_core::dynamic_calculator` and `lending_ui::calculator` modules, affecting all health calculations throughout the protocol. The issue is exacerbated when protocols integrate with multiple oracles and support many assets, as the probability of at least one oracle failure at any moment increases proportionally.

This is a systemic availability issue that converts oracle fragility into protocol-wide DoS, violating the principle that isolated component failures should not cascade into complete system failure.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/dynamic_calculator.move (L96-110)
```text
        while (i < len) {
            let asset_t = vector::borrow(&c, i);
            // let ltv = storage::get_asset_ltv(storage, *asset_t); // ltv for coin

            let estimate_value_t = 0;
            if (asset == *asset_t) {
                estimate_value_t = estimate_value;
            };

            // TotalCollateralValue = CollateralValue * LTV * Threshold
            let collateral_value = dynamic_user_collateral_value(clock, oracle, storage, *asset_t, user, estimate_value_t, is_increase); // total collateral in usd
            // value = value + ray_math::ray_mul(collateral_value, ltv);
            value = value + collateral_value;
            i = i + 1;
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L193-197)
```text
        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L91-91)
```text
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L154-155)
```text
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L212-212)
```text
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L429-438)
```text
        while (i < len) {
            let asset = vector::borrow(&collaterals, i);
            // let ltv = storage::get_asset_ltv(storage, *asset); // ltv for coin

            // TotalCollateralValue = CollateralValue * LTV * Threshold
            let collateral_value = user_collateral_value(clock, oracle, storage, *asset, user); // total collateral in usd
            // value = value + ray_math::ray_mul(collateral_value, ltv);
            value = value + collateral_value;
            i = i + 1;
        };
```
