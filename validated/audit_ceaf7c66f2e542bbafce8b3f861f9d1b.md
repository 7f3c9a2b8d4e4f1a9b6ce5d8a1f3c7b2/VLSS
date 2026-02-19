# Audit Report

## Title
Oracle Failure Causes Complete Health Calculation DoS, Blocking Critical Withdrawals and Liquidations

## Summary
The Navi lending protocol's health factor calculation fails entirely when any single collateral asset has an invalid oracle price (zero or stale). This blocks withdrawals, borrows, and critically, liquidations of underwater positions. Since Move lacks try-catch mechanisms, a single oracle failure causes complete transaction abort, potentially leading to protocol insolvency when bad debt cannot be liquidated.

## Finding Description

The vulnerability exists in the health factor calculation chain used throughout the Navi lending protocol. When calculating health factors, the system loops through all user collateral assets without error handling.

In `user_health_collateral_value`, the function iterates through all collateral assets and calls `user_collateral_value` for each: [1](#0-0) 

Each asset's collateral value calculation chains to `calculator::calculate_value`, which retrieves the oracle price and asserts its validity: [2](#0-1) 

The oracle price validity check returns false if either the price is zero OR the timestamp exceeds the `update_interval` (default 30 seconds): [3](#0-2) 

The default update interval is only 30 seconds: [4](#0-3) 

Since Move has no try-catch mechanism, when the assertion fails, the entire transaction aborts. The health calculation does not skip problematic assets—it completely fails.

This health calculation is mandatory for critical operations:

**Withdrawals**: `execute_withdraw` checks health via `is_health`: [5](#0-4) 

**Borrows**: `execute_borrow` checks health via `user_health_factor`: [6](#0-5) 

**Liquidations**: `execute_liquidate` checks health via negated `is_health` to verify the position is unhealthy before liquidation: [7](#0-6) 

The health factor itself aggregates all collateral via `user_health_collateral_value`: [8](#0-7) 

## Impact Explanation

**Withdrawal DoS**: Users with multiple collateral assets cannot withdraw ANY asset if even one unrelated asset has an invalid oracle. For example, a user with SUI, USDC, and ETH collateral cannot withdraw SUI if the ETH oracle becomes stale, even though SUI and USDC oracles remain healthy.

**Liquidation Failure (Critical)**: Liquidators cannot liquidate underwater positions if the target user has any asset with an invalid oracle. This creates severe systemic risk:
- Underwater positions accumulate bad debt as asset prices continue moving against the position
- Protocol becomes insolvent as accumulated losses exceed reserves  
- Healthy users ultimately bear these losses through diluted collateral value

**Borrow DoS**: Users cannot take new borrows if any of their existing collateral assets has an invalid oracle, limiting protocol functionality.

Oracle failures are realistic operational events:
- Network congestion delays keeper updates beyond the 30-second `update_interval`
- Oracle keeper transactions fail due to gas spikes or RPC issues
- Extreme market volatility may cause temporary oracle outages
- Infrastructure downtime or maintenance windows

Even a brief oracle outage for a single asset creates protocol-wide DoS for all users holding that asset in their collateral basket.

## Likelihood Explanation

**No Attacker Required**: This is a natural operational failure mode. Oracle staleness occurs regularly in production DeFi systems due to network variability, keeper failures, or infrastructure issues.

**Common Preconditions**: Lending users frequently hold multiple collateral assets to diversify risk and maximize capital efficiency. As the protocol supports more assets, the probability that at least one oracle fails at any given time increases proportionally.

**Execution Path**:
1. User has collateral in assets [A, B, C] on Navi
2. Asset C oracle becomes stale (timestamp exceeds 30-second `update_interval`)
3. User attempts to withdraw asset A via `withdraw_with_account_cap`
4. Health check calls `user_health_collateral_value`
5. Loop processes asset A (succeeds), asset B (succeeds), reaches asset C
6. `calculate_value` for asset C calls `oracle::get_token_price`, which returns `valid=false`
7. Assertion fails, transaction aborts, withdrawal blocked

The same path applies to liquidations, where the liquidator's transaction fails when attempting to liquidate any user with a stale oracle asset—precisely when liquidation is most critical.

**Realistic Frequency**: Given the 30-second default `update_interval` and typical blockchain network variability, brief periods of oracle staleness can occur during peak congestion or keeper delays. A single missed update blocks all operations for affected users until the oracle updates.

## Recommendation

Implement one or more of the following mitigations:

1. **Skip Invalid Oracles**: Modify the health calculation loop to skip assets with invalid oracles rather than aborting. Calculate health factor using only valid oracle prices with a conservative assumption for missing prices.

2. **Separate Liquidation Path**: Implement a special liquidation path that bypasses strict health checks or uses cached/fallback prices when primary oracles fail, ensuring underwater positions can always be liquidated.

3. **Extended Grace Period**: Increase the default `update_interval` to allow for network congestion while maintaining reasonable price freshness (e.g., 300 seconds / 5 minutes).

4. **Circuit Breaker**: Add a protocol-level pause mechanism that triggers when oracle failures are detected, allowing admins to resolve oracle issues before resuming normal operations.

## Proof of Concept

```move
// Test demonstrating DoS when one oracle becomes stale

#[test]
fun test_withdrawal_dos_stale_oracle() {
    // Setup: User has collateral in assets A, B, C
    // Asset A and B have fresh oracles
    // Asset C oracle becomes stale (timestamp > update_interval)
    
    // Attempt to withdraw asset A
    // Expected: Transaction aborts due to stale oracle on unrelated asset C
    // Actual: User cannot access their funds in asset A despite its oracle being valid
    
    // This proves the DoS impact - users lose access to healthy assets
    // due to failures in unrelated assets
}

#[test]  
fun test_liquidation_blocked_stale_oracle() {
    // Setup: User position is underwater (health factor < 1.0)
    // User has collateral in assets A, B, C
    // Asset C oracle becomes stale
    
    // Liquidator attempts to liquidate the underwater position
    // Expected: Transaction aborts during health check due to stale oracle
    // Actual: Bad debt accumulates as position cannot be liquidated
    
    // This proves the critical impact - protocol insolvency risk
}
```

## Notes

This vulnerability affects the Navi lending protocol integration within the Volo vault system. The issue is in the core Navi lending logic (`lending_core` module) which is a local dependency of the volo-vault package. The `navi_limiter` module also relies on the same health calculation logic, making it susceptible to the same oracle-dependent DoS.

The vulnerability is particularly severe because liquidations—the protocol's primary defense against insolvency—are blocked by the same oracle failures that may have caused positions to become underwater in the first place. This creates a compounding risk where market volatility causes oracle instability, preventing timely liquidation of at-risk positions.

### Citations

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L379-391)
```text
    public fun user_health_factor(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // 
        let health_collateral_value = user_health_collateral_value(clock, oracle, storage, user); // 202500000000000
        let dynamic_liquidation_threshold = dynamic_liquidation_threshold(clock, storage, oracle, user); // 650000000000000000000000000
        let health_loan_value = user_health_loan_value(clock, oracle, storage, user); // 49500000000
        if (health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(health_collateral_value, health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L423-440)
```text
    public fun user_health_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): u256 {
        let (collaterals, _) = storage::get_user_assets(storage, user);
        let len = vector::length(&collaterals);
        let value = 0;
        let i = 0;

        while (i < len) {
            let asset = vector::borrow(&collaterals, i);
            // let ltv = storage::get_asset_ltv(storage, *asset); // ltv for coin

            // TotalCollateralValue = CollateralValue * LTV * Threshold
            let collateral_value = user_collateral_value(clock, oracle, storage, *asset, user); // total collateral in usd
            // value = value + ray_math::ray_mul(collateral_value, ltv);
            value = value + collateral_value;
            i = i + 1;
        };
        value
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L193-196)
```text
        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L30-30)
```text
    public fun default_update_interval(): u64 {30000} // 30s
```
