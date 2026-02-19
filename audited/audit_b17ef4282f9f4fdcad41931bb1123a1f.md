### Title
Division by Zero in dynamic_liquidation_threshold Due to Missing Collateral Value Check

### Summary
The `dynamic_liquidation_threshold` function in `dynamic_calculator.move` performs division by `collateral_value` without checking if it equals zero, unlike its counterpart implementations in `logic.move` and `lending_ui/calculate.move`. This causes transaction abort when calculating dynamic health factors for users with no collateral, disrupting frontend preview operations and UI functionality.

### Finding Description

The `user_health_collateral_value()` function in `logic.move` returns 0 when a user has no collateral assets. [1](#0-0) 

While this function itself is used safely (division operations check loan value, not collateral value as the divisor), [2](#0-1) 

The related `dynamic_liquidation_threshold` function in `dynamic_calculator.move` has a critical missing check. It directly performs division by `collateral_value` without verifying it's non-zero: [3](#0-2) 

This contrasts with the safe implementation in `logic.move` which includes a zero-check: [4](#0-3) 

And the safe implementation in `lending_ui/calculate.move`: [5](#0-4) 

The `ray_div` function aborts when the divisor is zero: [6](#0-5) 

**Execution Path:**
1. User with no collateral (or UI/frontend) calls `dynamic_health_factor` [7](#0-6) 
2. This calls `dynamic_liquidation_threshold` at line 55-63
3. For a user with no collateral, the loop calculates `collateral_value = 0`
4. Line 261 attempts `ray_math::ray_div(collateral_health_value, 0)` 
5. Transaction aborts with `RAY_MATH_DIVISION_BY_ZERO` (error code 1103)

### Impact Explanation

**Operational Impact:**
- Frontend/UI applications attempting to preview borrow operations for users with no collateral will encounter transaction aborts
- Users exploring the protocol's lending interface before depositing collateral face degraded UX
- Integration partners calling `dynamic_health_factor` for risk assessment receive unexpected failures
- While this doesn't affect actual fund operations (which use `logic.move` functions with proper checks), it creates DoS conditions for legitimate preview/calculation functionality

**Severity Justification:**
Low severity because:
- Limited to read-only preview functions, not core operational flows
- Actual lending operations use different code paths with proper protections
- No direct fund loss or state corruption
- Impact confined to UI/frontend availability rather than protocol safety

### Likelihood Explanation

**Reachability:** The function is public and callable by any address. [8](#0-7) 

**Feasible Preconditions:**
- User has no collateral deposited (common for new users)
- User or frontend attempts to preview potential borrow operations
- No special permissions or state manipulation required

**Execution Practicality:**
- Normal user state triggers the issue
- Common frontend pattern to preview transactions before submission
- Direct function call with standard parameters causes abort

**Probability:** High likelihood of occurrence during normal protocol usage, especially for new users or during frontend development/integration testing.

### Recommendation

Add a zero-check before division in `dynamic_liquidation_threshold` at line 261 of `dynamic_calculator.move`, matching the pattern used in other implementations:

```move
if (collateral_value > 0) {
    ray_math::ray_div(collateral_health_value, collateral_value)
} else {
    0
}
```

**Additional Recommendations:**
1. Add test cases covering edge cases: users with zero collateral attempting to preview borrow operations
2. Consider adding assertion messages to clarify when preview functions return 0 vs valid calculated values
3. Audit all uses of `ray_div` throughout the codebase for similar missing zero-checks
4. Document expected behavior when collateral_value is 0 in function comments

### Proof of Concept

**Initial State:**
- User address has no collateral deposited in the lending protocol
- User attempts to check if they can borrow by calling `dynamic_health_factor`

**Transaction Steps:**
1. Call `dynamic_health_factor<CoinType>` with:
   - `user`: address with no collateral
   - `estimate_supply_value`: 0
   - `estimate_borrow_value`: 100 (attempting to preview borrowing 100 units)
   - `is_increase`: true

**Expected vs Actual Result:**
- **Expected:** Function returns a calculated health factor or 0 to indicate user cannot borrow
- **Actual:** Transaction aborts with error code 1103 (RAY_MATH_DIVISION_BY_ZERO)

**Success Condition:** Transaction completes without abort and returns a numeric result, allowing frontends to display "insufficient collateral" messages rather than encountering transaction failures.

### Citations

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L393-417)
```text
    public fun dynamic_liquidation_threshold(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // Power by Erin
        let (collaterals, _) = storage::get_user_assets(storage, user);
        let len = vector::length(&collaterals);
        let i = 0;

        let collateral_value = 0;
        let collateral_health_value = 0;

        while (i < len) {
            let asset = vector::borrow(&collaterals, i);
            let (_, _, threshold) = storage::get_liquidation_factors(storage, *asset); // liquidation threshold for coin
            let user_collateral_value = user_collateral_value(clock, oracle, storage, *asset, user); // total collateral in usd

            collateral_health_value = collateral_health_value + ray_math::ray_mul(user_collateral_value, threshold);
            collateral_value = collateral_value + user_collateral_value;
            i = i + 1;
        };

        if (collateral_value > 0) {
            return ray_math::ray_div(collateral_health_value, collateral_value)
        };

        0
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/dynamic_calculator.move (L13-72)
```text
    public fun dynamic_health_factor<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        oracle: &PriceOracle,
        pool: &mut Pool<CoinType>,
        user: address,
        asset: u8,
        estimate_supply_value: u64, 
        estimate_borrow_value: u64, 
        is_increase: bool
    ): u256 {
        assert!(!(estimate_supply_value > 0 && estimate_borrow_value > 0), error::non_single_value());
        let normal_estimate_supply_value: u64 = 0;
        if (estimate_supply_value > 0) {
            normal_estimate_supply_value = pool::normal_amount(pool, estimate_supply_value);
        };

        let normal_estimate_borrow_value: u64 = 0;
        if (estimate_borrow_value > 0) {
            normal_estimate_borrow_value = pool::normal_amount(pool, estimate_borrow_value);
        };

        let dynamic_health_collateral_value = dynamic_user_health_collateral_value(
            clock, 
            oracle, 
            storage, 
            user,
            asset,
            (normal_estimate_supply_value as u256),
            is_increase
        );

        let dynamic_health_loan_value = dynamic_user_health_loan_value(
            clock,
            oracle,
            storage,
            user,
            asset,
            (normal_estimate_borrow_value as u256),
            is_increase
        );

        let dynamic_liquidation_threshold = dynamic_liquidation_threshold(
            clock, 
            storage, 
            oracle, 
            user,
            asset,
            (normal_estimate_supply_value as u256),
            is_increase
            ); 

        if (dynamic_health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(dynamic_health_collateral_value, dynamic_health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/dynamic_calculator.move (L222-262)
```text
    public fun dynamic_liquidation_threshold(
        clock: &Clock, 
        storage: &mut Storage, 
        oracle: &PriceOracle, 
        user: address,
        asset: u8, 
        estimate_value: u256, 
        is_increase: bool
    ): u256 {
        // Power by Erin
        let (collaterals, _) = storage::get_user_assets(storage, user);
        let len = vector::length(&collaterals);
        let i = 0;

        let c = collaterals;
        if (!vector::contains(&collaterals, &asset)) {
            vector::push_back(&mut c, asset);
            len = len + 1;
        };

        let collateral_value = 0;
        let collateral_health_value = 0;

        while (i < len) {
            let asset_t = vector::borrow(&c, i);
            let (_, _, threshold) = storage::get_liquidation_factors(storage, *asset_t); // liquidation threshold for coin

            let estimate_value_t = 0;
            if (asset == *asset_t) {
                estimate_value_t = estimate_value;
            };

            let user_collateral_value = dynamic_user_collateral_value(clock, oracle, storage, *asset_t, user, estimate_value_t, is_increase); // total collateral in usd

            collateral_health_value = collateral_health_value + ray_math::ray_mul(user_collateral_value, threshold);
            collateral_value = collateral_value + user_collateral_value;
            i = i + 1;
        };

        ray_math::ray_div(collateral_health_value, collateral_value)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_ui/sources/calculate.move (L217-260)
```text
    public fun dynamic_liquidation_threshold(
        clock: &Clock, 
        storage: &mut Storage, 
        oracle: &PriceOracle, 
        user: address,
        asset: u8, 
        estimate_value: u256, 
        is_increase: bool
    ): u256 {
        let (collaterals, _) = storage::get_user_assets(storage, user);
        let len = vector::length(&collaterals);
        let i = 0;

        let c = collaterals;
        if (!vector::contains(&collaterals, &asset)) {
            vector::push_back(&mut c, asset);
            len = len + 1;
        };

        let collateral_value = 0;
        let collateral_health_value = 0;

        while (i < len) {
            let asset_t = vector::borrow(&c, i);
            let (_, _, threshold) = storage::get_liquidation_factors(storage, *asset_t); // liquidation threshold for coin

            let estimate_value_t = 0;
            if (asset == *asset_t) {
                estimate_value_t = estimate_value;
            };

            let user_collateral_value = dynamic_user_collateral_value(clock, oracle, storage, *asset_t, user, estimate_value_t, is_increase); // total collateral in usd

            collateral_health_value = collateral_health_value + ray_math::ray_mul(user_collateral_value, threshold);
            collateral_value = collateral_value + user_collateral_value;
            i = i + 1;
        };

        if (collateral_value > 0) {
            ray_math::ray_div(collateral_health_value, collateral_value)
        } else {
            0
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L85-92)
```text
    public fun ray_div(a: u256, b: u256): u256 {
        assert!(b != 0, RAY_MATH_DIVISION_BY_ZERO);
        let halfB = b / 2;

        assert!(a <= (address::max() - halfB) / RAY, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * RAY + halfB) / b
    }
```
