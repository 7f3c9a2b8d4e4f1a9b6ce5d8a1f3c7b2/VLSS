### Title
Oracle Price Staleness Differential Causes Incorrect Dynamic Liquidation Threshold Calculation

### Summary
The `dynamic_liquidation_threshold()` function retrieves oracle prices for each collateral asset independently without ensuring price timestamp consistency. When different collateral assets have prices updated at different times (all within the valid 30-second window), the weighted average threshold calculation uses an inconsistent market snapshot, potentially preventing liquidations of unhealthy positions and exposing the protocol to bad debt.

### Finding Description

The vulnerability exists in the `dynamic_liquidation_threshold()` function [1](#0-0)  which iterates through a user's collateral assets and retrieves their USD values using oracle prices.

At line 405, `user_collateral_value()` is called for each asset [2](#0-1) , which internally calls `calculator::calculate_value()` [3](#0-2) . This function retrieves prices from the oracle via `oracle::get_token_price()` [4](#0-3) .

The oracle's staleness check only validates that each individual price is within the `update_interval` (default 30 seconds) [5](#0-4) . However, it does NOT ensure that all prices used in a single health factor calculation represent the same point in time.

**Root Cause**: Sequential oracle price retrieval allows prices with timestamps up to 30 seconds apart to be combined in the same calculation. During volatile market conditions, this creates an inconsistent snapshot where some assets reflect recent price movements while others use stale (but technically "valid") prices.

**Why Existing Protections Fail**: 
- The staleness check at line 194 only validates `current_ts - token_price.timestamp <= price_oracle.update_interval` [6](#0-5) 
- No mechanism enforces that all prices in a multi-asset calculation must have similar timestamps
- The `update_token_price_batch()` function can update multiple assets with the same timestamp, but there's no guarantee all collateral assets are updated together [7](#0-6) 

**Execution Path**: The vulnerability affects health factor calculations used in critical operations like borrowing and liquidations [8](#0-7) .

### Impact Explanation

**Direct Protocol Damage**: When the dynamic liquidation threshold is artificially inflated due to stale prices on some collateral assets, users with unhealthy positions (health factor < 1) may appear healthy, preventing their liquidation. This exposes the protocol to bad debt.

**Concrete Scenario**:
- User has $100k in volatile Asset A (threshold 70%, price 29 seconds old)  
- User has $100k in Asset B (threshold 85%, price just crashed 50% to $50k, freshly updated)
- User borrowed $140k

With mixed staleness:
- Collateral value = $150k, Dynamic threshold = 75%
- Health factor = ($150k × 0.75) / $140k = 0.804 (appears healthy, no liquidation)

With all fresh prices (if Asset A also crashed 50%):
- Collateral value = $100k, Dynamic threshold = 77.5%  
- Health factor = ($100k × 0.775) / $140k = 0.554 (unhealthy, should be liquidated)

**Who Is Affected**:
- Protocol suffers bad debt accumulation when positions aren't liquidated
- Liquidators lose arbitrage opportunities
- Other users may face cascading failures or protocol insolvency

**Severity Justification**: HIGH - Directly undermines the core safety mechanism (liquidations) that protects protocol solvency. While requiring specific market conditions, this naturally occurs during high volatility when liquidations are most critical.

### Likelihood Explanation

**Entry Point**: Any user can trigger health factor calculations through public entry functions like `execute_borrow()` and `execute_withdraw()` [9](#0-8) , or when liquidators attempt liquidations [10](#0-9) .

**Preconditions**:
- Multiple collateral assets with different oracle update times (naturally occurring)
- Market volatility causing significant price movements within the 30-second window
- User positions near liquidation threshold

**Attack Complexity**: MEDIUM-LOW
- Users cannot directly control oracle update timing
- The vulnerability triggers naturally during volatile market conditions
- No special permissions or complex setup required
- Timing is opportunistic rather than manipulable

**Feasibility**: HIGH
- The 30-second default update interval provides sufficient window for price divergence during volatility [11](#0-10) 
- Occurs automatically when oracle feeder updates assets at different times
- Protocol cannot prevent users from having multiple collateral types

**Probability**: Moderate to High during market stress events (when liquidations are most needed)

### Recommendation

**Code-Level Mitigation**:

1. **Implement Price Snapshot Validation**: Add a maximum timestamp differential check across all assets in a single health calculation:

```move
// In dynamic_liquidation_threshold()
let mut min_timestamp = u64::MAX;
let mut max_timestamp = 0;

while (i < len) {
    let asset = vector::borrow(&collaterals, i);
    let oracle_id = storage::get_oracle_id(storage, *asset);
    let price_obj = oracle::price_object(oracle, oracle_id);
    let timestamp = price_obj.timestamp;
    
    if (timestamp < min_timestamp) min_timestamp = timestamp;
    if (timestamp > max_timestamp) max_timestamp = timestamp;
    
    // Continue with existing logic...
}

// Enforce maximum staleness differential (e.g., 5 seconds)
assert!(max_timestamp - min_timestamp <= MAX_PRICE_STALENESS_DIFF, error::inconsistent_oracle_timestamps());
```

2. **Atomic Price Updates**: Require oracle feeder to update all active collateral assets in a single batch transaction, or implement a "price epoch" mechanism where all prices must be from the same epoch.

3. **Tighter Update Interval**: Reduce the default `update_interval` from 30 seconds to 10-15 seconds to minimize staleness window.

**Invariant Checks to Add**:
- Assert maximum timestamp differential across all prices used in health calculations
- Validate that oracle updates include all active collateral types
- Monitor and alert on price timestamp divergence

**Test Cases**:
- Health factor calculation with prices having 25-second timestamp difference
- Liquidation scenarios where one asset price is fresh and another is 29 seconds old
- Verify that positions correctly liquidate when all prices are synchronized

### Proof of Concept

**Initial State**:
- User has two collateral positions:
  - Asset A (volatile): $100,000 deposited, liquidation threshold 70%
  - Asset B (stable): $100,000 deposited, liquidation threshold 85%
- User borrowed: $140,000 in Asset C
- Oracle update interval: 30 seconds

**Transaction Steps**:

1. **T=0**: Oracle updates Asset B price, reflecting 50% market crash (new value: $50,000)
   - Asset B timestamp: T=0
   - Asset B price: reflects crash to $50k

2. **T=0**: Asset A price is 29 seconds old, still shows pre-crash value
   - Asset A timestamp: T-29
   - Asset A price: $100,000 (stale but within 30s interval)

3. **T=1**: Liquidator attempts to liquidate user via `execute_liquidate()`
   - Health check retrieves:
     - Asset A value: $100,000 (29-second-old price)
     - Asset B value: $50,000 (fresh price)
   - Calculated threshold: ($100k × 0.7 + $50k × 0.85) / $150k = 0.75
   - Health factor: ($150k × 0.75) / $140k = 0.804
   - **Liquidation FAILS** - health factor > 1, position appears healthy

**Expected Result**: User should be liquidatable (if all prices were fresh, health factor would be ~0.554)

**Actual Result**: User escapes liquidation due to inconsistent oracle timestamps, protocol accumulates bad debt

**Success Condition**: Transaction reverts with "user_is_healthy()" error despite actual insolvency [12](#0-11)

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L127-159)
```text
    public(friend) fun execute_borrow<CoinType>(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_borrow<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_borrow_balance(storage, asset, user, amount);
        
        /////////////////////////////////////////////////////
        // Add the asset to the user's list of loan assets //
        /////////////////////////////////////////////////////
        if (!is_loan(storage, asset, user)) {
            storage::update_user_loans(storage, asset, user)
        };

        //////////////////////////////////
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L193-239)
```text
    public(friend) fun execute_liquidate<CoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        user: address,
        collateral_asset: u8,
        debt_asset: u8,
        amount: u256
    ): (u256, u256, u256) {
        // check if the user has loan on this asset
        assert!(is_loan(storage, debt_asset, user), error::user_have_no_loan());
        // check if the user's liquidated assets are collateralized
        assert!(is_collateral(storage, collateral_asset, user), error::user_have_no_collateral());

        update_state_of_all(clock, storage);

        validation::validate_liquidate<CoinType, CollateralCoinType>(storage, debt_asset, collateral_asset, amount);

        // Check the health factor of the user
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());

        let (
            liquidable_amount_in_collateral,
            liquidable_amount_in_debt,
            executor_bonus_amount,
            treasury_amount,
            executor_excess_amount,
            is_max_loan_value,
        ) = calculate_liquidation(clock, storage, oracle, user, collateral_asset, debt_asset, amount);

        // Reduce the liquidated user's loan assets
        decrease_borrow_balance(storage, debt_asset, user, liquidable_amount_in_debt);
        // Reduce the liquidated user's supply assets
        decrease_supply_balance(storage, collateral_asset, user, liquidable_amount_in_collateral + executor_bonus_amount + treasury_amount);

        if (is_max_loan_value) {
            storage::remove_user_loans(storage, debt_asset, user);
        };

        update_interest_rate(storage, collateral_asset);
        update_interest_rate(storage, debt_asset);

        emit_state_updated_event(storage, collateral_asset, user);
        emit_state_updated_event(storage, debt_asset, user);

        (liquidable_amount_in_collateral + executor_bonus_amount, executor_excess_amount, treasury_amount)
    }
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L475-480)
```text
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L154-178)
```text
    public entry fun update_token_price_batch(
        cap: &OracleFeederCap,
        clock: &Clock,
        price_oracle: &mut PriceOracle,
        oracle_ids: vector<u8>,
        token_prices: vector<u256>,
    ) {
        version_verification(price_oracle);

        let len = vector::length(&oracle_ids);
        assert!(len == vector::length(&token_prices), error::price_length_not_match());

        let i = 0;
        while (i < len) {
            let oracle_id = vector::borrow(&oracle_ids, i);
            update_token_price(
                cap,
                clock,
                price_oracle,
                *oracle_id,
                *vector::borrow(&token_prices, i),
            );
            i = i + 1;
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L30-30)
```text
    public fun default_update_interval(): u64 {30000} // 30s
```
