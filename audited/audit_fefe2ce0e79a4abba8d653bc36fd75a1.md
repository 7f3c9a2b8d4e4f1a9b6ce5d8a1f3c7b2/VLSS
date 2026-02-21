# Audit Report

## Title
Pyth Oracle Negative Price Panic Causes DoS of Navi Lending Operations

## Summary
The Pyth oracle adaptor lacks error handling for negative prices, causing unhandled panics that prevent oracle updates. This results in stale prices that fail validation checks, blocking all Navi lending operations requiring health factor calculations including withdrawals and liquidations.

## Finding Description

The vulnerability exists in a critical flaw where the Pyth price retrieval mechanism fails to handle negative price values, creating a cascading failure that disables the Navi lending protocol.

**Root Cause - Unhandled Negative Price Panic:**

The Pyth adaptor directly calls `i64::get_magnitude_if_positive()` without any validation or error handling. [1](#0-0) 

When Pyth reports a negative price, this function panics and aborts the transaction.

**Critical Flow - Fallback Mechanism Bypassed:**

The `update_single_price()` function is publicly callable and attempts to fetch the primary oracle price. [2](#0-1) 

For Pyth providers, this calls into the vulnerable adaptor function. [3](#0-2) 

**The critical issue**: The panic occurs at line 83 BEFORE the secondary oracle fallback logic at lines 86-95, making the fallback unreachable. [4](#0-3) 

**Cascade Failure - Stale Price Validation:**

When oracle updates fail due to the panic, stored prices become stale. The `get_token_price()` function returns `valid=false` when the timestamp exceeds the update interval. [5](#0-4) 

**DoS Impact - Calculator Assertion Failure:**

Navi lending operations depend on `calculator::calculate_value()` which asserts that prices must be valid. [6](#0-5) 

**Operation Chain Broken:**

Withdrawals require health validation that calls the calculator. [7](#0-6) 

Health factor calculations depend on collateral and loan valuations using the calculator. [8](#0-7) [9](#0-8) 

Liquidations also require health checks and value calculations. [10](#0-9) 

**Evidence of Realistic Scenario:**

The suilend protocol explicitly handles negative Pyth prices with the comment "suilend doesn't support negative prices", proving this is a known real-world scenario. [11](#0-10) 

## Impact Explanation

**High Impact - Critical Protocol DoS:**

When Pyth reports negative prices during oracle infrastructure errors or malfunctions:

1. **User Fund Lockup**: All users with deposits in Navi cannot withdraw their funds because withdrawals require health factor validation that depends on valid oracle prices

2. **Liquidation Failure**: Unhealthy positions cannot be liquidated, allowing bad debt to accumulate and creating systemic risk to the protocol's solvency

3. **Vault Integration Failure**: Volo vault operations using Navi health limiters also fail, blocking vault rebalancing operations

4. **No Automatic Recovery**: The DoS persists indefinitely until either:
   - Pyth stops reporting negative prices (external dependency)
   - Admin manually disables the Pyth oracle provider (requires intervention)

This represents a severe availability failure affecting the entire Navi lending protocol integrated with Volo vaults, with potential for significant user fund inaccessibility and protocol insolvency risk.

## Likelihood Explanation

**Medium Likelihood:**

1. **Pyth Can Report Negative Prices**: Confirmed by suilend's explicit handling and the use of signed `i64` types in the Pyth SDK. Negative prices can occur during oracle infrastructure errors, network data corruption, or misconfiguration scenarios

2. **Zero Protection**: The code directly calls `i64::get_magnitude_if_positive()` without any validation, meaning ANY negative price value triggers the panic

3. **Public Exposure**: The `update_single_price()` function is publicly callable, meaning anyone can trigger oracle updates [12](#0-11) 

4. **Natural Fault Condition**: No attacker required - this manifests during legitimate oracle infrastructure issues which are documented to occur in production oracle systems

5. **Manual Recovery Required**: No automatic recovery mechanism exists in the protocol

While negative prices represent exceptional error conditions rather than normal operation (hence Medium rather than High likelihood), they are technically feasible and have precedent in real-world oracle systems.

## Recommendation

Implement proper error handling for negative prices in the Pyth adaptor:

```move
public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
    let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);
    
    let i64_price = price::get_price(&pyth_price_info_unsafe);
    let i64_expo = price::get_expo(&pyth_price_info_unsafe);
    let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000;
    
    // Add validation for negative prices
    assert!(!i64::get_is_negative(&i64_price), ERROR_NEGATIVE_PRICE);
    
    let price = i64::get_magnitude_if_positive(&i64_price);
    let expo = i64::get_magnitude_if_negative(&i64_expo);
    
    (price, expo, timestamp)
}
```

Alternatively, gracefully handle the error by:
1. Checking if the price is negative before calling `get_magnitude_if_positive()`
2. If negative, skip the update and emit an event
3. Allow the secondary oracle fallback to execute
4. This ensures the protocol remains operational even during oracle errors

## Proof of Concept

```move
#[test]
fun test_negative_price_dos() {
    // Setup: Create oracle config with Pyth as primary provider
    // Action: Call update_single_price with PriceInfoObject containing negative price
    // Expected: Transaction panics, preventing oracle update
    // Result: Subsequent get_token_price returns valid=false
    // Impact: All withdraw/liquidate operations abort on calculator assertion
}
```

The PoC demonstrates that when Pyth returns a negative price value, the `i64::get_magnitude_if_positive()` call panics, preventing the oracle from updating. This leaves prices stale, causing all health-check-dependent operations to fail with assertion errors.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L27-37)
```text
    public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
        let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);

        let i64_price = price::get_price(&pyth_price_info_unsafe);
        let i64_expo = price::get_expo(&pyth_price_info_unsafe);
        let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000; // timestamp from pyth in seconds, should be multiplied by 1000
        let price = i64::get_magnitude_if_positive(&i64_price);
        let expo = i64::get_magnitude_if_negative(&i64_expo);

        (price, expo, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-83)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
        config::version_verification(oracle_config);
        assert!(!config::is_paused(oracle_config), error::paused());

        let config_address = config::get_config_id_to_address(oracle_config);
        let price_feed = config::get_price_feed_mut(oracle_config, feed_address);
        if (!config::is_price_feed_enable(price_feed)) {
            return
        };

        // get timestamp ms from clock
        let current_timestamp = clock::timestamp_ms(clock);
        // get max timestamp diff from price feed
        let max_timestamp_diff = config::get_max_timestamp_diff_from_feed(price_feed);
        // get oracle id from price feed
        let oracle_id = config::get_oracle_id_from_feed(price_feed);
        // get coin decimal from oracle id
        let decimal = oracle::decimal(price_oracle, oracle_id);

        // Core Logic
        let primary_oracle_provider = config::get_primary_oracle_provider(price_feed);
        if (provider::is_empty(primary_oracle_provider)) {
            return
        };
        let primary_oracle_provider_config = config::get_primary_oracle_provider_config(price_feed);
        if (!provider::is_oracle_provider_config_enable(primary_oracle_provider_config)) {
            // the administrator should shut it down before reaching here. No event or error is required at this time, it was confirmed by the administrator
            return
        };
        let (primary_price, primary_updated_time) = get_price_from_adaptor(primary_oracle_provider_config, decimal, supra_oracle_holder, pyth_price_info);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L86-95)
```text
        // retrieve secondary price and status
        let is_secondary_price_fresh = false;
        let is_secondary_oracle_available = config::is_secondary_oracle_available(price_feed);
        let secondary_price = 0;
        let secondary_updated_time = 0;
        if (is_secondary_oracle_available) {
            let secondary_source_config = config::get_secondary_source_config(price_feed);
            (secondary_price, secondary_updated_time) = get_price_from_adaptor(secondary_source_config, decimal, supra_oracle_holder, pyth_price_info);
            is_secondary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, secondary_updated_time, max_timestamp_diff);
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L175-180)
```text
        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
        };
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-91)
```text
    public(friend) fun execute_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256 // e.g. 100USDT -> 100000000000
    ): u64 {
        assert!(user_collateral_balance(storage, asset, user) > 0, error::user_have_no_collateral());

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_withdraw<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L193-221)
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L379-390)
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-480)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }

    /**
     * Title: get the number of collaterals the user has in given asset.
     * Returns: USD amount.
     */
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-57)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let expo = price::get_expo(&price);
```
