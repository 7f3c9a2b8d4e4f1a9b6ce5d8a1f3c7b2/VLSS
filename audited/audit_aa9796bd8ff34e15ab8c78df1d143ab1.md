# Audit Report

## Title
Pyth Oracle Negative Price Panic Causes DoS of Navi Lending Operations

## Summary
The Pyth oracle adaptor lacks error handling for negative prices, causing `i64::get_magnitude_if_positive()` to panic when Pyth reports negative values. This prevents oracle price updates and causes all Navi lending operations requiring health checks (withdrawals and liquidations) to fail due to stale price validation.

## Finding Description

The vulnerability exists in the Pyth price retrieval flow where negative prices cause unhandled panics:

**Root Cause**: The Pyth adaptor directly calls `i64::get_magnitude_if_positive()` without validation or error handling. [1](#0-0) 

**Critical Flow**:

1. `oracle_pro::update_single_price()` is a public function that fetches the primary oracle price at line 83 [2](#0-1) 

2. For Pyth providers, this calls `adaptor_pyth::get_price_unsafe_to_target_decimal()` [3](#0-2) 

3. Which internally calls `get_price_unsafe_native()` that panics on negative prices [4](#0-3) 

4. **Critical**: The panic at line 83 occurs BEFORE the secondary oracle fallback logic (lines 86-95), rendering the fallback mechanism unreachable [5](#0-4) 

**Cascade Failure**:

When oracle updates fail, stored prices become stale. The `get_token_price()` function returns `valid=false` when `current_ts - token_price.timestamp > update_interval`: [6](#0-5) 

Navi lending operations depend on `calculator::calculate_value()` which asserts on invalid prices: [7](#0-6) 

This breaks the entire operation chain:
- Withdrawals require health validation [8](#0-7) 
- Health checks call `user_health_factor()` [9](#0-8) 
- Which depends on collateral/loan value calculations using the calculator [10](#0-9) 

**Evidence that Pyth CAN return negative prices**: The suilend protocol explicitly handles this case with the comment "suilend doesn't support negative prices" [11](#0-10) 

## Impact Explanation

**High Impact - Critical DoS of Lending Operations**:

When Pyth reports negative prices (during oracle errors, malfunctions, or misconfigurations), the following operations become blocked:

1. **User Withdrawals Blocked**: All users lose access to their deposited funds because withdrawal requires health factor validation which depends on valid oracle prices

2. **Liquidations Impossible**: Unhealthy positions cannot be liquidated, creating systemic risk as bad debt accumulates

3. **Health Limiter Failures**: Vault operations using Navi health limiters also fail

4. **No Automatic Recovery**: The DoS persists until either Pyth stops reporting negative prices OR an admin manually disables the Pyth oracle provider

This creates a severe availability issue affecting all Navi lending protocol users integrated with the Volo vault system.

## Likelihood Explanation

**Medium Likelihood**:

1. **Pyth Can Report Negative Prices**: Confirmed by suilend's explicit handling and the use of signed `i64` types in the Pyth SDK. Negative prices can occur during:
   - Oracle infrastructure errors or malfunctions
   - Network data corruption
   - Misconfiguration scenarios

2. **No Validation**: The code directly calls `i64::get_magnitude_if_positive()` without any validation, so ANY negative price triggers the panic

3. **Public Entry Point**: `update_single_price()` is publicly callable [12](#0-11) 

4. **Natural Fault Condition**: No attacker required - this manifests during legitimate oracle infrastructure issues

5. **Recovery Requires Admin Intervention**: No automatic recovery mechanism exists

While negative prices are possible and technically realistic, they represent exceptional error conditions rather than normal operation, hence Medium (not High) likelihood.

## Recommendation

Implement error handling for negative Pyth prices to enable graceful degradation:

```move
public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (Option<u64>, u64, u64) {
    let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);
    let i64_price = price::get_price(&pyth_price_info_unsafe);
    let i64_expo = price::get_expo(&pyth_price_info_unsafe);
    let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000;
    
    // Check if price is negative
    if (i64::get_is_negative(&i64_price)) {
        return (option::none(), 0, timestamp)
    };
    
    let price = i64::get_magnitude_if_positive(&i64_price);
    let expo = i64::get_magnitude_if_negative(&i64_expo);
    
    (option::some(price), expo, timestamp)
}
```

Update `oracle_pro::update_single_price()` to handle None returns and gracefully fall back to secondary oracle or emit an error event without panicking.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a Pyth oracle as the primary price source for an asset
2. Simulating Pyth returning a negative price (via modified Pyth state object in testing)
3. Calling `update_single_price()` which will panic
4. Observing that prices become stale and cannot be updated
5. Attempting withdrawal operations which fail due to stale oracle prices

Due to the dependency on Pyth's external oracle infrastructure, a complete PoC requires either Pyth returning negative values in production or a test environment with mocked Pyth responses returning negative `i64` prices.

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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L48-53)
```text
    public fun get_price_unsafe_to_target_decimal(pyth_price_info: &PriceInfoObject, target_decimal: u8): (u256, u64) {
        let (price, decimal, timestamp) = get_price_unsafe_native(pyth_price_info);
        let decimal_price = utils::to_target_decimal_value_safe((price as u256), decimal, (target_decimal as u64));

        (decimal_price, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-54)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L83-83)
```text
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L193-196)
```text
        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-92)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L55-56)
```text
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```
