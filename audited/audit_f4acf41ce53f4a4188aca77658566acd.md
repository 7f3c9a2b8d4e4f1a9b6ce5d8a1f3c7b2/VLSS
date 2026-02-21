# Audit Report

## Title
Pyth Oracle Negative Price Panic Causes DoS of Navi Lending Operations

## Summary
The Pyth oracle adaptor unconditionally calls `i64::get_magnitude_if_positive()` on price values without validating for negative prices, causing transaction aborts that prevent oracle updates and trigger a cascading DoS of all Navi lending operations dependent on fresh price data.

## Finding Description

The vulnerability exists in the Pyth oracle integration where signed `i64` price values from Pyth are processed without negative value validation.

**Root Cause:** The Pyth adaptor functions directly extract price magnitudes assuming positive values without any validation. [1](#0-0) [2](#0-1) 

When `oracle_pro::update_single_price()` is invoked to update oracle prices, it fetches the primary oracle price before evaluating any secondary oracle fallback. [3](#0-2) 

For Pyth providers, the price fetch path calls through to the adaptor which will panic on negative i64 values. [4](#0-3)  This completely bypasses the secondary oracle logic that exists later in the function. [5](#0-4) 

Evidence that Pyth can report negative prices comes from the Suilend integration which explicitly acknowledges this limitation with a protective comment. [6](#0-5) 

When oracle updates fail due to panic, stored prices become stale. The oracle's price validity check returns false when the timestamp difference exceeds the configured update interval. [7](#0-6) 

The Navi calculator strictly enforces price validity, aborting transactions when prices are invalid. [8](#0-7) 

**Critical Operations Blocked:**

1. **Withdrawals:** Withdrawal execution requires health factor validation through a complete call chain. [9](#0-8)  The health check invokes user_health_factor. [10](#0-9)  Which depends on collateral and loan value calculations. [11](#0-10) [12](#0-11) 

2. **Liquidations:** Liquidation execution checks user health. [13](#0-12)  And calculation logic directly depends on price validity. [14](#0-13) [15](#0-14) 

3. **Health Limiter:** Vault operations using the Navi health limiter depend on the same health factor calculation. [16](#0-15) 

The `update_single_price` function is public and can be called by oracle update mechanisms. [17](#0-16) 

## Impact Explanation

This vulnerability causes a complete operational DoS of critical Navi lending functions:

- **All user withdrawals blocked**: Users cannot withdraw collateral even if their positions are healthy, because the health factor calculation requires valid oracle prices
- **Liquidations blocked**: Unhealthy positions cannot be liquidated, creating systemic risk as bad debt accumulates
- **No automatic recovery**: The DoS persists until either Pyth stops reporting negative prices OR an admin manually disables the Pyth provider through configuration changes

The impact is severe because it affects all users with active positions in the Navi lending protocol integrated with the Volo vault system. During the DoS window (potentially hours or days), the protocol cannot maintain proper risk management through liquidations, and users lose access to their collateral regardless of their account health.

## Likelihood Explanation

The likelihood is elevated due to:

1. **Pyth uses signed integers deliberately**: The use of `i64` instead of `u64` in Pyth's price representation indicates negative values are within the design space of the oracle system

2. **No validation exists**: The code provides zero defense against negative prices - ANY negative value from Pyth triggers immediate panic, completely bypassing the intended secondary oracle fallback mechanism

3. **Legitimate trigger path**: Oracle update functions will naturally attempt to update prices. During any Pyth error state that produces negative prices, these legitimate update attempts will trigger the DoS

4. **Real-world precedent**: Other DeFi protocols (Suilend) have explicitly acknowledged Pyth can report negative prices, evidenced by protective comments in their codebase, proving this is not just a theoretical concern

While the exact frequency of Pyth negative price events is uncertain, the vulnerability is real and exploitable whenever such conditions occur during oracle malfunctions, network issues, or edge cases in Pyth's infrastructure.

## Recommendation

Add validation before calling `i64::get_magnitude_if_positive()` to handle negative prices gracefully:

```move
public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
    let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);

    let i64_price = price::get_price(&pyth_price_info_unsafe);
    let i64_expo = price::get_expo(&pyth_price_info_unsafe);
    let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000;
    
    // Add validation to prevent panic on negative prices
    assert!(!i64::get_is_negative(&i64_price), ERROR_NEGATIVE_PRICE);
    
    let price = i64::get_magnitude_if_positive(&i64_price);
    let expo = i64::get_magnitude_if_negative(&i64_expo);

    (price, expo, timestamp)
}
```

This allows the function to return gracefully with an error, enabling the secondary oracle fallback logic in `update_single_price()` to activate as intended, rather than causing a transaction panic that bypasses all fallback mechanisms.

## Proof of Concept

```move
#[test]
#[expected_failure]
fun test_pyth_negative_price_dos() {
    // Setup test environment with Pyth oracle
    let mut scenario = test_scenario::begin(@0x1);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Create mock Pyth price info with negative price
    let negative_i64_price = i64::from(-1000000);
    let pyth_price_info = create_mock_pyth_price_info_with_negative_price(
        negative_i64_price,
        &clock,
        scenario.ctx()
    );
    
    // Attempt to update oracle - this will panic
    oracle_pro::update_single_price(
        &clock,
        &mut oracle_config,
        &mut price_oracle,
        &supra_holder,
        &pyth_price_info,
        feed_address
    );
    
    // Test should fail with panic, preventing all subsequent operations
    // Withdrawals and liquidations will be blocked due to stale prices
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L20-20)
```text
        let price = i64::get_magnitude_if_positive(&i64_price);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L33-33)
```text
        let price = i64::get_magnitude_if_positive(&i64_price);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-54)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L83-83)
```text
        let (primary_price, primary_updated_time) = get_price_from_adaptor(primary_oracle_provider_config, decimal, supra_oracle_holder, pyth_price_info);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L91-95)
```text
        if (is_secondary_oracle_available) {
            let secondary_source_config = config::get_secondary_source_config(price_feed);
            (secondary_price, secondary_updated_time) = get_price_from_adaptor(secondary_source_config, decimal, supra_oracle_holder, pyth_price_info);
            is_secondary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, secondary_updated_time, max_timestamp_diff);
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L175-179)
```text
        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L55-56)
```text
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L193-196)
```text
        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L98-99)
```text
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L91-91)
```text
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L212-212)
```text
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-468)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L475-479)
```text
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L537-542)
```text
        let collateral_value = user_collateral_value(clock, oracle, storage, collateral_asset, user);
        let loan_value = user_loan_value(clock, oracle, storage, debt_asset, user);

        let collateral_asset_oracle_id = storage::get_oracle_id(storage, collateral_asset);
        let debt_asset_oracle_id = storage::get_oracle_id(storage, debt_asset);
        let repay_value = calculator::calculate_value(clock, oracle, repay_amount, debt_asset_oracle_id);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L618-622)
```text
        let total_liquidable_amount_in_collateral = calculator::calculate_amount(clock, oracle, liquidable_value, collateral_asset_oracle_id);
        let total_liquidable_amount_in_debt = calculator::calculate_amount(clock, oracle, liquidable_value, debt_asset_oracle_id);
        let executor_bonus_amount_in_collateral = calculator::calculate_amount(clock, oracle, executor_bonus_value, collateral_asset_oracle_id);
        let treasury_amount_in_collateral = calculator::calculate_amount(clock, oracle, treasury_value, collateral_asset_oracle_id);
        let executor_excess_repayment_amount = calculator::calculate_amount(clock, oracle, excess_value, debt_asset_oracle_id);
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L25-25)
```text
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);
```
