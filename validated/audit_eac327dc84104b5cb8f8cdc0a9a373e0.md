# Audit Report

## Title
Missing Pyth Confidence Interval Validation Creates Oracle Price Reliability Risk in Navi Lending Integration

## Summary

The Navi protocol's Pyth oracle adaptor fails to validate confidence intervals when fetching prices, accepting potentially unreliable price data with wide uncertainty ranges. This affects health factor calculations used for liquidation decisions in the vault's integrated Navi lending positions. While Suilend's integration in the same codebase properly validates Pyth confidence intervals with a 10% threshold, the Navi oracle adaptor completely ignores this safety metadata.

## Finding Description

The vulnerability exists in the oracle price fetching mechanism used by the Navi lending protocol, which the vault integrates with for lending operations.

**Root Cause:**

The Pyth adaptor extracts only price magnitude, exponent, and timestamp, completely ignoring confidence interval data that Pyth explicitly provides via `price::get_conf()`. [1](#0-0) 

When `oracle_pro.move` fetches Pyth prices, it calls the unsafe price retrieval method without any confidence validation: [2](#0-1) 

**Comparison with Best Practice:**

The Suilend integration in the same codebase demonstrates proper Pyth confidence interval validation, extracting the confidence value and rejecting prices where `conf * MIN_CONFIDENCE_RATIO > price_mag` (ensuring confidence is less than 10% of price): [3](#0-2) 

This establishes that confidence interval validation is considered best practice within the codebase itself.

**Impact Propagation Path:**

The unreliable oracle prices are stored in the PriceOracle object via `oracle_pro::update_single_price()` [4](#0-3)  and subsequently used in health factor calculations through `calculator::calculate_value()` [5](#0-4) 

Health factors are computed using these oracle prices to determine collateral and loan values: [6](#0-5) 

The vault's Navi lending positions are protected by health factor verification through the health limiter: [7](#0-6) 

**Key Distinction:**

Confidence intervals represent **intra-source uncertainty** (how confident Pyth is in its own price from its data sources), which is fundamentally different from the existing **inter-source disagreement** checks (comparing Pyth vs Supra prices). A Pyth price with wide confidence intervals could match Supra's price and pass all existing validations, yet still be unreliable according to Pyth's own assessment.

## Impact Explanation

**Direct Financial Impact:**

During market volatility, Pyth confidence intervals can widen significantly. Without validation:

1. **Overvalued Collateral Risk**: A price with ±30% confidence interval would be accepted at face value, potentially showing lending positions as healthy when the true price uncertainty indicates they may be undercollateralized, leading to bad debt accumulation.

2. **Undervalued Collateral Risk**: Wide confidence intervals in the opposite direction could trigger incorrect liquidations of actually healthy positions.

3. **Vault Position Impact**: The vault's Navi lending positions depend on accurate health factors for maintaining borrowing positions and avoiding liquidation. Incorrect oracle prices directly compromise these critical decisions.

**Severity Assessment:**

- Suilend's 10% confidence threshold represents production-tested best practice within the same codebase
- Pyth provides confidence metadata specifically for safety checks - ignoring it bypasses Pyth's intended safety model
- Affects all lending calculations and liquidation decisions using Pyth oracle prices
- Impacts vault depositors' funds deployed in Navi lending positions

## Likelihood Explanation

**High Likelihood - Natural Occurrence:**

This vulnerability manifests passively during normal market conditions:

1. **No Attacker Required**: Market volatility naturally causes Pyth confidence intervals to widen during flash crashes, low liquidity periods, oracle data source disagreements, and network congestion.

2. **Regular Occurrence**: Volatile market conditions that cause wide confidence intervals occur multiple times per month in crypto markets.

3. **Reachable Entry Point**: Oracle price updates occur through normal protocol operation via `update_single_price()` which is designed to be called regularly to keep prices fresh.

4. **No Detection**: The protocol emits no warnings when accepting prices with wide confidence intervals, providing no visibility to operators.

5. **Opportunistic Exploitation**: While no attack is needed for the vulnerability to manifest, an opportunistic actor could monitor Pyth confidence intervals and time position changes when prices are most unreliable.

## Recommendation

Implement confidence interval validation in the Pyth adaptor following Suilend's approach:

1. Extract confidence interval data using `price::get_conf()` in `adaptor_pyth.move`
2. Validate that `conf * MIN_CONFIDENCE_RATIO <= price_mag` (e.g., with `MIN_CONFIDENCE_RATIO = 10` for 10% threshold)
3. Return an error or use a fallback mechanism when confidence exceeds the threshold
4. Consider emitting events when prices with elevated confidence intervals are encountered
5. Document the confidence threshold as a configurable parameter for different risk profiles

Example fix structure for `adaptor_pyth.move`:
```move
// Add confidence validation
let conf = price::get_conf(&pyth_price_info);
let price_mag = i64::get_magnitude_if_positive(&i64_price);
assert!(conf * MIN_CONFIDENCE_RATIO <= price_mag, error::confidence_too_wide());
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploy a test scenario where Pyth returns a price with confidence interval > 10% of the price magnitude
2. Call `oracle_pro::update_single_price()` with this Pyth price data
3. Observe that the price is accepted and stored without any validation or warning
4. Show that `logic::user_health_factor()` uses this unreliable price for health calculations
5. Demonstrate that positions could be incorrectly assessed as healthy/unhealthy based on the unreliable price

The critical code path is:
- Pyth price with wide confidence → `adaptor_pyth::get_price_unsafe_to_target_decimal()` (no validation) → `oracle_pro::update_single_price()` (stores price) → `calculator::calculate_value()` (uses price) → `logic::user_health_factor()` (makes liquidation decisions) → `navi_limiter::verify_navi_position_healthy()` (enforces health)

**Notes**

- This is a **missing safety check** vulnerability, not a bypassed security control
- The existing validations (staleness checks, primary/secondary price differences, historical price validation) provide complementary but not equivalent protection
- Confidence intervals signal a different type of reliability issue (intra-source uncertainty) than price disagreement (inter-source validation)
- The fact that Suilend validates confidence intervals in the same codebase proves this is recognized best practice, making its absence in Navi integration a genuine security gap
- This affects the Navi protocol integration (local_dependencies/protocol/oracle), which is part of the vault's DeFi integration scope

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L27-36)
```text
    public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
        let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);

        let i64_price = price::get_price(&pyth_price_info_unsafe);
        let i64_expo = price::get_expo(&pyth_price_info_unsafe);
        let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000; // timestamp from pyth in seconds, should be multiplied by 1000
        let price = i64::get_magnitude_if_positive(&i64_price);
        let expo = i64::get_magnitude_if_negative(&i64_expo);

        (price, expo, timestamp)
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-165)
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
        let is_primary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, primary_updated_time, max_timestamp_diff);

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

        // filter primary price and secondary price to get the final price
        let start_or_continue_diff_threshold2_timer = false;
        let final_price = primary_price;
        if (is_primary_price_fresh && is_secondary_price_fresh) { // if 2 price sources are fresh, validate price diff
            let (price_diff_threshold1, price_diff_threshold2) = (config::get_price_diff_threshold1_from_feed(price_feed), config::get_price_diff_threshold2_from_feed(price_feed));
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds_from_feed(price_feed);
            let diff_threshold2_timer = config::get_diff_threshold2_timer_from_feed(price_feed);
            let severity = strategy::validate_price_difference(primary_price, secondary_price, price_diff_threshold1, price_diff_threshold2, current_timestamp, max_duration_within_thresholds, diff_threshold2_timer);
            if (severity != constants::level_normal()) {
                emit (PriceRegulation {
                    level: severity,
                    config_address: config_address,
                    feed_address: feed_address,
                    price_diff_threshold1: price_diff_threshold1,
                    price_diff_threshold2: price_diff_threshold2,
                    current_time: current_timestamp,
                    diff_threshold2_timer: diff_threshold2_timer,
                    max_duration_within_thresholds: max_duration_within_thresholds,
                    primary_price: primary_price,
                    secondary_price: secondary_price,
                });
                if (severity != constants::level_warning()) { return };
                start_or_continue_diff_threshold2_timer = true;
            };
        } else if (is_primary_price_fresh) { // if secondary price not fresh and primary price fresh
            if (is_secondary_oracle_available) { // prevent single source mode from keeping emitting event
                emit(OracleUnavailable {type: constants::secondary_type(), config_address, feed_address, provider: provider::to_string(config::get_secondary_oracle_provider(price_feed)), price: secondary_price, updated_time: secondary_updated_time});
            };
        } else if (is_secondary_price_fresh) { // if primary price not fresh and secondary price fresh
            emit(OracleUnavailable {type: constants::primary_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            final_price = secondary_price;
        } else { // no fresh price, terminate price feed
            emit(OracleUnavailable {type: constants::both_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            return
        };

        // validate final price 
        let (maximum_effective_price, minimum_effective_price) = (config::get_maximum_effective_price_from_feed(price_feed), config::get_minimum_effective_price_from_feed(price_feed));
        let maximum_allowed_span_percentage = config::get_maximum_allowed_span_percentage_from_feed(price_feed);
        let historical_price_ttl = config::get_historical_price_ttl(price_feed);
        let (historical_price, historical_updated_time) = config::get_history_price_data_from_feed(price_feed);

        if (!strategy::validate_price_range_and_history(final_price, maximum_effective_price, minimum_effective_price, maximum_allowed_span_percentage, current_timestamp, historical_price_ttl, historical_price, historical_updated_time)) {
            emit(InvalidOraclePrice {
                config_address: config_address,
                feed_address: feed_address,
                provider: provider::to_string(primary_oracle_provider),
                price: final_price,
                maximum_effective_price: maximum_effective_price,
                minimum_effective_price: minimum_effective_price,
                maximum_allowed_span: maximum_allowed_span_percentage,
                current_timestamp: current_timestamp,
                historical_price_ttl: historical_price_ttl,
                historical_price: historical_price,
                historical_updated_time: historical_updated_time,
            });
            return
        };

        if (start_or_continue_diff_threshold2_timer) {
            config::start_or_continue_diff_threshold2_timer(price_feed, current_timestamp)
        } else {
            config::reset_diff_threshold2_timer(price_feed)
        };
        // update the history price to price feed
        config::keep_history_update(price_feed, final_price, clock::timestamp_ms(clock)); 
        // update the final price to PriceOracle
        oracle::update_price(clock, price_oracle, oracle_id, final_price); 
    }
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L31-38)
```text
        let conf = price::get_conf(&price);

        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
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

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-49)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);

    emit(NaviHealthFactorVerified {
        account,
        health_factor,
        safe_check_hf: min_health_factor,
    });

    let is_healthy = health_factor > min_health_factor;

    // hf_normalized has 9 decimals
    // e.g. hf = 123456 (123456 * 1e27)
    //      hf_normalized = 123456 * 1e9
    //      hf = 0.5 (5 * 1e26)
    //      hf_normalized = 5 * 1e8 = 0.5 * 1e9
    //      hf = 1.356 (1.356 * 1e27)
    //      hf_normalized = 1.356 * 1e9
    let mut hf_normalized = health_factor / DECIMAL_E18;

    if (hf_normalized > DECIMAL_E9) {
        hf_normalized = DECIMAL_E9;
    };

    assert!(is_healthy, hf_normalized as u64);
}
```
