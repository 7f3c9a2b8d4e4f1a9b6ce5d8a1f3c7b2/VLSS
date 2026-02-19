# Audit Report

## Title
Oracle Price Threshold Invariant Violation Allows Bypassing Price Validation

## Summary
The oracle system's price validation logic can be bypassed due to incomplete invariant validation in threshold configuration functions. The critical invariant `threshold1 <= threshold2` can be violated, causing price differences that should trigger `level_critical()` rejection to be incorrectly classified as `level_normal()` and accepted.

## Finding Description

The vulnerability exists in the threshold configuration functions that fail to consistently enforce the invariant `threshold1 <= threshold2`. This invariant is fundamental to the price validation logic in `strategy::validate_price_difference`.

**Vulnerability Path 1 - Missing Validation During Creation:**

The `new_price_feed` function accepts threshold parameters without validating the invariant: [1](#0-0) 

An admin can create a PriceFeed with `threshold1 = 100, threshold2 = 0` directly, and no validation prevents this.

**Vulnerability Path 2 - Conditional Validation During Updates:**

The `set_price_diff_threshold1_to_price_feed` function only validates the invariant when `threshold2 > 0`: [2](#0-1) 

When `threshold2 = 0`, the assertion at line 300 is skipped, allowing `threshold1` to be set to any value. This creates an exploitable path:
1. Set both thresholds to 0
2. Update `threshold1` to any value (e.g., 100) - validation is skipped
3. Final state: `threshold1 = 100, threshold2 = 0` (invariant violated)

In contrast, `set_price_diff_threshold2_to_price_feed` unconditionally validates: [3](#0-2) 

This asymmetry allows the invariant to be violated through specific update sequences.

**Breaking the Price Validation Logic:**

The price validation logic in `strategy::validate_price_difference` relies on this invariant: [4](#0-3) 

When `threshold1 > threshold2` (e.g., `threshold1 = 100, threshold2 = 50`):
- For a price difference of 75:
  - Line 12: `if (75 < 100)` evaluates to TRUE → returns `level_normal()`
  - Line 13 is never evaluated
  - **Expected behavior**: Since `75 > threshold2 (50)`, it should return `level_critical()`

**Impact on Price Updates:**

The severity level determines whether prices are accepted or rejected: [5](#0-4) 

- `level_normal()` or `level_warning()`: Price update proceeds
- `level_critical()` or `level_major()`: Function returns without updating (line 118)

When the invariant is violated, prices with deviations between `threshold2` and `threshold1` are incorrectly classified as `level_normal()`, bypassing the critical safety check.

## Impact Explanation

**Critical Oracle Validation Bypass:**

This vulnerability completely bypasses the oracle's multi-threshold price deviation safety mechanism. The oracle system is designed with two thresholds to provide graduated responses to price deviations:
- Threshold1 (lower): Normal → Warning boundary
- Threshold2 (higher): Warning → Critical boundary

When the invariant is violated, price differences that should be rejected as critical are accepted as normal, defeating this entire safety system.

**Direct Fund Impact:**

The vault system relies on oracle prices for USD valuations that determine:
- Share calculations for deposits/withdrawals
- Asset valuations for operations
- Health factor computations

Accepting oracle prices with excessive deviations can lead to:
- Incorrect share valuations (users receiving too many/few shares)
- Mispriced deposits/withdrawals
- Loss of funds for vault participants

**Severity Justification:**

This is a HIGH severity vulnerability because:
1. It completely disables a critical security control designed to protect against price manipulation
2. Can lead to direct financial losses through incorrect valuations
3. Affects all vault operations dependent on oracle prices
4. The vulnerability persists silently until detected and corrected

## Likelihood Explanation

**Entry Point:**

The configuration functions are accessible to anyone holding the `OracleAdminCap`: [6](#0-5) 

**Feasibility:**

While this requires admin privileges, it is a **configuration error vulnerability** that can occur through:

1. **During Creation**: Admin creates PriceFeed with reversed thresholds
2. **During Updates**: 
   - Set both thresholds to 0 (valid initial state)
   - Update threshold1 to desired value (validation skipped)
   - Invariant is now violated

**Detection Difficulty:**

The vulnerability is silent - there are no events or checks alerting operators that the invariant has been violated. Price updates that should fail will succeed with no indication of the misconfiguration. The existing test suite even includes a test expecting the validation to work, but it doesn't catch the bypass through the zero-threshold path.

**Key Point:**

This is not about assuming a malicious admin. This is about the protocol failing to enforce its own critical invariants through proper validation. Even honest administrators can make configuration mistakes, and the protocol should prevent invalid states through comprehensive validation checks.

## Recommendation

Add unconditional invariant validation in all functions that modify thresholds:

**Fix for `set_price_diff_threshold1_to_price_feed`:**
```move
public(friend) fun set_price_diff_threshold1_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
    assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
    let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
    let before_value = price_feed.price_diff_threshold1;
    
    // FIXED: Unconditionally validate invariant
    assert!(value <= price_feed.price_diff_threshold2, error::invalid_value());

    price_feed.price_diff_threshold1 = value;
    emit(PriceFeedSetPriceDiffThreshold1 {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
}
```

**Fix for `new_price_feed`:**
```move
public(friend) fun new_price_feed<CoinType>(
    cfg: &mut OracleConfig,
    // ... parameters ...
) {
    // ... existing checks ...
    
    // ADD: Validate invariant during creation
    assert!(price_diff_threshold1 <= price_diff_threshold2, error::invalid_value());
    
    // ... rest of function ...
}
```

## Proof of Concept

```move
#[test]
public fun test_threshold_invariant_violation() {
    let scenario = test_scenario::begin(OWNER);
    let ctx = test_scenario::ctx(&mut scenario);
    
    // Initialize oracle system
    oracle::init_for_testing(ctx);
    
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let oracle_admin_cap = test_scenario::take_from_sender<OracleAdminCap>(&scenario);
        oracle_manage::create_config(&oracle_admin_cap, test_scenario::ctx(&mut scenario));
        test_scenario::return_to_sender(&scenario, oracle_admin_cap);
    };
    
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let oracle_config = test_scenario::take_shared<OracleConfig>(&scenario);
        let oracle_admin_cap = test_scenario::take_from_sender<OracleAdminCap>(&scenario);
        
        // Create price feed with both thresholds = 0 (valid)
        oracle_manage::create_price_feed<TEST_COIN>(
            &oracle_admin_cap,
            &mut oracle_config,
            1, // oracle_id
            60000, // max_timestamp_diff
            0, // threshold1 = 0
            0, // threshold2 = 0
            10000,
            2000,
            10000000,
            100000,
            60000,
            test_scenario::ctx(&mut scenario)
        );
        
        let feeds = config::get_vec_feeds(&oracle_config);
        let feed_id = *vector::borrow(&feeds, 0);
        
        // Set threshold1 to 100 (validation skipped because threshold2 = 0)
        oracle_manage::set_price_diff_threshold1_to_price_feed(
            &oracle_admin_cap,
            &mut oracle_config,
            feed_id,
            100
        );
        
        // Verify invariant is violated: threshold1 (100) > threshold2 (0)
        let threshold1 = config::get_price_diff_threshold1(&oracle_config, feed_id);
        let threshold2 = config::get_price_diff_threshold2(&oracle_config, feed_id);
        
        assert!(threshold1 == 100, 0);
        assert!(threshold2 == 0, 0);
        assert!(threshold1 > threshold2, 0); // INVARIANT VIOLATED!
        
        test_scenario::return_to_sender(&scenario, oracle_admin_cap);
        test_scenario::return_shared(oracle_config);
    };
    
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability represents a **logic invariant violation** where the protocol fails to consistently enforce a critical safety invariant. The issue is not about malicious actors but about incomplete validation logic that can lead to silent security degradation. The oracle system's graduated response mechanism (normal → warning → critical) is fundamental to protecting against price manipulation and ensuring vault safety, making this invariant enforcement critical to the protocol's security model.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L215-256)
```text
    public(friend) fun new_price_feed<CoinType>(
        cfg: &mut OracleConfig,
        oracle_id: u8,
        max_timestamp_diff: u64,
        price_diff_threshold1: u64,
        price_diff_threshold2: u64,
        max_duration_within_thresholds: u64,
        maximum_allowed_span_percentage: u64,
        maximum_effective_price: u256,
        minimum_effective_price: u256,
        historical_price_ttl: u64,
        ctx: &mut TxContext,
    ) {
        assert!(!is_price_feed_exists<CoinType>(cfg, oracle_id), error::price_feed_already_exists());

        let uid = object::new(ctx);
        let object_address = object::uid_to_address(&uid);
        let feed = PriceFeed {
            id: uid,
            enable: true, // default is true
            max_timestamp_diff: max_timestamp_diff,
            price_diff_threshold1: price_diff_threshold1,
            price_diff_threshold2: price_diff_threshold2,
            max_duration_within_thresholds: max_duration_within_thresholds,
            diff_threshold2_timer: 0, // default is 0
            maximum_allowed_span_percentage: maximum_allowed_span_percentage,
            maximum_effective_price: maximum_effective_price,
            minimum_effective_price: minimum_effective_price,
            oracle_id: oracle_id,
            coin_type: type_name::into_string(type_name::get<CoinType>()),
            primary: oracle_provider::new_empty_provider(), // default empty provider
            secondary: oracle_provider::new_empty_provider(), // default empty provider
            oracle_provider_configs: table::new<OracleProvider, OracleProviderConfig>(ctx), // default empty
            historical_price_ttl: historical_price_ttl,
            history: History { price: 0, updated_time: 0 }, // both default 0
        };

        table::add(&mut cfg.feeds, object_address, feed);
        vector::push_back(&mut cfg.vec_feeds, object_address);

        emit(PriceFeedCreated {sender: tx_context::sender(ctx), config: object::uid_to_address(&cfg.id), feed_id: object_address})
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L296-306)
```text
    public(friend) fun set_price_diff_threshold1_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.price_diff_threshold1;
        if (price_feed.price_diff_threshold2 > 0) {
            assert!(value <= price_feed.price_diff_threshold2, error::invalid_value());
        };

        price_feed.price_diff_threshold1 = value;
        emit(PriceFeedSetPriceDiffThreshold1 {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L308-316)
```text
    public(friend) fun set_price_diff_threshold2_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.price_diff_threshold2;
        assert!(value >= price_feed.price_diff_threshold1, error::invalid_value());

        price_feed.price_diff_threshold2 = value;
        emit(PriceFeedSetPriceDiffThreshold2 {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L9-20)
```text
    public fun validate_price_difference(primary_price: u256, secondary_price: u256, threshold1: u64, threshold2: u64, current_timestamp: u64, max_duration_within_thresholds: u64, ratio2_usage_start_time: u64): u8 {
        let diff = utils::calculate_amplitude(primary_price, secondary_price);

        if (diff < threshold1) { return constants::level_normal() };
        if (diff > threshold2) { return constants::level_critical() };

        if (ratio2_usage_start_time > 0 && current_timestamp > max_duration_within_thresholds + ratio2_usage_start_time) {
            return constants::level_major()
        } else {
            return constants::level_warning()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L104-120)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L52-59)
```text
    public fun set_price_diff_threshold1_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_price_diff_threshold1_to_price_feed(oracle_config, feed_id, value)
    }

    public fun set_price_diff_threshold2_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_price_diff_threshold2_to_price_feed(oracle_config, feed_id, value)
```
