### Title
Oracle Price Threshold Invariant Violation Allows Bypassing Price Validation

### Summary
The invariant `threshold1 <= threshold2` can be violated due to a conditional check in `set_price_diff_threshold1_to_price_feed` that is skipped when `threshold2 = 0`. This allows an admin to set `threshold1` to any value greater than `threshold2`, breaking the price validation logic in `strategy::validate_price_difference` and allowing oracle price differences that should be rejected to be accepted as normal.

### Finding Description

The vulnerability exists in the threshold update functions in `config.move`: [1](#0-0) 

The function `set_price_diff_threshold1_to_price_feed` only validates the invariant when `threshold2 > 0` (line 300). If `threshold2 = 0`, the assertion is skipped, allowing `threshold1` to be set to any value.

In contrast, `set_price_diff_threshold2_to_price_feed` unconditionally validates: [2](#0-1) 

This creates an asymmetry that allows the invariant to be violated.

Additionally, the `new_price_feed` function does not validate the invariant during creation: [3](#0-2) 

The price validation logic relies on this invariant in `strategy::validate_price_difference`: [4](#0-3) 

When `threshold1 > threshold2`, the logic breaks because:
- Line 12: `if (diff < threshold1)` returns `level_normal()` 
- Line 13: `if (diff > threshold2)` returns `level_critical()`

For a price difference between `threshold2` and `threshold1`, line 12 evaluates to true (since `diff < threshold1`), returning `level_normal()` when it should return `level_critical()` (since `diff > threshold2`).

The oracle price update logic rejects prices based on severity: [5](#0-4) 

### Impact Explanation

**Security Integrity Impact - Critical Oracle Validation Bypass:**

When the invariant is violated (e.g., `threshold1 = 100`, `threshold2 = 50`), price differences between 50 and 100 that should trigger `level_critical()` and be rejected are instead treated as `level_normal()` and accepted. This bypasses the oracle's price deviation safety mechanism.

**Direct Fund Impact:**

The vault relies on oracle prices for USD valuation of assets, which determines share calculations for deposits/withdrawals. Accepting oracle prices with excessive deviations can lead to:
- Incorrect vault share valuations
- Users receiving more/fewer shares than they should
- Loss of funds for existing vault participants

**Severity Justification:**

This is HIGH severity because it:
1. Completely bypasses a critical security control (price deviation limits)
2. Can lead to direct financial losses through incorrect valuations
3. Affects all vault operations that depend on oracle prices
4. The oracle system is designed specifically to prevent accepting bad prices

### Likelihood Explanation

**Reachable Entry Point:**

The functions are admin-gated through `OracleAdminCap`: [6](#0-5) 

**Attack Complexity - Low:**

The attack requires only admin privileges and can occur through:

1. **During Creation:** Admin creates a PriceFeed with `threshold1 = 100`, `threshold2 = 0`
2. **During Updates:** 
   - Initial state: `threshold1 = 0`, `threshold2 = 0`
   - Update `threshold1` to 100 (check skipped because `threshold2 = 0`)
   - Final state: `threshold1 = 100`, `threshold2 = 0` (invariant violated)

**Feasibility - High:**

While this requires admin action, it is a configuration error vulnerability that:
- Can happen accidentally during legitimate configuration
- Is not prevented by any validation checks
- Persists until manually corrected
- No warnings or safeguards exist

**Detection Difficulty:**

The vulnerability is silent - there are no events or checks that would alert operators that the invariant has been violated. Price updates will succeed when they should fail, with no indication of the misconfiguration.

### Recommendation

Add unconditional invariant validation in `set_price_diff_threshold1_to_price_feed`:

```move
public(friend) fun set_price_diff_threshold1_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
    assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
    let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
    let before_value = price_feed.price_diff_threshold1;
    
    // Remove conditional check - always validate invariant
    assert!(value <= price_feed.price_diff_threshold2, error::invalid_value());

    price_feed.price_diff_threshold1 = value;
    emit(PriceFeedSetPriceDiffThreshold1 {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
}
```

Add validation in `new_price_feed`:

```move
public(friend) fun new_price_feed<CoinType>(
    // ... parameters ...
) {
    assert!(!is_price_feed_exists<CoinType>(cfg, oracle_id), error::price_feed_already_exists());
    
    // Add invariant check before creating feed
    assert!(price_diff_threshold1 <= price_diff_threshold2, error::invalid_value());
    
    // ... rest of function ...
}
```

Add test cases:
1. Verify that setting `threshold1 > threshold2` fails
2. Verify that creating a feed with `threshold1 > threshold2` fails  
3. Verify that updating thresholds maintains the invariant in all sequences

### Proof of Concept

**Initial State:**
- Create OracleConfig
- Create PriceFeed with `threshold1 = 0`, `threshold2 = 0`

**Exploit Sequence:**

1. Admin calls `oracle_manage::set_price_diff_threshold1_to_price_feed(feed_id, 10000)`
   - Function checks: `if (0 > 0)` → false, assertion skipped
   - `threshold1` set to 10000
   - State: `threshold1 = 10000`, `threshold2 = 0`

2. Oracle price update with primary_price = 100, secondary_price = 170
   - Price difference: 70% 
   - Call `validate_price_difference(100, 170, 10000, 0, ...)`
   - Check line 12: `70 < 10000`? → true → returns `level_normal()`
   - Price update **succeeds** (should have been rejected since 70% >> 0%)

**Expected Result:** Price difference of 70% should be rejected (critical level)

**Actual Result:** Price difference of 70% is accepted as normal

**Success Condition:** Invariant `threshold1 <= threshold2` is violated, and excessive price deviations are accepted when they should be rejected.

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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L230-238)
```text
        if (is_primary_price_fresh && is_secondary_price_fresh) { // if 2 price sources are fresh, validate price diff
            let (price_diff_threshold1, price_diff_threshold2) = (config::get_price_diff_threshold1_from_feed(price_feed), config::get_price_diff_threshold2_from_feed(price_feed));
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds_from_feed(price_feed);
            let diff_threshold2_timer = config::get_diff_threshold2_timer_from_feed(price_feed);
            let severity = strategy::validate_price_difference(primary_price, secondary_price, price_diff_threshold1, price_diff_threshold2, current_timestamp, max_duration_within_thresholds, diff_threshold2_timer);
            if (severity != constants::level_normal()) {
                if (severity != constants::level_warning()) { abort 2 };
                start_or_continue_diff_threshold2_timer = true;
            };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L52-60)
```text
    public fun set_price_diff_threshold1_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_price_diff_threshold1_to_price_feed(oracle_config, feed_id, value)
    }

    public fun set_price_diff_threshold2_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_price_diff_threshold2_to_price_feed(oracle_config, feed_id, value)
    }
```
