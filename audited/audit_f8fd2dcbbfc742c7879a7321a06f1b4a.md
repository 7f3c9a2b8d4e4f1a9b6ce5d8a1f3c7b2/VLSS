### Title
Oracle Price Validation Becomes Overly Restrictive When threshold2 Set to Zero

### Summary
Setting `price_diff_threshold2` to 0 in the oracle configuration makes price validation EXTREMELY STRICT rather than permissive, causing `get_dynamic_single_price()` to reject any non-zero price difference between primary and secondary sources. While this creates a design flaw that can disable oracle functionality, it requires `OracleAdminCap` and therefore does not meet the vulnerability criteria requiring "no reliance on trusted role compromise."

### Finding Description

**Answer to Security Question:** Setting `price_diff_threshold2` to 0 makes validation **EXTREMELY STRICT** (rejecting any difference), not permissive.

In `get_dynamic_single_price()`, when both primary and secondary prices are fresh, the function validates price differences: [1](#0-0) 

This calls `strategy::validate_price_difference()` with the configured thresholds: [2](#0-1) 

The validation logic calculates price amplitude (difference in basis points): [3](#0-2) 

**Root Cause:** When `threshold2 = 0`:
- Line 12: `if (diff < threshold1)` where `threshold1 = 0` becomes `if (diff < 0)` - never true since diff ≥ 0
- Line 13: `if (diff > threshold2)` where `threshold2 = 0` becomes `if (diff > 0)` - true for ANY non-zero difference
- Any price difference > 0 returns `level_critical` (0), which gets rejected in `get_dynamic_single_price()`
- Only EXACTLY identical prices (diff = 0) would pass through to warning/major levels

**Why Protections Fail:**
The configuration functions allow setting threshold2 to 0 without validation: [4](#0-3) 

The only check is `value >= threshold1`, which allows both thresholds to be 0. The test suite confirms this configuration is permitted: [5](#0-4) 

### Impact Explanation

**Operational Impact:** With threshold2 = 0, the oracle rejects any price feed where primary and secondary sources differ by even 0.01%. Since external oracle sources (Pyth, Supra, Switchboard) rarely return EXACTLY identical prices, this configuration effectively disables the oracle's dual-source validation, causing a denial of service on price feeds.

**Who is Affected:** Any system component relying on `get_dynamic_single_price()` for price data would be unable to obtain valid prices.

**Severity Note:** While this creates a severe operational issue (complete oracle DoS), the impact is limited by the fact that it requires administrative action via `OracleAdminCap`.

### Likelihood Explanation

**Required Preconditions:**
- Administrator must possess `OracleAdminCap`
- Administrator must call `set_price_diff_threshold2_to_price_feed()` with value 0 [6](#0-5) 

**Why This Might Occur:**
- Counter-intuitive behavior: An administrator might assume 0 means "no validation" rather than "maximum strictness"
- No input validation prevents this dangerous configuration
- Test suite includes this configuration, suggesting it may be considered valid

**Attack Complexity:** Not an attack scenario - requires trusted administrator action.

**Likelihood Assessment:** While the misconfiguration is technically possible, it requires action by a trusted role (OracleAdminCap holder), which violates the audit requirement of "no reliance on trusted role compromise."

### Recommendation

**Input Validation:**
Add minimum threshold validation in `config.move`:

```move
public(friend) fun set_price_diff_threshold2_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
    assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
    let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
    let before_value = price_feed.price_diff_threshold2;
    assert!(value >= price_feed.price_diff_threshold1, error::invalid_value());
    assert!(value > 0, error::invalid_value()); // Add this check
    
    price_feed.price_diff_threshold2 = value;
    emit(PriceFeedSetPriceDiffThreshold2 {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
}
```

**Alternative Fix:**
Modify the validation logic in `strategy.move` to handle zero thresholds explicitly, treating 0 as "no validation" rather than "maximum strictness."

**Test Cases:**
Add test cases that verify threshold2 cannot be set to 0, or if zero is intended to be valid, document the behavior clearly and test that only identical prices pass validation.

### Proof of Concept

**Initial State:**
- Oracle configured with primary and secondary price sources
- Both sources are fresh and enabled

**Misconfiguration Steps:**
1. Admin calls `set_price_diff_threshold1_to_price_feed(feed_id, 0)` - succeeds
2. Admin calls `set_price_diff_threshold2_to_price_feed(feed_id, 0)` - succeeds

**Result:**
3. When `get_dynamic_single_price()` is called:
   - Primary price: $2.0000
   - Secondary price: $2.0001 (0.005% difference)
   - `calculate_amplitude()` returns diff = 0 (rounds down) or 1 basis point
   - If diff > 0: `validate_price_difference()` returns `level_critical`
   - `get_dynamic_single_price()` returns `(error::invalid_price_diff(), 0)`
   - Oracle becomes unusable

**Conclusion:** This is a **design flaw** that makes validation extremely strict when threshold2 = 0, but does **NOT qualify as a reportable vulnerability** under the given audit criteria because it requires trusted administrator action (OracleAdminCap), violating the requirement of "no reliance on trusted role compromise."

**Notes:**
- The behavior is EXTREMELY STRICT, not permissive
- This should be documented or prevented through validation
- While operationally significant, it does not meet vulnerability reporting criteria due to trusted role requirement

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_dynamic_getter.move (L62-69)
```text
        if (is_primary_price_fresh && is_secondary_price_fresh) { // if 2 price sources are fresh, validate price diff
            let (price_diff_threshold1, price_diff_threshold2) = (config::get_price_diff_threshold1_from_feed(price_feed), config::get_price_diff_threshold2_from_feed(price_feed));
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds_from_feed(price_feed);
            let diff_threshold2_timer = config::get_diff_threshold2_timer_from_feed(price_feed);
            let severity = strategy::validate_price_difference(primary_price, secondary_price, price_diff_threshold1, price_diff_threshold2, current_timestamp, max_duration_within_thresholds, diff_threshold2_timer);
            if (severity != constants::level_normal()) {
                if (severity != constants::level_warning()) { return (error::invalid_price_diff(), 0)};
            };
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move (L40-57)
```text
    public fun calculate_amplitude(a: u256, b: u256): u64 {
        if (a == 0 || b == 0) {
            return U64MAX
        };
        let ab_diff = abs_sub(a, b);

        // prevent overflow 
        if (ab_diff > sui::address::max() / (constants::multiple() as u256)) {
            return U64MAX
        };

        let amplitude = (ab_diff * (constants::multiple() as u256) / a);
        if (amplitude > (U64MAX as u256)) {
            return U64MAX
        };

        (amplitude as u64)
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

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_config_manage_test.move (L1114-1116)
```text
            let address_vec = config::get_vec_feeds(&oracle_config);
            oracle_manage::set_price_diff_threshold2_to_price_feed(&oracle_admin_cap, &mut oracle_config, *vector::borrow(&address_vec, 0), 0);

```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L57-60)
```text
    public fun set_price_diff_threshold2_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_price_diff_threshold2_to_price_feed(oracle_config, feed_id, value)
    }
```
