### Title
Arithmetic Overflow in Oracle Price Validation Causes Complete Oracle DoS When max_duration_within_thresholds Set to Excessive Values

### Summary
The `set_max_duration_within_thresholds_to_price_feed()` function lacks input validation, allowing `max_duration_within_thresholds` to be set to values approaching `u64::MAX`. When oracle prices enter the warning zone (between threshold1 and threshold2), the timer validation logic performs arithmetic addition that overflows, causing transaction abort and complete denial-of-service on oracle price updates, which cascades to break all vault operations dependent on fresh price data.

### Finding Description

The admin function `set_max_duration_within_thresholds_to_price_feed()` in `oracle_manage.move` accepts a `u64` value without any bounds checking: [1](#0-0) 

This value is stored directly in the `PriceFeed` configuration without validation: [2](#0-1) 

The critical failure occurs in the price difference validation logic in `strategy.move`, which checks if prices have remained in the warning zone (between `threshold1` and `threshold2`) for too long: [3](#0-2) 

When `max_duration_within_thresholds` is set to a very large value (e.g., `u64::MAX = 18446744073709551615`), and prices enter the warning zone causing `ratio2_usage_start_time` to be set to a current timestamp (e.g., `1700000000000` ms), the addition `max_duration_within_thresholds + ratio2_usage_start_time` on line 15 causes arithmetic overflow. In Sui Move, arithmetic overflow results in transaction abort.

The execution path is:

1. Oracle price update calls `oracle_pro::update_single_price()` [4](#0-3) 

2. Which invokes `strategy::validate_price_difference()` at line 104
3. The overflow occurs at line 15 of `strategy.move`, aborting the entire price update transaction

**Root Cause**: Missing input validation on `max_duration_within_thresholds`. Unlike other oracle configuration parameters that have relationship validation (e.g., `threshold1 <= threshold2` at lines 300-302 and 312 of `config.move`), this parameter has no upper bound check. [5](#0-4) [6](#0-5) 

### Impact Explanation

**Operational Impact - Critical DoS**:

1. **Oracle System Failure**: Once `max_duration_within_thresholds` is set to an excessive value and prices enter the warning zone, ALL subsequent price update attempts abort due to arithmetic overflow. The oracle becomes completely non-functional for those price feeds.

2. **Vault Operations Blocked**: The vault system critically depends on fresh oracle prices. Vault operations (deposits, withdrawals, operations) require price data updated within specific intervals. A DoS'd oracle prevents all vault functionality.

3. **Permanent Lock Without Recovery**: The DoS persists as long as oracle prices remain in the warning zone. Since price updates themselves are blocked, the system cannot escape this state through normal operation. Only admin intervention to reduce `max_duration_within_thresholds` can restore functionality.

4. **Multi-Asset Impact**: If any single asset's oracle has this misconfiguration and enters warning zone, it can block operations across the entire multi-asset vault.

The severity is HIGH because this creates a complete operational freeze of core protocol functionality (oracle → vault pipeline) with no automatic recovery mechanism.

### Likelihood Explanation

**Likelihood: Medium to High**

**Reachable Entry Point**: The vulnerability is triggered through the admin-callable `set_max_duration_within_thresholds_to_price_feed()` function followed by normal oracle price updates.

**Feasibility of Misconfiguration**:
- Setting `max_duration_within_thresholds` to `u64::MAX` could occur through admin error, not malicious intent
- An admin might use `u64::MAX` thinking it means "effectively no time limit" or "disabled timer"
- The parameter name doesn't clearly indicate millisecond units or reasonable bounds
- Test configurations show values like `10000` (10 seconds), giving no indication that values near `u64::MAX` cause overflow rather than long timeouts [7](#0-6) 

**No Input Validation Pattern Inconsistency**: The codebase implements validation for related parameters (threshold relationships, price bounds), making the absence of validation here an inconsistency that suggests oversight rather than intentional design.

**Trigger Condition**: Prices entering the warning zone (threshold1 < diff < threshold2) is a normal operational scenario during market volatility or oracle provider divergence - the exact scenario the threshold system was designed to handle.

This is NOT a "trusted role compromise" scenario - it's a configuration error enabled by missing input validation, which is a standard security concern even for admin functions.

### Recommendation

**1. Add Maximum Bounds Validation**:

Implement a reasonable maximum value check in `set_max_duration_within_thresholds_to_price_feed()`:

```move
public(friend) fun set_max_duration_within_thresholds_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
    assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
    
    // Add validation: prevent values that could cause overflow
    // Max reasonable duration: 1 year = 365 * 24 * 60 * 60 * 1000 = 31,536,000,000 ms
    const MAX_DURATION_MS: u64 = 31536000000; // 1 year in milliseconds
    assert!(value <= MAX_DURATION_MS, error::invalid_value());
    
    let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
    let before_value = price_feed.max_duration_within_thresholds;

    price_feed.max_duration_within_thresholds = value;
    emit(PriceFeedSetMaxDurationWithinThresholds {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
}
```

**2. Alternative: Overflow-Safe Arithmetic**:

Modify the validation logic to handle large values gracefully:

```move
public fun validate_price_difference(primary_price: u256, secondary_price: u256, threshold1: u64, threshold2: u64, current_timestamp: u64, max_duration_within_thresholds: u64, ratio2_usage_start_time: u64): u8 {
    let diff = utils::calculate_amplitude(primary_price, secondary_price);

    if (diff < threshold1) { return constants::level_normal() };
    if (diff > threshold2) { return constants::level_critical() };

    // Safe arithmetic: check if duration exceeded without overflow
    if (ratio2_usage_start_time > 0) {
        let elapsed = current_timestamp - ratio2_usage_start_time;
        if (elapsed > max_duration_within_thresholds) {
            return constants::level_major()
        }
    };
    return constants::level_warning()
}
```

**3. Add Test Cases**:

Create tests for boundary conditions:
- Test with `max_duration_within_thresholds` near `u64::MAX`
- Test validation with timer overflow scenarios
- Test recovery after reducing misconfigured value

### Proof of Concept

**Initial State**:
- Oracle system deployed and operational
- Price feed configured with `max_duration_within_thresholds = 10000` (10 seconds)

**Exploitation Steps**:

1. **Admin Misconfigures Parameter**:
   ```move
   oracle_manage::set_max_duration_within_thresholds_to_price_feed(
       &admin_cap, 
       &mut oracle_config, 
       feed_id, 
       18446744073709551615  // u64::MAX
   )
   ```
   ✓ Transaction succeeds - no validation prevents this

2. **Normal Market Conditions - Prices Enter Warning Zone**:
   - Primary oracle reports: `1,000,000` USD
   - Secondary oracle reports: `1,150,000` USD  
   - Difference: `15%` (between threshold1=10% and threshold2=20%)
   - Timer starts: `diff_threshold2_timer = 1700000000000`

3. **DoS Trigger - Next Price Update Attempt**:
   ```move
   oracle_pro::update_single_price(
       &clock,
       &mut oracle_config,
       &mut price_oracle,
       &supra_holder,
       &pyth_info,
       feed_id
   )
   ```
   ✗ Transaction aborts with arithmetic overflow at `strategy::validate_price_difference` line 15
   
   Calculation attempted: `current_timestamp > (18446744073709551615 + 1700000000000)`
   Result: Overflow → Transaction abort

4. **System Impact**:
   - All subsequent price updates fail
   - Vault cannot update asset values
   - Deposits/withdrawals blocked due to stale prices
   - Operations cannot start/complete

**Expected vs Actual Result**:
- **Expected**: Large `max_duration_within_thresholds` allows prices to remain in warning zone for extended period
- **Actual**: Arithmetic overflow causes complete DoS on oracle price updates

**Success Condition for Exploit**: Oracle price update transactions consistently abort when prices are in warning zone, confirmed by transaction failure with arithmetic overflow error.

### Notes

The actual vulnerability differs from the question's premise. The question suggests that setting `max_duration_within_thresholds = u64::MAX` would allow the timer to "never expire," implying prices could stay in the warning zone indefinitely. However, the actual behavior is more severe: the arithmetic overflow causes transaction abort, creating a complete DoS rather than just extended warning-zone tolerance.

This finding demonstrates the importance of input validation even on admin functions, as configuration errors can have cascading operational impacts across interconnected protocol components (oracle → vault dependency chain).

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L62-65)
```text
    public fun set_max_duration_within_thresholds_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_max_duration_within_thresholds_to_price_feed(oracle_config, feed_id, value)
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L318-325)
```text
    public(friend) fun set_max_duration_within_thresholds_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.max_duration_within_thresholds;

        price_feed.max_duration_within_thresholds = value;
        emit(PriceFeedSetMaxDurationWithinThresholds {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L100-120)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_config_manage_test.move (L69-73)
```text
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds(&oracle_config ,feed_id);
            assert!(max_duration_within_thresholds == 10000, 0);

            let max_duration_within_thresholds_2 = config::get_max_duration_within_thresholds_from_feed(feed);
            assert!(max_duration_within_thresholds == max_duration_within_thresholds_2, 0);
```
