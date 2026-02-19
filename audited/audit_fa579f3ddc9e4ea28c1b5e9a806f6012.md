### Title
Missing Threshold Ordering Validation Allows Oracle Price Manipulation via Inverted Safety Thresholds

### Summary
The `new_price_feed()` function in the oracle config module does not validate that `price_diff_threshold1` is less than or equal to `price_diff_threshold2` during initialization. This allows creation of price feeds with inverted thresholds, causing the oracle's price validation logic to misclassify critical price divergences as normal, permitting acceptance of manipulated or incorrect prices that should be rejected. This directly compromises vault asset valuations and share calculations.

### Finding Description

The vulnerability exists in the `new_price_feed()` function which initializes price feed configurations without validating threshold ordering: [1](#0-0) 

The function directly assigns both thresholds without any comparison check: [2](#0-1) 

This broken invariant causes the `validate_price_difference()` function in strategy.move to malfunction. The validation logic assumes threshold1 < threshold2: [3](#0-2) 

When thresholds are inverted (threshold1 > threshold2), any price difference value falling in the range (threshold2, threshold1) will incorrectly return `level_normal()` at line 12 instead of `level_critical()` at line 13.

The oracle price update flow uses this validation: [4](#0-3) 

When severity is `level_normal()`, the price update is accepted. When severity is `level_critical()` or `level_major()`, the update is rejected (line 118). Therefore, inverted thresholds cause critical price divergences to be accepted when they should be rejected.

While setter functions exist, the `set_price_diff_threshold1_to_price_feed()` only validates ordering when threshold2 is non-zero: [5](#0-4) 

This conditional check at lines 300-302 means if threshold2 is initialized to zero or is very small, the invariant can remain broken even after setter calls.

### Impact Explanation

**Direct Fund Impact**: The vault system relies on oracle prices for all asset valuations. Incorrect oracle prices directly lead to incorrect `total_usd_value` calculations, which determine share prices for deposits and withdrawals. When critical price divergences (indicating potential oracle manipulation or failure) are misclassified as normal and accepted, the vault operates with corrupted price data.

**Concrete Attack Scenario**: 
- Admin initializes price feed with threshold1=2000 (20%) and threshold2=1000 (10%) - inverted values
- Primary oracle reports SUI = $1.00, Secondary oracle reports SUI = $1.15 
- Actual divergence = 15% (should trigger critical rejection as it exceeds 10% threshold2)
- System calculates diff = 1500 basis points
- `validate_price_difference()` evaluates: `1500 < 2000` → returns `level_normal()` 
- Price update accepted with $1.00 despite 15% oracle divergence
- Vault asset valuations use the $1.00 price
- Attacker deposits when real price is higher, withdraws when real price is lower
- Result: Value extraction from vault due to mispriced assets

**Severity**: HIGH - This is a critical security control bypass. The dual-oracle threshold mechanism exists specifically to detect and reject manipulated or failed oracle prices. Inverting thresholds completely disables this protection, allowing acceptance of prices that should be rejected, directly enabling fund theft through mispriced asset valuations.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is triggered through the admin-callable `oracle_manage::create_price_feed()` function: [6](#0-5) 

**Feasible Preconditions**: 
- Requires admin role (OracleAdminCap), but this is a legitimate operational action
- No malicious intent required - simple parameter ordering mistake during initialization
- Test configurations show typical values of threshold1=1000, threshold2=2000: [7](#0-6) 

Accidentally swapping these values (2000, 1000) is a realistic human error.

**Execution Practicality**: 
- Single transaction during price feed initialization
- No complex state setup required
- Broken state persists until admin notices and calls setters to fix
- During this window, all price updates are vulnerable

**Probability**: MEDIUM-HIGH - While requiring admin action, configuration mistakes during deployment are common. The lack of validation makes this error undetectable at initialization time. The impact window extends from initialization until the error is discovered and corrected through setter functions.

### Recommendation

**Immediate Fix**: Add threshold ordering validation in `new_price_feed()`:

```move
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
    
    // ADD THIS VALIDATION
    assert!(price_diff_threshold1 <= price_diff_threshold2, error::invalid_threshold_ordering());
    
    // ... rest of function
}
```

**Additional Hardening**:
1. Remove the conditional check in `set_price_diff_threshold1_to_price_feed()` - always enforce ordering:
```move
assert!(value <= price_feed.price_diff_threshold2, error::invalid_value());
```

2. Add invariant test cases:
```move
#[test]
#[expected_failure(abort_code = error::invalid_threshold_ordering())]
public fun test_inverted_thresholds_rejected() {
    // Attempt to create price feed with threshold1 > threshold2
    // Should abort
}

#[test]
public fun test_price_validation_with_inverted_thresholds() {
    // Verify that with inverted thresholds, critical divergences 
    // are misclassified as normal
}
```

3. Add deployment checklist validation script to verify all existing price feeds have correct threshold ordering.

### Proof of Concept

**Initial State**:
- Oracle system deployed
- Admin has OracleAdminCap
- No price feeds exist yet

**Attack Steps**:

1. **Admin initializes price feed with inverted thresholds** (accidental misconfiguration):
```move
// Admin accidentally swaps the threshold values
oracle_manage::create_price_feed<SUI>(
    &admin_cap,
    &mut oracle_config,
    0, // oracle_id
    60000, // max_timestamp_diff
    2000, // price_diff_threshold1 (20%) - SHOULD BE SMALLER
    1000, // price_diff_threshold2 (10%) - SHOULD BE LARGER
    10000, // max_duration
    2000, // span_percentage
    1000000000000, // max_price
    100000000, // min_price
    60000, // ttl
    ctx
);
```

2. **Price feed created with broken invariant** - no validation error occurs

3. **Oracle price update with 15% divergence**:
    - Primary oracle: 1000000000 (normalized price)
    - Secondary oracle: 1150000000 (15% higher)
    - Both prices fresh and valid

4. **Validation incorrectly passes**:
```move
// validate_price_difference() called with:
// primary_price = 1000000000
// secondary_price = 1150000000  
// threshold1 = 2000 (inverted - should be 1000)
// threshold2 = 1000 (inverted - should be 2000)

// diff = 1500 (15%)
// Line 12: if (diff < threshold1) → if (1500 < 2000) → TRUE
// Returns level_normal() instead of level_critical()
```

5. **Expected Result**: Price update should be REJECTED (15% > 10% threshold2)

6. **Actual Result**: Price update is ACCEPTED as normal (15% < 20% inverted threshold1)

7. **Exploitation**: Vault now has incorrect price. Attacker can:
    - Deposit when oracle shows $1.00 but real price is $1.15 (gets 15% more shares)
    - Withdraw when oracle shows $1.15 but real price is $1.00 (extracts 15% more value)

**Success Condition**: Price update with 15% divergence is accepted when it should be rejected, proving the threshold validation is broken and critical price divergences are misclassified as normal.

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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L100-118)
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
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L24-40)
```text
    public fun create_price_feed<CoinType>(
        _: &OracleAdminCap,
        oracle_config: &mut OracleConfig,
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
        config::version_verification(oracle_config);
        config::new_price_feed<CoinType>(oracle_config, oracle_id, max_timestamp_diff, price_diff_threshold1, price_diff_threshold2, max_duration_within_thresholds, maximum_allowed_span_percentage, maximum_effective_price, minimum_effective_price, historical_price_ttl, ctx)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/global_setup_tests.move (L215-228)
```text
            oracle_manage::create_price_feed<CoinType>(
                &oracle_admin_cap,
                &mut oracle_config,
                oracle_id,
                60 * 1000, // max_timestamp_diff
                1000, // price_diff_ratio1
                2000, // price_diff_ratio2
                10 * 1000, // maximum_allowed_ratio2_ttl
                2000 , // maximum_allowed_span_percentage histroy
                (oracle_lib::pow(10, (decimal as u64)) as u256) * 10, // max price 
                (oracle_lib::pow(10, (decimal as u64)) as u256) / 10, // min price
                60 * 1000, // historical_price_ttl
                ctx
            );
```
