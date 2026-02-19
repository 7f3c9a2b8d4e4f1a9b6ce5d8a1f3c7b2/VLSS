### Title
Oracle Price Feed Creation Bypasses Relational Parameter Validation Present in Update Functions

### Summary
The oracle module's `new_price_feed` function accepts price feed parameters without validating relational constraints (e.g., `price_diff_threshold1 <= price_diff_threshold2`, `minimum_effective_price <= maximum_effective_price`), while the corresponding setter functions enforce these constraints. This allows creation of oracle feeds with invalid configurations that cause permanent denial of service for price updates.

### Finding Description

**Vulnerability Class Mapping:**
The external report describes inconsistent validation between create and update functions where the create function lacks relational constraint checks present in update functions. The same pattern exists in Volo's oracle configuration.

**Root Cause in Volo:**

In `config::new_price_feed`, parameters are accepted without relational validation: [1](#0-0) 

However, the update functions enforce strict relational constraints:

1. `set_price_diff_threshold1_to_price_feed` validates threshold1 <= threshold2 when threshold2 > 0: [2](#0-1) 

2. `set_price_diff_threshold2_to_price_feed` always validates threshold2 >= threshold1: [3](#0-2) 

3. `set_maximum_effective_price_to_price_feed` always validates maximum >= minimum: [4](#0-3) 

4. `set_minimum_effective_price_to_price_feed` validates minimum <= maximum when maximum > 0: [5](#0-4) 

**Exploit Path:**

1. Admin calls `oracle_manage::create_price_feed` with invalid parameters (e.g., minimum_effective_price = 1000, maximum_effective_price = 100): [6](#0-5) 

2. Price feed is created with inverted price range constraints.

3. When `oracle_pro::update_single_price` attempts to update prices, the validation at line 139 calls `strategy::validate_price_range_and_history`: [7](#0-6) 

4. The validation logic checks if price exceeds maximum or falls below minimum: [8](#0-7) 

5. With inverted constraints (minimum > maximum), ALL prices are rejected: any price above maximum (100) is rejected by line 34-36, and any price below minimum (1000) is rejected by line 39-41, making the entire valid range [100, 1000] unreachable.

6. Price update aborts (line 153), oracle becomes permanently stuck with stale prices.

### Impact Explanation

**High-Confidence Protocol DoS:**
- Oracle price feed becomes permanently unusable for the affected asset
- All vault operations requiring that price feed fail or use stale data
- Lending protocol health calculations become unreliable
- Users cannot execute critical operations (deposits, withdrawals, liquidations) for affected assets
- Protocol availability is permanently compromised until admin intervention with correct configuration

**Severity:** This causes critical protocol functionality failure affecting all users, not just the misconfiguring admin.

### Likelihood Explanation

**Realistic Configuration Error:**
- Requires `OracleAdminCap` but NOT compromised keys - this is an honest admin making a configuration mistake
- Test suite uses correct parameters, so error wouldn't be caught in testing: [9](#0-8) 

- No documentation or inline comments warn about relational constraints
- Parameter relationships are non-obvious (e.g., minimum must be less than maximum)
- The inconsistency between create and update validation makes the constraints discoverable only through failed transactions
- Real-world scenario: Admin enters parameters in wrong order or with decimal errors

### Recommendation

Add relational validation to `config::new_price_feed` matching the constraints in setter functions:

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
    
    // ADD VALIDATION:
    if (price_diff_threshold2 > 0) {
        assert!(price_diff_threshold1 <= price_diff_threshold2, error::invalid_value());
    };
    if (maximum_effective_price > 0) {
        assert!(minimum_effective_price <= maximum_effective_price, error::invalid_value());
    };
    
    // ... rest of function
}
```

### Proof of Concept

**Setup:**
1. Admin has `OracleAdminCap` 
2. Admin intends to set minimum price = 0.1 USDC (1e5) and maximum price = 10 USDC (1e7)
3. Admin accidentally inverts parameters: minimum = 1e7, maximum = 1e5

**Execution:**
```move
oracle_manage::create_price_feed<USDC>(
    &admin_cap,
    &mut oracle_config,
    1, // oracle_id
    60_000, // max_timestamp_diff
    1000, // price_diff_threshold1
    2000, // price_diff_threshold2  
    10_000, // max_duration_within_thresholds
    2000, // maximum_allowed_span_percentage
    100_000, // maximum_effective_price (INVERTED - should be 10_000_000)
    10_000_000, // minimum_effective_price (INVERTED - should be 100_000)
    60_000, // historical_price_ttl
    ctx
);
```

**Result:**
- Price feed created successfully (no validation error)
- All subsequent `oracle_pro::update_single_price` calls fail validation
- Oracle permanently returns stale prices
- Vault operations depending on USDC price fail
- Protocol DoS for all USDC-related functionality

**Impact:** Complete denial of service for the affected asset's price feed, requiring admin to disable and recreate the feed.

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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L336-344)
```text
    public(friend) fun set_maximum_effective_price_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u256) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.maximum_effective_price;
        assert!(value >= price_feed.minimum_effective_price, error::invalid_value());

        price_feed.maximum_effective_price = value;
        emit(PriceFeedSetMaximumEffectivePrice {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L346-356)
```text
    public(friend) fun set_minimum_effective_price_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u256) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.minimum_effective_price;
        if (price_feed.maximum_effective_price > 0) {
            assert!(value <= price_feed.maximum_effective_price, error::invalid_value());
        };

        price_feed.minimum_effective_price = value;
        emit(PriceFeedSetMinimumEffectivePrice {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
    }
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L133-154)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L23-53)
```text
    public fun validate_price_range_and_history(
        price: u256,
        maximum_effective_price: u256,
        minimum_effective_price: u256,
        maximum_allowed_span_percentage: u64,
        current_timestamp: u64,
        historical_price_ttl: u64,
        historical_price: u256,
        historical_updated_time: u64,
    ): bool {
        // check if the price is greater than the maximum configuration value
        if (maximum_effective_price > 0 && price > maximum_effective_price) {
            return false
        };

        // check if the price is less than the minimum configuration value
        if (price < minimum_effective_price) {
            return false
        };

        // check the final price and the history price range is smaller than the acceptable range
        if (current_timestamp - historical_updated_time < historical_price_ttl) {
            let amplitude = utils::calculate_amplitude(historical_price, price);

            if (amplitude > maximum_allowed_span_percentage) {
                return false
            };
        };

        return true
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
