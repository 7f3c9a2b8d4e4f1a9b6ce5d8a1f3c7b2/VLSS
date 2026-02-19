### Title
Pyth Staleness Validation Bypass Enables Health Check Manipulation via Configurable Staleness Window

### Summary
The oracle system bypasses Pyth's native staleness validation by using `get_price_unsafe()` and relies on a configurable `max_timestamp_diff` parameter with no upper bound validation. When this parameter is set too high, stale Pyth prices reflecting outdated market conditions can be accepted and used for Navi health factor calculations, enabling positions that should be liquidatable to pass health checks.

### Finding Description

The navi_limiter does not directly call `get_price_unsafe_to_target_decimal()`, but the oracle price update mechanism it depends on does bypass Pyth's staleness validation.

**Price Update Flow:**

The oracle system fetches Pyth prices via `oracle_pro::update_single_price()`, which calls `get_price_from_adaptor()`: [1](#0-0) 

At line 178, for Pyth providers, it uses the unsafe variant that bypasses Pyth's native staleness check: [2](#0-1) 

This unsafe function internally calls `pyth::get_price_unsafe()` which skips the clock-based staleness validation that Pyth provides: [3](#0-2) 

The protocol implements custom staleness validation using `max_timestamp_diff`: [4](#0-3) 

**Configuration Vulnerability:**

The `max_timestamp_diff` parameter can be set to any value with no upper bound validation: [5](#0-4) [6](#0-5) 

**Health Check Dependency:**

The navi_limiter health verification depends on these oracle prices: [7](#0-6) 

The health factor calculation retrieves prices from the PriceOracle that was updated with potentially stale Pyth data: [8](#0-7) [9](#0-8) 

**Why Protections Fail:**

Unlike Suilend's implementation which uses Pyth's native staleness check with a 60-second maximum: [10](#0-9) 

Volo's custom implementation allows administrators to set `max_timestamp_diff` to dangerously high values (e.g., 300 seconds or more) without any constraints, accepting Pyth prices that are significantly stale relative to current market conditions.

### Impact Explanation

**Direct Security Impact:**
- Health checks can pass using prices that don't reflect current market conditions
- Positions that should be liquidatable (health factor < threshold) appear healthy with stale prices
- Undercollateralized borrowing enabled during high volatility periods
- Protocol insolvency risk as bad debt accumulates

**Affected Parties:**
- Protocol treasury: Absorbs losses from unliquidated positions
- Healthy borrowers: Subsidize undercollateralized positions
- Liquidators: Miss opportunities for legitimate liquidations

**Severity Justification:**
Critical - This vulnerability directly compromises the core solvency mechanism of the lending protocol. During market crashes or high volatility when Pyth feeds lag behind real prices, attackers can maintain undercollateralized positions that should be liquidated, creating systemic risk.

### Likelihood Explanation

**Attacker Capabilities:**
- Any user with a leveraged Navi position accessed through Volo vault
- Ability to monitor Pyth price feed timestamps and market prices
- Can call `update_single_price()` which is a public function

**Attack Complexity:**
- LOW - Requires only monitoring when Pyth feeds become stale relative to `max_timestamp_diff`
- No special permissions needed
- Standard transaction execution

**Feasibility Conditions:**
- `max_timestamp_diff` configured > 60 seconds (Pyth's typical staleness threshold)
- Market volatility causes price movements while Pyth feeds lag
- Common during network congestion or oracle downtime

**Probability:**
HIGH if `max_timestamp_diff` is misconfigured. Pyth feeds can experience delays during:
- Network congestion on Sui
- High transaction volume periods
- Oracle infrastructure issues
- Cross-chain bridge delays

**Economic Rationality:**
Highly profitable for attackers with large leveraged positions during market downturns. The cost is minimal (one transaction to trigger price update) while the benefit is avoiding liquidation and maintaining access to borrowed assets worth potentially millions of dollars.

### Recommendation

**Immediate Mitigation:**

1. Add strict upper bound validation for `max_timestamp_diff`:
```move
// In config.move set_max_timestamp_diff_to_price_feed()
assert!(value <= 60_000, error::max_timestamp_diff_too_high()); // Max 60 seconds
```

2. Consider using Pyth's native staleness check by switching to the safe variant:
```move
// In oracle_pro.move get_price_from_adaptor()
if (provider == provider::pyth_provider()) {
    // Use pyth_state and clock for native staleness validation
    let (price, timestamp) = oracle::adaptor_pyth::get_price_to_target_decimal(
        clock, pyth_state, pyth_price_info, target_decimal
    );
    return (price, timestamp)
}
```

3. Add emergency circuit breaker when price timestamps deviate significantly from current time:
```move
// In strategy.move
public fun is_oracle_price_fresh_with_circuit_breaker(
    current_timestamp: u64, 
    oracle_timestamp: u64, 
    max_timestamp_diff: u64
): bool {
    if (current_timestamp < oracle_timestamp) {
        return false
    };
    let age = current_timestamp - oracle_timestamp;
    // Hard limit regardless of configuration
    if (age > 120_000) { return false }; // 120 seconds absolute max
    return age < max_timestamp_diff
}
```

4. Add monitoring alerts when `max_timestamp_diff` is set above recommended thresholds.

**Test Cases:**

1. Test that `max_timestamp_diff` cannot be set above 60 seconds
2. Test health check rejection when Pyth price is >60 seconds stale
3. Test that price updates fail gracefully when Pyth feeds are stale
4. Integration test simulating market volatility with lagging oracle feeds

### Proof of Concept

**Initial State:**
- User has Navi position via Volo vault: 10,000 USDC collateral, 8,000 USDC borrowed
- Health factor = 1.25 (healthy)
- `max_timestamp_diff` configured to 300 seconds (5 minutes)
- Current USDC price: $1.00

**Attack Sequence:**

1. **T=0**: Market crash begins, USDC depegs to $0.90
2. **T=30s**: Pyth price feed hasn't updated yet (still shows $1.00)
3. **T=30s**: User's actual health factor = (10,000 * 0.90) / 8,000 = 1.125 (still healthy but borderline)
4. **T=60s**: USDC continues to $0.85, real health factor = 1.06 (should be liquidatable at 1.1 threshold)
5. **T=90s**: Attacker monitors - Pyth still shows $1.00 from T=0
6. **T=90s**: Attacker calls `update_single_price()`:
   - Fetches Pyth price: $1.00 with timestamp T=0
   - Staleness check: (T=90s - T=0) = 90 seconds < 300 seconds ✓ PASSES
   - Price stored as $1.00 with fresh storage timestamp
7. **T=91s**: Health check called via `verify_navi_position_healthy()`:
   - Retrieves price: $1.00 (stale market data)
   - Calculated health factor: 10,000 / 8,000 = 1.25 ✓ PASSES
   - Should FAIL with real price: 8,500 / 8,000 = 1.06 < 1.1 threshold

**Expected Result:** Position should be liquidatable with health factor 1.06

**Actual Result:** Position passes health check with stale $1.00 price showing health factor 1.25, avoiding liquidation and maintaining undercollateralized borrowing position.

**Success Condition:** Health check passes when it should fail, enabling attacker to maintain or withdraw from position that should be liquidated, causing protocol insolvency.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L167-183)
```text
    public fun get_price_from_adaptor(oracle_provider_config: &OracleProviderConfig, target_decimal: u8, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject): (u256, u64) {
        let (provider, pair_id) = (provider::get_provider_from_oracle_provider_config(oracle_provider_config), config::get_pair_id_from_oracle_provider_config(oracle_provider_config));
        if (provider == provider::supra_provider()) {
            let supra_pair_id = oracle::adaptor_supra::vector_to_pair_id(pair_id);
            let (price, timestamp) = oracle::adaptor_supra::get_price_to_target_decimal(supra_oracle_holder, supra_pair_id, target_decimal);
            return (price, timestamp)
        };

        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
        };

        abort error::invalid_oracle_provider()
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L26-37)
```text
    // get_price_unsafe_native: return the price(uncheck timestamp)/decimal(expo)/timestamp from pyth oracle
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L47-53)
```text
    // get_price_unsafe_to_target_decimal: return the target decimal price(uncheck timestamp) and timestamp
    public fun get_price_unsafe_to_target_decimal(pyth_price_info: &PriceInfoObject, target_decimal: u8): (u256, u64) {
        let (price, decimal, timestamp) = get_price_unsafe_native(pyth_price_info);
        let decimal_price = utils::to_target_decimal_value_safe((price as u256), decimal, (target_decimal as u64));

        (decimal_price, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L55-61)
```text
    public fun is_oracle_price_fresh(current_timestamp: u64, oracle_timestamp: u64, max_timestamp_diff: u64): bool {
        if (current_timestamp < oracle_timestamp) {
            return false
        };

        return (current_timestamp - oracle_timestamp) < max_timestamp_diff
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L287-294)
```text
    public(friend) fun set_max_timestamp_diff_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: u64) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.max_timestamp_diff;

        price_feed.max_timestamp_diff = value;
        emit(PriceFeedSetMaxTimestampDiff {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L47-50)
```text
    public fun set_max_timestamp_diff_to_price_feed(_: &OracleAdminCap, oracle_config: &mut OracleConfig, feed_id: address, value: u64) {
        config::version_verification(oracle_config);
        config::set_max_timestamp_diff_to_price_feed(oracle_config, feed_id, value)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L40-48)
```text
        // check current sui time against pythnet publish time. there can be some issues that arise because the
        // timestamps are from different sources and may get out of sync, but that's why we have a fallback oracle
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
```
