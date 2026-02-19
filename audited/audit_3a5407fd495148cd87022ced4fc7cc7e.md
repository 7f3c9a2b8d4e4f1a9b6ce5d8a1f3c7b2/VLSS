### Title
Historical Price Validation Blocks Legitimate Oracle Updates During Single-Source to Dual-Source Transitions

### Summary
When the secondary oracle becomes temporarily unavailable and the market price moves significantly, the historical price span validation rejects legitimate price updates for up to 60 seconds even when fresh oracle data is available. This causes the oracle to report stale prices that can affect vault operations dependent on accurate asset valuations.

### Finding Description

The vulnerability exists in the interaction between the single-source oracle path and historical price validation in `update_single_price()`. [1](#0-0) 

When only the primary oracle is fresh (secondary unavailable), the function uses `primary_price` as `final_price` and updates the historical price record. [2](#0-1) 

Subsequently, all price updates must pass historical validation that checks if the price change exceeds `maximum_allowed_span_percentage` within the `historical_price_ttl` window (typically 60 seconds). [3](#0-2) 

The validation logic in `strategy::validate_price_range_and_history()` compares any new price against the historical price if within the TTL: [4](#0-3) 

**Root Cause**: The historical price set during a single-source period may not represent market consensus. When the secondary oracle returns or when both oracles agree on a new price, if this new price differs from the single-source historical price by more than the configured span percentage, the update is rejected even though the new price is valid and fresh.

**Execution Path**:
1. Both oracles report $100 → History = ($100, T0)
2. Secondary goes stale; Primary = $100 (fresh) → History = ($100, T1)
3. Market moves; Primary = $80 (fresh), Secondary stale → Historical validation: |$80 - $100| / $100 = 20%
   - If `maximum_allowed_span_percentage` = 1500 (15%): 2000 > 1500 → **REJECTED** at line 153
4. Secondary returns; Primary = $80, Secondary = $80 (both fresh, agree) → Still checks against historical $100
   - If within 60s of T1: amplitude = 20% > 15% → **REJECTED** again
5. After 60s TTL expires: Historical check skipped, update finally succeeds

### Impact Explanation

**Operational Impact**: The oracle can be stuck reporting stale prices for up to `historical_price_ttl` (default 60,000ms) even when one or both oracle sources provide fresh, legitimate price data. [5](#0-4) 

**Affected Operations**: 
- Vault deposit/withdrawal valuations depend on oracle prices for accurate share calculations
- During the 60-second blackout, the vault uses stale prices which can lead to:
  - Users depositing at inflated/deflated prices (receiving incorrect share amounts)
  - Users withdrawing at inflated/deflated prices (receiving incorrect asset amounts)
  - Mispricing during vault operations that rely on real-time asset valuations

**Severity Justification**: Medium severity because:
- Temporary DoS (max 60 seconds) rather than permanent failure
- No direct fund theft, but potential for value extraction during stale pricing window
- Affects core oracle functionality critical to vault operations
- Self-resolves after TTL expiration

The typical configuration uses `maximum_allowed_span_percentage = 2000` (20%) [6](#0-5)  and `historical_price_ttl = 60000` (60 seconds). [7](#0-6) 

### Likelihood Explanation

**Reachable Entry Point**: `update_single_price()` is a public function called during normal oracle price updates. [8](#0-7) 

**Feasible Preconditions**:
1. Secondary oracle becomes temporarily unavailable (network issues, oracle downtime, staleness)
2. Market price moves by more than `maximum_allowed_span_percentage` (e.g., >20% for default config)
3. Secondary oracle returns or primary oracle catches up to market price
4. All within the `historical_price_ttl` window (60 seconds)

**Execution Practicality**: This scenario occurs naturally without attacker intervention:
- Oracle availability issues are common in production environments
- Volatile crypto markets can move >20% within 60 seconds
- No special permissions or manipulation required

**Economic Rationality**: Zero cost to trigger - happens organically during normal market conditions and oracle infrastructure issues.

**Probability**: Medium to High in volatile markets with occasional oracle infrastructure issues. The 60-second TTL window is short but realistic for rapid price movements in crypto assets.

### Recommendation

**Code-Level Mitigation**:

1. **Skip historical validation when transitioning states**: Modify the validation logic to detect when the historical price was set during a different oracle availability state (single-source vs dual-source) and either skip or use relaxed validation parameters.

2. **Separate historical tracking per source mode**: Maintain different historical price records for single-source and dual-source states, applying validation only within the same mode.

3. **Reset history on source transitions**: Clear or reset the historical price when transitioning between single-source and dual-source modes.

**Recommended Implementation** (Option 1 - Most Conservative):
```
In oracle_pro.move, before line 139, add:
- Track whether historical price was set during single-source mode
- If current update is dual-source (both fresh) and history was from single-source mode, skip historical validation for this update
- Update history with dual-source price
```

**Invariant Checks to Add**:
- Add event emission when historical validation blocks an update where both oracles agree
- Add monitoring for repeated historical validation failures indicating potential stuck state

**Test Cases**:
1. Test single-source → dual-source transition with price movement exceeding span
2. Test dual-source → single-source → dual-source cycle with price movements
3. Verify updates succeed after TTL expiration
4. Verify legitimate market movements aren't blocked during source transitions

### Proof of Concept

**Initial State**:
- Both oracles configured and enabled
- `historical_price_ttl = 60000` ms (60 seconds)
- `maximum_allowed_span_percentage = 1500` (15%)
- `max_timestamp_diff = 30000` ms (oracle staleness threshold)

**Transaction Sequence**:

**T1 (Time 100,000ms)**: Both oracles fresh at $100
```
Primary: price=$100, timestamp=100,000 (fresh)
Secondary: price=$100, timestamp=100,000 (fresh)
→ Final price: $100
→ History updated: (price=$100, time=100,000)
→ Oracle reports: $100 ✓
```

**T2 (Time 130,000ms)**: Secondary becomes stale
```
Primary: price=$100, timestamp=130,000 (fresh)
Secondary: price=$100, timestamp=100,000 (stale - 30s old)
→ Lines 121-124: Only primary fresh path
→ Final price: $100 (primary)
→ History updated: (price=$100, time=130,000)
→ Oracle reports: $100 ✓
```

**T3 (Time 160,000ms)**: Market moves to $80, primary catches up
```
Primary: price=$80, timestamp=160,000 (fresh)  
Secondary: price=$100, timestamp=100,000 (stale - 60s old)
→ Lines 121-124: Only primary fresh path
→ Final price: $80 (primary)
→ Historical validation (line 139):
  - Historical price: $100 from time 130,000
  - Time diff: 160,000 - 130,000 = 30,000ms < 60,000ms (within TTL)
  - Amplitude: |80 - 100| / 100 × 10000 = 2000 (20%)
  - Check: 2000 > 1500 (maximum_allowed_span_percentage)
  - Result: FAIL
→ Line 153: Return without updating
→ Oracle STUCK at: $100 (STALE) ✗
```

**T4 (Time 170,000ms)**: Secondary returns, both agree at $80
```
Primary: price=$80, timestamp=170,000 (fresh)
Secondary: price=$80, timestamp=170,000 (fresh)
→ Lines 100-120: Both fresh path
→ Primary/secondary diff: 0% (NORMAL severity)
→ Final price: $80 (primary)
→ Historical validation (line 139):
  - Historical price: $100 from time 130,000
  - Time diff: 170,000 - 130,000 = 40,000ms < 60,000ms (within TTL)
  - Amplitude: 2000 (20%) > 1500 (15%)
  - Result: FAIL
→ Line 153: Return without updating
→ Oracle STILL STUCK at: $100 (STALE) ✗
```

**T5 (Time 191,000ms)**: After TTL expiration
```
Primary: price=$80, timestamp=191,000 (fresh)
Secondary: price=$80, timestamp=191,000 (fresh)
→ Historical validation (line 139):
  - Historical price: $100 from time 130,000
  - Time diff: 191,000 - 130,000 = 61,000ms >= 60,000ms
  - Line 44 in strategy.move: TTL expired, historical check SKIPPED
  - Result: PASS
→ History updated: (price=$80, time=191,000)
→ Oracle FINALLY updates to: $80 ✓
```

**Expected Result**: Oracle should update to $80 when fresh data is available (T3 or T4)

**Actual Result**: Oracle stuck at stale $100 price for 61 seconds (from T3 to T5), creating temporary DoS on accurate pricing despite both oracles agreeing on the correct price at T4.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-54)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L121-124)
```text
        } else if (is_primary_price_fresh) { // if secondary price not fresh and primary price fresh
            if (is_secondary_oracle_available) { // prevent single source mode from keeping emitting event
                emit(OracleUnavailable {type: constants::secondary_type(), config_address, feed_address, provider: provider::to_string(config::get_secondary_oracle_provider(price_feed)), price: secondary_price, updated_time: secondary_updated_time});
            };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L139-154)
```text
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L162-162)
```text
        config::keep_history_update(price_feed, final_price, clock::timestamp_ms(clock)); 
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L44-50)
```text
        if (current_timestamp - historical_updated_time < historical_price_ttl) {
            let amplitude = utils::calculate_amplitude(historical_price, price);

            if (amplitude > maximum_allowed_span_percentage) {
                return false
            };
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L44-44)
```text
        historical_price_ttl: u64, // Is there any ambiguity about TTL(Time-To-Live)?
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_config_manage_test.move (L81-82)
```text
            let maximum_allowed_span_percentage = config::get_maximum_allowed_span_percentage(&oracle_config ,feed_id);
            assert!(maximum_allowed_span_percentage == 2000, 0);
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_config_manage_test.move (L111-112)
```text
            let get_historical_price_ttl = config::get_historical_price_ttl(feed);
            assert!(get_historical_price_ttl == 60000, 0);
```
