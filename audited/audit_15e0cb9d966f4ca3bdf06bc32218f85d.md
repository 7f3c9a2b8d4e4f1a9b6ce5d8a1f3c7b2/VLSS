### Title
Insufficient Price Validation When Switching to Secondary Oracle with Stale Historical Data

### Summary
When the primary oracle becomes stale and the system falls back to the secondary oracle, the price switch occurs with only a freshness check on the secondary price. If the historical price is also stale (beyond `historical_price_ttl`), the amplitude validation against historical data is skipped, allowing acceptance of potentially manipulated secondary prices that only need to satisfy wide min/max bounds.

### Finding Description

In `update_single_price()`, when the primary price is stale but the secondary price is fresh, the code switches to the secondary price at line 127: [1](#0-0) 

This assignment happens based solely on the freshness check of the secondary price (line 94): [2](#0-1) 

After the switch, `validate_price_range_and_history` is called at line 139: [3](#0-2) 

However, this validation function has a critical conditional check - the historical price amplitude validation is ONLY performed if the historical price is within its TTL: [4](#0-3) 

If `current_timestamp - historical_updated_time >= historical_price_ttl`, the entire amplitude check is skipped. The only remaining validations are the min/max effective price bounds: [5](#0-4) 

Test configurations show these bounds are set very wide (100x range - from 0.1x to 10x the base price): [6](#0-5) 

**Root Cause:** When both prices are fresh, the code validates price difference between primary and secondary (lines 100-120). However, when switching to secondary due to primary staleness, there is NO validation comparing the secondary price against the stale primary price, and if the historical price is also stale, no validation against historical data either.

### Impact Explanation

**Concrete Harm:**
- Acceptance of manipulated or erroneous secondary oracle prices without cross-validation
- Price manipulation bounded only by wide min/max effective price limits (100x range in test configs)
- If this oracle is used for asset valuation, incorrect prices could affect:
  - Share price calculations in vault operations
  - Collateral valuations in lending protocols
  - Position valuations in DeFi integrations

**Quantified Risk:**
- With `maximum_allowed_span_percentage` of 2000 (20%), test configuration shows `max_price = 10x` and `min_price = 0.1x`
- An attacker or malfunctioning oracle could provide any price within this 100x range when both primary and historical are stale
- A 50% price deviation would pass all checks if historical price has expired

**Affected Parties:**
- Vault users whose share values depend on oracle prices
- Protocol integrations relying on accurate price feeds

**Severity Justification:** Medium - requires specific preconditions (dual oracle staleness) but has concrete impact if triggered, bounded by configuration limits.

### Likelihood Explanation

**Attack/Failure Scenario:**
1. Primary oracle service experiences downtime (realistic - oracle failures occur)
2. Historical price ages beyond TTL (60 seconds in test config)
3. Secondary oracle is compromised, malfunctions, or experiences price manipulation

**Feasibility:**
- Oracle service disruptions are documented occurrences in DeFi
- Dual oracle failures within the TTL window create the vulnerable state
- No attacker capabilities beyond oracle compromise/malfunction needed
- The secondary oracle freshness check (60s window) is independent of primary status

**Execution Practicality:**
- Exploitable through normal `update_single_price()` call flow
- No special permissions required beyond triggering oracle updates
- Move execution model permits the described state transitions

**Probability:** 
- Low-to-Medium probability depending on oracle infrastructure reliability
- Historical TTL of 60s creates narrow window but realistic under sustained primary failure
- Secondary oracle manipulation/error is the key constraint

### Recommendation

**Immediate Fix:**
Add validation comparing secondary price against stale primary price before accepting the switch:

```move
} else if (is_secondary_price_fresh) { 
    emit(OracleUnavailable {type: constants::primary_type(), ...});
    
    // Add validation: even if primary is stale, check deviation
    if (primary_price > 0) {
        let price_deviation = utils::calculate_amplitude(primary_price, secondary_price);
        let max_deviation_when_stale = config::get_max_deviation_for_stale_switch(price_feed);
        assert!(price_deviation <= max_deviation_when_stale, error::excessive_price_deviation());
    };
    
    final_price = secondary_price;
}
```

**Configuration Enhancement:**
- Add `max_deviation_for_stale_switch` parameter (e.g., 1000 = 10%) stricter than normal `price_diff_threshold2`
- Require manual intervention (pause oracle) when historical price expires during primary failure
- Consider rejecting updates entirely when both primary and historical are stale

**Invariant Checks:**
- Assert that any price switch has at least one valid cross-validation source
- Ensure `validate_price_range_and_history` cannot pass with only min/max bounds for significant deviations

**Test Cases:**
- Test primary stale + historical stale + secondary fresh with extreme secondary value within bounds
- Verify rejection of secondary prices deviating >10% from stale primary
- Test historical TTL expiration during sustained primary failure

### Proof of Concept

**Initial State:**
- Primary oracle: $1.00, timestamp = T
- Secondary oracle: $1.00, timestamp = T  
- Historical price: $1.00, updated_time = T
- Config: `max_timestamp_diff = 60s`, `historical_price_ttl = 60s`, `maximum_allowed_span_percentage = 2000 (20%)`, `min_price = $0.10`, `max_price = $10.00`

**Step 1 (T+30s):** Primary becomes stale
- Call `update_single_price()` at T+30s
- Primary: $1.00, timestamp = T (61s ago, STALE)
- Secondary: $1.00, timestamp = T+30s (fresh)
- Code path: line 125-127, `final_price = $1.00`
- Historical updated to $1.00 at T+30s

**Step 2 (T+120s):** Secondary compromised, historical stale
- Call `update_single_price()` at T+120s
- Primary: $1.00, timestamp = T (STALE, 181s old)
- Secondary: $1.50, timestamp = T+120s (fresh, **50% increase**)
- Historical: $1.00, timestamp = T+30s (90s ago, **STALE**)
- Code path: line 125-127, `final_price = $1.50`

**Validation (line 139):**
- `maximum_effective_price`: $10.00, `$1.50 < $10.00` ✓
- `minimum_effective_price`: $0.10, `$1.50 > $0.10` ✓  
- Historical check: `current_timestamp - historical_updated_time = 90s >= 60s` → **SKIPPED**

**Expected Result:** Price update rejected due to excessive deviation

**Actual Result:** Price $1.50 accepted (50% increase from last validated price) without any cross-validation

**Success Condition:** Oracle price updated to manipulated value despite 50% deviation from previous price, demonstrating acceptance of unvalidated secondary price when safeguards expire.

---

**Notes:**
The vulnerability exists in the oracle validation logic where the fallback to secondary price lacks sufficient cross-validation when historical data ages out. While the impact depends on whether this oracle module is actively used in production (the vault primarily uses Switchboard), the code flaw is demonstrable and would pose risks if deployed. The wide min/max bounds (100x range) are insufficient protection against moderate price manipulation within that range.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L91-94)
```text
        if (is_secondary_oracle_available) {
            let secondary_source_config = config::get_secondary_source_config(price_feed);
            (secondary_price, secondary_updated_time) = get_price_from_adaptor(secondary_source_config, decimal, supra_oracle_holder, pyth_price_info);
            is_secondary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, secondary_updated_time, max_timestamp_diff);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L125-127)
```text
        } else if (is_secondary_price_fresh) { // if primary price not fresh and secondary price fresh
            emit(OracleUnavailable {type: constants::primary_type(), config_address, feed_address, provider: provider::to_string(primary_oracle_provider), price: primary_price, updated_time: primary_updated_time});
            final_price = secondary_price;
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L34-41)
```text
        if (maximum_effective_price > 0 && price > maximum_effective_price) {
            return false
        };

        // check if the price is less than the minimum configuration value
        if (price < minimum_effective_price) {
            return false
        };
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

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/global_setup_tests.move (L224-225)
```text
                (oracle_lib::pow(10, (decimal as u64)) as u256) * 10, // max price 
                (oracle_lib::pow(10, (decimal as u64)) as u256) / 10, // min price
```
