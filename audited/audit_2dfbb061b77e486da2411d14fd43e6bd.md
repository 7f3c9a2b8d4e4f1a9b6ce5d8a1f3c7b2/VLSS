### Title
Oracle Expiration Does Not Invalidate Historical Data - Stale Price Risk During Transition Window

### Summary
After an oracle's `expiration_time_ms` passes, the oracle does not automatically become inactive in a way that invalidates its previously submitted price data. While expired oracles cannot submit new data, their historical submissions remain accessible and can be used by the vault for up to `update_interval` (1 minute default) after expiration, creating a window where stale oracle data may be used during market volatility.

### Finding Description
The oracle expiration mechanism in Switchboard has a design limitation where oracle validity is only checked at data submission time, not at data consumption time.

**Code Locations:**

1. **Oracle expiration is enforced when submitting new data:** [1](#0-0) 

This check prevents expired oracles from submitting new price updates to the aggregator.

2. **Oracle struct stores expiration but doesn't auto-invalidate:** [2](#0-1) 

The `expiration_time_ms` field is stored but no mechanism exists to automatically invalidate past submissions when this time passes.

3. **Vault reads aggregator data without checking oracle expiration:** [3](#0-2) 

The vault's `get_current_price()` function only checks data staleness via `update_interval` (max 1 minute), not whether the oracles that submitted the data are currently expired.

4. **Aggregator filters by data timestamp, not oracle validity:** [4](#0-3) 

The `valid_update_indices()` function filters updates based on timestamp staleness (`max_staleness_ms`) but never checks if the source oracle is still valid (not expired).

**Root Cause:**
The system enforces oracle expiration at the submission boundary but not at the consumption boundary. When an oracle expires:
- New submissions are blocked by the validation check
- Existing data in the aggregator remains accessible
- The vault's staleness check is time-based (`update_interval`), not oracle-validity-based

**Why Protections Fail:**
The `update_interval` check limits the staleness window but doesn't verify oracle validity: [5](#0-4) 

This allows data submitted just before oracle expiration to remain usable for up to 1 minute after expiration.

### Impact Explanation
**Harm Scenario:**
1. Oracle expires at time T
2. Last valid price data was submitted at T-30 seconds
3. Between T and T+60 seconds, market price moves significantly
4. Vault operations during this window use the pre-expiration data
5. Deposits/withdrawals/collateral calculations are based on stale prices

**Quantified Impact:**
- **Time Window**: Up to `update_interval` (1 minute by default) after oracle expiration
- **Affected Operations**: All vault operations that rely on oracle prices (deposits, withdrawals, total value calculations, adaptor operations)
- **Value at Risk**: Depends on market volatility during the 1-minute window; in highly volatile conditions, 1-minute-old prices can diverge significantly from current market prices

**Who Is Affected:**
- Vault depositors/withdrawers who receive incorrect share valuations
- The vault itself if loss tolerance checks use stale prices
- Protocol operations relying on accurate asset valuations

**Severity Justification:**
Medium severity because:
- Impact window is limited but real (1 minute)
- Could lead to incorrect valuations during critical market movements
- No explicit mechanism to invalidate expired oracle data
- Multiple vault operations could be affected simultaneously

### Likelihood Explanation
**Attacker Capabilities:**
This is not an active attack but an operational vulnerability. No special attacker capabilities are required - normal vault users interacting during the vulnerability window would be affected.

**Preconditions:**
1. Oracle must reach its `expiration_time_ms` (currently set to 5 years in deployment scripts): [6](#0-5) 

2. Market conditions must be volatile enough that 1-minute-old data is materially different
3. Vault operations must occur during the transition window

**Complexity:**
Low complexity - no special actions needed, just normal vault operations during the vulnerability window.

**Feasibility Conditions:**
- Moderate likelihood: Oracle expiration is set far in the future (5 years), but operational lapses in renewal processes or emergency situations could trigger this
- Higher likelihood during periods of high market volatility when 1-minute price differences matter
- Detection difficulty: The vault would continue operating normally; stale data usage may go unnoticed

**Probability Reasoning:**
While oracle expiration is designed to be infrequent (5-year intervals), the lack of explicit invalidation creates an operational risk that should be addressed. The probability increases if oracle renewal processes fail or are delayed.

### Recommendation
**Code-Level Mitigation:**

1. **Add oracle expiration check when reading aggregator data:**
Modify `vault_oracle::get_current_price()` to verify that oracles contributing to the aggregator result are still valid. This would require the vault to track which oracles contributed to the current aggregator result and verify their expiration times.

2. **Implement explicit oracle state transitions:**
When `expiration_time_ms` is reached, add a mechanism to mark the oracle as inactive and clear/invalidate its contributions from aggregators. This could be done via:
   - An on-chain keeper that monitors oracle expiration times
   - A state flag in the Oracle struct that gets toggled at expiration
   - Automatic cleanup in aggregator result computation

3. **Add monitoring and alerts:**
Implement off-chain monitoring to alert operators when oracles are approaching expiration (e.g., 30 days before), ensuring proactive renewal.

**Invariant Checks to Add:**
```
// In vault_oracle::get_current_price() or similar consumption points:
assert!(
    all_contributing_oracles_are_valid(aggregator, clock),
    ERR_ORACLE_EXPIRED
);
```

**Test Cases to Prevent Regression:**
1. Test that attempts to read aggregator data fail if any contributing oracle is expired
2. Test that oracle expiration within `update_interval` of last submission triggers appropriate error
3. Test vault operations correctly reject stale data from expired oracles
4. Test that multi-oracle aggregators continue working if some (but not all) oracles expire

### Proof of Concept

**Initial State:**
- Oracle is configured with `expiration_time_ms = T`
- Oracle submits valid price data to aggregator at time T-30 seconds
- Aggregator's `max_staleness_seconds` is set to a large value (e.g., 1 hour)
- Vault's `update_interval` is set to default 60 seconds (1 minute)

**Execution Steps:**

1. **At time T-30 seconds:**
   - Oracle submits price data successfully (passes expiration check)
   - Aggregator stores this data with timestamp T-30s

2. **At time T:**
   - Oracle's `expiration_time_ms` is reached
   - No automatic state change occurs
   - Oracle's historical data remains in aggregator

3. **At time T+20 seconds:**
   - Attempt to submit new oracle data → FAILS (expiration check blocks it)
   - Vault calls `update_price(aggregator, clock, asset_type)`
   - `get_current_price()` reads aggregator data
   - Check: `now - max_timestamp = (T+20s) - (T-30s) = 50 seconds < 60 seconds`
   - Check PASSES → stale data from expired oracle is accepted

4. **At time T+20 seconds (continued):**
   - Vault operations (deposits/withdrawals) proceed using 50-second-old data
   - If market moved significantly during this period, valuations are incorrect

**Expected vs Actual Result:**
- **Expected:** Oracle expiration should invalidate its historical data immediately
- **Actual:** Historical data remains usable for up to `update_interval` after expiration

**Success Condition:**
The vulnerability is confirmed if vault operations can successfully use oracle data submitted before expiration, even after the oracle has expired, as long as the data is within the `update_interval` window.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L63-63)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L13-23)
```text
public struct Oracle has key {
    id: UID,
    oracle_key: vector<u8>,
    queue: ID,
    queue_key: vector<u8>,        
    expiration_time_ms: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    valid_attestations: vector<Attestation>,
    version: u8,
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L558-598)
```text
fun valid_update_indices(update_state: &UpdateState, max_staleness_ms: u64, now_ms: u64): vector<u64> {
    let results = &update_state.results;
    let mut valid_updates = vector::empty<u64>();
    let mut seen_oracles = vec_set::empty<ID>();

    // loop backwards through the results
    let mut idx =  update_state.curr_idx;
    let mut remaining_max_iterations = u64::min(MAX_RESULTS, results.length());
    
    if (remaining_max_iterations == 0) {
        return valid_updates
    };

    loop {

        // if there are no remaining iterations, or the current element is stale, break
        if (remaining_max_iterations == 0 || (results[idx].timestamp_ms + max_staleness_ms) < now_ms) {
            break
        };

        let result = &results[idx];
        let oracle = result.oracle;
        

        if (!seen_oracles.contains(&oracle)) {
            seen_oracles.insert(oracle);
            valid_updates.push_back(idx);
        };

        // step backwards
        if (idx == 0) {
            idx = results.length() - 1;
        } else {
            idx = idx - 1;
        };

        remaining_max_iterations = remaining_max_iterations - 1;
    };

    valid_updates
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/scripts/ts/testnet_oracle_queue_override.ts (L132-132)
```typescript
        expirationTimeMs: Date.now() + 1000 * 60 * 60 * 24 * 365 * 5,
```
