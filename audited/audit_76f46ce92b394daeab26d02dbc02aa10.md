### Title
Expired Oracle Data Remains Usable by Vault After Oracle Expiration

### Summary
After `expiration_time_ms` passes, oracles do not automatically become inactive—they only lose the ability to submit new price data. However, their last submitted prices remain usable by the Volo Vault for up to `update_interval` (1 minute default), allowing stale data from expired (potentially untrusted) oracles to influence vault valuations, deposits, withdrawals, and operations.

### Finding Description

The oracle expiration mechanism has three critical flaws:

**1. No Automatic State Change on Expiration**

The `actuate()` function calls `enable_oracle()` which simply stores `expiration_time_ms` as a field without any automatic invalidation mechanism. [1](#0-0) [2](#0-1) 

**2. Expiration Only Checked at Submission Time**

The expiration check only occurs when an oracle attempts to submit NEW data to the aggregator, preventing future submissions but not invalidating past data. [3](#0-2) 

**3. Vault Never Validates Oracle Expiration Status**

The Volo Vault's `get_current_price()` and `get_asset_price()` functions only check that the aggregator's price timestamp is within `update_interval`, but never verify if the oracle that submitted that price has expired. [4](#0-3) [5](#0-4) 

**Execution Path:**
1. Oracle submits price at time T-1 (just before expiration)
2. Oracle expires at time T when `clock.timestamp_ms() >= expiration_time_ms`
3. For the next `update_interval` (up to 60 seconds), the vault continues using the expired oracle's last price
4. Vault operations (deposit/withdraw/value updates) consume this stale data without checking oracle expiration status [6](#0-5) 

### Impact Explanation

**Direct Fund Impact:**
- Incorrect vault total USD valuations affect share minting/burning during deposits and withdrawals
- Users receive wrong share amounts or withdrawal values based on stale prices
- Loss tolerance checks can be bypassed with manipulated prices from expiring oracles
- Operation value validations use compromised pricing data

**Security Integrity Impact:**
- Oracle expiration is designed to revoke trust from oracles (natural expiration or security response)
- The system contradicts this security model by continuing to trust expired oracle data
- A compromised oracle can submit manipulated data knowing it will expire but remain usable

**Who is Affected:**
- All vault depositors/withdrawers during the 1-minute window post-expiration
- Protocol integrity as incorrect valuations cascade through operations
- Operators performing vault operations with stale price data

**Severity Justification (Medium):**
- Real financial impact through incorrect share calculations and valuations
- Time-limited window (1 minute) reduces but doesn't eliminate exploitability
- Likelihood is HIGH as oracles naturally expire based on `oracle_validity_length_ms`
- No attacker action required—natural oracle expiration triggers the issue

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required—oracle expiration is a natural occurrence
- A compromised oracle can deliberately submit bad data before expiring
- Alternatively, normal oracle expiration combined with market volatility creates pricing discrepancies

**Attack Complexity:**
- LOW: Oracle expiration is automatic based on `queue.oracle_validity_length_ms()`
- Timing: Submit price within 1 minute of expiration to maximize impact window
- No complex transaction sequencing or race conditions needed

**Feasibility Conditions:**
- Oracles naturally expire based on queue configuration
- `update_interval` defaults to 60 seconds, providing exploitation window
- If multiple oracles exist, attacker needs majority or sole active oracle near expiration

**Detection Constraints:**
- Difficult to distinguish malicious pre-expiration submissions from legitimate ones
- No on-chain mechanism alerts users that prices come from expired oracles
- Users and operators cannot easily verify oracle expiration status when consuming prices

**Probability Reasoning:**
- HIGH probability during normal oracle lifecycle (oracles routinely expire and renew)
- MEDIUM impact severity due to time-limited window
- Overall: Practical and realistic exploitation path

### Recommendation

**Code-Level Mitigation:**

1. **Add Oracle Expiration Check in Vault Oracle Module:**

Modify `get_current_price()` to accept and validate the oracle reference:

```move
// In volo-vault/sources/oracle.move
public fun get_current_price(
    config: &OracleConfig, 
    clock: &Clock, 
    aggregator: &Aggregator,
    oracle: &Oracle  // Add oracle parameter
): u256 {
    config.check_version();
    let now = clock.timestamp_ms();
    
    // NEW: Verify oracle hasn't expired
    assert!(oracle.expiration_time_ms() > now, ERR_ORACLE_EXPIRED);
    
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

2. **Store Oracle Reference in Aggregator Results:**

Modify the aggregator to track which oracle submitted each result, enabling expiration validation at consumption time.

3. **Add Oracle Expiration Check in Update Flow:**

Ensure `update_price()` validates oracle expiration before accepting aggregator data.

**Invariant Checks to Add:**
- Assert `oracle.expiration_time_ms() > clock.timestamp_ms()` before consuming any oracle-derived price
- Add error code: `const ERR_ORACLE_EXPIRED: u64 = 2_006;`

**Test Cases to Prevent Regression:**
- Test that expired oracle data is rejected by vault price queries
- Test vault operations fail with stale prices from expired oracles
- Test multi-oracle scenarios where some have expired
- Test oracle expiration timing edge cases (exactly at expiration moment)

### Proof of Concept

**Required Initial State:**
- Vault configured with Switchboard oracle integration
- Oracle enabled with `expiration_time_ms = T + 3600000` (1 hour validity)
- Oracle has submitted valid price to aggregator at time T

**Transaction Steps:**

1. **T + 3599000ms (59 seconds before expiration):**
   - Oracle submits manipulated price P_malicious to aggregator
   - Transaction succeeds (oracle still valid)
   - Aggregator stores P_malicious with timestamp T + 3599000ms

2. **T + 3600000ms (expiration moment):**
   - Oracle expires (expiration_time_ms reached)
   - No state change occurs—oracle simply cannot submit new prices
   - Previous price P_malicious remains in aggregator

3. **T + 3600030ms (30 seconds after expiration):**
   - User calls vault deposit/withdraw operation
   - Vault calls `get_asset_price()` → `get_current_price()`
   - Check: `now - max_timestamp = 30000ms < update_interval (60000ms)` ✓ PASSES
   - **Missing Check:** Oracle expiration status not validated
   - Vault uses P_malicious for share calculations

**Expected vs Actual Result:**
- **Expected:** Vault rejects price from expired oracle, requires fresh price from active oracle
- **Actual:** Vault accepts price from expired oracle, performs operations with stale/manipulated data

**Success Condition:**
Transaction at step 3 succeeds using price from expired oracle, demonstrating that oracle expiration does not automatically invalidate previous submissions within the `update_interval` window.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L46-71)
```text
fun actuate(
    oracle: &mut Oracle,
    queue: &mut Queue,
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
    clock: &Clock,
) {
    oracle.enable_oracle(
        secp256k1_key,
        mr_enclave,
        expiration_time_ms,
    ); 

    queue.set_last_queue_override_ms(clock.timestamp_ms());

    // emit queue override event
    let queue_override_event = QueueOracleOverride {
        oracle_id: oracle.id(),
        queue_id: queue.id(),
        secp256k1_key: secp256k1_key,
        mr_enclave: mr_enclave,
        expiration_time_ms: expiration_time_ms,
    };
    event::emit(queue_override_event);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L113-122)
```text
public(package) fun enable_oracle(
    oracle: &mut Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
) {
    oracle.secp256k1_key = secp256k1_key;
    oracle.mr_enclave = mr_enclave;
    oracle.expiration_time_ms = expiration_time_ms;
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L62-63)
```text
    // verify that the oracle is up
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
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

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```
