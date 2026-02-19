### Title
Stale Attestations Can Enable Oracle Due to Timestamp Validation Mismatch

### Summary
The Switchboard oracle attestation system allows guardians to submit attestations with timestamps up to 10 hours old, but the attestation counting logic does not verify timestamp freshness. This enables oracles to be activated based on severely outdated security attestations, undermining the integrity guarantees that fresh TEE attestations should provide.

### Finding Description

The vulnerability exists in the attestation validation and counting flow across two modules:

**Root Cause - Timestamp Validation Mismatch:**

In `oracle_attest_action.move`, the validation allows attestations with timestamps up to 10 HOURS old: [1](#0-0) [2](#0-1) 

However, in `oracle.move`, the filtering timeout for EXISTING attestations is only 10 MINUTES: [3](#0-2) 

**Insufficient Expiry Checking:**

The `add_attestation` function filters existing attestations by the 10-minute timeout, but the NEW attestation being added bypasses this check entirely: [4](#0-3) 

The filter at line 101-103 only applies to attestations already in the vector, checking `a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms`. The new attestation is unconditionally added at line 104, regardless of whether its timestamp is stale.

**No Timestamp Validation in Counting:**

When counting valid attestations to determine if an oracle should be enabled, no timestamp freshness check is performed: [5](#0-4) 

The counting only checks if the `secp256k1_key` matches, completely ignoring whether attestations are expired.

**Exploitation Flow:**

In the attestation flow, an attestation with a stale timestamp is immediately counted: [6](#0-5) [7](#0-6) 

**Test Coverage Gap:**

The test function uses identical timestamps throughout and never tests time progression scenarios: [8](#0-7) 

All attestations are added with `timestamp_ms = 1000` and the current time parameter is also `1000`, so the test never catches the staleness issue.

### Impact Explanation

**Security Integrity Compromise:**

Oracles provide critical price data for the Volo vault system. TEE attestations are meant to verify that oracles are running legitimate, secure enclave code at the time of attestation. The 10-minute timeout suggests the system intends to enforce recent attestations.

However, the vulnerability allows:
- Multiple guardians to submit attestations timestamped up to 10 hours in the past
- These stale attestations to be counted toward the minimum threshold (e.g., 3 attestations)
- The oracle to be enabled based on 10-hour-old security proofs

**Concrete Impact:**

If `min_attestations = 3`, an attacker or compromised guardians could:
1. Use 10-hour-old TEE measurements that may no longer reflect current oracle state
2. Enable an oracle that passed attestation 10 hours ago but has since been compromised
3. Provide incorrect price data to the Volo vault, affecting deposit/withdrawal valuations

The Volo vault relies on accurate oracle pricing for USD valuations of assets, which determine vault share values, deposit amounts, and withdrawal amounts. Stale oracle attestations could enable compromised price feeds.

### Likelihood Explanation

**High Likelihood - No Attack Barriers:**

The vulnerability is trivially exploitable because:

1. **Reachable Entry Point**: `oracle_attest_action::run()` is a public entry function that any guardian can call
2. **No Additional Permissions**: Guardians operate with their normal privileges; no compromise required
3. **Validation Explicitly Allows It**: The code at line 73 of oracle_attest_action.move explicitly validates and accepts 10-hour-old timestamps
4. **No Cost**: Simply requires using `timestamp_seconds` parameter that is 10 hours old (within the 10-hour validation window)
5. **No Detection**: The behavior is indistinguishable from normal operation since the validation passes

**Attack Scenario:**
- At time T=0, three guardians attest to oracle with legitimate TEE measurements
- At time T=10 hours, oracle enclave is compromised but produces same signatures
- Same three guardians submit attestations using `timestamp_seconds = 0` (10 hours old)
- Validation passes: `0 + 36000000 >= 36000000` (line 73)
- All three attestations counted, oracle enabled based on 10-hour-old security proofs

### Recommendation

**Fix 1: Add Timestamp Freshness Check in add_attestation**

Validate the incoming attestation timestamp before adding it:

```move
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    // Reject if the new attestation is already expired
    assert!(attestation.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms, EExpiredAttestation);
    
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

**Fix 2: Add Timestamp Check in valid_attestation_count**

Check expiry when counting attestations:

```move
public(package) fun valid_attestation_count(oracle: &Oracle, secp256k1_key: vector<u8>, current_time_ms: u64): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key && 
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > current_time_ms
    })
}
```

**Fix 3: Align Validation Timeout**

Reduce `ATTESTATION_VALIDITY_MS` in oracle_attest_action.move from 10 hours to 10 minutes to match the filtering timeout, or increase both to a consistent value if 10 hours is intentional.

**Test Case to Add:**

```move
#[test]
fun test_stale_attestation_rejected() {
    // Add attestation at T=0
    // Attempt to add 11-minute-old attestation at T=11 minutes
    // Verify it's not counted in valid_attestation_count
}
```

### Proof of Concept

**Initial State:**
- Queue has `min_attestations = 3`
- Three guardian oracles exist with valid secp256k1 keys
- Target oracle exists but is not yet enabled

**Transaction Sequence:**

1. **T=0**: Three guardians create legitimate TEE attestations with `timestamp_seconds = 0`
2. **T=10 hours (36,000,000 ms)**: Oracle enclave potentially compromised
3. **Guardian A submits attestation:**
   - Calls `oracle_attest_action::run()` with `timestamp_seconds = 0` (10 hours old)
   - Validation passes: `0 + 36000000 >= 36000000` ✓
   - Attestation created with `timestamp_ms = 0`
   - `add_attestation()` called with `attestation.timestamp_ms = 0`, `clock.timestamp_ms() = 36000000`
   - Filter keeps attestations where: `a.timestamp_ms + 600000 > 36000000` (removes any older than 10 min)
   - New attestation (timestamp_ms=0) added to vector ✓
   - `valid_attestation_count()` counts it ✓ (count = 1)

4. **Guardian B submits similar 10-hour-old attestation** (count = 2)
5. **Guardian C submits similar 10-hour-old attestation** (count = 3)
6. **Oracle enabled** based on three 10-hour-old attestations ✗

**Expected Result:** Attestations older than 10 minutes should be rejected or not counted

**Actual Result:** 10-hour-old attestations are accepted and counted, enabling the oracle

**Success Condition:** `oracle.expiration_time_ms > 0` (oracle is enabled) despite using 10-hour-old attestation data

### Notes

This vulnerability is particularly concerning because:

1. **Silent Failure**: The system appears to work correctly in normal operation since attestations are typically recent
2. **Test Blind Spot**: The test suite doesn't cover time progression scenarios, so this went undetected
3. **Semantic Gap**: The 60x difference between validation window (10 hours) and filtering window (10 minutes) suggests a design inconsistency
4. **Oracle Dependency**: The Volo vault's pricing mechanism depends on these Switchboard oracles, so compromised oracle data directly impacts fund safety

The fix should establish a consistent freshness requirement across validation, filtering, and counting operations, with comprehensive test coverage for time-based scenarios.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L41-41)
```text
const ATTESTATION_VALIDITY_MS: u64 = 1000 * 60 * 60 * 10;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L73-73)
```text
    assert!(timestamp_seconds * 1000 + ATTESTATION_VALIDITY_MS >= clock.timestamp_ms(), ETimestampInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L104-109)
```text
    let attestation = oracle::new_attestation( 
        guardian.id(),
        secp256k1_key,
        timestamp_seconds * 1000,
    );
    oracle.add_attestation(attestation, clock.timestamp_ms());
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-123)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L4-4)
```text
const ATTESTATION_TIMEOUT_MS: u64 = 1000 * 60 * 10; // 10 minutes
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L100-104)
```text
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L107-111)
```text
public(package) fun valid_attestation_count(oracle: &Oracle, secp256k1_key: vector<u8>): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key
    })
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L180-221)
```text
public fun test_attestations() {
    use sui::test_scenario;
    let owner = @0x26;
    let mut scenario = test_scenario::begin(owner);
    let ctx = scenario.ctx();

    let oracle_key = x"963fead0d455c024345ec1c3726843693bbe6426825862a6d38ba9ccd8e5bd7c";
    let queue = object::id_from_address(@0x27);
    let queue_key = x"963fead0d455c024345ec1c3726843693bbe6426825862a6d38ba9ccd8e5bd7c";
    let mut oracle = Oracle {
        id: object::new(ctx),
        oracle_key,
        queue,
        queue_key,
        expiration_time_ms: 0,
        secp256k1_key: vector::empty(),
        valid_attestations: vector::empty(),
        mr_enclave: vector::empty(),
        version: VERSION,
    };

    let guardian_id = object::id_from_address(@0x28);
    let secp256k1_key = x"963fead0d455c024345ec1c3726843693bbe6426825862a6d38ba9ccd8e5bd7c";
    let timestamp_ms = 1000;
    let attestation = Attestation {
        guardian_id,
        secp256k1_key,
        timestamp_ms,
    };
    add_attestation(&mut oracle, attestation, timestamp_ms);
    assert!(valid_attestation_count(&oracle, secp256k1_key) == 1);

    let guardian_id = object::id_from_address(@0x28);
    let secp256k1_key = x"963fead0d455c024345ec1c3726843693bbe6426825862a6d38ba9ccd8e5bd7c";
    let timestamp_ms = 1000;
    let attestation = Attestation {
        guardian_id,
        secp256k1_key,
        timestamp_ms,
    };
    add_attestation(&mut oracle, attestation, timestamp_ms);
    assert!(valid_attestation_count(&oracle, secp256k1_key) == 1);
```
