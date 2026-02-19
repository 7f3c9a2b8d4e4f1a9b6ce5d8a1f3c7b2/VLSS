### Title
Stale Oracle Attestations Can Enable Compromised Oracles Due to Missing Freshness Validation

### Summary
The `add_attestation()` function filters existing attestations for expiration but fails to validate the freshness of newly added attestations against the 10-minute timeout threshold. This allows attestations up to 10 hours old to be counted toward oracle enablement, potentially allowing compromised oracles to provide price data to the Volo Vault.

### Finding Description

The vulnerability exists in the oracle attestation validation flow with a critical mismatch between two timeout constants: [1](#0-0) [2](#0-1) 

The validation flow occurs as follows:

1. In `validate()`, the timestamp check allows attestations up to 10 hours old (note: the comment on line 72 incorrectly states "10 minutes"): [3](#0-2) 

2. In `actuate()`, a new attestation is created with the provided (potentially old) timestamp: [4](#0-3) 

3. The `add_attestation()` function filters EXISTING attestations based on the 10-minute timeout but adds the NEW attestation without checking its freshness: [5](#0-4) 

4. The `valid_attestation_count()` function then counts all attestations (including the stale one) without any expiration check: [6](#0-5) 

5. If the count meets the threshold, the oracle is enabled: [7](#0-6) 

**Root Cause:** The `add_attestation()` function only validates existing attestations' timestamps against the current time, but the newly added attestation bypasses this check. The filter at line 101-102 uses `timestamp_ms` (current blockchain time) to remove old attestations from the vector, but the new attestation being added can have `attestation.timestamp_ms` that is up to 10 hours behind the current time, far exceeding the intended 10-minute freshness requirement.

### Impact Explanation

**Security Integrity Impact - Critical:**

An attacker can enable oracles using attestations that are up to 10 hours stale, allowing potentially compromised oracles to provide data to the Volo Vault through the Switchboard aggregator system: [8](#0-7) 

The Volo Vault relies on Switchboard aggregators for price feeds, and while it checks that aggregator updates are fresh (within 1 minute), it cannot detect if the underlying oracle providing those updates was enabled using stale attestations from 10 hours ago.

**Concrete Harm:**
- An oracle's enclave measurement (`mr_enclave`) and key (`secp256k1_key`) attested 10 hours ago may no longer be trustworthy
- During those 10 hours, the enclave could have been compromised, keys could have been exposed, or security parameters could have changed
- The compromised oracle can then submit manipulated price updates to aggregators
- The Volo Vault would accept these prices (as long as they're within the 1-minute freshness window), leading to incorrect asset valuations
- This can result in:
  - Incorrect share pricing for deposits/withdrawals
  - Manipulation of vault total value calculations
  - Exploitation of price discrepancies across operations
  - Loss of funds for vault users

**Severity:** Critical - The attestation system is designed to ensure oracle trustworthiness, but this vulnerability undermines that security model by accepting stale attestations that may no longer reflect the oracle's current security posture.

### Likelihood Explanation

**High Likelihood:**

**Reachable Entry Point:** The vulnerability is exploitable through the public entry function: [9](#0-8) 

**Feasible Preconditions:**
- Attacker needs valid attestation signatures from guardians (which can be obtained by requesting attestations and storing them)
- Guardian oracles must remain valid during the attack window
- No special privileges required - any user can call the attestation function

**Execution Practicality:**
1. Attacker collects attestation signatures at T0 from multiple guardians
2. Waits up to 9 hours and 59 minutes
3. Submits the stored attestations via `oracle_attest_action::run()`
4. The attestations pass validation (within 10-hour window) and are added to the oracle
5. If sufficient attestations are collected, the oracle is enabled with stale security guarantees

**Attack Complexity:** Low - The attacker simply needs to:
- Request attestations from guardians (legitimate operation)
- Store the signed attestations
- Replay them before the 10-hour window expires

**Economic Rationality:** Highly profitable - If an oracle's enclave was compromised within the 10-hour window, the attacker can:
- Enable the compromised oracle
- Manipulate price feeds through the oracle
- Extract value from the Volo Vault based on price manipulation
- Attack cost is minimal (just transaction fees)

### Recommendation

**Code-Level Mitigation:**

Modify the `add_attestation()` function to validate the new attestation's timestamp before adding it:

```move
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    // Check that the new attestation is fresh
    assert!(attestation.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms, EAttestationExpired);
    
    // Filter existing attestations
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

**Alternative Fix:** Align `ATTESTATION_VALIDITY_MS` with `ATTESTATION_TIMEOUT_MS` in `oracle_attest_action.move`:

```move
const ATTESTATION_VALIDITY_MS: u64 = 1000 * 60 * 10; // 10 minutes (match ATTESTATION_TIMEOUT_MS)
```

**Invariant Checks to Add:**
- Assert that newly added attestations are within the timeout threshold
- Add integration tests verifying that attestations older than 10 minutes are rejected
- Document the intended freshness requirements clearly

**Test Cases:**
1. Test that attestations exactly at the 10-minute boundary are rejected
2. Test that attempting to enable an oracle with multiple old attestations fails
3. Test that mixing fresh and stale attestations only counts fresh ones
4. Verify the comment at line 72 in `oracle_attest_action.move` matches the actual constant value

### Proof of Concept

**Initial State:**
- Oracle X exists but is not yet enabled
- 3 guardian oracles (G1, G2, G3) are active and valid
- Queue requires `min_attestations = 3` to enable an oracle

**Attack Sequence:**

**Step 1 (T = 0ms):** Attacker requests attestations from all 3 guardians for Oracle X
- Each guardian signs attestation with `timestamp_seconds = 0`
- Attacker stores these signed attestations

**Step 2 (T = 35,000,000ms, ~9.7 hours later):** Attacker submits all 3 stored attestations

Transaction 1:
```
oracle_attest_action::run(
    oracle: &mut Oracle X,
    queue: &Queue,
    guardian: &Oracle G1,
    timestamp_seconds: 0,  // 9.7 hours old
    mr_enclave: <attacker_controlled>,
    secp256k1_key: <attacker_key>,
    signature: <stored_signature_from_G1>,
    clock: &Clock  // current time = 35,000,000ms
)
```

**Expected Result:** Should reject attestation as stale (older than 10 minutes)

**Actual Result:** 
- `validate()` passes: `0 + 36,000,000 >= 35,000,000` ✓
- `add_attestation()` adds the attestation with timestamp = 0
- `valid_attestation_count()` counts it as valid
- After submitting attestations from G2 and G3 similarly, count reaches 3
- Oracle X is enabled with 9.7-hour-old attestations

**Success Condition:** Oracle X is enabled and can now submit potentially malicious price updates to aggregators, which the Volo Vault will accept as long as they're within the 1-minute staleness check.

**Notes**

The vulnerability stems from an inconsistency between the validation constant (10 hours) and the storage filtering constant (10 minutes). The comment at line 72 of `oracle_attest_action.move` suggests the intended behavior is a 10-minute maximum age, but the implementation uses `ATTESTATION_VALIDITY_MS` (10 hours). This creates a 60x window where stale attestations can compromise oracle security. The Switchboard oracle system is a critical dependency for the Volo Vault's price feed infrastructure, making this vulnerability directly exploitable to manipulate vault operations.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L4-4)
```text
const ATTESTATION_TIMEOUT_MS: u64 = 1000 * 60 * 10; // 10 minutes
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L100-105)
```text
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L107-111)
```text
public(package) fun valid_attestation_count(oracle: &Oracle, secp256k1_key: vector<u8>): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key
    })
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L41-41)
```text
const ATTESTATION_VALIDITY_MS: u64 = 1000 * 60 * 60 * 10;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L72-73)
```text
    // check that the timestamp is a maximum of 10 minutes old (and not in the future)
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L135-144)
```text
public entry fun run(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    timestamp_seconds: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    signature: vector<u8>,
    clock: &Clock,
) {
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
