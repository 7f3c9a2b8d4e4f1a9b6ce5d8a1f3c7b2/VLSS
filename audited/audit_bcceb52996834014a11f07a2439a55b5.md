### Title
Attestations Not Cleared on Oracle Re-enablement Allows Cross-MR_Enclave Attestation Reuse

### Summary
The `enable_oracle()` function does not clear previous attestations when re-enabling an oracle with new parameters. Since attestations only store `secp256k1_key` but not `mr_enclave`, old attestations for one TEE enclave measurement can be incorrectly counted towards enabling a different enclave with the same key, breaking the Trusted Execution Environment security model.

### Finding Description

The vulnerability exists in the interaction between three functions in the oracle schema: [1](#0-0) 

The `enable_oracle()` function sets the oracle's `secp256k1_key`, `mr_enclave`, and `expiration_time_ms` but does not clear the `valid_attestations` vector. [2](#0-1) 

The `Attestation` struct only stores `guardian_id`, `secp256k1_key`, and `timestamp_ms` - notably **missing the `mr_enclave`** that the guardian attested to. [3](#0-2) 

The `valid_attestation_count()` function counts attestations matching only the `secp256k1_key`, not verifying they correspond to the current `mr_enclave`. [4](#0-3) 

When guardians sign attestations, they commit to **both** `secp256k1_key` and `mr_enclave` in the attestation message (lines 148, 150). However, once stored, this binding to a specific `mr_enclave` is lost. [5](#0-4) 

During re-enablement, if `valid_attestations >= queue.min_attestations()`, the oracle is enabled with the new `mr_enclave` parameter from the current attestation submission, but the count includes old attestations that may have been for a different `mr_enclave`. [6](#0-5) 

The `add_attestation()` function only filters attestations by timeout (10 minutes) and guardian ID, not by `mr_enclave` compatibility.

### Impact Explanation

**Security Integrity Breach**: This vulnerability breaks the TEE attestation security model. The `mr_enclave` is a cryptographic measurement that uniquely identifies the code running inside a Trusted Execution Environment. Different `mr_enclave` values represent different code - potentially benign vs. malicious oracle implementations.

**Concrete Harm**: An attacker who controls an oracle's `secp256k1_key` can:
1. Obtain legitimate guardian attestations for a benign `mr_enclave_A`
2. Within the 10-minute attestation timeout window, initiate re-enablement with a malicious `mr_enclave_B` using the same key
3. The system incorrectly counts attestations meant for `mr_enclave_A` towards enabling `mr_enclave_B`
4. The malicious enclave becomes enabled with insufficient proper attestations

**Affected Parties**: All users relying on Switchboard oracle price feeds for the Volo vault operations. Malicious oracle data could lead to incorrect asset valuations, improper vault operations, and potential fund loss.

**Severity Justification**: MEDIUM - While requiring specific timing (10-minute window) and oracle key control, the impact on protocol security is significant as it undermines the fundamental trust model of TEE-based oracles.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is exploitable through two public entry functions:
- `oracle_attest_action::run()` - allows anyone to submit guardian attestations
- `queue_override_oracle_action::run()` - allows queue authorities to directly enable oracles [7](#0-6) 

**Attack Complexity**: 
- **Basic Attack**: Requires controlling an oracle's `secp256k1_key` and timing the re-enablement within 10 minutes of previous attestations
- **Queue Authority Attack**: If attacker has queue authority access, they can directly override oracle parameters making the attack trivial

**Feasibility Conditions**:
1. Oracle must have been previously enabled with attestations
2. Re-enablement with same key but different `mr_enclave` must occur within 10-minute timeout window
3. For untrusted attackers: requires compromising an oracle key
4. For queue authorities: no additional requirements

**Detection Constraints**: The attack leaves no obvious on-chain trace as the attestation reuse appears normal - the system is working as (incorrectly) designed.

**Probability**: MEDIUM - Requires oracle key compromise or queue authority access, but once achieved, the attack is straightforward and the time window (10 minutes) is reasonable for exploitation.

### Recommendation

**Code-Level Mitigation**:

1. **Clear attestations on re-enablement**: Modify `enable_oracle()` to clear the `valid_attestations` vector:
```move
public(package) fun enable_oracle(
    oracle: &mut Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
) {
    oracle.secp256k1_key = secp256k1_key;
    oracle.mr_enclave = mr_enclave;
    oracle.expiration_time_ms = expiration_time_ms;
    oracle.valid_attestations = vector::empty(); // Clear old attestations
}
```

2. **Store mr_enclave in Attestation**: Modify the `Attestation` struct to include `mr_enclave`:
```move
public struct Attestation has copy, store, drop {
    guardian_id: ID, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,  // Add this field
    timestamp_ms: u64,
}
```

3. **Update counting logic**: Modify `valid_attestation_count()` to verify both key and enclave match:
```move
public(package) fun valid_attestation_count(
    oracle: &Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>
): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key && a.mr_enclave == mr_enclave
    })
}
```

**Invariant Checks**:
- Assert that all attestations in `valid_attestations` match the current `mr_enclave` before counting
- Add validation to prevent re-enablement with different parameters while oracle is still valid (not expired)

**Test Cases**:
- Test re-enablement with same key but different `mr_enclave` - should require fresh attestations
- Test that expired attestations don't contribute to new enablement counts
- Test that changing `mr_enclave` properly invalidates previous attestations

### Proof of Concept

**Initial State**:
- Oracle exists with ID `oracle_1`
- Queue requires `min_attestations = 3`
- Attestation timeout is 10 minutes

**Exploitation Steps**:

1. **T=0min**: Oracle enabled with (`key_A`, `enclave_benign`)
2. **T=1min**: Three guardians submit attestations for (`key_A`, `enclave_benign`)
   - Attestations stored with only `key_A`, missing `enclave_benign`
3. **T=65min**: Oracle expires (validity period ends)
4. **T=66min**: Attacker submits ONE attestation for (`key_A`, `enclave_malicious`)
   - Guardian signs message containing both `key_A` and `enclave_malicious`
   - But attestation stored with only `key_A`
5. **T=67min**: System counts attestations via `valid_attestation_count(oracle_1, key_A)`
   - Returns 4 (3 old + 1 new) even though old attestations were for different enclave
   - All four attestations are within 10-minute timeout from their respective creation times
6. **T=67min**: Since 4 >= 3, `enable_oracle()` called with `enclave_malicious`
   - Oracle now enabled with malicious enclave using only 1 proper attestation

**Expected Result**: Oracle should require 3 fresh attestations for `enclave_malicious`

**Actual Result**: Oracle enabled with `enclave_malicious` using 3 attestations meant for `enclave_benign` plus 1 for `enclave_malicious`

**Success Condition**: Oracle's `mr_enclave` field now contains `enclave_malicious` despite having only 1 valid attestation for that specific enclave, violating the 3-attestation security requirement.

### Notes

The vulnerability is particularly concerning because:

1. **Design Flaw Not Implementation Bug**: The issue stems from the attestation data model itself, not a coding error
2. **Queue Authority Bypass**: Queue authorities can directly call `queue_override_oracle_action::run()` to enable oracles with arbitrary parameters without any attestation checks, making attestation clearing even more critical
3. **Cross-Protocol Impact**: Since Volo vault relies on Switchboard oracles for asset valuation, compromised oracles directly threaten vault security

The 10-minute timeout provides some mitigation but is insufficient because:
- Attestations for initial enablement typically happen quickly (within minutes)
- Re-enablement scenarios (oracle renewal, parameter updates) are common operational events
- The timeout window is wide enough for coordinated attacks

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L7-11)
```text
public struct Attestation has copy, store, drop {
    guardian_id: ID, 
    secp256k1_key: vector<u8>,
    timestamp_ms: u64,
}
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L132-154)
```text
public fun generate_attestation_msg(
    oracle_key: vector<u8>, 
    queue_key: vector<u8>,
    mr_enclave: vector<u8>,
    slothash: vector<u8>,
    secp256k1_key: vector<u8>,
    timestamp: u64,
): vector<u8> {
    let mut hasher = new();
    assert!(oracle_key.length() == 32, EWrongOracleIdLength);
    assert!(queue_key.length() == 32, EWrongQueueLength);
    assert!(mr_enclave.length() == 32, EWrongMrEnclaveLength);
    assert!(slothash.length() == 32, EWrongSlothashLength);
    assert!(secp256k1_key.length() == 64, EWrongSec256k1KeyLength);
    hasher.push_bytes(oracle_key);
    hasher.push_bytes(queue_key);
    hasher.push_bytes(mr_enclave);
    hasher.push_bytes(slothash);
    hasher.push_bytes(secp256k1_key);
    hasher.push_u64_le(timestamp);
    let Hasher { buffer } = hasher;
    buffer
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-123)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L135-164)
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
    validate(
        oracle,
        queue,
        guardian,
        timestamp_seconds,
        mr_enclave,
        secp256k1_key,
        signature,
        clock,
    );
    actuate(
        oracle,
        queue,
        guardian,
        timestamp_seconds,
        mr_enclave,
        secp256k1_key,
        clock,
    );
}
```
