### Title
Guardian Attestation Replacement Vulnerability Enables Oracle State Manipulation and Denial of Service

### Summary
The `add_attestation()` function removes all previous attestations from a guardian without verifying that the new attestation is more recent, allowing attackers with multiple valid signatures to repeatedly replace attestations and prevent oracles from reaching the minimum attestation threshold required for enablement. This vulnerability enables oracle denial of service attacks that can disrupt the Volo vault's price feed integrity.

### Finding Description

The vulnerability exists in the `add_attestation()` function which filters out existing attestations from the same guardian but lacks timestamp ordering validation: [1](#0-0) 

The filter removes attestations where `a.guardian_id == attestation.guardian_id`, unconditionally replacing any existing attestation from that guardian regardless of timestamp ordering. This function is called from the public entry function `oracle_attest_action::run()`: [2](#0-1) 

The validation function verifies signature authenticity and timestamp freshness (within 10 minutes) but does not prevent replay of older valid signatures: [3](#0-2) 

**Root Cause**: The `add_attestation()` function has no check ensuring `attestation.timestamp_ms >= existing_attestation.timestamp_ms` when replacing attestations from the same guardian. This allows older attestations to replace newer ones as long as both are within the 10-minute validity window.

**Why Existing Protections Fail**: 
- The signature verification only confirms the signature is valid for the provided parameters, not that it's the most recent
- The timestamp check only validates the attestation isn't too old (>10 minutes), not that it's newer than existing attestations
- The guardian_id filter removes ALL previous attestations from that guardian without timestamp comparison

### Impact Explanation

**Oracle Denial of Service**: An attacker can prevent oracles from reaching `min_attestations` threshold required for enablement. The oracle counting logic shows this impact: [4](#0-3) 

If the attestation count never reaches `queue.min_attestations()`, the oracle cannot be enabled, breaking the price feed mechanism that the Volo vault depends on for USD valuations.

**Oracle State Manipulation**: An attacker can control which `secp256k1_key` a guardian appears to be attesting to by alternating between valid signatures for different keys. This could force an oracle to be enabled with an unintended key if the attacker has sufficient guardian signatures.

**Affected Parties**: 
- Volo vault operations that depend on Switchboard oracle price feeds
- Users unable to execute vault operations due to missing oracle data
- Protocol integrity compromised by oracle manipulation

**Severity**: HIGH - This directly impacts the vault's oracle dependency, a critical infrastructure component. The audit context identifies oracle integrity as a critical invariant that must hold at all times.

### Likelihood Explanation

**Attacker Capabilities**: Any user can call the public entry function with valid guardian signatures they collect. No special privileges required beyond obtaining legitimate signatures.

**Realistic Attack Scenario - Oracle Key Rotation**:
1. An oracle legitimately rotates from `key_A` to `key_B`
2. Guardians sign attestations for both keys during the transition period
3. Both sets of signatures are valid and available
4. Attacker alternates calling `run()` with signatures for `key_A` and `key_B`
5. Each call removes the previous attestation and adds a new one for the alternate key
6. The attestation count for any single key never reaches `min_attestations`

**Execution Practicality**: 
- Signatures are valid for 10 minutes (ATTESTATION_VALIDITY_MS)
- Within this window, an attacker can repeatedly call `run()` with different signatures
- Each transaction costs only gas fees
- No rate limiting or replay protection exists

**Feasibility**: HIGH - During normal oracle key rotation, the necessary signatures naturally exist. The attack requires no compromise of guardian keys, only collection of legitimately issued signatures.

### Recommendation

**1. Add Timestamp Ordering Check** in `add_attestation()`:

```move
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    // Check if guardian already has an attestation
    let existing = vector::find!(&oracle.valid_attestations, |a: &Attestation| {
        a.guardian_id == attestation.guardian_id
    });
    
    // If exists, only replace if new attestation is newer
    if (option::is_some(&existing)) {
        let existing_attestation = option::borrow(&existing);
        assert!(attestation.timestamp_ms >= existing_attestation.timestamp_ms, EAttestationNotNewer);
    };
    
    // Remove old attestations (expired or from same guardian)
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

**2. Add Nonce or Sequence Number** to prevent replay attacks:
- Include a monotonically increasing nonce in the Attestation struct
- Verify each new attestation has a higher nonce than previous ones from the same guardian

**3. Test Cases**:
- Test that older attestations cannot replace newer ones
- Test that the same attestation cannot be added twice
- Test key rotation scenarios with multiple guardian signatures

### Proof of Concept

**Initial State**:
- Oracle `oracle_X` created with `expiration_time_ms = 0`
- Queue requires `min_attestations = 3` 
- Three guardians: `guardian_A`, `guardian_B`, `guardian_C`

**Attack Steps**:

1. **Key Rotation Setup**: Oracle `oracle_X` rotates from `key_LEGIT` to `key_NEW`
   - Guardian A signs attestation for `key_LEGIT` at timestamp T1
   - Guardian A signs attestation for `key_NEW` at timestamp T2 (T2 > T1)
   - Similar signatures from guardians B and C for both keys

2. **Legitimate Oracle Enablement Attempt**:
   - Call `oracle_attest_action::run()` with guardian A's signature for `key_NEW` (T2)
   - Call `oracle_attest_action::run()` with guardian B's signature for `key_NEW` (T2)
   - Call `oracle_attest_action::run()` with guardian C's signature for `key_NEW` (T2)
   - Oracle now has 3 attestations for `key_NEW`, should be enabled

3. **Attack Execution**:
   - Attacker calls `oracle_attest_action::run()` with guardian A's signature for `key_LEGIT` (T1)
   - Result: Guardian A's newer attestation (T2 for `key_NEW`) is replaced with older attestation (T1 for `key_LEGIT`)
   - `valid_attestation_count(oracle, key_NEW)` drops from 3 to 2
   - Oracle loses enabled status or fails to reach enablement threshold

4. **Repeat for DoS**:
   - Continue alternating between old and new signatures
   - Oracle state continuously changes, preventing stable operation

**Expected vs Actual**:
- **Expected**: Older attestation (T1) should be rejected since newer one (T2) exists
- **Actual**: Older attestation replaces newer one, breaking oracle state integrity

**Success Condition**: Attestation count for `key_NEW` drops below `min_attestations` despite legitimate signatures being available, preventing oracle enablement.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L100-105)
```text
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L73-73)
```text
    assert!(timestamp_seconds * 1000 + ATTESTATION_VALIDITY_MS >= clock.timestamp_ms(), ETimestampInvalid);
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
