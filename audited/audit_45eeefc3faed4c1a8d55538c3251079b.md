### Title
Guardian Expiration Validation Checks Wrong Oracle Allowing Expired Guardians to Attest

### Summary
The `validate()` function in `oracle_attest_action.move` incorrectly validates the target oracle's expiration time instead of the guardian's expiration time. This allows expired guardians to continue providing attestations to already-valid oracles, bypassing the security mechanism designed to revoke expired guardian credentials.

### Finding Description

The validation function contains a critical bug at line 67 where it checks the wrong oracle's expiration status: [1](#0-0) 

The comment indicates the intent is to "check that the guardian is valid", but the code checks `oracle.expiration_time_ms()` (the target oracle being attested) rather than `guardian.expiration_time_ms()` (the guardian providing the attestation).

The validation function accepts three oracle parameters: [2](#0-1) 

The correct check should validate that the guardian oracle itself is not expired. Instead, the current implementation validates that the target oracle is not expired, which creates the following exploitation path:

1. Guardian oracle expires (current_time > guardian.expiration_time_ms)
2. Target oracle remains valid (target.expiration_time_ms > current_time) 
3. Line 67 check passes because it validates the target oracle, not the guardian
4. Expired guardian successfully adds attestation
5. If sufficient attestations accumulate, the actuate function extends the target oracle's validity: [3](#0-2) 

This bypasses the guardian expiration mechanism that exists specifically to revoke attestation privileges from expired guardians.

Regarding the original question about empty guardian queues: the check at line 64 validates guardian membership: [4](#0-3) 

For guardian queues, the `guardian_queue_id` is self-referential: [5](#0-4) 

An empty guardian queue would have no oracles registered, preventing attestations unless new oracles are created and bootstrapped (requiring attestations from the same queue, creating a circular dependency). The line 67 bug is the exploitable vulnerability, not the empty queue scenario itself.

### Impact Explanation

**Security Integrity Impact**: The expiration mechanism for guardians is completely bypassed. Once any oracle in a queue has been attested and becomes valid, expired guardians can continue providing attestations indefinitely, as long as at least one oracle remains valid.

**Operational Impact**: 
- Compromised or revoked guardian credentials remain functional after expiration
- The protocol loses the ability to effectively revoke guardian attestation privileges through expiration
- Oracle validity can be maintained by expired guardians, undermining the trust model

**Affected Parties**: Any oracle queue relying on guardian attestations for security. The Volo vault depends on Switchboard oracles for price data, making this a critical dependency: [6](#0-5) 

This is a **High severity** issue because it breaks a fundamental security control in the oracle attestation system.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is triggered through the public entry function: [7](#0-6) 

**Feasible Preconditions**:
1. A guardian oracle has expired (natural occurrence over time)
2. Guardian's private key is available (legitimate guardian operator or compromised key)
3. Target oracle is currently valid (common state)

**Execution Practicality**: The attack is straightforward - simply call the `run()` function with an expired guardian. All other validations pass:
- Version checks (lines 55-61)
- Guardian queue membership (line 64)
- Signature verification (lines 69-92)

**Economic Rationality**: No additional cost beyond normal attestation fees. The exploit allows indefinite use of expired credentials without requiring fresh valid guardians.

**Probability**: High - guardians naturally expire over time, and the bug allows any expired guardian with available keys to continue functioning. This is not theoretical; it will occur in normal operations when guardians expire.

### Recommendation

**Code-Level Mitigation**: Change line 67 to validate the guardian's expiration instead of the target oracle's expiration:

```move
// Current (incorrect):
assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);

// Should be:
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**Invariant to Add**: Ensure all attestation validations explicitly check guardian validity before allowing attestations to be added.

**Test Cases**: 
1. Attempt attestation with expired guardian on valid oracle (should fail)
2. Attempt attestation with expired guardian on non-enabled oracle (currently fails, should continue to fail)
3. Verify valid guardian can attest to both enabled and non-enabled oracles
4. Test time boundary conditions around guardian expiration

### Proof of Concept

**Initial State**:
- Oracle queue O with guardian_queue_id pointing to guardian queue G
- Target oracle T in queue O is valid (expiration_time_ms = current_time + 1 day)
- Guardian oracle GExpired in queue G has expired (expiration_time_ms = current_time - 1 day)
- Attacker has GExpired's private key

**Transaction Steps**:
1. Attacker creates valid signature using GExpired's private key for attestation message
2. Attacker calls `oracle_attest_action::run()` with:
   - oracle = T (target oracle) 
   - queue = O
   - guardian = GExpired (expired)
   - timestamp_seconds, mr_enclave, secp256k1_key, signature, clock

**Expected Result**: Transaction should abort with `EGuardianInvalid` because GExpired has expired

**Actual Result**: Transaction succeeds because line 67 validates T.expiration_time_ms (valid) instead of GExpired.expiration_time_ms (expired). The attestation is added to T, potentially extending its validity.

**Success Condition**: `oracle.valid_attestations` contains an attestation from the expired guardian, proving the expiration check was bypassed.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L43-46)
```text
public fun validate(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L63-64)
```text
    // check that guardian queue (for the target queue) is the guardian's queue
    assert!(guardian.queue() == queue.guardian_queue_id(), EInvalidGuardianQueue);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L66-67)
```text
    // check that the guardian is valid
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L120-122)
```text
    if (is_guardian_queue) {
        let guardian_queue_id = *(id.as_inner());
        let guardian_queue = Queue {
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L18-19)
```text
    expiration_time_ms: u64,
    mr_enclave: vector<u8>,
```
