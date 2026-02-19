### Title
Missing Queue-Oracle Binding Validation Allows Cross-Queue Attestation Replay with Configuration Bypass

### Summary
The `oracle_attest_action::validate()` function fails to verify that the Queue parameter matches the Oracle's designated queue, allowing attestations to be replayed across different queues. This enables attackers to bypass min_attestations requirements and apply incorrect oracle validity periods by using a different queue's configuration than the one the oracle was created for.

### Finding Description

The vulnerability exists in the attestation validation flow where an oracle's attestations are verified and counted toward enabling the oracle. [1](#0-0) 

The `validate()` function retrieves the `queue_key` from the oracle object itself (line 77), not from the Queue parameter, to generate and verify the attestation message. However, it never validates that the Queue parameter actually matches the oracle's designated queue stored in the oracle object.

When an oracle is created, it stores both the queue ID and queue_key: [2](#0-1) 

The Oracle struct maintains these relationships: [3](#0-2) 

In the `actuate()` function, the Queue parameter's configuration (min_attestations and oracle_validity_length_ms) is used to determine whether to enable the oracle: [4](#0-3) 

The missing validation is evident when comparing with `queue_override_oracle_action`, which correctly validates the queue-oracle relationship: [5](#0-4) 

Lines 40-41 show the required checks that are absent in `oracle_attest_action`:
- `assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);`
- `assert!(queue.id() == oracle.queue(), EInvalidQueueId);`

### Impact Explanation

**Security Integrity Bypass - High Severity:**

1. **Min Attestations Bypass**: An oracle created on QueueA requiring 5 attestations can be enabled with only 1 attestation by replaying through QueueB that requires min_attestations=1. This undermines the guardian attestation security model.

2. **Incorrect Oracle Validity Period**: The oracle receives an expiration time based on the wrong queue's `oracle_validity_length_ms` parameter, potentially extending oracle validity beyond intended security boundaries.

3. **Protocol Trust Violation**: Each queue is designed with specific security parameters. This vulnerability allows mixing configurations, breaking the isolation between different security domains.

4. **Widespread Impact**: Any oracle on any queue is vulnerable if an attacker can create or access another queue with relaxed parameters that shares the same guardian queue.

The vulnerability directly violates the critical invariant that oracle enablement must follow designated queue configuration parameters.

### Likelihood Explanation

**High Likelihood:**

1. **Public Entry Point**: The `run()` function is a public entry function accessible to any caller: [6](#0-5) 

2. **Feasible Attack Scenario**:
   - Attacker creates QueueB with min_attestations=1 and their chosen guardian_queue_id
   - If multiple queues legitimately share the same guardian queue (common in multi-tenant oracle systems), the attack is trivial
   - Guardian signatures for legitimate oracles can be intercepted from on-chain events and replayed

3. **No Special Privileges Required**: Attackers only need:
   - Ability to create a queue (public function in queue initialization modules)
   - Valid guardian attestation signatures (observable on-chain)
   - Gas fees for transactions

4. **Economic Viability**: Queue creation is permissionless with minimal cost. The attacker gains the ability to enable oracles with insufficient security validation, which could be exploited for oracle manipulation attacks in dependent protocols.

5. **Detection Difficulty**: The transaction appears valid - all signature checks pass, guardian verification succeeds. Only off-chain monitoring comparing oracle.queue() with the queue parameter would detect the mismatch.

### Recommendation

**Immediate Fix**: Add queue-oracle binding validation in `oracle_attest_action::validate()`:

```move
public fun validate(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    timestamp_seconds: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    signature: vector<u8>,
    clock: &Clock,
) {
    // Add these critical checks at the beginning
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    
    // ... existing validation logic
}
```

**Define Error Constants**:
```move
#[error]
const EInvalidQueueId: vector<u8> = b"Invalid queue id";
#[error]
const EInvalidQueueKey: vector<u8> = b"Invalid queue key";
```

**Test Cases**:
1. Verify attestation fails when oracle.queue() != queue.id()
2. Verify attestation fails when oracle.queue_key() != queue.queue_key()
3. Verify attestation succeeds only with matching queue
4. Add integration test attempting cross-queue replay to ensure it reverts

### Proof of Concept

**Initial State:**
- GuardianQueue exists with ID = 0xGUARDIAN
- QueueA created: guardian_queue_id = 0xGUARDIAN, min_attestations = 5, queue_key = 0xKEYA
- QueueB created: guardian_queue_id = 0xGUARDIAN, min_attestations = 1, queue_key = 0xKEYB
- OracleX created on QueueA: stores queue = QueueA.id(), queue_key = 0xKEYA
- GuardianOracle in GuardianQueue signs attestation for OracleX (signature includes 0xKEYA)

**Attack Steps:**
1. Attacker observes valid attestation signature for OracleX from on-chain events
2. Attacker calls `oracle_attest_action::run()` with:
   - oracle = OracleX (reference to oracle on QueueA)
   - queue = QueueB (wrong queue!)
   - guardian = GuardianOracle (from shared GuardianQueue)
   - signature + parameters from observed attestation

**Expected Result:** Transaction should revert with queue mismatch error

**Actual Result:** 
- Validation passes (uses oracle.queue_key() = 0xKEYA for signature verification)
- Guardian check passes (both queues use same GuardianQueue)
- Attestation is added to OracleX
- OracleX is enabled after 1 attestation instead of required 5
- Oracle receives validity period from QueueB instead of QueueA

**Success Condition:** OracleX.expiration_time_ms() becomes non-zero after only 1 attestation, bypassing QueueA's min_attestations=5 requirement.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L43-93)
```text
public fun validate(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    timestamp_seconds: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    signature: vector<u8>,
    clock: &Clock,
) {

    // check the queue version
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);

    // check the oracle version
    assert!(oracle.version() == EXPECTED_ORACLE_VERSION, EInvalidOracleVersion);
    
    // check the guardian version
    assert!(guardian.version() == EXPECTED_ORACLE_VERSION, EInvalidOracleVersion);

    // check that guardian queue (for the target queue) is the guardian's queue
    assert!(guardian.queue() == queue.guardian_queue_id(), EInvalidGuardianQueue);

    // check that the guardian is valid
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);

    // check that the signature is valid length
    assert!(signature.length() == 65, EWrongSignatureLength);

    // check that the timestamp is a maximum of 10 minutes old (and not in the future)
    assert!(timestamp_seconds * 1000 + ATTESTATION_VALIDITY_MS >= clock.timestamp_ms(), ETimestampInvalid);
    
    // check that signature maps to the guardian, and that the guardian is valid
    let oracle_key = oracle.oracle_key();
    let queue_key = oracle.queue_key();
    let attestation_msg = hash::generate_attestation_msg(
        oracle_key,
        queue_key,
        mr_enclave,
        x"0000000000000000000000000000000000000000000000000000000000000000",
        secp256k1_key,
        timestamp_seconds,
    );

    // recover the guardian pubkey from the signature
    let recovered_pubkey_compressed = ecdsa_k1::secp256k1_ecrecover(&signature, &attestation_msg, 1);
    let recovered_pubkey = ecdsa_k1::decompress_pubkey(&recovered_pubkey_compressed);

    // check that the recovered pubkey is valid
    assert!(hash::check_subvec(&recovered_pubkey, &guardian.secp256k1_key(), 1), EInvalidSignature);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L95-133)
```text
fun actuate(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    timestamp_seconds: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    clock: &Clock,
) {
    let attestation = oracle::new_attestation( 
        guardian.id(),
        secp256k1_key,
        timestamp_seconds * 1000,
    );
    oracle.add_attestation(attestation, clock.timestamp_ms());

    // emit creation event
    let attestation_created = AttestationCreated {
        oracle_id: oracle.id(),
        guardian_id: guardian.id(),
        secp256k1_key,
        timestamp_ms: clock.timestamp_ms(),
    };
    event::emit(attestation_created);

    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
        
        // emit resolution event
        let attestation_resolved = AttestationResolved {
            oracle_id: oracle.id(),
            secp256k1_key,
            timestamp_ms: clock.timestamp_ms(),
        };
        event::emit(attestation_resolved);
    };
}
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move (L28-48)
```text
fun actuate(
    queue: &mut Queue,
    oracle_key: vector<u8>,
    ctx: &mut TxContext,
) {
    let oracle_id = oracle::new(
        oracle_key,
        queue.id(),
        queue.queue_key(),
        ctx,
    );
    queue.add_existing_oracle(oracle_key, oracle_id);

    // emit oracle init event
    let created_event = OracleCreated {
        oracle_id,
        queue_id: queue.id(),
        oracle_key,
    };
    event::emit(created_event);
}
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L32-44)
```text
public fun validate(
    queue: &Queue,
    oracle: &Oracle, 
    expiration_time_ms: u64,
    ctx: &mut TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(oracle.version() == EXPECTED_ORACLE_VERSION, EInvalidOracleVersion);
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(expiration_time_ms > 0, EInvalidExpirationTime);
}
```
