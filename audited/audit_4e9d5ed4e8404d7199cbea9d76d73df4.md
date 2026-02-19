### Title
Attestation Signature Replay via Duplicate Queue/Oracle Objects with Identical Data Fields

### Summary
The attestation validation mechanism binds signatures to data fields (oracle_key, queue_key) rather than unique object IDs, allowing attackers to replay valid signatures on different oracle/queue objects that contain the same data field values. With unrestricted queue and oracle creation and no global uniqueness enforcement, an attacker can create duplicate objects and successfully replay attestation signatures, bypassing the intended security model.

### Finding Description

The vulnerability exists in the attestation signature validation flow across multiple files:

**Root Cause:** The signature is generated over data fields, not object identifiers: [1](#0-0) 

The message hash includes `oracle_key` and `queue_key` extracted from the oracle object, which are simple byte vector fields, not unique object IDs. [2](#0-1) 

**Missing Protection #1:** Queue creation has no authorization or uniqueness enforcement: [3](#0-2) 

Anyone can create a Queue with any `queue_key` value - there's no global registry or uniqueness check. The `queue_key` is just stored as a data field: [4](#0-3) 

**Missing Protection #2:** Oracle creation only prevents duplicates within the same queue: [5](#0-4) 

This check only prevents duplicate `oracle_key` on a single queue, not globally. An attacker can create oracles with the same `oracle_key` on different queues.

**Validation Checks Don't Prevent Replay:** [6](#0-5) 

Lines 55-64 only check version numbers and object relationships, not uniqueness of data fields. Line 64 checks that the guardian belongs to the queue's guardian queue, but the attacker controls `queue.guardian_queue_id()` when creating their duplicate queue. Line 67 contains a bug (checks `oracle.expiration_time_ms()` instead of `guardian.expiration_time_ms()` based on error message), but this doesn't prevent the attack fundamentally.

**Attack Execution Path:**

1. Legitimate state: Queue A (queue_key="QK1", guardian_queue_id=GQ) has Oracle 1 (oracle_key="OK1")
2. Guardian on GQ signs attestation for (oracle_key="OK1", queue_key="QK1", mr_enclave, secp256k1_key, timestamp)
3. Attacker creates Queue B with queue_key="QK1" and guardian_queue_id=GQ (pointing to same guardian queue)
4. Attacker creates Oracle 2 on Queue B with oracle_key="OK1" (inherits queue_key="QK1" from Queue B)
5. Attacker calls `oracle_attest_action.run()` with oracle=Oracle 2, queue=Queue B, guardian=same guardian, captured signature
6. Validation passes because the reconstructed message is identical (same oracle_key, queue_key)
7. Attestation is added to Oracle 2, potentially enabling it

### Impact Explanation

**Security Integrity Impact:**
- Attestation system is fundamentally compromised - signatures can be replayed to attest unintended oracles
- An attacker can create oracle objects that appear legitimately attested by trusted guardians without those guardians actually attesting to them
- Breaks the trust model where attestations should be unique to specific oracle instances
- If downstream systems rely on queue_key as a trusted identifier (assuming it's unique), they could interact with malicious oracles thinking they're legitimate

**Affected Parties:**
- Any protocol or user relying on Switchboard oracle attestations
- Guardian operators whose signatures are replayed without consent
- Users who trust oracle data based on attestation status

**Severity Justification:**
This is a CRITICAL security integrity bypass. The attestation mechanism is core to establishing trust in oracles. Allowing arbitrary replay means an attacker can bootstrap fake oracles with stolen legitimacy.

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required - all entry functions are publicly accessible
- `oracle_queue_init_action.run()` and `oracle_init_action.run()` have no authorization checks
- Attacker only needs to observe legitimate transactions to capture signatures

**Attack Complexity:**
- LOW - straightforward sequence of public function calls
- No need to compromise keys or bypass access controls
- Can be executed by any user with basic transaction capabilities

**Feasibility Conditions:**
- Line 67 bug currently prevents attack on newly created oracles (checks oracle expiration instead of guardian)
- Attack would work immediately for re-attestations of already-enabled oracles
- Attack becomes fully viable if line 67 bug is fixed (which it should be for legitimate functionality)
- All other preconditions are already satisfied in current implementation

**Probability:**
HIGH if line 67 is corrected, MEDIUM in current state (limited to re-attestation scenarios)

### Recommendation

**Immediate Fixes:**

1. **Include object IDs in signature:** [2](#0-1) 

Modify `generate_attestation_msg()` to include the actual Sui object IDs:
```move
public fun generate_attestation_msg(
    oracle_id: ID,  // Add object ID
    queue_id: ID,   // Add object ID
    oracle_key: vector<u8>, 
    queue_key: vector<u8>,
    mr_enclave: vector<u8>,
    slothash: vector<u8>,
    secp256k1_key: vector<u8>,
    timestamp: u64,
): vector<u8>
```

Then hash oracle_id and queue_id into the message to cryptographically bind the signature to specific object instances.

2. **Add global uniqueness registry:**
Create a shared global registry object that tracks all queue_key and oracle_key values to prevent duplicates across the entire system.

3. **Add authorization to queue creation:**
Require a capability or authority check in `oracle_queue_init_action.run()` and `guardian_queue_init_action.run()`.

4. **Fix Line 67 bug:** [7](#0-6) 

Change to: `assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);`

### Proof of Concept

**Initial State:**
- Guardian Queue GQ exists at object ID 0xGQ
- Queue A exists with queue_key=0xQK1, guardian_queue_id=0xGQ
- Oracle 1 exists on Queue A with oracle_key=0xOK1, queue_key=0xQK1 (inherited)
- Guardian G exists on GQ with secp256k1_key=0xGKEY, expiration_time_ms=future_time
- Guardian G signs attestation: signature=ECDSA_sign(hash(0xOK1 || 0xQK1 || mr || zeros || sk || ts))

**Attack Sequence:**

Transaction 1 - Create duplicate queue:
```
oracle_queue_init_action::run(
    queue_key: 0xQK1,  // SAME as Queue A
    authority: attacker_address,
    name: "Fake Queue",
    fee: 0,
    fee_recipient: attacker_address,
    min_attestations: 1,
    oracle_validity_length_ms: 1000000,
    guardian_queue: GQ  // Point to SAME guardian queue
)
// Creates Queue B with queue_key=0xQK1, guardian_queue_id=0xGQ
```

Transaction 2 - Create duplicate oracle:
```
oracle_init_action::run(
    oracle_key: 0xOK1,  // SAME as Oracle 1
    queue: Queue B
)
// Creates Oracle 2 with oracle_key=0xOK1, queue_key=0xQK1 (from Queue B)
```

Transaction 3 - Replay signature:
```
oracle_attest_action::run(
    oracle: Oracle 2,
    queue: Queue B,
    guardian: G,
    timestamp_seconds: ts,
    mr_enclave: mr,
    secp256k1_key: sk,
    signature: signature  // REPLAYED from original
)
```

**Expected Result:** Transaction fails with signature validation error
**Actual Result:** Validation passes, attestation added to Oracle 2, oracle potentially enabled

**Success Condition:** Oracle 2 receives attestation it never legitimately earned, demonstrated by checking `oracle_2.valid_attestations` contains an entry for the guardian.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L54-67)
```text
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L76-85)
```text
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/oracle_queue_init_action.move (L67-94)
```text
public entry fun run(
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    guardian_queue: &Queue,
    ctx: &mut TxContext
) {   
    validate(
        guardian_queue,
        min_attestations,
        oracle_validity_length_ms,
    );
    actuate(
        queue_key,
        authority,
        name,
        fee,
        fee_recipient,
        min_attestations,
        oracle_validity_length_ms,
        guardian_queue.id(),
        ctx,
    );
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L16-32)
```text
public struct Queue has key {
    id: UID,
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    last_queue_override_ms: u64,
    guardian_queue_id: ID,

    // to ensure that oracles are only mapped once (oracle pubkeys)
    existing_oracles: Table<vector<u8>, ExistingOracle>,
    fee_types: vector<TypeName>,
    version: u8,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move (L20-26)
```text
public fun validate(
    oracle_key: &vector<u8>,
    queue: &Queue,
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(!queue.existing_oracles_contains(*oracle_key), EOracleKeyExists);
}
```
