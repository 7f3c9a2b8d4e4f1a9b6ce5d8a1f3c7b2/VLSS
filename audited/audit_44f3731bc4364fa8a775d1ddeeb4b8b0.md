### Title
Unbounded Guardian Attestation Vector Growth Enables Denial of Service

### Summary
The `add_attestation()` function in `oracle.move` has no limit on the number of unique guardians that can attest to an oracle. Since oracle creation is permissionless and attestations only filter expired entries and same-guardian duplicates, an attacker can create N guardian oracles and have them all attest to a target oracle, causing the `valid_attestations` vector to grow to size N. This results in O(N) filtering operations on every subsequent attestation, leading to prohibitively high gas costs and potential denial of service.

### Finding Description

The vulnerability exists in the `add_attestation()` function which only removes expired attestations and duplicate attestations from the same guardian, but imposes no limit on the total number of unique guardians: [1](#0-0) 

The function filters the vector to keep attestations that are not expired (`timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms`) and not from the same guardian (`guardian_id != attestation.guardian_id`), then adds the new attestation. With N unique guardians, the vector can grow to size N.

The root cause is that guardian oracle creation is permissionless - anyone can call the public entry function to create oracles on the guardian queue with no authority check: [2](#0-1) 

The validation only checks for queue version and duplicate oracle keys, but does not require queue authority: [3](#0-2) 

Once created, each guardian can submit attestations through the public entry function: [4](#0-3) 

The attestation timeout is set to 10 minutes: [5](#0-4) 

### Impact Explanation

**Operational Impact - Denial of Service:**

1. **Gas Cost Escalation**: Every call to `add_attestation()` must iterate through all N attestations in the filtering operation (line 101-103), resulting in O(N) computational complexity. Similarly, `valid_attestation_count()` must iterate through all attestations: [6](#0-5) 

2. **Oracle Enablement Blocked**: Legitimate guardians attempting to attest face prohibitively high gas costs or may hit Sui transaction gas limits if the vector is sufficiently large, preventing the oracle from accumulating the required `min_attestations` to become enabled.

3. **Storage Bloat**: The Oracle shared object grows linearly with the number of unique guardian attestations, consuming on-chain storage.

4. **Volo Vault Impact**: Since Volo Vault depends on Switchboard oracles for price data, an oracle that cannot be enabled due to this DoS attack would prevent vault operations requiring price updates.

**Affected Parties**: Any oracle relying on guardian attestations, including those used by Volo Vault for USD valuations and operation value checks.

**Severity**: Medium - causes operational DoS but does not directly steal funds or corrupt custody.

### Likelihood Explanation

**High Likelihood - Easily Exploitable:**

1. **Attacker Capabilities**: Any untrusted user can execute the attack with no special permissions. The attack requires:
   - Creating N guardian oracles (N transaction calls to `oracle_init_action::run()`)
   - Having each guardian attest to the target oracle (N transaction calls to `oracle_attest_action::run()`)

2. **Attack Complexity**: Low - the attack is straightforward:
   - Step 1: Create N unique guardian oracles on the guardian queue with different oracle_keys
   - Step 2: Within a 10-minute window, call attestation function from each guardian
   - Step 3: Target oracle's vector now contains N attestations
   - Step 4: Legitimate attestations become expensive/impossible

3. **Economic Feasibility**: 
   - Cost: Only Sui transaction gas fees (no protocol fees for oracle creation or attestation)
   - Benefit: Successful DoS of target oracle with N proportional to desired impact
   - Persistence: Attacker must re-attest every 10 minutes to maintain attack, but initial setup (creating N guardians) is one-time

4. **Detection Constraints**: Attack is on-chain visible but may be difficult to prevent once guardians are created. No rate limiting or size checks exist in the protocol.

### Recommendation

**Immediate Mitigations:**

1. **Add Maximum Attestation Limit**: Implement a configurable maximum on the `valid_attestations` vector size in the `add_attestation()` function:

```move
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    
    // Add size limit check
    assert!(oracle.valid_attestations.length() < MAX_ATTESTATIONS, ETooManyAttestations);
    
    vector::push_back(&mut oracle.valid_attestations, attestation);
}
```

2. **Add Guardian Queue Authority Check**: Require queue authority permission to create guardian oracles in `oracle_init_action.move`:

```move
public fun validate(
    oracle_key: &vector<u8>,
    queue: &Queue,
    ctx: &TxContext,
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(!queue.existing_oracles_contains(*oracle_key), EOracleKeyExists);
    assert!(queue.has_authority(ctx), EUnauthorized); // Add this check
}
```

3. **Add Rate Limiting**: Implement per-oracle rate limiting on attestations to prevent rapid spam.

**Test Cases:**
- Test that vector cannot exceed MAX_ATTESTATIONS
- Test that non-authority users cannot create guardian oracles
- Test gas costs remain bounded with maximum attestation count

### Proof of Concept

**Initial State:**
- Guardian queue exists with authority set to a trusted address
- Target oracle X exists on an oracle queue that references the guardian queue

**Attack Sequence:**

1. **Attacker creates 1000 guardian oracles** (assuming no authority check):
   ```
   For i = 1 to 1000:
       Call oracle_init_action::run(unique_oracle_key_i, guardian_queue, ctx)
       // Creates guardian oracle i
   ```

2. **Attacker has all 1000 guardians attest to oracle X within 10-minute window**:
   ```
   For i = 1 to 1000:
       Call oracle_attest_action::run(
           oracle_X,
           oracle_queue,
           guardian_i,
           timestamp,
           mr_enclave,
           secp256k1_key,
           valid_signature_i,
           clock
       )
       // Adds attestation from guardian i to oracle X
   ```

3. **Result - Oracle X state**:
   - `oracle_X.valid_attestations.length() == 1000`
   - Every subsequent `add_attestation()` call must filter through 1000 items
   - Legitimate guardians face high gas costs (1000x normal)

4. **Expected vs Actual**:
   - **Expected**: Guardian attestations should be bounded by protocol limits
   - **Actual**: Vector grows unbounded (limited only by Sui object size limits)
   - **Success Condition**: `valid_attestations.length()` >> `queue.min_attestations()`, causing DoS

**Validation**: The attack succeeds because no maximum attestation count check exists in `add_attestation()` and oracle creation is permissionless.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move (L50-64)
```text
public entry fun run(
    oracle_key: vector<u8>,
    queue: &mut Queue,
    ctx: &mut TxContext
) {   
    validate(
        &oracle_key,
        queue,
    );
    actuate(
        queue,
        oracle_key,
        ctx,
    );
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
