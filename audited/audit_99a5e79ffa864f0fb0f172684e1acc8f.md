# Audit Report

## Title
Missing Queue-Oracle Binding Validation Allows Cross-Queue Attestation Replay with Configuration Bypass

## Summary
The `oracle_attest_action::validate()` function fails to verify that the Queue parameter matches the Oracle's designated queue, allowing attestations to be processed using any queue's security parameters. This enables attackers to bypass `min_attestations` requirements and apply incorrect `oracle_validity_length_ms` values by substituting a malicious queue with relaxed parameters.

## Finding Description

The vulnerability exists in the attestation validation flow where guardian signatures are verified to enable oracles. When an oracle is created through `oracle_init_action`, it stores both the queue ID and queue_key from its designated queue. [1](#0-0) [2](#0-1) 

However, the `oracle_attest_action::validate()` function retrieves the `queue_key` from the oracle object itself (not from the Queue parameter) to generate the attestation message for signature verification, but never validates that the Queue parameter actually matches the oracle's stored queue. [3](#0-2) 

The critical missing validation is evident when comparing with `queue_override_oracle_action`, which correctly validates the queue-oracle relationship: [4](#0-3) 

In the `actuate()` function, the Queue parameter's configuration is used to determine oracle enablement, without verifying it matches the oracle's designated queue: [5](#0-4) 

**Attack Scenario:**
1. Oracle1 is created on QueueA requiring `min_attestations=5`
2. Oracle1 collects only 3 valid attestations (insufficient for QueueA)
3. Attacker creates QueueB with `min_attestations=1` and same `guardian_queue_id` as QueueA
4. Attacker calls `oracle_attest_action::run(oracle=Oracle1, queue=QueueB, ...)`
5. Validation passes because guardian belongs to shared guardian_queue_id
6. Signature verification passes because it uses Oracle1's stored `queue_key` (from QueueA)
7. Actuate uses QueueB's `min_attestations=1`, enabling Oracle1 with only 3 attestations
8. Oracle1 receives wrong `oracle_validity_length_ms` from QueueB instead of QueueA

## Impact Explanation

**High Severity - Oracle Security Parameter Bypass:**

1. **Min Attestations Bypass**: The guardian attestation security model requires multiple guardians to sign off before an oracle is enabled. By substituting a queue with `min_attestations=1`, an attacker can enable oracles with insufficient validation, undermining the multi-signature security guarantees.

2. **Incorrect Oracle Validity Period**: Oracles receive expiration times based on the wrong queue's `oracle_validity_length_ms`, potentially extending oracle validity far beyond intended security boundaries (e.g., using a queue with 5-year validity instead of 7-day validity).

3. **Protocol Trust Violation**: Each queue is designed with specific security parameters appropriate for its use case. This vulnerability allows mixing configurations, breaking the isolation between different security domains and trust boundaries.

4. **Widespread Impact**: Any oracle on any queue can be compromised if an attacker creates a malicious queue sharing the same guardian queue - a common pattern in multi-tenant oracle systems where multiple oracle queues legitimately reference the same guardian queue.

## Likelihood Explanation

**High Likelihood:**

1. **Public Entry Point**: The attestation function is publicly accessible to any caller: [6](#0-5) 

2. **Permissionless Queue Creation**: Queue creation is a public entry function with minimal validation: [7](#0-6) 

3. **Architectural Design Enables Attack**: Multiple queues can legitimately share the same `guardian_queue_id`, which is passed as a parameter during queue initialization. This is by design for multi-tenant oracle systems.

4. **No Special Privileges Required**: Attackers only need:
   - Gas fees to create a malicious queue
   - Valid guardian attestation signatures (observable on-chain through events)
   - Ability to call public entry functions

5. **Detection Difficulty**: The malicious transaction appears completely valid - all signature checks pass, guardian verification succeeds, and events are emitted normally. Only off-chain monitoring comparing `oracle.queue()` with the queue parameter would detect the mismatch.

## Recommendation

Add queue-oracle binding validation to `oracle_attest_action::validate()` function, consistent with the checks in `queue_override_oracle_action`:

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
    // ... existing version checks ...
    
    // ADD THESE CHECKS:
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
    
    // ... rest of validation ...
}
```

These assertions ensure that the Queue parameter used for configuration retrieval is the same queue that the oracle was created for, preventing cross-queue parameter substitution attacks.

## Proof of Concept

```move
#[test]
fun test_cross_queue_attestation_bypass() {
    use sui::test_scenario;
    use switchboard::oracle_attest_action;
    use switchboard::oracle_init_action;
    use switchboard::oracle_queue_init_action;
    
    let admin = @0x1;
    let attacker = @0x2;
    let mut scenario = test_scenario::begin(admin);
    
    // 1. Create guardian queue (shared by both QueueA and QueueB)
    let guardian_queue_id = create_guardian_queue(&mut scenario);
    
    // 2. Admin creates QueueA with strict parameters (min_attestations=5)
    scenario.next_tx(admin);
    let queue_a_id = create_oracle_queue(
        &mut scenario,
        guardian_queue_id,
        5, // min_attestations
        7 * 24 * 60 * 60 * 1000 // oracle_validity_length_ms = 7 days
    );
    
    // 3. Admin creates Oracle1 on QueueA
    scenario.next_tx(admin);
    let oracle1_id = create_oracle(&mut scenario, queue_a_id);
    
    // 4. Oracle1 collects 3 attestations (insufficient for QueueA's requirement of 5)
    collect_attestations(&mut scenario, oracle1_id, 3);
    
    // 5. Attacker creates QueueB with relaxed parameters (min_attestations=1)
    scenario.next_tx(attacker);
    let queue_b_id = create_oracle_queue(
        &mut scenario,
        guardian_queue_id, // Same guardian queue!
        1, // min_attestations - RELAXED
        5 * 365 * 24 * 60 * 60 * 1000 // oracle_validity_length_ms = 5 years - EXTENDED
    );
    
    // 6. Attacker calls attest with Oracle1 from QueueA but using QueueB's parameters
    scenario.next_tx(attacker);
    {
        let mut oracle1 = test_scenario::take_shared_by_id<Oracle>(&scenario, oracle1_id);
        let queue_b = test_scenario::take_shared_by_id<Queue>(&scenario, queue_b_id);
        let guardian = test_scenario::take_shared_by_id<Oracle>(&scenario, guardian_id);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        
        // This should FAIL but currently SUCCEEDS due to missing validation
        oracle_attest_action::run(
            &mut oracle1,
            &queue_b, // Wrong queue! Should use QueueA
            &guardian,
            timestamp_seconds,
            mr_enclave,
            secp256k1_key,
            valid_signature,
            &clock
        );
        
        // Oracle1 is now enabled with QueueB's parameters despite being created on QueueA
        assert!(oracle1.expiration_time_ms() > 0); // Oracle enabled
        // Uses QueueB's min_attestations (1) instead of QueueA's (5)
        // Uses QueueB's oracle_validity_length_ms (5 years) instead of QueueA's (7 days)
        
        test_scenario::return_shared(oracle1);
        test_scenario::return_shared(queue_b);
        test_scenario::return_shared(guardian);
        test_scenario::return_shared(clock);
    };
    
    test_scenario::end(scenario);
}
```

### Citations

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move (L33-38)
```text
    let oracle_id = oracle::new(
        oracle_key,
        queue.id(),
        queue.queue_key(),
        ctx,
    );
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L40-41)
```text
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/oracle_queue_init_action.move (L67-77)
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
```
