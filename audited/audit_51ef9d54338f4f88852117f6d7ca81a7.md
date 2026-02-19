# Audit Report

## Title
Cross-Queue Oracle Attestation Authorization Bypass via Missing Queue Ownership Validation

## Summary
The Switchboard on-demand oracle attestation mechanism contains a critical authorization bypass that allows an attacker to enable oracles using guardians from a different queue than the oracle belongs to. This breaks the fundamental security model where each queue has its own trusted guardian set, enabling oracle manipulation that directly impacts Volo Vault's price feeds and asset valuations.

## Finding Description

The `oracle_attest_action::validate()` function fails to verify that the oracle being attested belongs to the queue whose guardians are authorizing it. [1](#0-0) 

The validation only checks that the guardian belongs to the queue's guardian queue, but never validates that the oracle itself belongs to that same queue. This differs from other oracle-related actions that properly enforce this check: [2](#0-1) [3](#0-2) 

The oracle registration mechanism only enforces per-queue uniqueness, allowing the same oracle_key to be registered across multiple queues: [4](#0-3) 

**Attack Execution Path:**

1. An Oracle object O1 exists belonging to Queue1 (O1.queue == Queue1.id) with strict guardian requirements
2. Attacker creates Queue2 with compromised guardians under their control
3. Attacker invokes the public entry function with mismatched parameters:
   - oracle: &mut O1 (belongs to Queue1)
   - queue: &Queue2 (attacker's queue)
   - guardian: Guardian from Queue2's guardian queue

4. The validation passes because it only checks guardian membership in Queue2, not oracle membership
5. The attestation message is generated using O1's stored queue_key (Queue1's key): [5](#0-4) 

6. Queue2's compromised guardians sign the attestation for Queue1's oracle
7. Once sufficient attestations accumulate, O1 is enabled: [6](#0-5) 

8. The enabled Queue1 oracle can now submit malicious price data to Queue1 aggregators
9. Volo Vault reads these corrupted prices: [7](#0-6) 

## Impact Explanation

**Critical Security Boundary Collapse:**
This vulnerability completely bypasses the queue-specific guardian authorization model, which is the foundational security mechanism for oracle attestation. Each queue is designed to maintain its own trusted guardian set, creating isolated trust domains. This vulnerability collapses these boundaries.

**Direct Path to Fund Loss:**
- Compromised oracle data flows into Volo's price calculation system
- Vault valuation becomes manipulated, affecting share pricing and withdrawal calculations
- Attackers can inflate/deflate asset values to extract funds through arbitrage or manipulated withdrawals
- All protocols consuming the affected Switchboard aggregators are vulnerable

**Affected Security Guarantees:**
- Queue isolation and guardian authorization enforcement
- Oracle attestation integrity
- Price feed reliability for Volo Vault and other consuming protocols

## Likelihood Explanation

**Attacker Capabilities Required:**
- Create a queue with controlled guardians (permissionless operation)
- Access shared Oracle and Queue objects (publicly accessible by design)
- Invoke public entry function `oracle_attest_action::run()`

**Attack Complexity: LOW**
1. Register oracle_key in target queue (standard operation, no privileges needed)
2. Create attacker-controlled queue with compromised guardians (permissionless)
3. Call attestation function with mismatched oracle/queue parameters (single transaction)

**No Barriers:**
- No special privileges required beyond standard transaction submission
- All necessary objects are shared and accessible
- No economic costs prevent queue creation
- Missing validation makes the bypass deterministic

**Detection Difficulty:**
- All function calls succeed normally without errors
- Events show attestations but don't flag the queue mismatch
- Would require off-chain monitoring of oracle-queue relationships to detect

**Probability: HIGH** - The attack is straightforward, requires no special access, and the missing validation makes it reliably exploitable.

## Recommendation

Add explicit validation that the oracle belongs to the queue whose guardians are attesting it:

```move
public fun validate(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    // ... other params
) {
    // ... existing validations ...
    
    // check that guardian queue (for the target queue) is the guardian's queue
    assert!(guardian.queue() == queue.guardian_queue_id(), EInvalidGuardianQueue);
    
    // ADD THIS VALIDATION:
    assert!(oracle.queue() == queue.id(), EInvalidQueueId);
    
    // ... rest of validation ...
}
```

This ensures that only guardians from an oracle's assigned queue can attest it, maintaining the intended trust boundary separation.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Create Queue1 with honest guardians
2. Register oracle_key "ABC" in Queue1, creating Oracle O1
3. Create Queue2 with attacker-controlled guardians
4. Call `oracle_attest_action::run(&mut O1, &Queue2, &Guardian2, ...)` 
5. Verify that Queue2's guardians successfully attest O1 (should fail but doesn't)
6. Verify O1 becomes enabled after sufficient Queue2 guardian attestations
7. Demonstrate O1 can submit results to Queue1 aggregators
8. Show corrupted price data flows into Volo Vault's oracle system

The test would prove that cross-queue attestation bypasses the intended guardian authorization model, enabling oracle manipulation with direct impact on Volo's price integrity.

---

**Notes:**

This vulnerability exists in the Switchboard dependency integrated into Volo Vault. While it affects the external oracle system, it has direct and severe impact on Volo's security because Volo relies on Switchboard aggregators for critical price feeds. The missing validation in `oracle_attest_action` creates a complete bypass of the queue security model, allowing any attacker to enable oracles in any queue using guardians from their own controlled queue.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L63-64)
```text
    // check that guardian queue (for the target queue) is the guardian's queue
    assert!(guardian.queue() == queue.guardian_queue_id(), EInvalidGuardianQueue);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L40-41)
```text
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L59-60)
```text
    // verify that the oracle is servicing the correct queue
    assert!(oracle.queue() == aggregator.queue(), EAggregatorQueueMismatch);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move (L24-25)
```text
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(!queue.existing_oracles_contains(*oracle_key), EOracleKeyExists);
```

**File:** volo-vault/sources/oracle.move (L250-261)
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
```
