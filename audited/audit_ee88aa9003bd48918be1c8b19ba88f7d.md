# Audit Report

## Title
Cross-Queue Oracle Attestation Authorization Bypass via Missing Queue Ownership Validation

## Summary
The Switchboard on-demand oracle attestation mechanism contains a critical authorization bypass allowing attackers to enable oracles using guardians from a different queue. This completely breaks the queue-specific guardian authorization model, enabling oracle manipulation that directly impacts Volo Vault's price feeds and asset valuations, creating a direct path to fund loss.

## Finding Description

The `oracle_attest_action::validate()` function fails to verify that the oracle being attested belongs to the queue whose guardians are authorizing it. [1](#0-0) 

The validation only checks that the guardian belongs to the queue's guardian queue, but never validates that the oracle itself belongs to that same queue. This differs from other oracle-related actions that properly enforce this check. The `queue_override_oracle_action` properly validates both queue key and ID match: [2](#0-1) 

Similarly, `aggregator_submit_result_action` enforces oracle-aggregator queue matching: [3](#0-2) 

**Attack Execution:**

1. Oracle O1 exists belonging to Queue1 with strict guardian requirements
2. Attacker creates Queue2 with compromised guardians under their control (permissionless operation)
3. Attacker calls the public entry function with mismatched parameters: oracle from Queue1, queue=Queue2, guardian from Queue2
4. Validation passes because it only checks guardian membership in Queue2, not oracle membership
5. The attestation message is generated using O1's stored queue_key (Queue1's key): [4](#0-3) 
6. Queue2's compromised guardians sign the attestation
7. When sufficient attestations accumulate (controlled by Queue2.min_attestations), O1 is enabled with attacker's keys: [5](#0-4) 
8. The oracle belongs to Queue1 but has attacker-controlled secp256k1_key
9. When submitting to Queue1 aggregators, the queue match check passes, but signature validation uses the attacker's key: [6](#0-5) 
10. Attacker can sign arbitrary price data and submit to aggregators
11. Volo Vault reads these corrupted prices: [7](#0-6) 

## Impact Explanation

**Critical Security Boundary Collapse:**
This vulnerability completely bypasses the queue-specific guardian authorization model, which is the foundational security mechanism for oracle attestation. Each queue is designed to maintain its own trusted guardian set, creating isolated trust domains. This vulnerability collapses these boundaries entirely.

**Direct Path to Fund Loss:**
- Compromised oracle data flows into Volo's price calculation system through the aggregator interface
- Vault valuation becomes manipulated, affecting share pricing (used throughout operation.move and user_entry.move) and withdrawal calculations
- Attackers can inflate/deflate asset values to extract funds through arbitrage or manipulated withdrawals
- The vault's total_usd_value calculations become unreliable, potentially bypassing loss_tolerance checks
- All protocols consuming the affected Switchboard aggregators are vulnerable

**Affected Security Guarantees:**
- Queue isolation and guardian authorization enforcement
- Oracle attestation integrity  
- Price feed reliability for Volo Vault asset valuation
- Vault share pricing accuracy

## Likelihood Explanation

**Attacker Capabilities Required:**
- Create a queue with controlled guardians (permissionless operation via `oracle_queue_init_action`)
- Attest own guardian oracles (standard operation)
- Access shared Oracle and Queue objects (publicly accessible by design)
- Invoke public entry function `oracle_attest_action::run()`

**Attack Complexity: LOW**
1. Create attacker-controlled queue with compromised guardians (permissionless, single transaction)
2. Attest own guardians to enable them (standard operation)
3. Call attestation function with mismatched oracle/queue parameters (single transaction)
4. Once threshold met, oracle is enabled with attacker's keys

**No Barriers:**
- No special privileges required beyond standard transaction submission
- All necessary objects are shared and accessible
- No economic costs prevent queue creation (only standard gas)
- Missing validation makes the bypass deterministic and reliable

**Detection Difficulty:**
- All function calls succeed normally without errors
- Events show attestations but don't expose the queue mismatch
- Would require off-chain monitoring of oracle-queue relationships to detect

**Probability: HIGH** - The attack is straightforward, requires no special access, and the missing validation makes it reliably exploitable.

## Recommendation

Add oracle-queue ownership validation to the `oracle_attest_action::validate()` function, consistent with other oracle actions:

```move
public fun validate(
    oracle: &mut Oracle,
    queue: &Queue,
    guardian: &Oracle,
    // ... other params
) {
    // Existing checks...
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(oracle.version() == EXPECTED_ORACLE_VERSION, EInvalidOracleVersion);
    assert!(guardian.version() == EXPECTED_ORACLE_VERSION, EInvalidOracleVersion);
    
    // ADD THESE CHECKS:
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
    
    // check that guardian belongs to queue's guardian queue
    assert!(guardian.queue() == queue.guardian_queue_id(), EInvalidGuardianQueue);
    
    // Remaining validation...
}
```

Define the new error constants:
```move
#[error]
const EInvalidQueueKey: vector<u8> = b"Invalid queue key";
#[error]
const EInvalidQueueId: vector<u8> = b"Invalid queue id";
```

## Proof of Concept

This vulnerability can be demonstrated with a test showing:
1. Oracle O1 created for Queue1
2. Queue2 created with attacker's guardian
3. Calling `oracle_attest_action::run(oracle=O1, queue=Queue2, guardian=Queue2_guardian, ...)` succeeds
4. O1's secp256k1_key is now set to attacker's value despite belonging to Queue1

The test would verify that the validation passes incorrectly and the oracle is enabled with cross-queue attestations, violating the intended queue isolation security model.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L64-64)
```text
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L121-123)
```text
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L40-41)
```text
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L60-60)
```text
    assert!(oracle.queue() == aggregator.queue(), EAggregatorQueueMismatch);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L91-91)
```text
    assert!(hash::check_subvec(&recovered_pubkey, &oracle.secp256k1_key(), 1), ERecoveredPubkeyInvalid);
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
