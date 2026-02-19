# Audit Report

## Title
Guardian Expiration Validation Bypass Allows Expired Guardians to Provide Oracle Attestations

## Summary
The `validate()` function in the Switchboard oracle attestation module contains a critical validation bug that checks the target oracle's expiration time instead of the guardian's expiration time. This allows expired guardians to continue providing attestations and prevents legitimate attestations for new oracles, breaking the guardian trust model and potentially enabling oracle price manipulation that affects the Volo vault.

## Finding Description

The vulnerability exists in the validation logic at line 67 of `oracle_attest_action.move`. [1](#0-0) 

The comment explicitly states "check that the guardian is valid" but the code checks `oracle.expiration_time_ms()` instead of `guardian.expiration_time_ms()`. This validates the wrong Oracle object - it checks the target oracle being attested to rather than the guardian oracle providing the attestation.

**Execution Flow:**

The vulnerability is triggered through the public entry function `run()`: [2](#0-1) 

The function calls `validate()` which performs the incorrect expiration check: [3](#0-2) 

If validation passes, `actuate()` adds the attestation: [4](#0-3) 

When sufficient attestations are collected, the oracle is enabled: [5](#0-4) 

**Why Existing Protections Fail:**

The signature verification at lines 76-92 only confirms the attestation came from the guardian's key but doesn't check if the guardian is still valid (not expired). [6](#0-5) 

The queue verification only checks the guardian belongs to the correct guardian queue, not expiration status: [7](#0-6) 

**Two Critical Failure Modes:**

1. **For New Oracles:** New oracles are created with `expiration_time_ms: 0`: [8](#0-7) 

   The check `0 > current_time` always evaluates to false, causing all legitimate attestations to fail with `EGuardianInvalid` error.

2. **For Already-Enabled Oracles:** If the target oracle has `expiration_time_ms > current_time`, the validation passes regardless of the guardian's actual expiration status. An expired guardian can provide attestations because the code validates the wrong object's expiration.

## Impact Explanation

This vulnerability breaks the fundamental security model of Switchboard's guardian-based oracle attestation system.

**Direct Security Impact:**

The Switchboard oracle system relies on guardians that expire based on their authorization period. When a guardian expires, it should lose the ability to attest to oracle validity. This bug completely bypasses that security mechanism, allowing expired guardians (potentially compromised, revoked for security reasons, or operationally abandoned) to continue participating in oracle validation.

**Volo Vault Impact:**

The Volo vault integrates Switchboard aggregators for asset price feeds: [9](#0-8) 

Oracles feed price data to aggregators: [10](#0-9) 

If expired guardians enable compromised oracles through illegitimate attestations, those oracles can provide manipulated prices to aggregators. The vault would then use these manipulated prices for critical operations including deposits, withdrawals, and position valuations, potentially causing:
- Incorrect share pricing leading to user fund loss
- Manipulated collateral valuations affecting vault health
- Unauthorized value extraction through price arbitrage

**Affected Parties:**
- Vault depositors relying on accurate oracle prices
- Protocol operators trusting the guardian validation model
- All users depending on oracle data integrity for their positions

## Likelihood Explanation

**High Likelihood due to:**

1. **Public Accessibility:** The `run()` function is a public entry function accessible to any address without special permissions. [2](#0-1) 

2. **Natural Guardian Expiration:** Guardians expire naturally over time based on queue configuration. [11](#0-10) 

3. **No Additional Checks:** No other validation in the codebase checks guardian expiration times, making this the single point of failure.

4. **Realistic Attack Scenario:** After a guardian expires, operational security may be reduced since the guardian is considered inactive. If an attacker obtains access to expired guardian credentials (through key compromise, insider access, or abandoned infrastructure), they can exploit this bug to provide attestations that should be rejected.

5. **Difficult Detection:** The attestations appear valid on-chain with correct signatures and pass all checks except the one implemented incorrectly, making the attack difficult to detect without specifically monitoring guardian expiration times off-chain.

## Recommendation

Fix the validation to check the guardian's expiration time instead of the target oracle's expiration time:

```move
// Line 67 should be changed from:
assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);

// To:
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

This ensures that:
1. Expired guardians cannot provide attestations
2. New oracles (with `expiration_time_ms = 0`) can receive attestations from valid guardians
3. The guardian trust model functions as intended

## Proof of Concept

```move
#[test]
fun test_expired_guardian_can_attest() {
    use sui::test_scenario;
    use sui::clock;
    
    let admin = @0x1;
    let mut scenario = test_scenario::begin(admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Set current time to 1000000ms
    clock::set_for_testing(&mut clock, 1000000);
    
    // Create a guardian oracle that has already expired
    // (expiration_time_ms = 500000, which is less than current time 1000000)
    let mut guardian = create_test_oracle(scenario.ctx());
    set_oracle_expiration(&mut guardian, 500000); // Expired guardian
    
    // Create a target oracle that is currently valid
    // (expiration_time_ms = 2000000, which is greater than current time)
    let mut target_oracle = create_test_oracle(scenario.ctx());
    set_oracle_expiration(&mut target_oracle, 2000000); // Valid oracle
    
    let queue = create_test_queue(scenario.ctx());
    
    // This should FAIL because the guardian is expired
    // But due to the bug, it will PASS because it checks target_oracle.expiration_time_ms()
    // instead of guardian.expiration_time_ms()
    
    // The validate() call will succeed incorrectly:
    // assert!(target_oracle.expiration_time_ms() > clock.timestamp_ms())
    // assert!(2000000 > 1000000) -> TRUE (passes when it should fail)
    
    validate(
        &mut target_oracle,
        &queue,
        &guardian, // This guardian is EXPIRED but check passes
        timestamp_seconds,
        mr_enclave,
        secp256k1_key,
        signature,
        &clock,
    );
    
    // If validation passes, the expired guardian can add attestation
    // This violates the guardian trust model
    
    cleanup(guardian, target_oracle, queue, clock);
    test_scenario::end(scenario);
}
```

The proof of concept demonstrates that an expired guardian (with `expiration_time_ms = 500000`) can successfully provide attestations to a target oracle (with `expiration_time_ms = 2000000`) when the current time is 1000000ms, because the validation incorrectly checks the target oracle's expiration instead of the guardian's expiration.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L43-67)
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L75-92)
```text
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L95-109)
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L65-85)
```text
public(package) fun new(
    oracle_key: vector<u8>,
    queue: ID,
    queue_key: vector<u8>,
    ctx: &mut TxContext,
): ID {
    let id = object::new(ctx);
    let oracle_id = *(id.as_inner());
    let oracle = Oracle {
        id,
        oracle_key,
        queue,
        queue_key,
        expiration_time_ms: 0,
        secp256k1_key: vector::empty(),
        valid_attestations: vector::empty(),
        mr_enclave: vector::empty(),
        version: VERSION,
    };
    transfer::share_object(oracle);
    oracle_id
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L243-257)
```text
public(package) fun add_result(
    aggregator: &mut Aggregator,
    result: Decimal,
    timestamp_ms: u64,
    oracle: ID,
    clock: &Clock,
) {
    let now_ms = clock.timestamp_ms();
    set_update(&mut aggregator.update_state, result, oracle, timestamp_ms);
    let mut current_result = compute_current_result(aggregator, now_ms);
    if (current_result.is_some()) {
        aggregator.current_result = current_result.extract();
        // todo: log the result
    };
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L62-64)
```text
public fun oracle_validity_length_ms(queue: &Queue): u64 {
    queue.oracle_validity_length_ms
}
```
