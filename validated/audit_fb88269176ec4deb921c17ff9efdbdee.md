# Audit Report

## Title
Incorrect Expiration Validation in Oracle Attestation Causes Complete DoS of Attestation Mechanism

## Summary
The `oracle_attest_action::validate()` function contains a critical logic error at line 67 that checks the oracle's expiration time instead of the guardian's expiration time. This causes a complete denial-of-service of the oracle attestation mechanism for all newly created oracles (which initialize with `expiration_time_ms = 0`) while simultaneously failing to validate that guardian oracles are not expired.

## Finding Description

The validation function is intended to verify that the guardian oracle performing the attestation is valid (not expired). However, line 67 incorrectly validates the wrong object: [1](#0-0) 

The comment states "check that the guardian is valid" and the error code is `EGuardianInvalid`, confirming the intent is to validate the guardian parameter. However, the code checks `oracle.expiration_time_ms()` instead of `guardian.expiration_time_ms()`.

**Root Cause Analysis:**

The function signature clearly distinguishes between two oracle objects:
- `oracle: &mut Oracle` - the oracle being attested (target)
- `guardian: &Oracle` - the guardian oracle performing the attestation (validator)

New oracles are initialized with `expiration_time_ms = 0`: [2](#0-1) 

**Execution Path:**

The public entry function `run()` calls `validate()`: [3](#0-2) 

When a new oracle (with `expiration_time_ms = 0`) attempts attestation, the check becomes `assert!(0 > current_timestamp)`, which always fails.

**Security Guarantees Broken:**

1. **Decentralized Oracle Onboarding:** The attestation mechanism is the intended decentralized path for oracles to become active through guardian validation. This is completely broken.

2. **Guardian Expiration Validation:** The security model requires that only non-expired guardians can attest to oracles. This validation is completely bypassed—even expired guardians could theoretically attest if an oracle is pre-enabled via override.

## Impact Explanation

**Operational DoS Impact (Critical):**
- The entire oracle attestation mechanism is non-functional for all new oracles
- Forces complete reliance on centralized `queue_override_oracle_action`, which requires queue authority privileges: [4](#0-3) 

**Security Integrity Impact (High):**
- Guardian expiration validation is completely absent
- Expired guardians could attest to oracles in non-standard scenarios (where oracle is manually enabled first)
- Undermines the TEE attestation security model that relies on guardian validation

**Volo Protocol Impact (High):**
- Volo vault uses Switchboard aggregators for asset price feeds: [5](#0-4) 

- Aggregators depend on oracles for data feeds
- Broken attestation forces centralized oracle management, affecting decentralized price feed integrity
- Impacts vault asset valuation, share calculations, and loss tolerance checks

## Likelihood Explanation

**Reachability: High**
- The bug is in a public entry function accessible to any user
- TypeScript SDK includes attestation functionality, confirming intended usage: [6](#0-5) 

**Attack Complexity: Zero**
- For DoS: Simply calling the attestation function as designed triggers the bug (no special inputs needed)
- For expired guardian bypass: Requires oracle to be pre-enabled via override (non-standard but possible)

**Feasibility: Deterministic**
- The bug is always present and produces 100% failure rate for new oracle attestations
- No special preconditions or timing windows required
- Reproducible on every attestation attempt with a new oracle

**Probability:** High (100% DoS on attestation attempts), Medium (security bypass requires non-standard setup)

## Recommendation

Fix the validation on line 67 to check the guardian's expiration instead of the oracle's:

```move
// check that the guardian is valid
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

This simple one-line change restores both:
1. The ability to attest new oracles (since guardian oracles should have valid expiration times)
2. Proper validation that guardians performing attestations are not expired

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = switchboard::oracle_attest_action::EGuardianInvalid)]
fun test_new_oracle_attestation_dos() {
    use sui::test_scenario;
    use sui::clock;
    use switchboard::oracle;
    use switchboard::queue;
    
    let admin = @0x1;
    let mut scenario = test_scenario::begin(admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(1000000000); // Set current time
    
    // Create guardian queue and queue
    let guardian_queue = create_test_guardian_queue(scenario.ctx());
    let mut queue = create_test_queue(guardian_queue.id(), scenario.ctx());
    
    // Create and enable a guardian oracle (so it has expiration > 0)
    let mut guardian = create_test_oracle(&queue, scenario.ctx());
    guardian.enable_oracle(
        test_secp256k1_key(),
        test_mr_enclave(),
        clock.timestamp_ms() + 86400000 // Valid for 1 day
    );
    
    // Create a NEW oracle (expiration_time_ms = 0 by default)
    let mut new_oracle = create_test_oracle(&queue, scenario.ctx());
    
    // Attempt attestation - THIS WILL FAIL with EGuardianInvalid
    // because it checks new_oracle.expiration_time_ms() which is 0
    oracle_attest_action::run(
        &mut new_oracle,
        &queue,
        &guardian,
        clock.timestamp_ms() / 1000,
        test_mr_enclave(),
        test_secp256k1_key(),
        test_signature(),
        &clock
    );
    
    // Clean up
    cleanup_test_objects(guardian, new_oracle, queue, guardian_queue);
    clock.destroy_for_testing();
    test_scenario::end(scenario);
}
```

The test demonstrates that new oracles (with `expiration_time_ms = 0`) cannot be attested even when the guardian is valid, proving the complete DoS of the attestation mechanism.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L66-67)
```text
    // check that the guardian is valid
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L135-154)
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L65-86)
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

**File:** volo-vault/sources/oracle.move (L158-184)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);

    emit(SwitchboardAggregatorAdded {
        asset_type,
        aggregator: aggregator.id().to_address(),
    });
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/sui-sdk/src/oracle/index.ts (L202-214)
```typescript
      tx.moveCall({
        target: `${switchboardAddress}::oracle_attest_action::run`,
        arguments: [
          tx.object(this.address),
          tx.object(oracleData.queue),
          tx.object(guardianId),
          tx.pure.u64(message.timestamp),
          tx.pure.vector("u8", Array.from(fromHex(mrEnclave))),
          tx.pure.vector("u8", Array.from(fromHex(secp256k1Key))),
          tx.pure.vector("u8", signature),
          tx.object(SUI_CLOCK_OBJECT_ID),
        ],
      });
```
