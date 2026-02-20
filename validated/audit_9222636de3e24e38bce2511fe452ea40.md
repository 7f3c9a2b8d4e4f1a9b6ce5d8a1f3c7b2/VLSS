# Audit Report

## Title
Incorrect Expiration Validation in Oracle Attestation Causes Complete DoS of Attestation Mechanism

## Summary
The `oracle_attest_action::validate()` function contains a critical logic error that checks the oracle's expiration time instead of the guardian's expiration time. This causes a complete denial-of-service of the oracle attestation mechanism for all newly created oracles (which initialize with `expiration_time_ms = 0`) while simultaneously failing to validate that guardian oracles are not expired.

## Finding Description

The validation function is intended to verify that the guardian oracle performing the attestation is valid (not expired). However, the code incorrectly validates the wrong object: [1](#0-0) 

The comment states "check that the guardian is valid" and the error code is `EGuardianInvalid`, confirming the intent is to validate the `guardian` parameter. However, the code checks `oracle.expiration_time_ms()` instead of `guardian.expiration_time_ms()`.

**Root Cause Analysis:**

The function signature clearly distinguishes between two oracle objects:
- `oracle: &mut Oracle` - the oracle being attested (target)
- `guardian: &Oracle` - the guardian oracle performing the attestation (validator)

New oracles are initialized with `expiration_time_ms = 0`: [2](#0-1) 

**Execution Path:**

The public entry function `run()` calls `validate()`: [3](#0-2) 

When a new oracle (with `expiration_time_ms = 0`) attempts attestation, the check becomes `assert!(0 > current_timestamp)`, which always fails.

**Security Guarantees Broken:**

1. **Decentralized Oracle Onboarding:** The attestation mechanism is the intended decentralized path for oracles to become active through guardian validation. This is completely broken. The only alternative paths that call `enable_oracle` are attestation (broken) and override (requires queue authority): [4](#0-3) 

2. **Guardian Expiration Validation:** The security model requires that only non-expired guardians can attest to oracles. This validation is completely bypassed—even expired guardians could theoretically attest if an oracle is pre-enabled via override.

## Impact Explanation

**Operational DoS Impact (Critical):**
- The entire oracle attestation mechanism is non-functional for all new oracles
- Forces complete reliance on centralized `queue_override_oracle_action`, which requires queue authority privileges
- Breaks the decentralized TEE attestation workflow

**Security Integrity Impact (High):**
- Guardian expiration validation is completely absent
- Expired guardians could attest to oracles in non-standard scenarios (where oracle is manually enabled first)
- Undermines the TEE attestation security model that relies on guardian validation

**Volo Protocol Impact (High):**
- Volo vault uses Switchboard aggregators for asset price feeds: [5](#0-4) [6](#0-5) 

- Aggregators depend on oracles for data feeds, and oracles must have valid `expiration_time_ms` to submit results: [7](#0-6) 

- Broken attestation forces centralized oracle management, affecting decentralized price feed integrity
- Impacts vault asset valuation, share calculations, and loss tolerance checks

## Likelihood Explanation

**Reachability: High**
- The bug is in a public entry function accessible to any user
- No special privileges or preconditions required

**Attack Complexity: Zero**
- For DoS: Simply calling the attestation function as designed triggers the bug (no special inputs needed)
- For expired guardian bypass: Requires oracle to be pre-enabled via override (non-standard but possible)

**Feasibility: Deterministic**
- The bug is always present and produces 100% failure rate for new oracle attestations
- No special preconditions or timing windows required
- Reproducible on every attestation attempt with a new oracle

**Probability:** High (100% DoS on attestation attempts), Medium (security bypass requires non-standard setup)

## Recommendation

Change line 67 to validate the guardian's expiration time instead of the oracle's expiration time:

```move
// check that the guardian is valid
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

This simple one-line fix ensures:
1. Guardian oracles are properly validated before they can attest
2. New oracles with `expiration_time_ms = 0` can successfully receive attestations
3. The decentralized oracle onboarding mechanism functions as intended

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = switchboard::oracle_attest_action::EGuardianInvalid)]
fun test_new_oracle_attestation_fails() {
    use sui::test_scenario;
    use sui::clock;
    use switchboard::oracle;
    use switchboard::queue;
    use switchboard::oracle_attest_action;
    
    let admin = @0xADMIN;
    let mut scenario = test_scenario::begin(admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(1000000); // Set current time to 1000 seconds
    
    // Create queue and guardian queue
    let mut queue = queue::new_for_testing(scenario.ctx());
    let guardian_queue = queue::new_guardian_queue_for_testing(scenario.ctx());
    queue.set_guardian_queue_id(guardian_queue.id());
    
    // Create guardian oracle with valid expiration (not expired)
    let mut guardian = oracle::new_for_testing(
        b"guardian_key",
        guardian_queue.id(),
        b"queue_key",
        scenario.ctx()
    );
    guardian.enable_oracle(
        b"guardian_secp_key",
        b"guardian_mr_enclave",
        2000000 // Expires in the future
    );
    
    // Create new oracle (expiration_time_ms = 0)
    let mut oracle = oracle::new_for_testing(
        b"oracle_key",
        queue.id(),
        b"queue_key",
        scenario.ctx()
    );
    
    // Attempt attestation - this will fail because line 67 checks oracle.expiration_time_ms() which is 0
    // assert!(0 > 1000000) fails with EGuardianInvalid
    oracle_attest_action::run(
        &mut oracle,
        &queue,
        &guardian,
        1000, // timestamp_seconds
        b"mr_enclave",
        b"secp256k1_key",
        vector::empty(), // signature (would be validated later)
        &clock,
    );
    
    // Clean up
    test_scenario::end(scenario);
}
```

This test demonstrates that calling the attestation function with a newly created oracle (which has `expiration_time_ms = 0`) will always fail with `EGuardianInvalid`, even when the guardian is valid and not expired. The bug causes the validation to check the wrong object's expiration time.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L73-83)
```text
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

**File:** volo-vault/sources/oracle.move (L8-8)
```text
use switchboard::aggregator::Aggregator;
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L62-63)
```text
    // verify that the oracle is up
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```
