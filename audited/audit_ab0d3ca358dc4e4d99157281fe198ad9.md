# Audit Report

## Title
Guardian Expiration Check Validates Wrong Oracle Object, Breaking Attestation Flow for New Oracles

## Summary
The `validate()` function in the oracle attestation action incorrectly validates the target oracle's expiration time instead of the guardian oracle's expiration time. This logic error causes a complete denial-of-service for attesting new oracles and allows expired guardians to continue providing attestations, violating the security model.

## Finding Description

The vulnerability exists in the validation logic that checks whether a guardian oracle is authorized to attest to a target oracle. The function receives two oracle parameters: `oracle: &mut Oracle` (the target being attested) and `guardian: &Oracle` (the oracle providing the attestation). [1](#0-0) 

The comment states "check that the guardian is valid" and the error constant is `EGuardianInvalid`, but the code checks `oracle.expiration_time_ms()` instead of `guardian.expiration_time_ms()`. This validates the **target oracle** rather than the **guardian oracle**.

When new oracles are created, they are initialized with `expiration_time_ms = 0`: [2](#0-1) 

The oracle is then shared for anyone to access: [3](#0-2) 

The entry point is publicly accessible: [4](#0-3) 

**Root Cause**: Line 67 checks the wrong oracle's expiration. It should validate `guardian.expiration_time_ms() > clock.timestamp_ms()` to ensure the guardian providing the attestation is valid.

**Why This Breaks the Protocol**:
- For new oracles with `expiration_time_ms = 0`: The check `0 > current_time` is always false, causing the assertion to fail with `EGuardianInvalid`, making attestation impossible
- For expired guardians: If the target oracle is already enabled (non-zero expiration), the check passes even when `guardian.expiration_time_ms() <= current_time`, allowing expired guardians to attest

## Impact Explanation

**Primary Impact - Complete DoS of Attestation System**:

New oracles cannot receive attestations through the guardian-based decentralized flow. Since all newly created oracles have `expiration_time_ms = 0`, any attempt to attest them will fail at line 67, rendering the guardian attestation mechanism completely non-functional.

**Secondary Impact - Expired Guardian Bypass**:

Expired guardians can continue attesting to already-enabled oracles, bypassing the security model that requires only valid (non-expired) guardians to provide attestations.

**Protocol-Level Consequences**:

The Switchboard oracle integration becomes non-functional for onboarding new oracles through the intended decentralized path. Operators must instead use the centralized queue authority override mechanism, which defeats the purpose of having a multi-guardian attestation security model. [5](#0-4) 

This centralized workaround requires privileged queue authority access and undermines the decentralized attestation design.

## Likelihood Explanation

**Likelihood: CERTAIN (100%)**

This is a deterministic bug that manifests during normal protocol operation, not an attack scenario.

**Execution Path**:
1. Any user calls `oracle_init_action::run()` to create a new oracle
2. Oracle is created with `expiration_time_ms = 0` and shared as a public object
3. A guardian with valid credentials attempts `oracle_attest_action::run()` with proper signature
4. Validation reaches line 67: `assert!(0 > current_time, EGuardianInvalid)`
5. Assertion ALWAYS fails for new oracles
6. Transaction aborts with `EGuardianInvalid` error

**No Attack Complexity**: This is not an attack - it's a critical malfunction in the intended usage. Anyone attempting to use the attestation system as designed will encounter this failure immediately.

**Detection**: Will be discovered on first attempt to attest any newly created oracle. The only functional workaround is the centralized `queue_override_oracle_action`, which requires queue authority privileges.

## Recommendation

Change line 67 to validate the guardian oracle's expiration instead of the target oracle's expiration:

```move
// check that the guardian is valid
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

This ensures:
1. New oracles (with `expiration_time_ms = 0`) can receive attestations from valid guardians
2. Expired guardians cannot provide attestations regardless of the target oracle's state
3. The decentralized attestation security model functions as designed

## Proof of Concept

```move
#[test]
fun test_attestation_dos_for_new_oracle() {
    use sui::test_scenario;
    use sui::clock;
    
    let admin = @0x1;
    let mut scenario = test_scenario::begin(admin);
    let ctx = scenario.ctx();
    
    // Create a new oracle with expiration_time_ms = 0
    let oracle_key = x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let queue_id = object::id_from_address(@0x999);
    let queue_key = x"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    
    // Create oracle (will have expiration_time_ms = 0)
    let oracle_id = oracle::new(oracle_key, queue_id, queue_key, ctx);
    
    // Create guardian oracle (enabled, non-expired)
    let guardian_key = x"1111111111111111111111111111111111111111111111111111111111111111";
    let guardian_id = oracle::new(guardian_key, queue_id, queue_key, ctx);
    
    let mut clock = clock::create_for_testing(ctx);
    let current_time = 1000000000000; // Some timestamp in milliseconds
    clock.set_for_testing(current_time);
    
    // Get mutable references to the shared oracles
    test_scenario::next_tx(&mut scenario, admin);
    let mut oracle = test_scenario::take_shared_by_id<Oracle>(&scenario, oracle_id);
    let guardian = test_scenario::take_shared_by_id<Oracle>(&scenario, guardian_id);
    
    // Enable guardian (so it has valid expiration)
    let guardian_secp_key = x"04abcd..."; // Valid secp256k1 key
    let mr_enclave = x"deed...";
    oracle::enable_oracle(
        &mut guardian,
        guardian_secp_key,
        mr_enclave,
        current_time + 1000000 // Guardian expires in future
    );
    
    // Try to attest - this will FAIL because oracle.expiration_time_ms() = 0
    // Even though guardian is valid and non-expired
    // The check at line 67: assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid)
    // becomes: assert!(0 > 1000000000000, EGuardianInvalid) which is FALSE
    
    // This will abort with EGuardianInvalid despite guardian being perfectly valid
    let signature = x"..."; // Valid 65-byte signature
    oracle_attest_action::run(
        &mut oracle,
        &queue,
        &guardian,
        current_time / 1000, // timestamp_seconds
        mr_enclave,
        guardian_secp_key,
        signature,
        &clock
    ); // ABORTS with EGuardianInvalid
    
    test_scenario::return_shared(oracle);
    test_scenario::return_shared(guardian);
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

This test demonstrates that even with a valid, non-expired guardian oracle, attestation fails for newly created oracles due to the incorrect validation logic at line 67.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L66-67)
```text
    // check that the guardian is valid
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L84-84)
```text
    transfer::share_object(oracle);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L74-82)
```text
public entry fun run(
    queue: &mut Queue,
    oracle: &mut Oracle,
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {   
```
