### Title
Guardian Expiration Check Validates Wrong Oracle Object, Breaking Attestation Flow for New Oracles

### Summary
The `validate()` function in `oracle_attest_action.move` incorrectly validates the target oracle's expiration time instead of the guardian oracle's expiration time. This logic error causes a complete denial-of-service for attesting new oracles (which have `expiration_time_ms = 0`) and allows expired guardians to continue providing attestations, violating the security model.

### Finding Description

The vulnerability exists in the validation function of the oracle attestation action: [1](#0-0) 

The code checks `oracle.expiration_time_ms() > clock.timestamp_ms()` but the comment states "check that the guardian is valid". This validates the **target oracle** being attested rather than the **guardian oracle** providing the attestation.

The function is called from the public entry point: [2](#0-1) 

Oracle objects are shared objects that anyone can pass to entry functions: [3](#0-2) 

When new oracles are created, they have `expiration_time_ms = 0`: [4](#0-3) 

**Root Cause**: The assertion checks the wrong object's expiration time. It should validate `guardian.expiration_time_ms()` to ensure the guardian is authorized to attest, not `oracle.expiration_time_ms()`.

**Why Protection Fails**: 
- For new oracles: `0 > current_time` is always false → assertion fails → attestation impossible
- For expired guardians: If target oracle is enabled, the check passes even when `guardian.expiration_time_ms() <= current_time` → unauthorized attestations succeed

### Impact Explanation

**Primary Impact - Complete DoS of Attestation System**:
New oracles created via `oracle_init_action` cannot receive attestations through the designed guardian-based flow. The assertion at line 67 will always fail for any oracle with `expiration_time_ms = 0`, preventing the decentralized attestation mechanism from functioning.

**Secondary Impact - Expired Guardian Bypass**:
Expired guardians (whose `expiration_time_ms` has passed) can continue attesting to already-enabled oracles, bypassing the security model that requires only valid guardians to provide attestations.

**Protocol-Level Consequences**:
- The Switchboard oracle integration documented in the system architecture becomes non-functional for onboarding new oracles
- Operators must use `queue_override_oracle_action` (centralized authority override) instead of decentralized guardian attestation
- Oracle price feeds cannot be established through the intended security model
- Volo Vault's multi-provider oracle strategy is compromised as Switchboard oracles cannot be properly validated

**Who is Affected**:
- Any protocol attempting to create and attest new Switchboard oracles
- Volo Vault's oracle configuration that depends on Switchboard price feeds
- The entire decentralized attestation security model

### Likelihood Explanation

**Likelihood: CERTAIN (100%)**

**Reachable Entry Point**: The public entry function `run()` is directly callable by any transaction.

**Attack Complexity**: None - this is a deterministic bug that triggers during normal protocol operation.

**Feasibility Conditions**:
- **For DoS**: Simply create a new oracle and attempt attestation → 100% reproducible failure
- **For expired guardian bypass**: Guardian must be expired but the check passes if target oracle is enabled

**Execution Path**:
1. User calls `oracle_init_action::run()` to create new oracle
2. Oracle is created with `expiration_time_ms = 0` and shared
3. Guardian attempts to call `oracle_attest_action::run()` with valid signature
4. Validation reaches line 67: `assert!(0 > current_time, EGuardianInvalid)` → FAILS
5. Transaction aborts with `EGuardianInvalid` error

**Economic Rationality**: No attack cost - this manifests as a critical system malfunction during intended usage.

**Detection**: Will be immediately discovered when attempting to use the attestation system as designed. The only workaround is using the centralized queue authority override, defeating the purpose of guardian-based decentralization.

### Recommendation

**Immediate Fix**: Change line 67 to validate the guardian's expiration time:

```move
// check that the guardian is valid
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**Additional Validation**: Add explicit check for guardian validity earlier in the validation flow to make the security model clear.

**Testing Requirements**:
1. Test case: Create new oracle (expiration = 0) → attempt attestation with valid guardian → should succeed
2. Test case: Use expired guardian → attempt attestation → should fail with EGuardianInvalid
3. Test case: Use valid guardian on enabled oracle → should succeed
4. Integration test: Full oracle onboarding flow from creation through attestation to enablement

**Invariant to Enforce**: Guardian oracles must have `expiration_time_ms > current_timestamp` to provide attestations, regardless of target oracle state.

### Proof of Concept

**Initial State**:
- Guardian Queue exists with `min_attestations = 1`
- Guardian Oracle exists with `expiration_time_ms = current_time + 1_hour`
- New Oracle created via `oracle_init_action::run()` with `expiration_time_ms = 0`

**Attack Steps**:

**Transaction 1**: Create new oracle
```
oracle_init_action::run(
    queue: &Queue,
    oracle_key: vector<u8>,
    ctx: &mut TxContext
)
// Result: Oracle created with expiration_time_ms = 0
```

**Transaction 2**: Attempt guardian attestation
```
oracle_attest_action::run(
    oracle: &mut Oracle,  // expiration_time_ms = 0
    queue: &Queue,
    guardian: &Oracle,    // expiration_time_ms = current_time + 1_hour (VALID)
    timestamp_seconds: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    signature: vector<u8>,  // Valid guardian signature
    clock: &Clock
)
```

**Expected Result**: Guardian provides valid attestation → oracle receives attestation → if min_attestations reached, oracle becomes enabled

**Actual Result**: Transaction aborts at line 67 with error `EGuardianInvalid` because the assertion checks `oracle.expiration_time_ms() (0) > clock.timestamp_ms() (current_time)` which is false.

**Success Condition for Vulnerability**: Any attempt to attest a newly created oracle fails with `EGuardianInvalid`, despite guardian being valid and signature being correct. The attestation system is completely non-functional for new oracles.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L67-67)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L78-78)
```text
        expiration_time_ms: 0,
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L84-84)
```text
    transfer::share_object(oracle);
```
