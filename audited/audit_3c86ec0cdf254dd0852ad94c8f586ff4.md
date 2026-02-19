### Title
Incorrect Guardian Expiration Validation in Oracle Attestation Enables Dual Security Failures

### Summary
The `validate()` function in oracle attestation checks the target oracle's expiration time instead of the guardian's expiration time, causing two critical failures: (1) legitimate guardian attestations of new oracles fail completely, forcing reliance on centralized admin override, and (2) expired guardians can continue attesting to already-enabled oracles, bypassing expiration controls.

### Finding Description [1](#0-0) 

The validation logic checks `oracle.expiration_time_ms()` (the target oracle being attested) instead of `guardian.expiration_time_ms()` (the oracle providing the attestation). The error message `EGuardianInvalid` confirms this check should validate the guardian, not the target oracle.

**Root Cause:** Variable confusion - the function receives both `oracle` (target) and `guardian` (attester) parameters, but line 67 validates the wrong one.

**Execution Path:**
1. New oracles are created with `expiration_time_ms: 0` [2](#0-1) 
2. Guardian attempts attestation via public entry `run()` [3](#0-2) 
3. Validation checks `oracle.expiration_time_ms() > clock.timestamp_ms()` which evaluates to `0 > current_time` = false
4. Transaction aborts with `EGuardianInvalid` even when guardian is valid
5. Conversely, if target oracle is already enabled (expiration > 0) but guardian is expired, the check incorrectly passes

**Why Protections Fail:**
- The check validates the wrong object entirely
- No secondary validation of guardian expiration exists
- The signature verification (line 92) only confirms the guardian signed the message, not that the guardian is currently valid

### Impact Explanation

**Scenario 1 - New Oracle Attestation DoS (Operational Impact):**
- All new oracle attestations through guardian consensus fail immediately
- The decentralized attestation mechanism is completely non-functional
- System forced to rely solely on centralized admin override [4](#0-3) 
- Affects protocol's security model by eliminating guardian-based oracle enablement

**Scenario 2 - Expired Guardian Bypass (Security Integrity Impact):**
- Expired guardians can continue attesting to already-enabled oracles
- Attestation accumulation can enable oracles even with expired guardian votes [5](#0-4) 
- Undermines the temporal validity guarantees of the guardian system
- Allows potentially compromised or outdated guardians to influence oracle enablement

**Volo Vault Impact:**
The vault relies on Switchboard aggregators for price feeds [6](#0-5) , which depend on valid oracles [7](#0-6) . The broken attestation system compromises oracle availability and integrity, potentially affecting vault pricing accuracy and operation execution.

### Likelihood Explanation

**Reachability:** Public entry function accessible to any caller with guardian credentials [8](#0-7) 

**Preconditions:**
- Scenario 1: Normal guardian operation attempting to attest new oracles (expected workflow)
- Scenario 2: Expired guardian with retained private key attempting attestation

**Execution Practicality:**
- Scenario 1 triggers on EVERY new oracle attestation attempt - 100% occurrence rate in normal operations
- Scenario 2 requires expired guardian to actively attempt attestation, but no additional exploitation complexity

**Detection:** 
- Scenario 1 manifests as immediate transaction failures, highly visible
- Scenario 2 may go undetected if attestation counts are monitored without expiration status verification

**Probability:** Scenario 1 is deterministic (affects all new oracle attestations). Scenario 2 depends on expired guardians attempting attestations, which could occur accidentally or maliciously.

### Recommendation

**Code-Level Fix:**
Change line 67 from:
```move
assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```
to:
```move
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**Additional Validation:**
Consider adding explicit validation that the target oracle being attested is either uninitialized (expiration = 0) or expired, to ensure attestations are only needed for oracles requiring enablement:
```move
// Ensure target oracle needs attestation
assert!(oracle.expiration_time_ms() <= clock.timestamp_ms(), ETargetOracleAlreadyValid);
```

**Test Cases:**
1. Guardian attestation of new oracle (expiration = 0) with valid guardian should succeed
2. Guardian attestation with expired guardian should fail with EGuardianInvalid
3. Valid guardian attesting already-enabled oracle should be allowed if re-attestation is intended, or rejected if not
4. Edge case: guardian expiration = current time should fail (use >= instead of >)

### Proof of Concept

**Initial State:**
- Guardian oracle G with `expiration_time_ms = current_time + 1000` (valid)
- Target oracle T with `expiration_time_ms = 0` (new, needs attestation)
- Queue configured with `min_attestations = 1`

**Scenario 1 - New Oracle Attestation Failure:**
1. Guardian G calls `run()` with valid signature for oracle T
2. Validation reaches line 67: `assert!(oracle.expiration_time_ms() > clock.timestamp_ms())`
3. Evaluates to: `assert!(0 > current_time)` = FALSE
4. Transaction aborts with `EGuardianInvalid` error
5. **Expected:** Guardian attestation succeeds
6. **Actual:** Transaction fails despite valid guardian

**Scenario 2 - Expired Guardian Bypass:**
- Guardian G with `expiration_time_ms = current_time - 1000` (expired)
- Target oracle T with `expiration_time_ms = current_time + 5000` (already enabled)

1. Expired guardian G calls `run()` with valid signature for oracle T
2. Validation reaches line 67: `assert!(oracle.expiration_time_ms() > clock.timestamp_ms())`
3. Evaluates to: `assert!(current_time + 5000 > current_time)` = TRUE
4. Validation passes, attestation is added
5. **Expected:** Transaction fails with EGuardianInvalid
6. **Actual:** Expired guardian successfully attests

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L67-67)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-123)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L78-78)
```text
        expiration_time_ms: 0,
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L42-43)
```text
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(expiration_time_ms > 0, EInvalidExpirationTime);
```

**File:** volo-vault/sources/manage.move (L99-108)
```text
public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L63-63)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```
