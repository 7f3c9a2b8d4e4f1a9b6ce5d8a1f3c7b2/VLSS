# Audit Report

## Title
Gas Exhaustion DoS via Signature Verification Bypass in Oracle Attestation Mechanism

## Summary
A critical vulnerability in the Switchboard oracle attestation system allows attackers to bypass signature verification and spam fake attestations, causing gas exhaustion that prevents legitimate oracle renewals and leads to protocol-wide denial of service affecting Volo Vault operations.

## Finding Description

The vulnerability chains six distinct root causes to achieve a complete bypass of oracle attestation security:

**Root Cause 1 - Empty Vector Bypass in `check_subvec`:**
The `check_subvec` utility function returns `true` when the second vector parameter is empty. [1](#0-0) 

When `v2.length() == 0`, iterations is set to 0, the while loop never executes, and the function returns `true` without comparing any bytes.

**Root Cause 2 - Oracles Initialized with Empty Keys:**
New oracle objects are created with empty `secp256k1_key` vectors. [2](#0-1) 

This initialization state allows non-enabled guardians to exist without cryptographic keys.

**Root Cause 3 - Permissionless Oracle Registration:**
The `oracle_init_action::run` entry function has no authorization check. [3](#0-2) 

Anyone can register guardian oracles by calling this public entry function - it only validates queue version and oracle key uniqueness.

**Root Cause 4 - Buggy Guardian Validation:**
The attestation validation contains a critical bug that checks the wrong object's expiration. [4](#0-3) 

Despite the comment "check that the guardian is valid" and error name `EGuardianInvalid`, the code validates `oracle.expiration_time_ms()` (the target oracle) instead of `guardian.expiration_time_ms()`. This allows non-enabled guardians with empty keys to pass validation if the target oracle is enabled.

**Root Cause 5 - Signature Verification Uses Guardian's Empty Key:**
The signature verification relies on `check_subvec` with the guardian's key. [5](#0-4) 

When `guardian.secp256k1_key()` returns an empty vector, the `check_subvec` assertion always passes due to Root Cause 1, completely bypassing cryptographic verification.

**Root Cause 6 - Expensive Filter Operation:**
The `add_attestation` function filters the entire attestations vector on each call. [6](#0-5) 

With thousands of attestations from different fake guardians, this `vector::filter!` operation consumes excessive gas.

**Exploitation Path:**

1. Attacker calls `oracle_init_action::run` repeatedly with different oracle keys to register thousands of fake guardian oracles (no authorization required)
2. Each fake guardian has empty `secp256k1_key` from initialization
3. Attacker calls `oracle_attest_action::run` for each fake guardian to attest to an existing enabled oracle
4. The buggy guardian validation passes because it checks the target oracle's expiration
5. Signature verification passes because guardian's `secp256k1_key` is empty
6. Each attestation is added to the oracle's `valid_attestations` vector
7. When legitimate guardians attempt to attest, the `vector::filter!` operation on thousands of entries exceeds gas limits
8. Legitimate attestation transactions fail, preventing oracle renewal

## Impact Explanation

**Critical Severity - Protocol-Wide Denial of Service**

The impact cascades through multiple protocol layers:

**Oracle Layer:** Enabled oracles cannot receive legitimate attestations for renewal, causing them to expire and become unusable.

**Aggregator Layer:** Switchboard aggregators require non-expired oracles to submit price updates. [7](#0-6) 

Without valid oracles, aggregators cannot receive updates and become stale.

**Volo Vault Impact:** The Volo Vault depends on Switchboard aggregators for price valuations. [8](#0-7) 

The `get_current_price` function enforces staleness checks with a 1-minute default interval. [9](#0-8)  If aggregator prices aren't updated within this window, the function reverts, breaking all vault operations requiring price data including deposits, withdrawals, and position valuations.

**Permanence:** Once an oracle's attestations vector is filled with thousands of fake entries, the gas exhaustion persists. All subsequent attestation attempts fail, making the oracle permanently unusable without a protocol upgrade.

## Likelihood Explanation

**High Likelihood - Easily Executable Attack**

**Attacker Capabilities:** No privileged access required - any untrusted attacker with standard transaction capabilities can execute this attack.

**Attack Complexity:** Low - Oracle registration is permissionless via a public entry function with no authorization checks. The signature bypass is trivial due to the empty vector bug. The attacker only needs to call two entry functions repeatedly.

**Preconditions:** Minimal - at least one oracle must be enabled (normal operational state) and the attacker needs gas for transactions (standard conditions).

**Economic Viability:** Registration and attestation costs are modest (gas fees only) compared to the severe impact of disabling critical oracle infrastructure for an entire protocol. The attack is persistent once executed, blocking operations indefinitely until a protocol upgrade.

**Detection Difficulty:** Attack transactions appear as legitimate entry function calls with no obvious malicious pattern until gas exhaustion occurs.

## Recommendation

Implement the following fixes:

1. **Add Authorization Check to Oracle Registration:**
   Modify `oracle_init_action::run` to require queue authority or implement permissioned guardian registration.

2. **Fix Guardian Validation Bug:**
   Change line 67 in `oracle_attest_action.move` from:
   ```
   assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
   ```
   to:
   ```
   assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
   ```

3. **Prevent Empty Key Signature Bypass:**
   Add validation in `oracle_attest_action::run` to ensure `guardian.secp256k1_key()` is not empty before performing signature verification.

4. **Optimize Attestation Storage:**
   Consider using a more gas-efficient data structure for attestations (e.g., Table with guardian_id as key) to prevent gas exhaustion attacks.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploying a test scenario with a guardian queue and target oracle queue
2. Registering 100+ fake guardian oracles via `oracle_init_action::run` without authorization
3. Attesting from each fake guardian to an enabled target oracle via `oracle_attest_action::run`
4. Attempting a legitimate attestation and observing gas exhaustion in the `vector::filter!` operation
5. Verifying that the target oracle eventually expires due to inability to receive renewal attestations
6. Confirming that aggregator price updates fail due to expired oracles
7. Demonstrating that Volo Vault operations revert due to stale prices

The test would validate each root cause independently and then demonstrate the complete attack chain.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L156-171)
```text
public fun check_subvec(v1: &vector<u8>, v2: &vector<u8>, start_idx: u64): bool {
    if (v1.length() < start_idx + v2.length()) {
        return false
    };

    let mut iterations = v2.length();
    while (iterations > 0) {
        let idx = iterations - 1;
        if (v1[start_idx + idx] != v2[idx]) {
            return false
        };
        iterations = iterations - 1;
    };

    true
}
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L100-105)
```text
public(package) fun add_attestation(oracle: &mut Oracle, attestation: Attestation, timestamp_ms: u64) {
    oracle.valid_attestations = vector::filter!(oracle.valid_attestations, |a: &Attestation| {
        a.timestamp_ms + ATTESTATION_TIMEOUT_MS > timestamp_ms && a.guardian_id != attestation.guardian_id
    });
    vector::push_back(&mut oracle.valid_attestations, attestation);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L66-67)
```text
    // check that the guardian is valid
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L92-92)
```text
    assert!(hash::check_subvec(&recovered_pubkey, &guardian.secp256k1_key(), 1), EInvalidSignature);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L63-63)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);
```

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
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
