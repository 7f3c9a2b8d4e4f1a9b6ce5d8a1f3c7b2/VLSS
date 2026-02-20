# Audit Report

## Title
Oracle Attestation Count Manipulation via Unvalidated Guardian Oracles

## Summary
A critical vulnerability in the Switchboard oracle attestation system allows attackers to hijack legitimate oracles by creating unlimited malicious guardian oracles that bypass the min_attestations security mechanism. Two bugs enable this: incorrect expiration validation checking the target oracle instead of the guardian, and empty secp256k1_key bypassing signature verification. Attackers can submit arbitrary prices to Volo vault aggregators, enabling complete price manipulation and fund drainage.

## Finding Description

The vulnerability exists through two critical bugs in the oracle attestation validation flow:

**Bug #1 - Incorrect Expiration Validation:**

The attestation validation checks the target oracle's expiration instead of the guardian's expiration. [1](#0-0)  The error constant `EGuardianInvalid` confirms the intended validation target was the guardian oracle. [2](#0-1)  This allows unvalidated guardians (with `expiration_time_ms = 0`) to attest to any already-enabled oracle.

**Bug #2 - Empty Key Signature Bypass:**

The signature verification uses `check_subvec` to match the recovered public key against the guardian's secp256k1_key. [3](#0-2)  However, when the guardian's secp256k1_key is empty (as it is for newly created oracles), the `check_subvec` function returns true without performing any verification. [4](#0-3)  When `v2.length()` is 0, the while loop never executes and the function returns true, accepting any signature.

**Exploitation Flow:**

1. Attacker creates multiple guardian oracles via the public entry function with no authorization checks. [5](#0-4) 

2. Each newly created guardian oracle has an empty secp256k1_key. [6](#0-5) 

3. The attacker calls the public attestation entry function multiple times with different malicious guardians. [7](#0-6) 

4. Each attestation is added with a unique guardian_id, and the filter only prevents duplicate attestations from the same guardian. [8](#0-7) 

5. Once the valid attestation count reaches the minimum threshold, the oracle is re-enabled with the attacker's secp256k1_key. [9](#0-8) 

6. The attacker can now submit arbitrary price updates to aggregators using the compromised oracle. [10](#0-9) 

7. Volo vault relies on these Switchboard aggregators for all asset price valuations. [11](#0-10) 

## Impact Explanation

**Critical Fund Impact:** The Volo vault uses Switchboard oracle prices for calculating USD values of all assets, which directly affects share ratio calculations during deposits and withdrawals, loss tolerance enforcement during vault operations, and asset valuation across all DeFi adaptors. An attacker controlling oracle keys can submit arbitrary false prices to manipulate share valuations to extract value, bypass loss_tolerance limits by reporting inflated asset values, and drain vault funds through systematic price manipulation.

**Security Integrity Compromise:** The `min_attestations` requirement (typically 3-5 independent guardians) is a core security mechanism designed to require consensus from multiple trusted entities. This vulnerability completely breaks this guarantee by allowing a single attacker to create unlimited fake guardians and achieve any attestation threshold.

**Affected Parties:** All Volo vault users are affected, as oracle pricing impacts every vault operation including deposits, withdrawals, and position valuations. The entire protocol's economic security depends on accurate oracle data.

## Likelihood Explanation

**High Likelihood - All Preconditions Met:**

1. **No Authorization Required:** Both oracle creation and attestation entry functions are public with no capability checks or authorization requirements.

2. **Minimal Cost:** Attack requires only gas fees (~0.1 SUI total for creating 5-10 guardian oracles and attestations).

3. **Simple Execution:** No complex state manipulation, timing dependencies, or external compromises needed. Just repeated calls to public functions.

4. **Feasible Preconditions:** Guardian and oracle queues exist in production Volo deployment. Target oracles are already enabled for normal operation.

5. **Fast Execution:** Attacker can create multiple guardians and complete attestations in under a minute, faster than any monitoring system could respond.

6. **High Economic Incentive:** Potential profit is unlimited - attacker can drain entire vault value by manipulating prices, then executing profitable deposit/withdrawal cycles.

## Recommendation

**Fix Bug #1 - Correct Expiration Validation:**
Change line 67 in `oracle_attest_action.move` to validate the guardian's expiration:
```move
assert!(guardian.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**Fix Bug #2 - Reject Empty Guardian Keys:**
Add validation in `oracle_attest_action.move` to reject guardians with empty secp256k1_key:
```move
assert!(guardian.secp256k1_key().length() == 64, EGuardianInvalid);
```

**Additional Hardening:**
Consider requiring guardian oracles to be explicitly authorized or registered by a trusted authority before they can attest, rather than allowing any oracle on the guardian queue to attest.

## Proof of Concept

The PoC would demonstrate:
1. Creating multiple guardian oracles on a guardian queue
2. Attesting to a target oracle with these unvalidated guardians
3. Re-enabling the target oracle with attacker-controlled keys
4. Submitting arbitrary prices to an aggregator
5. Showing how the Volo vault consumes these manipulated prices

The test would validate that both bugs exist and can be exploited to hijack oracle attestations and manipulate prices without any authorization.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L16-16)
```text
const EGuardianInvalid: vector<u8> = b"Guardian is invalid";
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L67-67)
```text
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EGuardianInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L92-92)
```text
    assert!(hash::check_subvec(&recovered_pubkey, &guardian.secp256k1_key(), 1), EInvalidSignature);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L120-132)
```text
    let valid_attestations = oracle.valid_attestation_count(secp256k1_key);
    if (valid_attestations >= queue.min_attestations()) {
        let expiration_time_ms = clock.timestamp_ms() + queue.oracle_validity_length_ms();
        oracle.enable_oracle(secp256k1_key, mr_enclave, expiration_time_ms);
        
        // emit resolution event
        let attestation_resolved = AttestationResolved {
            oracle_id: oracle.id(),
            secp256k1_key,
            timestamp_ms: clock.timestamp_ms(),
        };
        event::emit(attestation_resolved);
    };
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L79-79)
```text
        secp256k1_key: vector::empty(),
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L133-147)
```text
public entry fun run<T>(
    aggregator: &mut Aggregator,
    queue: &Queue,
    value: u128,
    neg: bool,
    timestamp_seconds: u64,
    oracle: &Oracle,
    signature: vector<u8>,
    clock: &Clock,
    fee: Coin<T>,
) {
    let value = decimal::new(value, neg);
    validate<T>(aggregator, queue, oracle, timestamp_seconds, &value, signature, clock, &fee);
    actuate(aggregator, queue, value, timestamp_seconds, oracle, clock, fee);
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
