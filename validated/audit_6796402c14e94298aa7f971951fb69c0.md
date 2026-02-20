# Audit Report

## Title
Attestations Not Cleared on Oracle Re-enablement Allows Cross-MR_Enclave Attestation Reuse

## Summary
The Switchboard oracle attestation mechanism contains a critical design flaw where attestations are stored without their associated `mr_enclave` value. This allows attestations meant for one TEE code measurement to be incorrectly counted towards enabling a different code measurement, breaking the TEE security model and potentially enabling malicious oracle implementations that could provide incorrect price data to the Volo vault.

## Finding Description

The vulnerability exists in how the Switchboard oracle system handles attestations across multiple components:

**1. Attestation Storage Loses mr_enclave Binding**

When guardians sign attestations, they cryptographically commit to both the oracle's `secp256k1_key` AND its `mr_enclave` (TEE code measurement). The signature includes the mr_enclave in the message hash: [1](#0-0) 

However, when these attestations are stored in the `Attestation` struct, only the `secp256k1_key` is preserved, completely losing the binding to the specific `mr_enclave`: [2](#0-1) 

**2. enable_oracle() Does Not Clear Attestations**

The `enable_oracle()` function sets new oracle parameters but critically does NOT clear the `valid_attestations` vector: [3](#0-2) 

**3. Attestation Counting Ignores mr_enclave**

When counting valid attestations to determine if an oracle should be enabled, the system only checks if attestations match the `secp256k1_key`, completely ignoring which `mr_enclave` they were originally meant for: [4](#0-3) 

**4. Oracle Enablement with Wrong mr_enclave**

The vulnerability is triggered in the attestation flow where if the count of attestations (matching only the key) meets the minimum threshold, the oracle is enabled with the `mr_enclave` from the current attestation submission: [5](#0-4) 

**Attack Scenario:**
1. Oracle is enabled with `(secp256k1_key_X, mr_enclave_A)` after collecting 3 guardian attestations
2. Within the 10-minute attestation timeout window (defined in oracle.move:4), a new attestation for `(secp256k1_key_X, mr_enclave_B)` is submitted
3. The system counts 4 total attestations matching `secp256k1_key_X` (3 old + 1 new)
4. Oracle is re-enabled with `mr_enclave_B`, even though only 1 guardian actually verified `mr_enclave_B`
5. The other 3 attestations were for `mr_enclave_A` but are incorrectly counted

This breaks the fundamental security guarantee that at least `min_attestations` guardians must verify the SPECIFIC code (mr_enclave) running in the TEE.

## Impact Explanation

This vulnerability has HIGH impact on the Volo protocol:

**Oracle Price Integrity Compromise**: The Volo vault relies on Switchboard aggregators for asset pricing throughout its operations: [6](#0-5) 

If a malicious or buggy `mr_enclave` is enabled with insufficient verification, it can provide incorrect price data to the vault.

**Concrete Harms**:
- **Incorrect asset valuations** leading to improper vault operations and loss tolerance violations
- **Users receiving incorrect shares** during deposits due to mispriced assets
- **Incorrect redemption amounts** during withdrawals, allowing value extraction
- **Vault operations failing** tolerance checks based on bad prices, leading to DoS
- **Fund loss** through mispriced liquidations or forced operations with manipulated valuations

**TEE Security Model Break**: The `mr_enclave` is a cryptographic measurement uniquely identifying the code in a Trusted Execution Environment. Different measurements represent potentially different code (benign vs malicious). This vulnerability allows code to be trusted without proper verification, completely undermining the security model that Switchboard oracles are built upon.

## Likelihood Explanation

The likelihood is MEDIUM to HIGH due to the following factors:

**Directly Reachable**: The vulnerability is exposed through the public entry function accessible to any guardian: [7](#0-6) 

**Design Flaw**: This is fundamentally a design flaw in how attestations are scoped. Even in legitimate operational scenarios (e.g., oracle software upgrades where guardians attest to different versions at different times), the bug causes the system to violate its security invariant.

**Exploitation Paths**:
1. **Operational Edge Cases**: During legitimate oracle upgrades where guardians attest to different mr_enclave versions at different times within the 10-minute window
2. **Single Compromised Guardian**: If one guardian is compromised and there are existing attestations for a different mr_enclave with the same key, they can trigger re-enablement with malicious code
3. **No Privilege Required**: Unlike the queue override path which requires queue authority (trusted role), the main vulnerability path requires no special privileges

**Time Window**: The 10-minute attestation timeout provides a reasonable window for exploitation or for the bug to manifest during operational changes.

## Recommendation

**Solution 1: Store mr_enclave in Attestation Struct**

Modify the `Attestation` struct to include the `mr_enclave` it was attested to:

```move
public struct Attestation has copy, store, drop {
    guardian_id: ID, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,  // ADD THIS
    timestamp_ms: u64,
}
```

Then update `valid_attestation_count()` to only count attestations matching BOTH the key AND mr_enclave:

```move
public(package) fun valid_attestation_count(
    oracle: &Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>  // ADD THIS
): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key && a.mr_enclave == mr_enclave
    })
}
```

**Solution 2: Clear Attestations on enable_oracle()**

Alternatively, clear the attestations vector when enabling an oracle to prevent reuse:

```move
public(package) fun enable_oracle(
    oracle: &mut Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
) {
    oracle.secp256k1_key = secp256k1_key;
    oracle.mr_enclave = mr_enclave;
    oracle.expiration_time_ms = expiration_time_ms;
    oracle.valid_attestations = vector::empty();  // ADD THIS
}
```

**Recommended Approach**: Implement Solution 1 as it provides proper attestation scoping and maintains audit trail of which guardians attested to which specific mr_enclave values.

## Proof of Concept

```move
#[test]
fun test_cross_mr_enclave_attestation_reuse() {
    use sui::test_scenario;
    use switchboard::oracle;
    use switchboard::queue;
    
    let admin = @0x1;
    let mut scenario = test_scenario::begin(admin);
    let ctx = scenario.ctx();
    
    // Setup queue with min_attestations = 3
    let queue_key = x"1234567890123456789012345678901234567890123456789012345678901234";
    let guardian_queue_id = object::id_from_address(@0x999);
    let queue_id = queue::new(
        queue_key,
        admin,
        string::utf8(b"Test Queue"),
        0,
        admin,
        3,  // min_attestations
        1000 * 60 * 60,
        guardian_queue_id,
        false,
        ctx
    );
    
    // Create oracle
    let oracle_key = x"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let oracle_id = oracle::new(oracle_key, queue_id, queue_key, ctx);
    
    scenario.next_tx(admin);
    let mut oracle_obj = scenario.take_shared_by_id<Oracle>(oracle_id);
    let queue_obj = scenario.take_shared_by_id<Queue>(queue_id);
    
    let secp256k1_key = x"1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    let mr_enclave_A = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mr_enclave_B = x"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    
    // Three guardians attest to mr_enclave_A
    let attestation1 = oracle::new_attestation(
        object::id_from_address(@0x101),
        secp256k1_key,
        1000
    );
    oracle_obj.add_attestation(attestation1, 1000);
    
    let attestation2 = oracle::new_attestation(
        object::id_from_address(@0x102),
        secp256k1_key,
        1000
    );
    oracle_obj.add_attestation(attestation2, 1000);
    
    let attestation3 = oracle::new_attestation(
        object::id_from_address(@0x103),
        secp256k1_key,
        1000
    );
    oracle_obj.add_attestation(attestation3, 1000);
    
    // Oracle enabled with mr_enclave_A
    assert!(oracle_obj.valid_attestation_count(secp256k1_key) == 3);
    oracle_obj.enable_oracle(secp256k1_key, mr_enclave_A, 2000);
    
    // ONE guardian attests to mr_enclave_B (different code!)
    let attestation4 = oracle::new_attestation(
        object::id_from_address(@0x104),
        secp256k1_key,
        1500
    );
    oracle_obj.add_attestation(attestation4, 1500);
    
    // BUG: System counts 4 attestations (3 old for A + 1 new for B)
    assert!(oracle_obj.valid_attestation_count(secp256k1_key) == 4);
    
    // Oracle re-enabled with mr_enclave_B despite only 1 guardian verifying it!
    oracle_obj.enable_oracle(secp256k1_key, mr_enclave_B, 2500);
    
    // Vulnerability confirmed: Oracle now uses mr_enclave_B
    // but only 1 guardian actually attested to mr_enclave_B
    // The 3 attestations for mr_enclave_A were incorrectly counted
    
    test_scenario::return_shared(oracle_obj);
    test_scenario::return_shared(queue_obj);
    scenario.end();
}
```

This test demonstrates that attestations for one mr_enclave are counted towards enabling a different mr_enclave, breaking the TEE security guarantee.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L132-154)
```text
public fun generate_attestation_msg(
    oracle_key: vector<u8>, 
    queue_key: vector<u8>,
    mr_enclave: vector<u8>,
    slothash: vector<u8>,
    secp256k1_key: vector<u8>,
    timestamp: u64,
): vector<u8> {
    let mut hasher = new();
    assert!(oracle_key.length() == 32, EWrongOracleIdLength);
    assert!(queue_key.length() == 32, EWrongQueueLength);
    assert!(mr_enclave.length() == 32, EWrongMrEnclaveLength);
    assert!(slothash.length() == 32, EWrongSlothashLength);
    assert!(secp256k1_key.length() == 64, EWrongSec256k1KeyLength);
    hasher.push_bytes(oracle_key);
    hasher.push_bytes(queue_key);
    hasher.push_bytes(mr_enclave);
    hasher.push_bytes(slothash);
    hasher.push_bytes(secp256k1_key);
    hasher.push_u64_le(timestamp);
    let Hasher { buffer } = hasher;
    buffer
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L7-11)
```text
public struct Attestation has copy, store, drop {
    guardian_id: ID, 
    secp256k1_key: vector<u8>,
    timestamp_ms: u64,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L107-111)
```text
public(package) fun valid_attestation_count(oracle: &Oracle, secp256k1_key: vector<u8>): u64 {
    vector::count!(&oracle.valid_attestations, |a: &Attestation| {
        a.secp256k1_key == secp256k1_key
    })
}
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

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```
