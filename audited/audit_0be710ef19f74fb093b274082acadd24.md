### Title
Missing Cryptographic Validation of Oracle Key Ownership Enables Oracle Key Squatting and Unauthorized Oracle Registration

### Summary
The Switchboard oracle registration system lacks cryptographic validation that the `oracle_key` corresponds to the `oracle_id` or is controlled by the registrant. This allows any user to register an oracle with an arbitrary `oracle_key`, enabling oracle key squatting attacks that block legitimate oracles and potentially allowing malicious oracles to be attested if guardians don't perform off-chain verification.

### Finding Description

The oracle registration flow in `oracle_init_action.move` allows any user to create an oracle with an arbitrary `oracle_key` without proving ownership of the corresponding private key. [1](#0-0) 

The `validate` function only checks queue version and oracle key uniqueness, but performs no cryptographic validation: [2](#0-1) 

The `oracle::new` function simply stores the provided `oracle_key` and generates a new random `oracle_id` without any binding validation: [3](#0-2) 

The `ExistingOracle` struct stores both values independently without cryptographic linkage: [4](#0-3) 

The `add_existing_oracle` function simply adds them to the table without validation: [5](#0-4) 

While oracle attestation by guardians is required before an oracle can submit price data, the attestation message includes the arbitrary `oracle_key`: [6](#0-5) 

The vault relies on Switchboard aggregators for price feeds, which aggregate data from these oracles: [7](#0-6) 

### Impact Explanation

**Security Integrity Impact:**
- Oracles can be registered with arbitrary `oracle_key` values without proving ownership, bypassing the intended oracle authorization mechanism
- If guardians don't perform thorough off-chain verification, malicious oracles could be attested and authorized to submit price data

**Operational Impact - Oracle Key Squatting (DoS):**
- Attackers can front-run legitimate oracle registrations by monitoring mempool and registering with the target `oracle_key` first
- The uniqueness check prevents the legitimate oracle from ever registering with their own key
- This blocks legitimate oracle providers from participating in the network

**Indirect Fund Impact:**
- If malicious oracles successfully get attested (due to insufficient guardian verification), they can submit manipulated prices to aggregators
- The vault uses aggregator prices for asset valuation, affecting deposit/withdrawal calculations and operation decisions
- Manipulated prices could lead to incorrect share pricing, asset valuations, and potential exploitation of vault operations

The severity is **Critical** because oracle pricing is fundamental to vault security, and the lack of cryptographic validation creates an exploitable attack vector with both immediate DoS impact and potential for price manipulation if guardian verification processes fail.

### Likelihood Explanation

**Reachable Entry Point:**
The `oracle_init_action::run` function is a public entry point callable by any user.

**Feasible Preconditions:**
- Attacker only needs to know the target `oracle_key` (32 bytes) they want to squat
- No special permissions or setup required
- Can be called directly from any account

**Execution Practicality:**
- Simple function call with a 32-byte vector parameter
- No complex transaction sequencing required
- For DoS: Front-run legitimate registrations by monitoring transactions
- For malicious oracle: Register with any key and hope guardians don't verify properly

**Economic Rationality:**
- Attack cost is minimal (just transaction gas fees)
- DoS impact is guaranteed (legitimate oracle is permanently blocked)
- Price manipulation impact depends on guardian verification practices, but represents significant upside for attackers

**Detection/Operational Constraints:**
- Guardian attestation process is supposed to catch malicious oracles, but relies entirely on off-chain verification
- No on-chain mechanism to verify oracle legitimacy
- If guardians use automated or insufficient verification, malicious oracles could get attested

The likelihood is **High** for oracle key squatting DoS and **Medium-to-High** for price manipulation depending on guardian verification practices.

### Recommendation

**Immediate Fix - Add Cryptographic Proof of Ownership:**

1. Modify the oracle registration to require proof that the registrant controls the private key for `oracle_key`:
   - Add a signature parameter to `oracle_init_action::run`
   - Generate a registration message that includes the oracle_key and transaction context
   - Use ECDSA recovery to verify the signature was created by the private key corresponding to oracle_key
   - Only allow registration if the proof is valid

2. Example implementation in `oracle_init_action.move`:
```move
public entry fun run(
    oracle_key: vector<u8>,
    signature: vector<u8>, // NEW: signature proving ownership
    queue: &mut Queue,
    ctx: &mut TxContext
) {
    // NEW: Verify signature proves ownership of oracle_key
    assert!(signature.length() == 65, EInvalidSignature);
    let registration_msg = hash_registration_message(oracle_key, ctx.sender(), queue.id());
    let recovered_pubkey = ecdsa_k1::secp256k1_ecrecover(&signature, &registration_msg, 1);
    // Verify recovered key matches oracle_key
    assert!(verify_key_match(&recovered_pubkey, &oracle_key), EKeyOwnershipProofFailed);
    
    validate(&oracle_key, queue);
    actuate(queue, oracle_key, ctx);
}
```

**Additional Mitigations:**

3. Add oracle ID derivation from oracle_key to create cryptographic binding:
   - Derive oracle_id deterministically from hash(oracle_key) instead of random generation
   - This creates an immutable binding between oracle_key and oracle_id

4. Implement guardian verification guidelines:
   - Document explicit off-chain verification steps guardians must perform
   - Require guardians to verify oracle operator identity before attestation
   - Add monitoring for suspicious oracle registrations

**Test Cases to Add:**
- Test that registration fails without valid signature
- Test that signature from wrong key fails validation
- Test that oracle_id correctly derives from oracle_key
- Test that key squatting attack is prevented

### Proof of Concept

**Oracle Key Squatting Attack:**

1. **Initial State:**
   - Legitimate Oracle Provider wants to register with oracle_key = `0xABCD...` (their public key)
   - Attacker monitors for oracle registration transactions

2. **Attack Steps:**
   - Attacker sees legitimate provider's registration transaction in mempool
   - Attacker submits front-running transaction with higher gas:
     ```
     oracle_init_action::run(
         oracle_key: 0xABCD...,  // Victim's key
         queue: &mut queue_ref,
         ctx: &mut attacker_ctx
     )
     ```
   - Attacker's transaction executes first due to higher gas

3. **Result:**
   - Attacker successfully registers oracle with victim's key
   - When legitimate provider's transaction executes, it fails with `EOracleKeyExists`
   - Legitimate provider is permanently blocked from registering with their own key
   - Attacker's oracle has victim's key in `existing_oracles` table mapping

4. **Success Condition:**
   - `queue.existing_oracles.contains(0xABCD...)` returns `true`
   - `queue.existing_oracles[0xABCD...].oracle_id` points to attacker's oracle
   - Legitimate provider cannot register and receives error

**Expected vs Actual:**
- Expected: Only the owner of oracle_key can register an oracle with that key
- Actual: Any user can register with any oracle_key, enabling squatting and impersonation

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_init_action.move (L20-26)
```text
public fun validate(
    oracle_key: &vector<u8>,
    queue: &Queue,
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(!queue.existing_oracles_contains(*oracle_key), EOracleKeyExists);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L11-14)
```text
public struct ExistingOracle has copy, drop, store {
    oracle_id: ID,
    oracle_key: vector<u8>,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L160-162)
```text
public(package) fun add_existing_oracle(queue: &mut Queue, oracle_key: vector<u8>, oracle_id: ID) {
    queue.existing_oracles.add(oracle_key, ExistingOracle { oracle_id, oracle_key });
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L75-93)
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
}
```

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```
