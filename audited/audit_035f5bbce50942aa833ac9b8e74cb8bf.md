### Title
Lack of Feed-Level Authorization Allows Oracle Cross-Feed Price Manipulation

### Summary
The Switchboard oracle system only enforces queue-level authorization, allowing any oracle within a queue to submit price updates to any aggregator (feed) in that queue. An oracle operator with legitimate access to one feed can manipulate prices for all other feeds in the same queue, enabling targeted price manipulation attacks against the Volo vault's asset valuation system.

### Finding Description

The vulnerability exists in the oracle result submission validation logic. [1](#0-0) 

The `validate()` function only checks that the oracle and aggregator belong to the same queue (line 60), but performs no verification that the oracle is authorized for that specific feed_hash. The validation logic:

1. Verifies oracle and aggregator are in the same queue
2. Checks oracle is not expired
3. Validates the signature against oracle's secp256k1_key
4. **Missing**: No check binding the oracle to the specific feed_hash

The message generation combines oracle.queue_key() and aggregator.feed_hash() without authorization validation. [2](#0-1) 

The Oracle structure only tracks queue membership, not authorized feeds. [3](#0-2) 

The Aggregator structure has an authority field for configuration control, but this is never checked during price submissions. [4](#0-3) 

### Impact Explanation

This authorization gap enables direct fund theft from the Volo vault through price manipulation:

1. **Price Manipulation**: A compromised oracle can submit fraudulent prices to any feed in its queue, not just its designated feed
2. **Vault Asset Valuation**: The Volo vault relies on these prices for critical operations. [5](#0-4) 
3. **Financial Damage**: Manipulated prices affect share calculations, deposit/withdrawal valuations, and loss tolerance checks, enabling theft of vault assets
4. **Scope Amplification**: A single compromised oracle threatens all feeds in the queue, not just one feed

The vault enforces strict price staleness checks but cannot detect cross-feed authorization violations. [6](#0-5) 

### Likelihood Explanation

**Attacker Capabilities**: Requires compromising one oracle's private key (secp256k1) within a queue containing valuable feeds

**Attack Complexity**: Moderate - once oracle access is obtained, the attack is straightforward through the public entry function `aggregator_submit_result_action::run()`

**Feasibility Conditions**:
- Oracle key compromise (through TEE vulnerability, key leakage, or malicious operator)
- Target feeds exist in the same queue as the compromised oracle
- No feed-level authorization checks exist to prevent cross-feed updates

**Probability**: Medium-Low for initial compromise, but HIGH impact amplification if any oracle in a multi-feed queue is compromised. The lack of defense-in-depth means a single oracle compromise affects all feeds in that queue.

### Recommendation

**Code-Level Mitigation**: Add feed-level authorization to the validation logic:

1. In `Aggregator`, add an authorized_oracles field: `authorized_oracles: VecSet<ID>`
2. In `aggregator_submit_result_action::validate()`, add after line 60:
   ```move
   assert!(aggregator.authorized_oracles.contains(&oracle.id()), EUnauthorizedOracle);
   ```
3. Add management functions to add/remove authorized oracles per aggregator (authority-gated)

**Invariant Check**: Enforce "an oracle can only submit results to aggregators it is explicitly authorized for" in addition to queue-level membership

**Test Cases**: 
- Test that oracle A authorized for Feed 1 cannot update Feed 2 in the same queue
- Test that authorization changes are properly enforced
- Test that removal from authorized list immediately prevents updates

### Proof of Concept

**Initial State**:
- Queue X contains Oracle A and Oracle B
- Feed 1 (price feed for Asset 1) in Queue X, intended for Oracle A
- Feed 2 (price feed for Asset 2) in Queue X, intended for Oracle B
- Volo vault uses both feeds for asset valuation

**Attack Steps**:
1. Attacker compromises Oracle A's private key
2. Attacker constructs price update for Feed 2 (not A's designated feed):
   - Calls `hash::generate_update_msg()` with oracle_A.queue_key() and feed_2.feed_hash()
   - Signs the message with Oracle A's private key
3. Attacker submits via `aggregator_submit_result_action::run()` with Oracle A reference and Feed 2 aggregator
4. Validation passes:
   - oracle_A.queue() == feed_2.queue() ✓ (both in Queue X)
   - Signature verifies against oracle_A.secp256k1_key() ✓
   - No feed-level authorization check exists ✗

**Expected Result**: Transaction should fail with "Oracle not authorized for this feed"

**Actual Result**: Transaction succeeds, Feed 2 price is manipulated, Volo vault uses fraudulent price for Asset 2 valuations, enabling fund theft through arbitrage or incorrect share calculations

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L42-96)
```text
public fun validate<T>(
    aggregator: &Aggregator,
    queue: &Queue,
    oracle: &Oracle,
    timestamp_seconds: u64,
    value: &Decimal,
    signature: vector<u8>,
    clock: &Clock,
    coin: &Coin<T>,
) {

    // check that the versions are correct
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);

    // check that the aggregator version is correct
    assert!(aggregator.version() == EXPECTED_AGGREGATOR_VERSION, EInvalidAggregatorVersion);

    // verify that the oracle is servicing the correct queue
    assert!(oracle.queue() == aggregator.queue(), EAggregatorQueueMismatch);

    // verify that the oracle is up
    assert!(oracle.expiration_time_ms() > clock.timestamp_ms(), EOracleInvalid);

    // make sure that update staleness point is not in the future
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);

    // check that the signature is valid length
    assert!(signature.length() == 65, ESignatureInvalid);

    // check that the signature is valid
    let update_msg = hash::generate_update_msg(
        value,
        oracle.queue_key(),
        aggregator.feed_hash(),
        x"0000000000000000000000000000000000000000000000000000000000000000",
        aggregator.max_variance(),
        aggregator.min_responses(),
        timestamp_seconds,
    );

    // recover the pubkey from the signature
    let recovered_pubkey_compressed = ecdsa_k1::secp256k1_ecrecover(
        &signature, 
        &update_msg, 
        1,
    );
    let recovered_pubkey = ecdsa_k1::decompress_pubkey(&recovered_pubkey_compressed);

    // check that the recovered pubkey is valid
    assert!(hash::check_subvec(&recovered_pubkey, &oracle.secp256k1_key(), 1), ERecoveredPubkeyInvalid);

    // fee check
    assert!(queue.has_fee_type<T>(), EInvalidFeeType);
    assert!(coin.value() >= queue.fee(), EInsufficientFee);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L108-130)
```text
public fun generate_update_msg(
    value: &Decimal,
    queue_key: vector<u8>,
    feed_hash: vector<u8>,
    slothash: vector<u8>,
    max_variance: u64,
    min_responses: u32,
    timestamp: u64,
): vector<u8> {
    let mut hasher = new();
    assert!(queue_key.length() == 32, EWrongQueueLength);
    assert!(feed_hash.length() == 32, EWrongFeedHashLength);
    assert!(slothash.length() == 32, EWrongSlothashLength);
    hasher.push_bytes(queue_key);
    hasher.push_bytes(feed_hash);
    hasher.push_decimal_le(value);
    hasher.push_bytes(slothash);
    hasher.push_u64_le(max_variance);
    hasher.push_u32_le(min_responses);
    hasher.push_u64_le(timestamp);
    let Hasher { buffer } = hasher;
    buffer
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L13-23)
```text
public struct Oracle has key {
    id: UID,
    oracle_key: vector<u8>,
    queue: ID,
    queue_key: vector<u8>,        
    expiration_time_ms: u64,
    mr_enclave: vector<u8>,
    secp256k1_key: vector<u8>,
    valid_attestations: vector<Attestation>,
    version: u8,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L35-78)
```text
public struct Aggregator has key {
    id: UID,

    // The queue this aggregator is associated with
    queue: ID,

    // The time this aggregator was created
    created_at_ms: u64,

    // -- Configs --

    // The name of the aggregator
    name: String,

    // The address of the authority that created this aggregator
    authority: address,

    // The hash of the feed this aggregator is associated with
    feed_hash: vector<u8>,

    // The minimum number of updates to consider the result valid
    min_sample_size: u64,

    // The maximum number of samples to consider the an update valid
    max_staleness_seconds: u64,

    // The maximum variance between jobs required for a result to be computed
    max_variance: u64,  

    // Minimum number of job successes required to compute a valid update
    min_responses: u32,


    // -- State --

    // The current result of the aggregator
    current_result: CurrentResult,

    // The state of the updates
    update_state: UpdateState,

    // version
    version: u8,
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
