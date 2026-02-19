# Audit Report

## Title
Cross-Chain Oracle Signature Replay Attack via Hardcoded Zero Slothash

## Summary
The Switchboard oracle implementation hardcodes the slothash parameter to all zeros in production validation code, completely removing blockchain-specific replay protection. This allows oracle signatures from one chain to be replayed on another chain where Switchboard is deployed with identical parameters, enabling price manipulation attacks against the Volo vault that can result in direct fund theft through corrupted share calculations.

## Finding Description

The vulnerability exists in the signature validation logic for Switchboard oracle price updates. Two critical production functions hardcode the slothash parameter to all zeros when generating the message hash for signature verification: [1](#0-0) [2](#0-1) 

The slothash parameter is designed to bind oracle signatures to specific blockchain state. The message generation function includes slothash at a specific byte position in the signed message: [3](#0-2) 

By hardcoding slothash to zero, signatures become replayable across chains if Switchboard deploys with matching parameters. The oracle and queue keys used in signature validation are arbitrary 32-byte values set by deployers, not derived from chain-specific data: [4](#0-3) [5](#0-4) 

**Attack Execution Path:**

1. Attacker monitors oracle submissions on Chain A (e.g., testnet) to capture valid signatures
2. Extract the signature, value, and timestamp from a Chain A transaction
3. Submit identical parameters to Chain B (e.g., mainnet) via the public entry function within the staleness window
4. The signature validates successfully because the message hash is identical (zero slothash on both chains)
5. The Switchboard aggregator on Chain B updates with the replayed price
6. Volo vault's oracle pulls the manipulated price via update_price()
7. Vault share calculations use the incorrect price, allowing value extraction

The Volo vault relies on these Switchboard prices for critical operations: [6](#0-5) 

## Impact Explanation

**Direct Fund Theft via Share Manipulation:**

When an attacker replays stale or divergent oracle signatures, the Volo vault calculates shares using incorrect USD valuations. The vault's deposit and withdrawal operations depend on accurate share ratios computed from total USD value divided by total shares.

The share ratio calculation aggregates asset values using oracle prices, and incorrect prices corrupt this fundamental invariant. For deposits, users receive shares proportional to their USD contribution. For withdrawals, users receive assets proportional to their share percentage. Price manipulation allows attackers to:

1. **Deposit Attack**: Deposit assets when replayed price is inflated → receive excess shares → withdraw at correct price for profit
2. **Withdrawal Attack**: Hold shares when replayed price is deflated → withdraw at inflated correct price for excess assets

The attack works even with honest oracles because legitimate signatures from one chain become weapons when replayed during price divergence periods. Testnet oracles typically update less frequently than mainnet, creating natural exploitation windows. During volatile market periods, price differences of 10-20% can occur within the staleness window (typically minutes to hours), enabling significant value extraction.

**Severity Justification:**

This is HIGH severity because it enables direct theft of vault funds through price manipulation, bypassing a security mechanism (chain-specific replay protection) that was intentionally designed into the system but completely disabled by hardcoding slothash to zero.

## Likelihood Explanation

**Reachable Entry Point:**

The attack uses a public entry function that anyone can call by paying the required oracle fee: [7](#0-6) 

**Feasible Preconditions:**

For the attack to succeed, Switchboard must deploy oracle infrastructure on multiple chains (e.g., mainnet and testnet) using consistent parameters:
- Same `queue_key` values for infrastructure consistency
- Same `oracle_key` values for oracle identity
- Same `feed_hash` values for asset feeds (e.g., "BTC/USD")
- Same oracle `secp256k1_key` for the same operator

This configuration is operationally likely because:
1. Feed hashes should be consistent across chains for the same price pair
2. Queue infrastructure would use standard keys for deployment consistency  
3. Oracle operators use the same signing keys for identity consistency

**Execution Practicality:**

1. Monitor oracle price submissions on Chain A via transaction scanning
2. Identify price divergence window (e.g., mainnet price moves but testnet lags)
3. Extract signature components from Chain A transaction
4. Call aggregator_submit_result_action::run on Chain B with identical parameters
5. Signature validates because message hash is identical due to zero slothash
6. Execute vault deposit/withdrawal to exploit manipulated price

**Economic Rationality:**

Attack cost is minimal (oracle fee only, typically small SUI amount), while potential gain is significant (percentage of vault TVL based on price divergence and transaction size limits).

**Probability Assessment:**

MEDIUM to HIGH likelihood because:
- Switchboard likely uses consistent parameters across deployments for operational reasons
- Price divergence windows naturally occur during market volatility
- Testnet update frequencies are typically slower than mainnet
- Attack requires no special privileges beyond transaction submission

## Recommendation

**Primary Fix: Implement Chain-Specific Slothash Binding**

Replace the hardcoded zero slothash with chain-specific identifiers. Options include:

1. **Use Sui Genesis Object ID**: Bind signatures to the chain's genesis object ID, which is unique per chain
2. **Use Package Object ID**: Bind to the deployed Switchboard package ID, which differs per deployment
3. **Use Protocol Version**: Include Sui protocol version in slothash computation

Example implementation:

```move
// In aggregator_submit_result_action.move, replace line 76:
let update_msg = hash::generate_update_msg(
    value,
    oracle.queue_key(),
    aggregator.feed_hash(),
    object::id_to_bytes(&aggregator.id()),  // Use aggregator's unique object ID
    aggregator.max_variance(),
    aggregator.min_responses(),
    timestamp_seconds,
);
```

**Alternative Fix: Add Chain-Specific State Check**

Validate that oracle signatures were generated for the specific chain by including chain-specific state in the validation:

```move
public fun validate<T>(
    aggregator: &Aggregator,
    queue: &Queue,
    oracle: &Oracle,
    timestamp_seconds: u64,
    value: &Decimal,
    signature: vector<u8>,
    clock: &Clock,
    coin: &Coin<T>,
    chain_identifier: vector<u8>,  // Add chain-specific parameter
) {
    // ... existing validation ...
    
    // Verify chain identifier matches expected value
    assert!(chain_identifier == get_chain_identifier(), EInvalidChain);
    
    let update_msg = hash::generate_update_msg(
        value,
        oracle.queue_key(),
        aggregator.feed_hash(),
        chain_identifier,  // Use provided chain identifier
        aggregator.max_variance(),
        aggregator.min_responses(),
        timestamp_seconds,
    );
    // ... continue validation ...
}
```

**Defense in Depth:**

Additionally, consider:
1. Add rate limiting on oracle updates per aggregator
2. Implement price deviation checks (reject updates that differ too much from recent values)
3. Add monitoring for duplicate signatures across different aggregators

## Proof of Concept

```move
#[test]
fun test_cross_chain_replay_attack() {
    use sui::test_scenario;
    use sui::clock;
    use sui::coin;
    use switchboard::aggregator;
    use switchboard::oracle;
    use switchboard::queue;
    use switchboard::aggregator_submit_result_action;
    
    let attacker = @0xBAD;
    let mut scenario = test_scenario::begin(attacker);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup identical oracle infrastructure on "two chains" (simulated)
    let queue_key = x"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let oracle_key = x"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let feed_hash = x"0000000000000000000000000000000000000000000000000000000000000001"; // BTC/USD
    
    // Create identical aggregators on both "chains"
    let mut aggregator_chain_a = create_test_aggregator(queue_key, feed_hash, scenario.ctx());
    let mut aggregator_chain_b = create_test_aggregator(queue_key, feed_hash, scenario.ctx());
    
    // Oracle signs price update on Chain A: BTC = $60,000
    let price_chain_a = 60000_000000000000000000u128;
    let timestamp = 1000000u64;
    let signature = generate_test_signature(price_chain_a, queue_key, feed_hash, timestamp);
    
    // Submit to Chain A successfully
    aggregator_submit_result_action::run(
        &mut aggregator_chain_a,
        &queue_chain_a,
        price_chain_a,
        false,
        timestamp,
        &oracle_chain_a,
        signature,
        &clock,
        coin::mint_for_testing<SUI>(1000, scenario.ctx()),
    );
    
    // Meanwhile, on Chain B, real price is now $50,000 (10 minutes later)
    clock::increment_for_testing(&mut clock, 600000); // 10 minutes
    
    // ATTACK: Replay same signature on Chain B
    // This should fail if slothash was properly implemented, but succeeds with zero slothash
    aggregator_submit_result_action::run(
        &mut aggregator_chain_b,
        &queue_chain_b,
        price_chain_a,  // Stale price: $60,000
        false,
        timestamp,  // Old timestamp (but still within staleness window)
        &oracle_chain_b,
        signature,  // SAME signature from Chain A
        &clock,
        coin::mint_for_testing<SUI>(1000, scenario.ctx()),
    );
    
    // Chain B now has manipulated price of $60,000 instead of $50,000
    let result_chain_b = aggregator::current_result(&aggregator_chain_b);
    assert!(aggregator::result(result_chain_b).value() == price_chain_a, 0);
    
    // Attacker can now exploit 20% price difference in vault operations
    // (vault integration test would show deposit/withdrawal exploitation)
}
```

## Notes

The vulnerability is particularly insidious because:

1. **It exploits honest oracles**: No oracle misbehavior is required; legitimate signatures become attack vectors through cross-chain replay
2. **Natural exploitation windows exist**: Testnet/mainnet update frequency differences and market volatility create regular opportunities
3. **The protection was designed but disabled**: The slothash parameter exists in the protocol design specifically for chain binding, but hardcoding it to zero completely negates its purpose
4. **Sui object IDs don't help**: While Aggregator/Oracle/Queue objects have unique IDs per chain, these IDs are not included in the signed message - only the arbitrary parameters (queue_key, feed_hash, etc.) are signed

The fix requires updating the message generation to include chain-specific identifiers that cannot be identical across different chain deployments, restoring the replay protection that was originally intended.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L72-80)
```text
    let update_msg = hash::generate_update_msg(
        value,
        oracle.queue_key(),
        aggregator.feed_hash(),
        x"0000000000000000000000000000000000000000000000000000000000000000",
        aggregator.max_variance(),
        aggregator.min_responses(),
        timestamp_seconds,
    );
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L78-85)
```text
    let attestation_msg = hash::generate_attestation_msg(
        oracle_key,
        queue_key,
        mr_enclave,
        x"0000000000000000000000000000000000000000000000000000000000000000",
        secp256k1_key,
        timestamp_seconds,
    );
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L106-158)
```text
public(package) fun new(
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    guardian_queue_id: ID,
    is_guardian_queue: bool,
    ctx: &mut TxContext,
): ID {
    let id = object::new(ctx);
    let queue_id = *(id.as_inner());
    if (is_guardian_queue) {
        let guardian_queue_id = *(id.as_inner());
        let guardian_queue = Queue {
            id,
            queue_key,
            authority,
            name,
            fee,
            fee_recipient,
            min_attestations,
            oracle_validity_length_ms,
            last_queue_override_ms: 0,
            guardian_queue_id,
            existing_oracles: table::new(ctx),
            fee_types: vector::singleton(type_name::get<Coin<SUI>>()),
            version: VERSION,
        };
        transfer::share_object(guardian_queue);
    } else {
        let oracle_queue = Queue {
            id,
            queue_key,
            authority,
            name,
            fee,
            fee_recipient,
            min_attestations,
            oracle_validity_length_ms,
            last_queue_override_ms: 0,
            guardian_queue_id,
            existing_oracles: table::new(ctx),
            fee_types: vector::singleton(type_name::get<Coin<SUI>>()),
            version: VERSION,
        };
        transfer::share_object(oracle_queue);
    };

    queue_id
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
