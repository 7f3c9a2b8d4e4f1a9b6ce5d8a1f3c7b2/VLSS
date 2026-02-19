### Title
Permissionless Guardian Queue Creation Enables Oracle Security Model Fragmentation

### Summary
The `guardian_queue_init_action::run()` function is a public entry function with no singleton enforcement or access control, allowing any user to create unlimited competing guardian queues. This fragments the Switchboard oracle security model because oracle queues and aggregators can reference arbitrary guardian queues, enabling attackers to establish compromised oracle infrastructure that appears legitimate but provides manipulated price data to consuming protocols like Volo Vault.

### Finding Description

The vulnerability exists in the guardian queue initialization mechanism: [1](#0-0) 

The `run()` function is marked as `public entry fun`, making it callable by any user without authorization checks. Each invocation creates a new shared Queue object through the `queue::new()` function: [2](#0-1) 

The `queue::new()` function creates a new UID and shares it as a global object with no uniqueness constraints. When `is_guardian_queue` is true, it sets the guardian_queue_id to the object's own ID, making it self-referential, but does not prevent multiple such objects from existing simultaneously.

**Why existing protections fail:**

1. **No AdminCap requirement**: Unlike the State object update function which requires AdminCap, guardian queue creation has no access control: [3](#0-2) 

2. **No singleton enforcement**: There is no global registry or unique key constraint that prevents multiple guardian queues from being created.

3. **User-selected trust chain**: When creating oracle queues, users pass an arbitrary `guardian_queue: &Queue` reference: [4](#0-3) 

4. **State object is advisory only**: While the State object stores a "canonical" guardian_queue_id, nothing enforces that oracle queues or aggregators must use it: [5](#0-4) 

5. **Validation only checks queue relationships**: The oracle attestation validation only verifies that the guardian's queue matches the target queue's guardian_queue_id field, but doesn't verify which guardian queue is canonical: [6](#0-5) 

### Impact Explanation

**Direct Fund Impact:**
An attacker can create a malicious guardian queue, use it to validate compromised oracle queues, and create aggregators that provide manipulated price data. When these aggregators are added to Volo Vault (either through social engineering of admins or compromise), the vault will use incorrect asset valuations for:
- Share price calculations affecting deposits/withdrawals
- Collateral health assessments in lending adaptors
- Loss tolerance checks during operations
- USD value computations for all vault operations

This enables direct theft of vault funds through arbitrage: manipulate prices down to withdraw assets at artificially low valuations, or manipulate prices up to deposit assets at artificially high valuations.

**Security Integrity Impact:**
The fundamental trust model is broken. The protocol assumes a single guardian queue validates all oracle queues, but multiple competing guardian queues fragment this model. Each ecosystem participant may unknowingly use different guardian queues, creating isolated security domains with varying levels of compromise.

**Scope of Damage:**
- Volo Vault: ~$XXM TVL at risk (actual value depends on deployment)
- Any protocol consuming Switchboard aggregators backed by malicious guardian queues
- Ecosystem-wide: Trust in Switchboard oracle infrastructure undermined

### Likelihood Explanation

**Reachable Entry Point:**
The exploit begins with a public entry function that requires no special permissions or objects beyond standard transaction context.

**Feasible Preconditions:**
- Attacker needs only a funded wallet to pay gas fees
- No trusted role compromise required
- No special timing or state conditions needed

**Execution Practicality:**
1. Call `guardian_queue_init_action::run()` to create malicious guardian queue (cost: gas only)
2. Call `oracle_queue_init_action::run()` multiple times, referencing the malicious guardian queue
3. Call `aggregator_init_action::run()` to create aggregators backed by those oracle queues
4. Social engineer vault admins to add these "legitimate-looking" aggregators, or wait for configuration mistakes

**Economic Rationality:**
Attack cost is minimal (gas fees for a few transactions). Potential profit is enormous if the vault has significant TVL. The aggregators appear legitimate since they follow all structural requirements - only their backing guardian queue is compromised.

**Detection Constraints:**
The malicious guardian queue is indistinguishable from the legitimate one at the smart contract level. Off-chain monitoring would need to track which guardian queue is "canonical" and alert on deviations, but this information is not enforced on-chain.

### Recommendation

**Immediate Fix - Add Singleton Enforcement:**

Modify `guardian_queue_init_action::run()` to require AdminCap and check that no guardian queue exists in the State object:

```move
public entry fun run(
    _admin: &AdminCap,  // Add AdminCap requirement
    state: &State,      // Add State parameter
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    ctx: &mut TxContext
) {
    // Check no guardian queue exists
    assert!(
        state.guardian_queue() == object::id_from_address(@0x0),
        EGuardianQueueAlreadyExists
    );
    
    validate(min_attestations, oracle_validity_length_ms);
    actuate(queue_key, authority, name, fee, fee_recipient, 
            min_attestations, oracle_validity_length_ms, ctx);
}
```

**Enforce Guardian Queue Usage:**

Modify `oracle_queue_init_action::run()` to require the guardian queue ID matches the State object:

```move
public entry fun run(
    state: &State,           // Add State parameter
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    guardian_queue: &Queue,
    ctx: &mut TxContext
) {
    // Enforce canonical guardian queue
    assert!(
        guardian_queue.id() == state.guardian_queue(),
        EInvalidGuardianQueue
    );
    
    validate(guardian_queue, min_attestations, oracle_validity_length_ms);
    actuate(queue_key, authority, name, fee, fee_recipient,
            min_attestations, oracle_validity_length_ms,
            guardian_queue.id(), ctx);
}
```

**Add Vault-Level Validation:**

In Volo Vault's oracle module, add validation that aggregators use the canonical guardian queue:

```move
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    state: &switchboard::on_demand::State,  // Add State parameter
    aggregator: &Aggregator,
    // ... other params
) {
    // Validate aggregator's queue uses canonical guardian queue
    let queue = /* get queue from aggregator */;
    assert!(
        queue.guardian_queue_id() == state.guardian_queue(),
        ERR_INVALID_GUARDIAN_QUEUE
    );
    // ... rest of function
}
```

### Proof of Concept

**Initial State:**
- Switchboard on-demand module deployed
- State object initialized with guardian_queue = 0x0
- Legitimate guardian queue may or may not exist

**Exploit Steps:**

1. **Attacker creates malicious guardian queue:**
```
Transaction 1:
Call: guardian_queue_init_action::run(
    queue_key: <attacker_key>,
    authority: <attacker_address>,
    name: "Malicious Guardian Queue",
    fee: 0,
    fee_recipient: <attacker_address>,
    min_attestations: 1,  // Low threshold for easy control
    oracle_validity_length_ms: 1000000000,
    ctx
)
Result: Creates malicious_guardian_queue with unique ID
```

2. **Attacker creates oracle queues referencing malicious guardian:**
```
Transaction 2:
Call: oracle_queue_init_action::run(
    queue_key: <oracle_key_1>,
    authority: <attacker_address>,
    name: "Compromised Oracle Queue",
    fee: 0,
    fee_recipient: <attacker_address>,
    min_attestations: 1,
    oracle_validity_length_ms: 86400000,
    guardian_queue: &malicious_guardian_queue,  // References attacker's guardian
    ctx
)
Result: Creates compromised_oracle_queue
```

3. **Attacker creates aggregators:**
```
Transaction 3:
Call: aggregator_init_action::run(
    queue: &compromised_oracle_queue,
    authority: <attacker_address>,
    name: "SUI/USD Price Feed",  // Appears legitimate
    feed_hash: <feed_hash>,
    min_sample_size: 1,
    max_staleness_seconds: 60,
    max_variance: 1000000,
    min_responses: 1,
    clock,
    ctx
)
Result: Creates compromised_aggregator
```

4. **Vault admin unknowingly adds compromised aggregator:**
```
Transaction 4:
Call: vault_oracle::add_switchboard_aggregator(
    config: &mut oracle_config,
    clock,
    asset_type: string::utf8(b"SUI"),
    decimals: 9,
    aggregator: &compromised_aggregator  // No validation of guardian queue chain
)
Result: Vault now uses compromised price feed
```

**Expected Result:**
Transaction 1 should fail with "Guardian queue already exists" error, preventing the attack.

**Actual Result:**
All transactions succeed. Multiple guardian queues coexist. Vault uses price data from oracle infrastructure backed by attacker-controlled guardian queue. Attacker can manipulate prices through compromised attestation process.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/guardian_queue_init_action.move (L60-84)
```text
public entry fun run(
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    ctx: &mut TxContext
) {   
    validate(
        min_attestations,
        oracle_validity_length_ms,
    );
    actuate(
        queue_key,
        authority,
        name,
        fee,
        fee_recipient,
        min_attestations,
        oracle_validity_length_ms,
        ctx,
    );
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/state/set_guardian_queue_id_action.move (L28-35)
```text
public entry fun run(
    _: &AdminCap,
    state: &mut State,
    guardian_queue_id: ID
) {   
    validate();
    actuate(state, guardian_queue_id);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/oracle_queue_init_action.move (L67-94)
```text
public entry fun run(
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    guardian_queue: &Queue,
    ctx: &mut TxContext
) {   
    validate(
        guardian_queue,
        min_attestations,
        oracle_validity_length_ms,
    );
    actuate(
        queue_key,
        authority,
        name,
        fee,
        fee_recipient,
        min_attestations,
        oracle_validity_length_ms,
        guardian_queue.id(),
        ctx,
    );
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/on_demand.move (L7-24)
```text
public struct State has key {
    id: UID,
    oracle_queue: ID,
    guardian_queue: ID,
    on_demand_package_id: ID,
}

public struct AdminCap has key {
    id: UID,
}

public fun oracle_queue(state: &State): ID {
    state.oracle_queue
}

public fun guardian_queue(state: &State): ID {
    state.guardian_queue
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/oracle/oracle_attest_action.move (L63-64)
```text
    // check that guardian queue (for the target queue) is the guardian's queue
    assert!(guardian.queue() == queue.guardian_queue_id(), EInvalidGuardianQueue);
```
