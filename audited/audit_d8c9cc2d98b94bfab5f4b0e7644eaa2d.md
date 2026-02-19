### Title
Missing Authorization Check in Oracle Registration Allows Unauthorized Oracle Registration and Frontrunning

### Summary
The `oracle_init_action::run()` function lacks authorization checks, allowing any user to register oracles to any queue immediately after creation. This enables attackers to frontrun legitimate oracle registration by registering oracle keys before the queue authority, creating operational complexity and potential for griefing attacks. All other queue modification operations require authority validation, making this an inconsistent security control.

### Finding Description

**Root Cause:** The oracle registration function does not validate queue authority before allowing oracle registration. [1](#0-0) 

The `validate()` function only checks queue version and oracle key uniqueness, with no authority verification: [2](#0-1) 

**Execution Path:**
1. Queue authority creates a new queue via `oracle_queue_init_action::actuate()` [3](#0-2) 

2. The queue is immediately shared as a public object: [4](#0-3) 

3. Attacker observes queue creation and frontrun-registers oracles with known or random oracle_keys
4. Once registered, oracle_keys cannot be re-registered due to the duplicate check: [5](#0-4) 

5. No removal function exists to delete malicious oracle registrations (search found zero matches)

**Why Existing Protections Fail:**
All other queue operations require `has_authority()` checks:
- `queue_set_configs_action`: [6](#0-5) 
- `queue_set_authority_action`: [7](#0-6) 
- `queue_add_fee_coin_action`: [8](#0-7) 
- `queue_override_oracle_action`: [9](#0-8) 

Oracle registration is the only queue modification operation without authorization enforcement.

### Impact Explanation

**Security Integrity Impact:**
- **Authorization Bypass**: Violates the principle that only queue authority should control oracle registration, creating an inconsistent security model
- **Operational Griefing**: Attacker can register malicious oracles forcing the authority to use `queue_override_oracle_action` to reconfigure them, adding operational overhead and complexity
- **Frontrunning Window**: If attacker registers oracle_keys that legitimate operators plan to use, it forces those operators to either change keys or wait for authority override

**Affected Parties:**
- Queue authorities who must spend additional gas and time managing malicious registrations
- Legitimate oracle operators who may have their intended oracle_keys pre-registered by attackers
- Volo vault operations that depend on Switchboard oracle data quality and configuration integrity

**No Direct Fund Loss:** While this doesn't directly steal funds, it creates operational DoS conditions and undermines the oracle authorization model. Oracle data integrity is critical for vault pricing and operations.

### Likelihood Explanation

**High Likelihood due to:**
1. **Low Attack Cost**: Only requires gas fees to call `oracle_init_action::run()` - no economic barriers
2. **Observable Entry Point**: Queue creation is publicly visible on-chain, enabling frontrunning
3. **No Technical Barriers**: Attack requires no special privileges, just monitoring mempool and submitting transactions
4. **Persistent Impact**: No removal mechanism exists, so malicious registrations are permanent until authority override

**Attack Complexity**: Low - attacker simply needs to:
- Monitor for queue creation transactions
- Submit oracle registration transactions with chosen oracle_keys (either targeted or random)
- No cryptographic attacks or complex state manipulation required

**Detection**: While malicious registrations are detectable via events, there's no automated prevention mechanism

### Recommendation

**Add Authority Check to Oracle Registration:**

Modify `oracle_init_action::validate()` to include authority verification:

```move
public fun validate(
    oracle_key: &vector<u8>,
    queue: &Queue,
    ctx: &TxContext,  // Add TxContext parameter
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(!queue.existing_oracles_contains(*oracle_key), EOracleKeyExists);
    assert!(queue.has_authority(ctx), EInvalidAuthority);  // Add authority check
}
```

Update the `run()` function signature to pass `ctx` to `validate()`.

**Add Error Constant:**
```move
#[error]
const EInvalidAuthority: vector<u8> = b"Invalid authority";
```

**Additional Improvements:**
1. Consider implementing an oracle removal function for queue authority to clean up malicious registrations
2. Add rate limiting or minimum fee requirements for oracle registration to increase attack cost
3. Document that queue creation and oracle registration should happen in a single transaction or with minimal delay

**Test Cases:**
1. Verify unauthorized users cannot register oracles (should fail with EInvalidAuthority)
2. Verify queue authority can successfully register oracles
3. Test frontrunning scenario where attacker attempts registration before authority

### Proof of Concept

**Initial State:**
- Queue authority prepares to create a new queue with intended oracle_key `0xABCD...`

**Attack Sequence:**

1. **Queue Authority** submits transaction calling `oracle_queue_init_action::run()` to create queue with ID `queue_123`
   - Queue becomes shared object
   
2. **Attacker** observes queue creation in mempool or immediately after
   - Submits transaction calling `oracle_init_action::run(oracle_key: 0xABCD..., queue: queue_123, ctx)`
   - Transaction succeeds because no authority check exists
   - Oracle registered with attacker's chosen key

3. **Queue Authority** attempts to register legitimate oracle with same key `0xABCD...`
   - Transaction fails with `EOracleKeyExists` error
   - Authority forced to either:
     - Use different oracle_keys (operational disruption)
     - Call `queue_override_oracle_action` to reconfigure attacker's oracle (added complexity and gas cost)

**Expected Result:** Oracle registration should fail for unauthorized users

**Actual Result:** Anyone can register oracles to any queue, enabling frontrunning and griefing attacks

**Success Condition:** Attacker successfully registers oracle before legitimate authority, and that registration cannot be removed (only overridden), demonstrating the authorization bypass vulnerability

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/oracle_queue_init_action.move (L32-64)
```text
fun actuate(
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    guardian_queue_id: ID,
    ctx: &mut TxContext
) {
    let queue_id = queue::new(
        queue_key,
        authority,
        name,
        fee,
        fee_recipient,
        min_attestations,
        oracle_validity_length_ms,
        guardian_queue_id,
        false,
        ctx,
    );

    // emit the creation event
    let created_event = OracleQueueCreated {
        queue_id,
        guardian_queue_id: guardian_queue_id,
        queue_key: queue_key,
    };
    event::emit(created_event);
    
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_configs_action.move (L34-34)
```text
    assert!(queue.has_authority(ctx), EInvalidAuthority);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_authority_action.move (L24-24)
```text
    assert!(queue.has_authority(ctx), EInvalidAuthority);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_add_fee_coin_action.move (L25-25)
```text
    assert!(queue.has_authority(ctx), EInvalidAuthority);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L42-42)
```text
    assert!(queue.has_authority(ctx), EInvalidAuthority);
```
