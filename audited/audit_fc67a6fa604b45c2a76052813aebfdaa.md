### Title
Permanent DoS for All Queue Operations Due to Missing Version Migration Function

### Summary
The Switchboard Queue module implements version checking in all action functions but lacks a version migration function to update existing Queue objects after upgrades. If `EXPECTED_QUEUE_VERSION` is changed during a module upgrade, all existing Queue objects become permanently unusable, causing complete DoS for fee type management and all other queue operations.

### Finding Description

The `queue_add_fee_coin_action::run()` function validates the queue version before executing: [1](#0-0) [2](#0-1) 

The Queue struct stores a version field initialized to 1: [3](#0-2) [4](#0-3) 

**Root Cause:** The Queue module provides NO function to update the version field of existing Queue objects. All public(package) functions in queue.move modify other fields but never the version: [5](#0-4) 

This same version check pattern exists in ALL queue action modules: [6](#0-5) [7](#0-6) [8](#0-7) 

**Upgrade Scenario:** During a module upgrade, if developers change `EXPECTED_QUEUE_VERSION` from 1 to 2 (e.g., to enforce new validation logic or fix a bug), the version check will fail for all existing Queue objects (which still have `version = 1` in their stored state), causing an abort with `EInvalidQueueVersion`.

**Why Protections Fail:** Unlike other modules in the broader Volo codebase that implement version migration patterns (e.g., OracleConfig has `version_migrate`, RewardManager has `upgrade_reward_manager`, StakePool has `migrate_version`), the Switchboard Queue module completely lacks such functionality.

### Impact Explanation

**Complete Protocol Disruption:**
- All queue operations permanently blocked: `add_fee_type`, `remove_fee_type`, `set_configs`, `set_authority`, `queue_override_oracle`
- Existing Queue objects (guardian and oracle queues) become permanently unusable
- All oracles registered to these queues become inaccessible
- The entire Switchboard oracle system deployed on-chain stops functioning
- Users depending on these oracles for price feeds lose access to critical infrastructure

**Severity Justification:** HIGH
- **Irreversible damage:** No recovery path exists without deploying new queue objects and re-registering all oracles
- **Widespread impact:** Affects all existing queues and their dependent oracles
- **Critical functionality loss:** Oracle price feeds are essential for DeFi operations including the Volo vault's USD valuation

The Switchboard upgrade history shows multiple deployments have already occurred: [9](#0-8) 

### Likelihood Explanation

**Realistic Upgrade Trigger:**
- Module upgrades are normal protocol operations, as evidenced by Switchboard's deployment history
- Developers may legitimately need to increment `EXPECTED_QUEUE_VERSION` when:
  - Adding new validation logic
  - Fixing security issues
  - Changing queue behavior requirements
- Once triggered, the DoS affects ALL users attempting any queue operation

**No Attack Required:**
- This is a design flaw, not an exploit requiring attacker capabilities
- The vulnerability manifests through legitimate protocol upgrade processes
- No special permissions or economic resources needed to trigger once upgrade occurs

**High Probability:**
- The codebase shows other modules follow proper version migration patterns, indicating awareness of this need
- The absence of migration logic in Queue module makes version incompatibility inevitable during future upgrades
- Standard software evolution practices make version changes likely over the protocol's lifetime

### Recommendation

**Add Version Migration Function:**

Add a public(package) or admin-gated function to update the Queue version field:

```move
// In queue.move
public(package) fun migrate_version(queue: &mut Queue) {
    assert!(queue.version <= VERSION, /* error */);
    queue.version = VERSION;
}
```

**Add Migration Action Module:**

Create `queue_migrate_version_action.move` following the pattern used in other Volo modules:

```move
module switchboard::queue_migrate_version_action;

public entry fun run(
    queue: &mut Queue,
    ctx: &mut TxContext
) {
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    queue.migrate_version();
}
```

**Test Coverage:**
- Add tests simulating version upgrades with migration
- Verify all existing Queue operations work after migration
- Test that migration is idempotent and cannot downgrade versions

### Proof of Concept

**Initial State:**
- Queue object exists with `version = 1`
- `EXPECTED_QUEUE_VERSION = 1` in all action modules
- Fee type additions work normally via `queue_add_fee_coin_action::run()`

**Upgrade Step:**
1. Protocol team upgrades the Switchboard module
2. New version changes `EXPECTED_QUEUE_VERSION` to `2` in `queue_add_fee_coin_action.move` (and other action modules)
3. Existing Queue objects still have `version = 1` in their on-chain state

**Exploitation Result:**
1. Any user calls `queue_add_fee_coin_action::run<T>(queue, ctx)`
2. Function executes `validate(queue, ctx)`
3. Assertion fails: `assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion)` where `queue.version() = 1` and `EXPECTED_QUEUE_VERSION = 2`
4. Transaction aborts with `EInvalidQueueVersion` error
5. Same failure occurs for ALL queue action functions
6. Queue becomes permanently unusable with no recovery path

**Success Condition:** All queue operations are permanently disabled for existing Queue objects, requiring complete redeployment of new queues and re-registration of all oracles.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_add_fee_coin_action.move (L8-8)
```text
const EXPECTED_QUEUE_VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_add_fee_coin_action.move (L20-26)
```text
public fun validate(
    queue: &Queue,
    ctx: &mut TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L9-9)
```text
const VERSION: u8 = 1;
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L16-32)
```text
public struct Queue has key {
    id: UID,
    queue_key: vector<u8>,
    authority: address,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    last_queue_override_ms: u64,
    guardian_queue_id: ID,

    // to ensure that oracles are only mapped once (oracle pubkeys)
    existing_oracles: Table<vector<u8>, ExistingOracle>,
    fee_types: vector<TypeName>,
    version: u8,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L160-209)
```text
public(package) fun add_existing_oracle(queue: &mut Queue, oracle_key: vector<u8>, oracle_id: ID) {
    queue.existing_oracles.add(oracle_key, ExistingOracle { oracle_id, oracle_key });
}

public(package) fun set_last_queue_override_ms(queue: &mut Queue, last_queue_override_ms: u64) {
    queue.last_queue_override_ms = last_queue_override_ms;
}

public(package) fun set_guardian_queue_id(queue: &mut Queue, guardian_queue_id: ID) {
    queue.guardian_queue_id = guardian_queue_id;
} 

public(package) fun set_queue_key(queue: &mut Queue, queue_key: vector<u8>) {
    queue.queue_key = queue_key;
}

public(package) fun set_authority(queue: &mut Queue, authority: address) {
    queue.authority = authority;
}

public(package) fun set_configs(
    queue: &mut Queue,
    name: String,
    fee: u64,
    fee_recipient: address,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
) {
    queue.name = name;
    queue.fee = fee;
    queue.fee_recipient = fee_recipient;
    queue.min_attestations = min_attestations;
    queue.oracle_validity_length_ms = oracle_validity_length_ms;
}

public (package) fun add_fee_type<T>(queue: &mut Queue) {
    if (queue.fee_types.contains(&type_name::get<Coin<T>>())) {
        return
    };
    queue.fee_types.push_back(type_name::get<Coin<T>>());
}

public (package) fun remove_fee_type<T>(queue: &mut Queue) {
    let (has_type, index) = queue.fee_types.index_of(&type_name::get<Coin<T>>());
    if (has_type == false) {
        return
    };
    queue.fee_types.swap_remove(index);
}

```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_configs_action.move (L27-37)
```text
public fun validate(
    queue: &Queue,
    min_attestations: u64,
    oracle_validity_length_ms: u64,
    ctx: &TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    assert!(min_attestations > 0, EInvalidMinAttestations);
    assert!(oracle_validity_length_ms > 0, EInvalidOracleValidityLength);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_authority_action.move (L19-25)
```text
public fun validate(
    queue: &Queue,
    ctx: &mut TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_remove_fee_coin_action.move (L20-26)
```text
public fun validate(
    queue: &Queue,
    ctx: &mut TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/Move.mainnet.toml (L10-23)
```text
# Old version:
# First Publish: 0x0b884dbc39d915f32a82cc62dabad75ca3efd3c568c329eba270b03c6f58cbd8
# Second Publish: 0x1b03b77082cdb9d6b3febc6294f36d999d8556583616fadc84199a8e66371d60
# Third Publish: 0xbd22434e506314abc0cd981447fbf42139fa04aa09b5a8a7d7789826883e8e0a
# AdminCap: 0xe10be54c1686c5d5e6ccd74b7589a7362e7d075d6e4c513c8af379fdaf4c5f36
# State: 0x90a2829005435005300abaf7ce8115814b38c8d42a6de5aaf311774c60603b68
# UpgradeCap: 0xda0d1de2ce8afde226f66b1963c3f6afc929ab49eaeed951c723a481499e31e9

# New version:
# First Publish: 0xc3c7e6eb7202e9fb0389a2f7542b91cc40e4f7a33c02554fec11c4c92f938ea3
# Second Publish: 0xe6717fb7c9d44706bf8ce8a651e25c0a7902d32cb0ff40c0976251ce8ac25655
# AdminCap: 0xf02428df77e94f22df093b364d7e2b47cacb96a1856f49f5e1c4927705d50050
# State: 0x93d2a8222bb2006d16285ac858ec2ae5f644851917504b94debde8032664a791
# UpgradeCap: 0xe4b73392789cbda0420785a98eae24a4eef3a263317247c16fd1d192c1db2b93
```
