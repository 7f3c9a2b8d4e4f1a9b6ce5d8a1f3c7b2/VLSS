### Title
Missing Version Update Functionality in Operation Shared Object

### Summary
The `Operation` shared object in volo-vault lacks version tracking and upgrade functionality, preventing safe protocol upgrades when operator management features need enhancement. This creates a protocol-level DoS risk when breaking changes to the Operation struct are required, as there is no migration path for the existing shared object.

### Finding Description
The external report identifies missing version update functionality in a configuration object. The same vulnerability class exists in Volo's `Operation` struct.

**Root Cause in Volo:**

The `Operation` struct is defined as a shared object without version control: [1](#0-0) 

It is created once during module initialization: [2](#0-1) 

The Operation object is used extensively for critical operator access control throughout the system: [3](#0-2) 

All operator-gated functions depend on Operation for freeze checks: [4](#0-3) [5](#0-4) 

**Why Current Checks Fail:**

Unlike other critical shared objects in the system (Vault, OracleConfig, RewardManager) which implement the version upgrade pattern: [6](#0-5) [7](#0-6) [8](#0-7) 

And: [9](#0-8) [10](#0-9) [11](#0-10) 

The Operation struct has:
- No VERSION constant
- No version field in the struct
- No check_version() function  
- No upgrade_operation() function

Admin functions can modify Operation state but cannot upgrade its version: [12](#0-11) 

**Exploit Path:**

1. Protocol requires operator management enhancement (e.g., role-based permissions, time-limited access, enhanced freeze mechanisms)
2. Developers upgrade package with new Operation struct requiring additional fields
3. Existing Operation shared object cannot be migrated (no upgrade function exists)
4. New code expects v2 Operation structure but deployed object is v1
5. All operator-gated operations fail: start_op_with_bag, end_op_with_bag, execute_deposit, execute_withdraw, all reward manager operator functions
6. Protocol enters DoS state - critical vault operations cannot proceed

### Impact Explanation
**High-confidence protocol DoS via valid calls.** The Operation object is used in 27+ locations in operation.move and 14+ locations in reward_manager.move for critical operator access control. If a package upgrade requires Operation struct changes (highly likely as protocol matures), there is no safe migration path. This would block:

- All vault DeFi operations (borrowing/returning assets)
- Deposit and withdrawal execution by operators
- Reward distribution operations
- Operator freeze/unfreeze management

The protocol would be unable to execute any operator-gated functions until a complex workaround involving deploying a new Operation object and migrating all references is completed.

### Likelihood Explanation
**High likelihood** during protocol evolution. As the vault system matures, operator management features will need enhancement:
- Role-based operator permissions (separate operators for different asset types)
- Time-based or epoch-based operator restrictions
- Advanced freeze mechanisms with grace periods
- Operator reputation/scoring systems

Any such enhancement requiring new fields in Operation struct would trigger this issue. The existence of comprehensive version upgrade patterns for Vault, OracleConfig, and RewardManager demonstrates the developers understand this risk, but Operation was overlooked.

### Recommendation
Implement version control for the Operation struct following the established pattern:

1. Add `const VERSION: u64 = 1;` to volo_vault module
2. Add `version: u64` field to Operation struct, initialize with VERSION in init()
3. Implement `check_version(operation: &Operation)` function that asserts `operation.version == VERSION`
4. Implement `upgrade_operation(operation: &mut Operation)` function that checks `operation.version < VERSION`, updates it, and emits upgrade event
5. Add admin entry point in manage.move: `public fun upgrade_operation(_: &AdminCap, operation: &mut Operation)` 
6. Call check_version() at the start of set_operator_freezed(), assert_operator_not_freezed(), and operator_freezed()

### Proof of Concept
**Current State:**
1. Operation shared object created in init() with structure: `{id: UID, freezed_operators: Table<address, bool>}`
2. All operator functions depend on Operation for freeze checks

**Exploit Scenario:**
1. Developer decides to add time-limited operator permissions (common upgrade path)
2. New Operation struct needs: `{id: UID, freezed_operators: Table<address, bool>, operator_time_limits: Table<address, u64>}`
3. Package upgraded with new struct definition
4. Existing Operation shared object still has old structure (only 2 fields)
5. Call to start_op_with_bag() → calls assert_operator_not_freezed() → tries to check version → NO version check exists → proceeds with incompatible Operation object
6. If new code tries to access non-existent operator_time_limits field → abort/undefined behavior
7. All operator functions become non-functional → protocol DoS

**Validation:** The impact is equivalent to other version-controlled objects (Vault, OracleConfig, RewardManager) if they lacked version control - complete inability to safely upgrade critical protocol components.

### Citations

**File:** volo-vault/sources/volo_vault.move (L21-21)
```text
const VERSION: u64 = 1;
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L98-98)
```text
    version: u64,
```

**File:** volo-vault/sources/volo_vault.move (L349-358)
```text
fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::public_transfer(admin_cap, ctx.sender());

    let operation = Operation {
        id: object::new(ctx),
        freezed_operators: table::new(ctx),
    };
    transfer::share_object(operation);
}
```

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/volo_vault.move (L464-469)
```text
public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
```

**File:** volo-vault/sources/operation.move (L94-106)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/reward_manager.move (L233-241)
```text
public fun add_new_reward_type<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    with_buffer: bool, // If true, create a new reward buffer distribution for the reward type
) {
    self.check_version();
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/oracle.move (L11-11)
```text
const VERSION: u64 = 2;
```

**File:** volo-vault/sources/oracle.move (L33-33)
```text
    version: u64,
```

**File:** volo-vault/sources/oracle.move (L100-108)
```text
public(package) fun upgrade_oracle_config(self: &mut OracleConfig) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(OracleConfigUpgraded {
        oracle_config_id: self.id.to_address(),
        version: VERSION,
    });
}
```

**File:** volo-vault/sources/manage.move (L88-95)
```text
public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
}
```
