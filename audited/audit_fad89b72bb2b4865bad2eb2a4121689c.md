### Title
Multi-Package Version Inconsistency Causes Protocol-Wide DoS During Upgrades

### Summary
The lending_core protocol uses a compile-time constant `constants::version()` for version checking across multiple independent shared objects (Storage, Incentive, FlashLoanConfig). When a new package version is deployed, these objects must be migrated separately in non-atomic transactions, creating a window where cross-object operations fail completely, causing protocol-wide DoS until all migrations complete.

### Finding Description

The version checking mechanism relies on a hardcoded constant that changes between package deployments: [1](#0-0) [2](#0-1) 

Multiple shared objects maintain independent version fields that must be migrated separately: [3](#0-2) [4](#0-3) 

Each requires separate migration transactions: [5](#0-4) [6](#0-5) 

Critical issue: Entry functions access multiple versioned objects with independent checks: [7](#0-6) 

The function checks both objects' versions: [8](#0-7) [9](#0-8) 

When Package V2 (version=13) is deployed but Storage is migrated while Incentive remains at version 12, `constants::version()` returns 13 but `incentive.version` is 12, causing all cross-object operations to abort.

### Impact Explanation

**Complete Protocol Lockup:**
- All user-facing operations fail: deposits, withdrawals, borrows, repayments, reward claims
- Funds remain locked in the protocol until all objects are migrated
- No way to execute operations during the partial migration window
- Affects 100% of protocol users

**Severity Justification:**
- Critical operational failure during every upgrade
- No workaround available during migration window
- Multi-transaction migration creates unavoidable inconsistency window
- Even brief delays between migrations cause widespread user transaction failures

### Likelihood Explanation

**Highly Likely - Occurs During Every Upgrade:**

**Reachable Entry Points:**
All public entry functions that access multiple shared objects are affected, including `entry_deposit`, `entry_withdraw`, `entry_borrow`, `entry_repay`, `claim_reward_entry`.

**Feasibility:**
- Requires no attacker - this is an operational design flaw
- Happens automatically when admin deploys new package and begins migration
- Cannot be prevented without modifying version check mechanism
- Sui Move does not support atomic multi-object migration across separate shared objects

**Attack Complexity: None**
Normal users calling standard protocol functions during upgrade window experience transaction failures.

**Detection/Operational Constraints:**
- Migration requires multiple transactions (one per shared object)
- Even with careful orchestration, network latency creates inconsistency window
- If any migration transaction fails or is delayed, protocol remains partially broken

### Recommendation

**1. Remove version checking from cross-object operations:**
Modify functions that access multiple shared objects to only check the version of the primary object being modified, not all objects accessed.

**2. Implement version compatibility ranges:**
Instead of exact version matching, allow a configurable range of compatible versions so Storage v13 can work with Incentive v12 during migration windows.

**3. Add migration coordination:**
Create a single migration coordinator function that takes references to all shared objects and migrates them in a single transaction context (if possible), or implement a two-phase migration protocol with a "migration in progress" state that disables operations.

**4. Version check consolidation:**
Store version in a single global object that all other objects reference, eliminating per-object version fields.

### Proof of Concept

**Initial State:**
- Package V1 deployed at address 0xA with `constants::version() = 12`
- Storage object created with `version = 12`
- Incentive object created with `version = 12`
- Protocol functioning normally

**Transaction Sequence:**
1. Admin deploys Package V2 at address 0xB with `constants::version() = 13`
2. Admin calls `storage::version_migrate()` → `storage.version = 13`
3. **BEFORE admin migrates Incentive:**
4. User calls `incentive_v3::entry_deposit<USDC>()` from Package V2

**Expected Result:**
Deposit succeeds and user receives deposit receipt.

**Actual Result:**
Transaction aborts at `update_reward_state_by_asset()` → `version_verification(incentive)` → `assert!(12 == 13)` fails.

**Success Condition for Attack:**
Protocol DoS confirmed when any user transaction accessing multiple versioned objects fails during partial migration state. This affects all deposit, withdraw, borrow, and claim operations until ALL shared objects are migrated to the new version.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L14-14)
```text
    public fun version(): u64 {13}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/version.move (L5-7)
```text
    public fun this_version(): u64 {
        constants::version()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L32-40)
```text
    struct Storage has key, store {
        id: UID,
        version: u64,
        paused: bool, // Whether the pool is paused
        reserves: Table<u8, ReserveData>, // Reserve list. like: {0: ReserveData<USDT>, 1: ReserveData<ETH>}
        reserves_count: u8, // Total reserves count
        users: vector<address>, // uset list, like [0x01, 0x02]
        user_info: Table<address, UserInfo>
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L149-152)
```text
    public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
        assert!(storage.version < version::this_version(), error::not_available_version());
        storage.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L34-40)
```text
    struct Incentive has key, store {
        id: UID,
        version: u64,
        pools: VecMap<String, AssetPool>,
        borrow_fee_rate: u64,
        fee_balance: Bag, // K: TypeName(CoinType): V: Balance<CoinType>
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L516-518)
```text
    public fun update_reward_state_by_asset<T>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, user: address) {
        version_verification(incentive);
        let coin_type = type_name::into_string(type_name::get<T>());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L780-796)
```text
    public entry fun entry_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_coin<CoinType>(clock, storage, pool, asset, deposit_coin, amount, ctx);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L94-98)
```text
    public fun incentive_v3_version_migrate(_: &StorageAdminCap, incentive: &mut IncentiveV3) {
        assert!(incentive_v3::version(incentive) < version::this_version(), error::incorrect_version());

        incentive_v3::version_migrate(incentive, version::this_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L184-185)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);
```
