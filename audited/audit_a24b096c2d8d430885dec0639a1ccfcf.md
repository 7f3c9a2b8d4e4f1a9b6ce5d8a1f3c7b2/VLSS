### Title
Missing Cross-Object Version Validation Allows Operations with Mismatched Protocol Versions

### Summary
Functions in `lending_core::manage` that operate on multiple shared objects (Storage, IncentiveV3, FlashLoanConfig) validate only one object's version while reading data from others without version checks. This allows operations to proceed with objects from different protocol versions during migration windows, leading to incorrect reward calculations, asset misconfigurations, and potential fund loss.

### Finding Description

The `lending_core::manage` module contains administrative functions that operate on multiple shared objects but fail to validate they are from the same protocol version. [1](#0-0) 

In `create_flash_loan_asset()`, the function reads data from Storage (lines 34-38) but only validates FlashLoanConfig's version when calling `flash_loan::create_asset()`. Storage is never version-checked. [2](#0-1) 

Similarly, `create_incentive_v3_pool()` and `set_incentive_v3_reward_rate_by_rule_id()` in manage.move read from Storage but only verify IncentiveV3's version: [3](#0-2) [4](#0-3) 

The root cause is that Storage getter functions have NO version verification: [5](#0-4) 

These getters (`get_coin_type`, `get_index`, `get_total_supply`, `get_user_balance`) are pure data accessors with no version checks, unlike Storage modification functions: [6](#0-5) 

IncentiveV3 extensively reads from Storage without version validation: [7](#0-6) [8](#0-7) 

Each object has separate `version_migrate` entry functions that must be called independently: [9](#0-8) [10](#0-9) [11](#0-10) 

### Impact Explanation

**Direct Fund Impact:**

1. **Incorrect Reward Calculations**: If IncentiveV3 is migrated to version N+1 but Storage remains at N, `update_reward_state_by_asset()` reads stale data structures from Storage v1 and applies v2 calculation logic. This results in:
   - Users claiming more/less rewards than entitled
   - Wrong asset targeting if asset ID mappings changed
   - Corrupted reward tracking state

2. **Flash Loan Misconfiguration**: If FlashLoanConfig is migrated to v2 but Storage remains at v1, `create_flash_loan_asset()` reads asset information from v1 Storage and configures v2 FlashLoanConfig. This could:
   - Configure flash loans for wrong assets if coin type formats changed
   - Apply incorrect fee rates to wrong pools
   - Enable flash loans on assets that should be restricted in v2

3. **Data Structure Incompatibility**: Protocol versions typically involve structural changes (new fields, modified calculations, updated semantics). Reading v1 data with v2 logic violates invariants and corrupts protocol state.

The impact is measurable fund loss through incorrect reward distributions and flash loan misconfigurations affecting all protocol users.

### Likelihood Explanation

**Realistic Operational Error:**

The vulnerability requires an admin mistake during protocol upgrades, but this is highly realistic:

1. **Non-Atomic Migration**: Each shared object requires a separate `version_migrate` entry function call. There's no atomic migration mechanism forcing all objects to upgrade together.

2. **Complex Multi-Object Coordination**: The protocol has at least 3 separate shared objects (Storage, IncentiveV3, FlashLoanConfig) that must be migrated in any order, creating a coordination challenge.

3. **No Migration Safeguards**: Unlike the liquid staking migration which uses `MigrationCap` to enforce sequencing, the lending protocol has no safeguards preventing partial migrations or enforcing migration order.

4. **Operational Window**: Between upgrading contract code and completing all object migrations, there's a window where mismatched versions can occur. If admin migrates IncentiveV3 first, any delay in migrating Storage creates the vulnerability window.

5. **Silent Failure Mode**: The protocol doesn't fail safely - operations succeed with wrong results rather than aborting, making the issue harder to detect.

**Attack Complexity:** None required - this is an admin operational error that creates conditions for unintentional exploitation through normal protocol usage.

**Detection:** Difficult to detect in production since transactions succeed and produce plausible but incorrect results.

### Recommendation

**1. Add Cross-Object Version Validation:**

Add validation functions that check all related objects have matching versions:

```move
public fun validate_storage_incentive_version(storage: &Storage, incentive: &IncentiveV3) {
    assert!(storage.version == incentive.version, error::version_mismatch());
    version_verification(storage);
    version_verification(incentive);
}

public fun validate_storage_flashloan_version(storage: &Storage, config: &FlashLoanConfig) {
    assert!(storage.version == config.version, error::version_mismatch());
    version_verification(storage);
    version_verification(config);
}
```

**2. Add Version Checks to manage.move Functions:**

In `create_flash_loan_asset()`:
```move
validate_storage_flashloan_version(storage, config);
```

In `create_incentive_v3_pool()` and `set_incentive_v3_reward_rate_by_rule_id()`:
```move
validate_storage_incentive_version(storage, incentive);
```

**3. Add Version Checks to Storage Getters:**

Add version verification to critical getter functions:
```move
public fun get_total_supply(storage: &mut Storage, asset: u8): (u256, u256) {
    version_verification(storage);
    // existing logic
}
```

**4. Implement Atomic Migration Mechanism:**

Create a migration capability pattern similar to liquid staking's `MigrationCap` that ensures all objects are migrated atomically or enforces migration order.

**5. Add Migration Tests:**

Test cases validating:
- All objects must be at same version before operations
- Partial migrations are detected and rejected
- Cross-version operations fail safely

### Proof of Concept

**Initial State:**
- Protocol code upgraded from version 1 to version 2
- Storage at version 1 (not yet migrated)
- IncentiveV3 migrated to version 2
- FlashLoanConfig migrated to version 2

**Exploitation Steps:**

**Step 1 - Admin migrates IncentiveV3:**
```move
manage::incentive_v3_version_migrate(&admin_cap, &mut incentive_v3);
// IncentiveV3.version = 2
```

**Step 2 - Admin migrates FlashLoanConfig:**
```move
flash_loan::version_migrate(&storage_admin_cap, &mut flashloan_config);
// FlashLoanConfig.version = 2
```

**Step 3 - Admin forgets to migrate Storage:**
```move
// Storage.version = 1 (forgotten migration)
```

**Step 4 - Admin creates flash loan asset:**
```move
manage::create_flash_loan_asset<USDC>(
    &storage_admin_cap,
    &mut flashloan_config,  // v2
    &storage,               // v1 - NO VERSION CHECK!
    &mut pool,
    asset_id,
    rate_to_supplier,
    rate_to_treasury,
    maximum,
    minimum,
    ctx
);
```

**Expected Result:** Transaction should abort with version mismatch error.

**Actual Result:** Transaction succeeds, reads asset data from Storage v1, configures FlashLoanConfig v2 with potentially incorrect asset mapping if version 2 changed asset ID semantics or coin type formats.

**Success Condition:** Flash loan created with wrong asset configuration, enabling incorrect flash loans or fee rates.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L22-53)
```text
    public fun create_flash_loan_asset<T>(
        _: &StorageAdminCap,
        config: &mut FlashLoanConfig,
        storage: &Storage,
        pool: &Pool<T>,
        asset_id: u8,
        rate_to_supplier: u64,
        rate_to_treasury: u64,
        maximum: u64,
        minimum: u64,
        ctx: &mut TxContext
    ) {
        let reserves_count = storage::get_reserves_count(storage);
        assert!(asset_id < reserves_count, error::reserve_not_found());

        let coin_type_from_storage = storage::get_coin_type(storage, asset_id);
        assert!(type_name::into_string(type_name::get<T>()) == coin_type_from_storage, error::invalid_coin_type());

        let pool_address = object::uid_to_address(pool::uid(pool));

        flash_loan::create_asset(
            config,
            asset_id,
            coin_type_from_storage,
            pool_address,
            rate_to_supplier,
            rate_to_treasury,
            maximum,
            minimum,
            ctx
        );
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L94-98)
```text
    public fun incentive_v3_version_migrate(_: &StorageAdminCap, incentive: &mut IncentiveV3) {
        assert!(incentive_v3::version(incentive) < version::this_version(), error::incorrect_version());

        incentive_v3::version_migrate(incentive, version::this_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L124-126)
```text
    public fun create_incentive_v3_pool<T>(_: &IncentiveOwnerCap, incentive: &mut IncentiveV3, storage: &Storage, asset_id: u8, ctx: &mut TxContext) {
        incentive_v3::create_pool<T>(incentive, storage, asset_id, ctx)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L140-142)
```text
    public fun set_incentive_v3_reward_rate_by_rule_id<T>(_: &IncentiveOwnerCap, clock: &Clock, incentive: &mut IncentiveV3, storage: &mut Storage, rule_id: address, total_supply: u64, duration_ms: u64, ctx: &mut TxContext) {
        incentive_v3::set_reward_rate_by_rule_id<T>(clock, incentive, storage, rule_id, total_supply, duration_ms, ctx)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L55-58)
```text
    public fun version_migrate(_: &StorageAdminCap, cfg: &mut Config) {
        assert!(cfg.version < version::this_version(), error::incorrect_version());
        cfg.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L102-113)
```text
    public(friend) fun create_asset(
        config: &mut Config,
        _asset_id: u8,
        _coin_type: String,
        _pool: address,
        _rate_to_supplier: u64,
        _rate_to_treasury: u64,
        _max: u64,
        _min: u64,
        ctx: &mut TxContext
    ) {
        version_verification(config);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L149-152)
```text
    public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
        assert!(storage.version < version::this_version(), error::not_available_version());
        storage.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L378-427)
```text
    public fun get_coin_type(storage: &Storage, asset: u8): String {
        table::borrow(&storage.reserves, asset).coin_type
    }

    public fun get_supply_cap_ceiling(storage: &mut Storage, asset: u8): u256 {
        table::borrow(&storage.reserves, asset).supply_cap_ceiling
    }

    public fun get_borrow_cap_ceiling_ratio(storage: &mut Storage, asset: u8): u256 {
        table::borrow(&storage.reserves, asset).borrow_cap_ceiling
    }

    public fun get_current_rate(storage: &mut Storage, asset: u8): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        (
            reserve.current_supply_rate,
            reserve.current_borrow_rate
        )
    }

    public fun get_index(storage: &mut Storage, asset: u8): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        (
            reserve.current_supply_index,
            reserve.current_borrow_index
        )
    }

    public fun get_total_supply(storage: &mut Storage, asset: u8): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        (
            reserve.supply_balance.total_supply,
            reserve.borrow_balance.total_supply
        )
    }

    public fun get_user_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        let supply_balance = 0;
        let borrow_balance = 0;

        if (table::contains(&reserve.supply_balance.user_state, user)) {
            supply_balance = *table::borrow(&reserve.supply_balance.user_state, user)
        };
        if (table::contains(&reserve.borrow_balance.user_state, user)) {
            borrow_balance = *table::borrow(&reserve.borrow_balance.user_state, user)
        };

        (supply_balance, borrow_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L506-513)
```text
    public(friend) fun increase_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        let supply_balance = &mut reserve.supply_balance;

        increase_balance(supply_balance, user, amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L483-508)
```text
    public fun get_effective_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256, u256, u256) {
        // get the total supply and borrow
        let (total_supply, total_borrow) = storage::get_total_supply(storage, asset);
        let (user_supply, user_borrow) = storage::get_user_balance(storage, asset, user);
        let (supply_index, borrow_index) = storage::get_index(storage, asset);

        // calculate the total supply and borrow
        let total_supply = ray_math::ray_mul(total_supply, supply_index);
        let total_borrow = ray_math::ray_mul(total_borrow, borrow_index);
        let user_supply = ray_math::ray_mul(user_supply, supply_index);
        let user_borrow = ray_math::ray_mul(user_borrow, borrow_index);

        // calculate the user effective supply
        let user_effective_supply: u256 = 0;
        if (user_supply > user_borrow) {
            user_effective_supply = user_supply - user_borrow;
        };

        // calculate the user effective borrow
        let user_effective_borrow: u256 = 0;
        if (user_borrow > user_supply) {
            user_effective_borrow = user_borrow - user_supply;
        };

        (user_effective_supply, user_effective_borrow, total_supply, total_borrow)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L516-534)
```text
    public fun update_reward_state_by_asset<T>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, user: address) {
        version_verification(incentive);
        let coin_type = type_name::into_string(type_name::get<T>());
        if (!vec_map::contains(&incentive.pools, &coin_type)) {
            return
        };
        let pool = vec_map::get_mut(&mut incentive.pools, &coin_type);
        let (user_effective_supply, user_effective_borrow, total_supply, total_borrow) = get_effective_balance(storage, pool.asset, user);

        // update rewards
        let rule_keys = vec_map::keys(&pool.rules);
        while (vector::length(&rule_keys) > 0) {
            let key = vector::pop_back(&mut rule_keys);
            let rule = vec_map::get_mut(&mut pool.rules, &key);

            // update the user reward
            update_reward_state_by_rule_and_balance(clock, rule, user, user_effective_supply, user_effective_borrow, total_supply, total_borrow);
        }
    }
```
