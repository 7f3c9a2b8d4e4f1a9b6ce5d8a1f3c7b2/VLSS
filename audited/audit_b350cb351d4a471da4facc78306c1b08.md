### Title
Migration Completion Without Stake Transfer - Complete Loss of User Funds

### Summary
The `destroy_migration_cap()` function can be called successfully without ever exporting or importing user stakes from v1 to v2, allowing migration to be marked complete while all user funds remain stuck in the v1 ValidatorSet. The attacker bypasses proper migration by manually funding fees and passing `target_exported_count=0` to match the never-incremented `exported_count`.

### Finding Description

The migration flow in `migrate.move` is documented to follow this sequence:
1. create_stake_pool
2. export_stakes (extract stakes from v1)
3. take_unclaimed_fees
4. import_stakes (move stakes to v2)
5. destroy_migration_cap [1](#0-0) 

However, `destroy_migration_cap()` only validates four conditions without verifying that stakes were actually migrated: [2](#0-1) 

**Root Cause:** The function checks `exported_count == target_exported_count` but accepts `target_exported_count=0` as valid input. There is no minimum threshold enforcement and no verification that `import_stakes()` was ever called.

**Attack Path:**

1. **create_stake_pool()** - Sets `pool_created = true` [3](#0-2) 

2. **deposit_sui()** - Manually add SUI to cover `collected_rewards` amount: [4](#0-3) 

3. **take_unclaimed_fees()** - Drains the deposited SUI as fees, sets `fees_taken = true`, leaves `sui_balance = 0`: [5](#0-4) 

4. **destroy_migration_cap(target_exported_count=0)** - Passes all checks:
   - `exported_count` remains 0 (never incremented by `export_stakes`)
   - `sui_balance` is 0 (fees drained in step 3)
   - `pool_created` is true (step 1)
   - `fees_taken` is true (step 3)

**Why Protections Fail:**

The `export_stakes()` function is responsible for extracting stakes from v1 and incrementing `exported_count`: [6](#0-5) 

The `export_stakes_from_v1()` function in ValidatorSet withdraws staked SUI from validators: [7](#0-6) 

By skipping `export_stakes()`, all user stakes remain in the v1 ValidatorSet vaults, never withdrawn or transferred to v2. The migration is irreversibly marked complete through `mark_cap_created()`: [8](#0-7) 

### Impact Explanation

**Complete loss of all user staked funds:**
- All StakedSui objects remain in v1 ValidatorSet vaults (never exported)
- The v2 StakePool is created but contains no migrated stakes (import_stakes never called or called with amount=0)
- Users cannot access their staked positions as they exist only in the now-deprecated v1 system
- The v1 NativePool is paused during migration initialization and never properly deprecated

**Irreversible state:**
- The `mark_cap_created()` dynamic field prevents re-initialization
- The MigrationCap is destroyed, preventing migration retry
- The migration is marked complete in the protocol's state

**Affected parties:**
- All v1 liquid staking users lose access to their staked SUI
- Total loss equals the entire v1 total staked amount across all validators

**Severity:** CRITICAL - Complete, permanent loss of all user funds in the v1 staking system.

### Likelihood Explanation

**Attacker capabilities required:**
- Possession of MigrationCap (transferred to migration operator in `init_objects`)
- Ability to fund `collected_rewards` amount temporarily (immediately recoverable as fees)

**Attack complexity:** LOW
- 4 simple transaction steps with no complex preconditions
- No timing constraints or race conditions
- No sophisticated exploit techniques required

**Feasibility conditions:**
- MigrationCap holder can be malicious, compromised, or make an operational error
- The code design fails to enforce migration integrity invariants
- No on-chain monitoring or validation prevents this bypass

**Economic rationality:**
- Attack cost: Only fronting `collected_rewards` amount (typically 10% of rewards, small relative to total stake)
- Attacker recovers the fronted amount immediately in `take_unclaimed_fees()`
- Net cost: Near-zero (only gas fees)

**Detection/prevention:** The protocol has no mechanism to detect or prevent this bypass once the MigrationCap is issued.

### Recommendation

**1. Enforce minimum stake migration threshold in destroy_migration_cap():**

```move
public fun destroy_migration_cap(
    migration_cap: MigrationCap,
    migration_storage: &MigrationStorage,
    target_exported_count: u64,
    minimum_stake_migrated: u64, // NEW: require minimum stakes migrated
) {
    assert!(migration_storage.exported_count == target_exported_count, 1);
    assert!(migration_storage.exported_count >= minimum_stake_migrated, 4); // NEW
    assert!(migration_storage.sui_balance.value() == 0, 3);
    // ... rest of function
}
```

**2. Track total imported amount and validate it matches exported amount:**

Add to MigrationStorage:
```move
public struct MigrationStorage has key, store {
    id: UID,
    sui_balance: Balance<SUI>,
    exported_count: u64,
    total_exported_amount: u64, // NEW: track total SUI exported
    total_imported_amount: u64, // NEW: track total SUI imported
}
```

Update `import_stakes()` to increment `total_imported_amount` and add validation in `destroy_migration_cap()`:
```move
assert!(migration_storage.total_imported_amount >= migration_storage.total_exported_amount, 5);
```

**3. Add import_stakes completion flag:**

```move
public struct MigrationCap has key, store {
    id: UID,
    pool_created: bool,
    fees_taken: bool,
    stakes_imported: bool, // NEW: require import_stakes called
}
```

Validate in `destroy_migration_cap()`:
```move
assert!(stakes_imported, 6);
```

**4. Test cases to add:**
- Attempt to destroy cap with exported_count=0 (should fail)
- Attempt to destroy cap without calling import_stakes (should fail)
- Attempt to destroy cap with imported_amount < exported_amount (should fail)
- Verify successful migration only when all stakes properly transferred

### Proof of Concept

**Initial State:**
- V1 NativePool contains 1,000,000 SUI in user stakes across ValidatorSet
- collected_rewards = 10,000 SUI (protocol fees)
- init_objects() called, MigrationCap issued to migration operator

**Attack Sequence:**

**Transaction 1:** Create v2 stake pool
```
create_stake_pool(migration_cap)
// Result: pool_created = true
```

**Transaction 2:** Manually fund migration storage
```
deposit_sui(migration_storage, migration_cap, sui_coin, 10_000_SUI)
// Result: migration_storage.sui_balance = 10,000 SUI
```

**Transaction 3:** Extract fees
```
take_unclaimed_fees(migration_storage, migration_cap, attacker_address, native_pool)
// Result: fees_taken = true, sui_balance = 0, attacker receives 10,000 SUI back
```

**Transaction 4:** Complete migration
```
destroy_migration_cap(migration_cap, migration_storage, target_exported_count=0)
// Checks pass:
// - exported_count (0) == target_exported_count (0) ✓
// - sui_balance (0) == 0 ✓
// - pool_created == true ✓
// - fees_taken == true ✓
// Result: SUCCESS - MigrationCap destroyed
```

**Expected Result:** Migration should FAIL because no stakes were exported or imported.

**Actual Result:** Migration completes successfully with all user stakes (1,000,000 SUI) remaining stuck in v1 ValidatorSet, inaccessible to users.

**Success Condition:** The attacker successfully marks migration complete while retaining all attack costs and leaving user funds permanently locked in the deprecated v1 system.

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L4-10)
```text
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
/// 6. unpause the pool (after migration)
```

**File:** liquid_staking/sources/migration/migrate.move (L94-101)
```text
    public fun create_stake_pool(
        migration_cap: &mut MigrationCap,
        ctx: &mut TxContext
    ) {
        assert!(!migration_cap.pool_created, 0);
        migration_cap.pool_created = true;
        stake_pool::create_stake_pool(ctx);
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L104-134)
```text
    public fun export_stakes(
        migration_storage: &mut MigrationStorage,
        _: &MigrationCap,
        native_pool: &mut NativePool,
        system_state: &mut SuiSystemState,
        max_iterations: u64,
        ctx: &mut TxContext
    ) {
        let validator_set = native_pool.mut_validator_set();
        let (exported_sui, exported_count, exported_sui_amount)
        = export_stakes_from_v1(validator_set, system_state, max_iterations, ctx);

        migration_storage.sui_balance.join(exported_sui);
        migration_storage.exported_count = migration_storage.exported_count + exported_count;

        // take pending
        let pending = native_pool.mut_pending();
        let pending_sui = pending.balance_mut().withdraw_all();
        let pending_sui_amount = pending_sui.value();
        migration_storage.sui_balance.join(pending_sui);

        event::emit(
            ExportedEvent {
                total_sui_balance: migration_storage.sui_balance.value(),
                exported_count,
                sui_amount: exported_sui_amount,
                pending_sui_amount: pending_sui_amount,
                epoch: ctx.epoch(),
            }
        );
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L137-155)
```text
    public fun take_unclaimed_fees(
        migration_storage: &mut MigrationStorage,
        migration_cap: &mut MigrationCap,
        recipient: address,
        native_pool: &mut NativePool,
        ctx: &mut TxContext
    ) {
        let unclaimed_fees = native_pool.mut_collected_rewards();
        let fee_amount = *unclaimed_fees;
        let fees = migration_storage.sui_balance.split(fee_amount);
        transfer::public_transfer(fees.into_coin(ctx), recipient);
        *unclaimed_fees = 0;
        migration_cap.fees_taken = true;
        event::emit(
            UnclaimedFeesEvent {
                amount: fee_amount,
            }
        );
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L188-200)
```text
    public fun destroy_migration_cap(
        migration_cap: MigrationCap,
        migration_storage: &MigrationStorage,
        target_exported_count: u64,
    ) {
        assert!(migration_storage.exported_count == target_exported_count, 1);
        assert!(migration_storage.sui_balance.value() == 0, 3);

        let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
        assert!(pool_created, 0);
        assert!(fees_taken, 2);
        id.delete();
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L203-218)
```text
    public fun deposit_sui(
        migration_storage: &mut MigrationStorage,
        _: &mut MigrationCap,
        sui_balance: &mut Coin<SUI>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        migration_storage.sui_balance.join(
            sui_balance.split(amount, ctx).into_balance()
        );
        event::emit(
            SuiChangedEvent {
                amount: migration_storage.sui_balance.value(),
            }
        );
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L306-342)
```text
    public(package) fun export_stakes_from_v1(
        validator_set: &mut ValidatorSet,
        system_state: &mut SuiSystemState,
        max_iterations: u64,
        ctx: &mut TxContext
    ):(Balance<SUI>, u64, u64) {
        let mut i = 0;
        let mut iterations = max_iterations;
        let mut exported_count = 0;
        let mut exported_sui_amount = 0;
        let mut total_exported_sui = balance::zero<SUI>();

        let validators = validator_set.get_validators();

        while (i < validators.length() && iterations > 0) {
            let validator = *validators.borrow(i);

            if (!validator_set.vaults.contains(validator)) {
                i = i + 1;
                continue
            };

            let exported_sui = export_stakes(
                validator_set.vaults.borrow_mut(validators[i]),
                &mut iterations,
                &mut exported_count,
                &mut exported_sui_amount,
                system_state,
                ctx
            );

            total_exported_sui.join(exported_sui);
            i = i + 1;
        };

        (total_exported_sui, exported_count, exported_sui_amount)
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L599-604)
```text
    public(package) fun mark_cap_created(self: &mut NativePool) {
        if (dynamic_field::exists_<vector<u8>>(&self.id, CAP_CREATED)) {
            abort 0;
        };
        dynamic_field::add(&mut self.id, CAP_CREATED, true);
    }
```
