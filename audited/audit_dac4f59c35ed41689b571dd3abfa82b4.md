### Title
Accounting Corruption in Migration: export_stakes_from_v1() Fails to Update vault.total_staked

### Summary
The `export_stakes_from_v1()` function removes StakedSui objects from validator vaults during migration but fails to decrement `vault.total_staked`, breaking the critical accounting invariant. This causes permanent accounting corruption where `vault.total_staked` becomes inflated by the total amount of exported stakes, affecting any operations that rely on accurate stake accounting during or after the migration process.

### Finding Description

**Root Cause:**

The `export_stakes()` helper function removes StakedSui from vaults but does not update the `vault.total_staked` field: [1](#0-0) 

Specifically, line 355 removes the StakedSui object and line 356 increments the gap, but there is **no corresponding decrement of vault.total_staked**.

**Comparison with Normal Operations:**

The `remove_stakes()` function correctly maintains accounting by tracking principal values and decrementing `vault.total_staked`: [2](#0-1) 

Line 234 captures the principal value, line 252 accumulates it, and line 257 decrements `vault.total_staked` by the total withdrawn principal value.

The `add_stake()` function also maintains the invariant by incrementing `vault.total_staked`: [3](#0-2) 

**Vault Structure:**

The Vault maintains `total_staked` as a critical accounting field: [4](#0-3) 

The invariant should be: `vault.total_staked = sum of all staked_sui_amount() in vault.stakes`

**Why Protections Fail:**

1. The migration process pauses the native_pool but validator_set functions have no pause guards: [5](#0-4) [6](#0-5) 

Both are `public(package)` with no state checks.

2. Migration completion checks do not verify accounting consistency: [7](#0-6) 

Line 193 checks exported count but there is no verification that `vault.total_staked` is correct.

3. The `export_stakes_from_v1()` entry point calls `export_stakes()` in a loop across validators: [8](#0-7) 

### Impact Explanation

**Concrete Harm:**

1. **Accounting Corruption**: After each call to `export_stakes_from_v1()`, `vault.total_staked` is inflated by exactly the sum of principal amounts of all exported stakes. For example, if 1000 SUI worth of stakes are exported, `vault.total_staked` remains 1000 SUI higher than actual.

2. **Multi-Batch Migration Risk**: The migration supports batched exports via `max_iterations` parameter (line 309). Between batches, the accounting is incorrect, affecting any logic that reads `vault.total_staked`: [9](#0-8) 

3. **Permanent State Corruption**: The corrupted `vault.total_staked` values persist after migration completes. If the volo_v1 system is accessed for any reason (audit, cleanup, recovery), the incorrect values could cause operational issues.

4. **Invariant Violation**: The fundamental invariant that `vault.total_staked` equals the sum of stake principals is permanently broken, violating the protocol's accounting integrity.

**Who is Affected:**

- The volo_v1 system accounting state
- Any monitoring or verification logic that checks stake consistency
- Migration process integrity verification

**Severity Justification:**

HIGH severity because:
- Deterministically breaks accounting invariant
- Affects critical migration process
- Permanent corruption with no built-in recovery mechanism
- Violates the CRITICAL INVARIANT #3: "Pricing & Funds - total value correctness"

### Likelihood Explanation

**Deterministic Trigger:**

This is not a race condition vulnerability—it is a deterministic accounting bug that will occur **every single time** `export_stakes_from_v1()` is called during migration.

**Execution Path:**

1. Migration initiated via `migration::export_stakes()`: [10](#0-9) 

2. Line 114 calls `export_stakes_from_v1()` which processes validators and calls `export_stakes()`
3. Each stake exported leaves `vault.total_staked` unchanged
4. Accounting corruption accumulates with each exported stake

**Feasibility:**

- Requires authorized migration process (MigrationCap holder)
- No additional preconditions needed
- Follows normal migration flow as designed
- 100% probability when migration is executed

**Detection:**

The corruption is difficult to detect because:
- No checks exist to verify `vault.total_staked` consistency
- Migration completion checks only verify export counts, not accounting accuracy
- The vaults may contain remaining stakes after partial export, masking the discrepancy

### Recommendation

**Immediate Fix:**

Add `vault.total_staked` accounting to the `export_stakes()` function, mirroring the logic in `remove_stakes()`:

```move
fun export_stakes(
    vault: &mut Vault,
    iterations: &mut u64,
    exported_count: &mut u64,
    exported_sui_amount: &mut u64,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext
):(Balance<SUI>) {
    let mut exported_sui = balance::zero<SUI>();
    let mut exported_principal = 0;  // ADD THIS
    
    while (*iterations > 0 && vault.gap < vault.length) {
        let staked_sui_to_withdraw = object_table::remove(&mut vault.stakes, vault.gap);
        
        // ADD THIS: capture principal before withdrawing
        let principal = staking_pool::staked_sui_amount(&staked_sui_to_withdraw);
        exported_principal = exported_principal + principal;
        
        vault.gap = vault.gap + 1;
        let withdrawn = sui_system::request_withdraw_stake_non_entry(system_state, staked_sui_to_withdraw, ctx);

        *exported_sui_amount = *exported_sui_amount + withdrawn.value();
        *exported_count = *exported_count + 1;
        *iterations = *iterations - 1;

        exported_sui.join(withdrawn);
    };
    
    // ADD THIS: update total_staked
    vault.total_staked = vault.total_staked - exported_principal;
    
    exported_sui
}
```

**Additional Safeguards:**

1. Add invariant check in `export_stakes_from_v1()` to verify accounting:
   - Before: capture sum of all `vault.total_staked` values
   - After: verify sum decreased by expected principal amounts

2. Add verification check in `destroy_migration_cap()`:
   - Assert that all vaults have `total_staked == 0` OR `total_staked` matches remaining stakes

3. Add test cases:
   - Test single-batch complete export
   - Test multi-batch partial exports
   - Verify `vault.total_staked` consistency after each batch

### Proof of Concept

**Initial State:**
- Vault has 3 StakedSui objects with principals: 1000 SUI, 2000 SUI, 3000 SUI
- `vault.total_staked = 6000` SUI
- `vault.length = 3`, `vault.gap = 0`

**Transaction 1: First Export Batch**
```
export_stakes_from_v1(validator_set, system_state, max_iterations=2, ctx)
```

**Expected Result:**
- 2 stakes exported (1000 + 2000 = 3000 SUI principals)
- `vault.total_staked` should be 3000 SUI
- `vault.gap = 2`, `vault.length = 3`

**Actual Result:**
- 2 stakes exported
- **`vault.total_staked` remains 6000 SUI** ❌ (INCORRECT by 3000 SUI)
- `vault.gap = 2`, `vault.length = 3`

**Transaction 2: Second Export Batch**
```
export_stakes_from_v1(validator_set, system_state, max_iterations=1, ctx)
```

**Expected Final Result:**
- All 3 stakes exported (total 6000 SUI principals)
- `vault.total_staked = 0` SUI
- `vault.gap = vault.length = 3`

**Actual Final Result:**
- All 3 stakes exported
- **`vault.total_staked` still 6000 SUI** ❌ (INCORRECT - should be 0)
- `vault.gap = vault.length = 3`
- Vault appears to have 6000 SUI staked but actually has 0 stakes

**Success Condition:**
The bug is confirmed when `vault.total_staked` does not decrease despite stakes being removed, violating the accounting invariant.

### Citations

**File:** liquid_staking/sources/volo_v1/validator_set.move (L44-49)
```text
    public struct Vault has store {
        stakes: ObjectTable<u64, StakedSui>,
        gap: u64,
        length: u64,
        total_staked: u64,
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L104-111)
```text
    public fun get_total_stake(self: &ValidatorSet, validator: address): u64 {
        if (!table::contains(&self.vaults, validator)) {
            return 0
        } else {
            let vault = table::borrow<address, Vault>(&self.vaults, validator);
            vault.total_staked
        }
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L186-206)
```text
    public(package) fun add_stake(self: &mut ValidatorSet, validator: address, staked_sui: StakedSui, ctx: &mut TxContext) {
        let value = staking_pool::staked_sui_amount(&staked_sui);

        if (table::contains(&mut self.vaults, validator)) {
            let vault = table::borrow_mut(&mut self.vaults, validator);
            object_table::add(&mut vault.stakes, vault.length, staked_sui);

            // save new length and total
            vault.total_staked = vault.total_staked + value;
            vault.length = vault.length + 1;
        } else {
            let mut vault = Vault {
                total_staked: value,
                gap: 0,
                length: 1,
                stakes: object_table::new(ctx),
            };
            object_table::add(&mut vault.stakes, 0, staked_sui);
            table::add(&mut self.vaults, validator, vault);
        };
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L215-216)
```text
    public(package) fun remove_stakes(self: &mut ValidatorSet, wrapper: &mut SuiSystemState, validator: address, requested_amount: u64, ctx: &mut TxContext): (Balance<SUI>, u64, u64) {
    
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L234-257)
```text
            let mut principal_value = ::sui_system::staking_pool::staked_sui_amount(staked_sui_mut_ref);

            let mut staked_sui_to_withdraw;
            let mut rest_requested_amount = requested_amount - balance::value(&total_withdrawn);
            if (rest_requested_amount < MIST_PER_SUI) {
                rest_requested_amount = MIST_PER_SUI
            };
            if (principal_value > rest_requested_amount && principal_value - rest_requested_amount >= MIST_PER_SUI) {
                // it's possible to split StakedSui
                staked_sui_to_withdraw = staking_pool::split(staked_sui_mut_ref, rest_requested_amount, ctx);
                principal_value = rest_requested_amount;
            } else {
                staked_sui_to_withdraw = object_table::remove(&mut vault_mut_ref.stakes, vault_mut_ref.gap);
                vault_mut_ref.gap = vault_mut_ref.gap + 1; // increase table gap
            };

            let withdrawn = sui_system::request_withdraw_stake_non_entry(wrapper, staked_sui_to_withdraw, ctx);

            total_withdrawn_principal_value = total_withdrawn_principal_value + principal_value;
            balance::join(&mut total_withdrawn, withdrawn);
        };

        let withdrawn_reward = balance::value(&total_withdrawn) - total_withdrawn_principal_value;
        vault_mut_ref.total_staked = vault_mut_ref.total_staked - total_withdrawn_principal_value;
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

**File:** liquid_staking/sources/volo_v1/validator_set.move (L344-366)
```text
    fun export_stakes(
        vault: &mut Vault,
        iterations: &mut u64,
        exported_count: &mut u64,
        exported_sui_amount: &mut u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ):(Balance<SUI>) {
        let mut exported_sui = balance::zero<SUI>();
        
        while (*iterations > 0 && vault.gap < vault.length) {
            let staked_sui_to_withdraw = object_table::remove(&mut vault.stakes, vault.gap);
            vault.gap = vault.gap + 1; // increase table gap
            let withdrawn = sui_system::request_withdraw_stake_non_entry(system_state, staked_sui_to_withdraw, ctx);

            *exported_sui_amount = *exported_sui_amount + withdrawn.value();
            *exported_count = *exported_count + 1;
            *iterations = *iterations - 1;

            exported_sui.join(withdrawn);
        };
        exported_sui
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
