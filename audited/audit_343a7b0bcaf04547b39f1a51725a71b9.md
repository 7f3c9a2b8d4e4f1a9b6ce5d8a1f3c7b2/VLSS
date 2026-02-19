### Title
Incomplete Migration Allows Permanent Loss of User Funds Due to Unverified Export Completion

### Summary
The migration flow from volo_v1 to v2 can be finalized without exporting all staked assets, resulting in permanent loss of user funds. The `destroy_migration_cap` function accepts a caller-provided `target_exported_count` without verifying that all stakes from the v1 validator vaults have been exported, allowing the operator to prematurely complete migration and leave user funds irrecoverably locked in the deprecated v1 system.

### Finding Description

**Root Cause:**

The `destroy_migration_cap` function validates migration completion by comparing `migration_storage.exported_count` against a caller-provided `target_exported_count` parameter, without any verification that this target represents the actual total number of stakes in the v1 system. [1](#0-0) 

The function only checks:
1. That `exported_count` matches the caller-provided target
2. That `sui_balance` is zero (all exported SUI was imported)
3. That `pool_created` and `fees_taken` flags are true

**Why Existing Protections Fail:**

The v1 `ValidatorSet` stores stakes in vaults with `gap` and `length` fields tracking removal progress. Each vault is fully exported when `gap == length`. However, there is no check in `destroy_migration_cap` that verifies all vaults have reached this state. [2](#0-1) 

The `export_stakes` function iterates through stakes until `vault.gap < vault.length` becomes false, but the operator can stop calling this function before all vaults are exhausted: [3](#0-2) 

**No Recovery Path:**

Once `destroy_migration_cap` is called, the `MigrationCap` is consumed and permanently destroyed. The `init_objects` function can only be called once due to the `mark_cap_created` protection: [4](#0-3) [5](#0-4) 

All v1 staking functions are deprecated and abort, making remaining stakes permanently inaccessible: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Fund Loss:**
- User funds (StakedSui objects) remaining in v1 vaults become permanently locked
- No mechanism exists to recover un-exported stakes after migration cap destruction
- Loss amount is proportional to the number of un-exported stakes

**Who is Affected:**
- Users whose stakes were not exported before migration completion
- With thousands of stakes across multiple validators, a significant portion could be left behind

**Severity Justification:**
- **HIGH severity**: Permanent, unrecoverable loss of user principal
- No way to unstake from v1 (all functions deprecated)
- No way to continue migration (cap destroyed, cannot be recreated)
- Directly violates fund custody invariant

### Likelihood Explanation

**Attack/Error Scenario:**
This is an **operational error** rather than a malicious attack:

1. **Realistic Preconditions**: 
   - The operator has legitimate access to MigrationCap
   - With gas limits and thousands of stakes, `export_stakes` must be called multiple times
   - No on-chain verification of progress or completeness

2. **Execution Complexity**:
   - Operator calls `export_stakes` multiple times but loses track of progress
   - Checks only that `sui_balance == 0` (all exported funds are imported)
   - Provides partial count as `target_exported_count`
   - `destroy_migration_cap` accepts the partial count and succeeds

3. **Detection Difficulty**:
   - No event or check indicates incomplete export
   - Balance being zero seems like a complete migration
   - Off-chain tracking required but not enforced

4. **Probability**: **MEDIUM to HIGH**
   - Single-shot operation with no rollback
   - Complex multi-step process prone to human error
   - No programmatic safeguards against premature completion

### Recommendation

**Immediate Fix:**

Add verification in `destroy_migration_cap` that all validator vaults are fully exported:

```move
public fun destroy_migration_cap(
    migration_cap: MigrationCap,
    migration_storage: &MigrationStorage,
    native_pool: &NativePool,  // ADD THIS PARAMETER
) {
    // Verify all vaults are fully exported
    let validator_set = native_pool.get_validator_set();
    let validators = validator_set.get_validators();
    let mut i = 0;
    while (i < validators.length()) {
        let validator = validators[i];
        if (validator_set.vaults.contains(validator)) {
            let vault = validator_set.vaults.borrow(validator);
            assert!(vault.gap == vault.length, ERROR_INCOMPLETE_EXPORT);
        };
        i = i + 1;
    };
    
    assert!(migration_storage.sui_balance.value() == 0, 3);
    // ... rest of checks
}
```

**Additional Safeguards:**

1. Store total stake count in `MigrationStorage` during `init_objects` by iterating all vaults
2. Remove `target_exported_count` parameter - use the stored total instead
3. Add events showing export progress (vaults completed, stakes remaining)
4. Add view functions to check vault export status before finalizing

**Test Cases:**

1. Attempt to destroy cap with partial export → should fail
2. Complete full export → should succeed
3. Verify all vaults have `gap == length` after successful migration

### Proof of Concept

**Initial State:**
- V1 NativePool has 100 StakedSui objects across 3 validators
  - Validator A: 40 stakes (vault.length = 40, vault.gap = 0)
  - Validator B: 35 stakes (vault.length = 35, vault.gap = 0)
  - Validator C: 25 stakes (vault.length = 25, vault.gap = 0)

**Attack Sequence:**

1. Operator calls `init_objects()` → Creates MigrationCap, pauses v1 pool

2. Operator calls `create_stake_pool()` → Creates v2 pool (paused by default)

3. Operator calls `export_stakes(migration_storage, migration_cap, native_pool, system_state, 50)` 
   - Exports 40 stakes from Validator A (vault.gap = 40)
   - Exports 10 stakes from Validator B (vault.gap = 10)
   - Result: `exported_count = 50`, `sui_balance = X SUI`

4. Operator calls `take_unclaimed_fees()` → Withdraws fees, `sui_balance = X - fees`

5. Operator calls `import_stakes()` → Imports all remaining SUI to v2 pool
   - Result: `sui_balance = 0` (all exported SUI now in v2)

6. Operator calls `destroy_migration_cap(migration_cap, migration_storage, 50)`
   - Check passes: `exported_count (50) == target (50)` ✓
   - Check passes: `sui_balance == 0` ✓
   - Check passes: `pool_created == true` ✓
   - Check passes: `fees_taken == true` ✓
   - **MigrationCap destroyed successfully**

**Actual Result:**
- Migration marked complete
- 25 stakes from Validator B (vault.gap=10, vault.length=35) still in v1
- 25 stakes from Validator C (vault.gap=0, vault.length=25) still in v1
- **Total: 50 stakes (50% of user funds) permanently locked**

**Expected Result:**
- Migration should FAIL with assertion error
- Require all vaults fully exported before cap destruction
- Prevent permanent fund loss

### Notes

The vulnerability exploits the lack of ground truth verification in the migration finalization. While the `sui_balance == 0` check ensures accounting consistency for *exported* stakes, it provides no guarantee that *all* stakes were exported. The operator's ability to provide an arbitrary `target_exported_count` combined with the one-time-only nature of migration creates an irreversible fund loss scenario if executed incorrectly.

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L69-70)
```text
        // ensure this function is only called once
        native_pool.mark_cap_created();
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

**File:** liquid_staking/sources/volo_v1/validator_set.move (L44-49)
```text
    public struct Vault has store {
        stakes: ObjectTable<u64, StakedSui>,
        gap: u64,
        length: u64,
        total_staked: u64,
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L354-356)
```text
        while (*iterations > 0 && vault.gap < vault.length) {
            let staked_sui_to_withdraw = object_table::remove(&mut vault.stakes, vault.gap);
            vault.gap = vault.gap + 1; // increase table gap
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L385-387)
```text
    public entry fun stake(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, coin: Coin<SUI>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L400-402)
```text
    public entry fun unstake(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, cert: Coin<CERT>, ctx: &mut TxContext) {
        abort E_DEPRECATED
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
