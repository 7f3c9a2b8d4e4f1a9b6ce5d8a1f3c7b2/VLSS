# Audit Report

## Title
Incomplete Migration Can Be Finalized Due to Lack of Total Export Count Validation

## Summary
The `destroy_migration_cap()` function validates that `target_exported_count` matches `exported_count`, but provides no mechanism to verify that this count represents ALL StakedSui objects from the v1 pool. This allows migration to be finalized with funds remaining locked in the v1 validator vaults, resulting in permanent loss of user funds.

## Finding Description

The migration flow exports StakedSui objects from v1's ValidatorSet in batches. The `export_stakes()` function calls `export_stakes_from_v1()` which iterates through validators and withdraws stakes. [1](#0-0) [2](#0-1) 

Each call to export increments `migration_storage.exported_count` by the number of StakedSui objects actually withdrawn. The export process accepts a `max_iterations` parameter, allowing partial exports across multiple transactions. [3](#0-2) 

The critical flaw exists in `destroy_migration_cap()` - it only validates that the caller-provided `target_exported_count` matches the on-chain `exported_count`, but has NO validation that this represents the total number of StakedSui objects that should have been migrated. [4](#0-3) 

Each validator's Vault tracks StakedSui objects in an ObjectTable with `gap` and `length` fields, where remaining objects = `length - gap`. [5](#0-4)  However, there are no public functions to query these values or validate that all vaults are fully exported (gap == length).

**Exploitation Scenario:**
1. V1 pool has 100 StakedSui objects worth 10,000 SUI across multiple validators
2. Operator calls `export_stakes()` with limited iterations, exporting only 90 objects (~9,000 SUI)
3. `migration_storage.exported_count = 90`, `sui_balance = ~9,000 SUI`
4. Operator calls `take_unclaimed_fees()` to extract fees
5. Operator calls `import_stakes()` to import all SUI to v2 pool, `sui_balance` becomes 0
6. Operator calls `destroy_migration_cap(cap, storage, 90)` with `target_exported_count = 90`
7. All validation passes: `exported_count (90) == target (90)`, `sui_balance == 0`, flags set
8. MigrationCap is destroyed, but 10 StakedSui objects (~1,000 SUI) remain in v1 vaults

After cap destruction, `export_stakes()` cannot be called again (requires MigrationCap reference). All normal v1 pool operations are deprecated and abort with `E_DEPRECATED`. [6](#0-5)  The v1 pool is paused during migration. [7](#0-6) 

This permanently locks remaining funds with no recovery path.

## Impact Explanation

**Direct Fund Loss:** User funds corresponding to unexported StakedSui objects are permanently locked in the v1 pool. With no recovery mechanism and the MigrationCap destroyed, these funds become inaccessible.

**Affected Users:** All users whose StakedSui objects were not exported before migration finalization lose their staked funds and accumulated rewards.

**Quantified Impact:** If even 10% of stakes are left unexported in a pool with $1M TVL, that's $100,000 in permanent user fund loss. The actual percentage depends on operator diligence with no protocol-level safeguards.

**No Recovery Path:**
- The v1 pool is paused during migration
- `export_stakes()` requires the now-destroyed MigrationCap
- No alternative function exists to withdraw remaining stakes
- All v1 pool operations are deprecated
- Validator vaults remain populated but inaccessible

## Likelihood Explanation

**Operator Error:** The migration operator must manually track the total number of StakedSui objects across all validators. With no on-chain query function to verify completeness, miscounting is highly likely for pools with many validators and stakes.

**Feasible Conditions:**
- Migration requires OwnerCap (trusted role), but the vulnerability is in missing validation, not role compromise
- Export process with `max_iterations` limits naturally creates scenarios where operators must track partial exports across multiple transactions
- No warning or check indicates when all stakes have been exported

**Execution Complexity:** LOW - Operator simply needs to miscalculate total count or stop exporting early, then proceed with normal migration steps.

**Detection Difficulty:** HIGH - The protocol provides no mechanism to detect incomplete export. The migration appears successful as all checks pass.

## Recommendation

Add validation in `destroy_migration_cap()` to ensure all vaults are fully exported before allowing cap destruction:

```move
public fun destroy_migration_cap(
    migration_cap: MigrationCap,
    migration_storage: &MigrationStorage,
    native_pool: &NativePool,  // Add parameter to access validator set
    target_exported_count: u64,
) {
    assert!(migration_storage.exported_count == target_exported_count, 1);
    assert!(migration_storage.sui_balance.value() == 0, 3);
    
    // NEW: Validate all vaults are fully exported
    let validator_set = native_pool.get_validator_set();
    let validators = validator_set.get_validators();
    let mut i = 0;
    while (i < validators.length()) {
        let validator = validators[i];
        if (validator_set.vaults.contains(validator)) {
            let vault = validator_set.vaults.borrow(validator);
            assert!(vault.gap == vault.length, 4); // Ensure vault fully exported
        };
        i = i + 1;
    };

    let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
    assert!(pool_created, 0);
    assert!(fees_taken, 2);
    id.delete();
}
```

Alternatively, add a public view function to query total remaining stakes across all vaults, allowing operators to verify completeness before calling `destroy_migration_cap()`.

## Proof of Concept

This vulnerability requires integration testing with the actual Sui system state and staking mechanisms. A proof of concept would demonstrate:

1. Initialize v1 pool with multiple StakedSui objects across validators
2. Call `export_stakes()` with `max_iterations` set to export only partial stakes
3. Verify `exported_count` < total stakes
4. Complete migration steps (take fees, import stakes)
5. Call `destroy_migration_cap()` with partial count - verify it succeeds
6. Verify remaining StakedSui objects are locked with no recovery mechanism
7. Attempt to call `export_stakes()` again - verify it fails due to destroyed MigrationCap

The test would confirm that incomplete migration can be finalized, permanently locking user funds.

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L67-91)
```text
    public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {

        // ensure this function is only called once
        native_pool.mark_cap_created();

        // sanity check to avoid double migration
        // collected_rewards will be set to 0 in the first migration
        assert!(native_pool.mut_collected_rewards() != 0, 0);
        native_pool.set_pause(owner_cap, true);

        let migration_storage = MigrationStorage {
            id: object::new(ctx),
            sui_balance: balance::zero<SUI>(),
            exported_count: 0,
        };

        let migration_cap = MigrationCap {  
            id: object::new(ctx),
            pool_created: false,
            fees_taken: false,
        };

        transfer::public_share_object(migration_storage);
        transfer::public_transfer(migration_cap, ctx.sender());
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

**File:** liquid_staking/sources/volo_v1/validator_set.move (L44-49)
```text
    public struct Vault has store {
        stakes: ObjectTable<u64, StakedSui>,
        gap: u64,
        length: u64,
        total_staked: u64,
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

**File:** liquid_staking/sources/volo_v1/native_pool.move (L385-420)
```text
    public entry fun stake(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, coin: Coin<SUI>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    // exchange SUI to CERT, add SUI to pending and try to stake pool
    public fun stake_non_entry(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, coin: Coin<SUI>, ctx: &mut TxContext): Coin<CERT> {
        abort E_DEPRECATED
    }

    // stake pending
    fun stake_pool(self: &mut NativePool, wrapper: &mut SuiSystemState, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    /// merge ticket with it burning to make instant unstake
    public entry fun unstake(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, cert: Coin<CERT>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    public entry fun mint_ticket(self: &mut NativePool, metadata: &mut Metadata<CERT>, cert: Coin<CERT>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    /// burns CERT and put output amount of SUI to it
    /// In case if issued ticket supply greater than active stake ticket should be locked until next epoch
    public fun mint_ticket_non_entry(self: &mut NativePool, metadata: &mut Metadata<CERT>, cert: Coin<CERT>, ctx: &mut TxContext): UnstakeTicket {
        abort E_DEPRECATED
    }

    // burn ticket to release unstake
    public entry fun burn_ticket(self: &mut NativePool, wrapper: &mut SuiSystemState, ticket: UnstakeTicket, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    public fun burn_ticket_non_entry(self: &mut NativePool, wrapper: &mut SuiSystemState, ticket: UnstakeTicket, ctx: &mut TxContext): Coin<SUI> {
        abort E_DEPRECATED
```
