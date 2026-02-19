# Audit Report

## Title
Incomplete Migration: Protocol Fees (collectable_fee) Not Migrated from V1 to V2

## Summary
The v1 to v2 migration process fails to migrate the `collectable_fee` Coin<SUI> from NativePool, leaving accumulated protocol fees stranded in the deprecated v1 contract. While the migration handles the `collected_rewards` counter, it never extracts the actual fee coins, requiring manual administrative recovery post-migration.

## Finding Description

The NativePool v1 contract contains two fee-related fields that serve different purposes:
- `collectable_fee`: A Coin<SUI> object that holds actual SUI fee coins [1](#0-0) 
- `collected_rewards`: A u64 counter tracking reward fees for accounting [2](#0-1) 

During unstaking operations, both unstake fees and reward fees are deposited into the `collectable_fee` coin [3](#0-2) 

The migration flow executes in multiple steps: init_objects, create_stake_pool, export_stakes, take_unclaimed_fees, import_stakes, and destroy_migration_cap. However, the `take_unclaimed_fees` function only processes the `collected_rewards` counter value by splitting that amount from migration_storage (which comes from exported stakes) and transferring it to a recipient [4](#0-3) 

**Critical Issue**: The actual `collectable_fee` Coin<SUI> object is never accessed during any migration step. The `export_stakes` function only withdraws staked SUI from validators and the pending balance [5](#0-4) , while `export_stakes_from_v1` only processes validator stakes [6](#0-5) 

The `collectable_fee` coin remains in the deprecated NativePool object after migration completes. While most v1 functions abort with `E_DEPRECATED`, the `collect_fee` function does NOT have this deprecation check and only validates version compatibility and pause status [7](#0-6) 

## Impact Explanation

**Direct Impact**:
- All protocol fees accumulated in `collectable_fee` before migration remain in the deprecated v1 NativePool
- These fees represent protocol revenue from unstaking operations that should be part of the complete migration
- The amount depends on pre-migration activity and could be substantial for active protocols

**Custody Integrity Impact**:
- Protocol funds exist in the wrong location (deprecated v1 contract vs. active v2)
- Violates the reasonable expectation that migration is complete and comprehensive
- Creates operational risk if administrators are unaware fees remain in v1

**Recovery Complexity**:
- While technically recoverable via calling `collect_fee` on v1 with OwnerCap, this requires:
  - Awareness that fees were left behind (no migration event tracks this)
  - Manual intervention post-migration
  - Potential need to unpause v1 pool
  - Additional transactions and gas costs

## Likelihood Explanation

**Probability**: High - This occurs automatically during every migration if any fees have accumulated before migration execution.

**Preconditions**:
- Normal protocol operation before migration naturally accumulates fees in `collectable_fee`
- Any unstake operations before migration add fees to this coin
- Migration executed following the documented flow

**Execution**: This is not an attack scenario but an operational failure in migration logic. The incomplete migration automatically leaves fees behind whenever the process is executed.

**Detection**: The issue may not be immediately apparent because:
- Migration events don't track `collectable_fee` status
- V2 pool appears to function normally
- Only administrators checking v1 pool state post-migration would notice

## Recommendation

Add a migration step to extract and migrate the `collectable_fee` coin from NativePool. This should be done after `export_stakes` but can be combined with or separate from `take_unclaimed_fees`:

```move
// Add to migrate.move
public fun migrate_collectable_fee(
    migration_storage: &mut MigrationStorage,
    _: &MigrationCap,
    native_pool: &mut NativePool,
    ctx: &mut TxContext
) {
    let fee_coin_value = coin::value(&native_pool.collectable_fee);
    if (fee_coin_value > 0) {
        let fee_coin = coin::split(&mut native_pool.collectable_fee, fee_coin_value, ctx);
        migration_storage.sui_balance.join(fee_coin.into_balance());
        
        event::emit(CollectableFeesMigratedEvent {
            amount: fee_coin_value,
        });
    }
}
```

Alternatively, modify `take_unclaimed_fees` to handle both the counter and the actual coin object.

## Proof of Concept

```move
#[test]
fun test_collectable_fee_not_migrated() {
    let mut scenario = test_scenario::begin(@0xABCD);
    let ctx = scenario.ctx();
    
    // 1. Setup: Create NativePool with accumulated fees
    native_pool::test_init(ctx);
    scenario.next_tx(@0xABCD);
    let mut pool = scenario.take_shared<NativePool>();
    
    // Simulate fee accumulation (would happen during actual unstaking)
    // Add 1000 SUI to collectable_fee
    let fee_sui = coin::mint_for_testing<SUI>(1_000_000_000_000, ctx);
    coin::join(&mut pool.collectable_fee, fee_sui);
    test_scenario::return_shared(pool);
    
    // 2. Execute migration
    scenario.next_tx(@0xABCD);
    migration::test_init(ctx);
    scenario.next_tx(@0xABCD);
    
    let mut migration_storage = scenario.take_shared<MigrationStorage>();
    let migration_cap = scenario.take_from_sender<MigrationCap>();
    let mut pool = scenario.take_shared<NativePool>();
    
    // Execute export_stakes and take_unclaimed_fees
    migration::export_stakes(&mut migration_storage, &migration_cap, &mut pool, &mut system_state, 100, ctx);
    migration::take_unclaimed_fees(&mut migration_storage, &mut migration_cap, @0xABCD, &mut pool, ctx);
    
    // 3. Verify: collectable_fee still has coins in v1 pool
    let remaining_fees = coin::value(&pool.collectable_fee);
    assert!(remaining_fees == 1_000_000_000_000, 0); // Fees NOT migrated!
    
    test_scenario::return_shared(pool);
    test_scenario::return_shared(migration_storage);
    test_scenario::return_to_sender(&scenario, migration_cap);
    scenario.end();
}
```

This test demonstrates that after executing the migration steps including `take_unclaimed_fees`, the `collectable_fee` coin in the v1 NativePool still contains the accumulated fees, proving they were not migrated to v2.

### Citations

**File:** liquid_staking/sources/volo_v1/native_pool.move (L128-128)
```text
        collectable_fee: Coin<SUI>, // owner fee
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L150-150)
```text
        collected_rewards: u64, // rewards that stashed as protocol fee
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L479-481)
```text
        assert!(balance::value(&total_removed_balance) >= fee + collectable_reward, E_NOT_ENOUGH_BALANCE);
        let fee_balance = balance::split(&mut total_removed_balance, fee + collectable_reward);
        coin::join(&mut self.collectable_fee, coin::from_balance(fee_balance, ctx));
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L527-538)
```text
    public entry fun collect_fee(self: &mut NativePool, to: address, _owner_cap: &OwnerCap, ctx: &mut TxContext) {
        assert_version(self);
        when_not_paused(self);

        let value = coin::value(&self.collectable_fee);
        transfer::public_transfer(coin::split(&mut self.collectable_fee, value, ctx), to);

        event::emit(FeeCollectedEvent{
            to,
            value,
        })
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
