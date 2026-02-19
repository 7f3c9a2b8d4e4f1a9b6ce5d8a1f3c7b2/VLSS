# Audit Report

## Title
Incomplete Migration: Protocol Fees (collectable_fee) Not Migrated from V1 to V2

## Summary
The v1 to v2 migration flow fails to migrate accumulated protocol fees stored in the `collectable_fee` Coin<SUI> field of the NativePool object. While the migration handles the `collected_rewards` counter, it does not extract the actual fee coins, leaving protocol revenue in the deprecated v1 contract and requiring manual administrative recovery.

## Finding Description

The NativePool struct contains two distinct fee-related fields:
- `collectable_fee: Coin<SUI>` - an actual Coin object holding accumulated SUI fees
- `collected_rewards: u64` - a counter tracking reward fee amounts for accounting [1](#0-0) 

During unstaking operations, protocol fees (both unstake fees and reward fees) are accumulated into the `collectable_fee` coin object: [2](#0-1) 

The migration module implements a documented 6-step flow. In step 2 (`export_stakes`), the migration extracts staked SUI from validators and pending SUI, storing them in `migration_storage.sui_balance`: [3](#0-2) 

The critical issue occurs in step 3 (`take_unclaimed_fees`), which only handles the `collected_rewards` counter: [4](#0-3) 

This function reads the `collected_rewards` counter value and splits that amount from `migration_storage.sui_balance` (which came from exported stakes and pending SUI, NOT from `collectable_fee`). The actual `collectable_fee` Coin<SUI> object is never accessed or migrated.

The `export_stakes_from_v1` function only withdraws staked assets from validators: [5](#0-4) 

None of the migration steps extract the `collectable_fee` coin. The entire migration module contains no reference to `collectable_fee` at all.

## Impact Explanation

**Direct Fund Custody Impact:**
- All protocol fees accumulated in `collectable_fee` before migration remain in the deprecated v1 NativePool object
- These fees represent protocol revenue from unstake fees and reward fees collected during normal v1 operations
- The migration appears complete but protocol funds remain in the wrong contract location

**Operational Risk:**
- Protocol administrators may not realize fees were left behind since migration events don't track `collectable_fee` status
- The v2 pool functions normally, masking the incomplete migration
- Creates confusion about which contract holds protocol revenue

**Recovery Requirements:**
While technically recoverable via the `collect_fee` function: [6](#0-5) 

This recovery path requires:
1. Awareness that fees were left behind
2. Unpausing the v1 pool (migration pauses it via line 75 of migrate.move)
3. Calling `collect_fee` on the deprecated v1 contract
4. Additional transactions and gas costs

Unlike most v1 functions which abort with `E_DEPRECATED`, `collect_fee` does NOT have the deprecation abort: [7](#0-6) 

This allows recovery but requires manual administrative intervention.

## Likelihood Explanation

**Probability: High** - This occurs automatically on every migration where fees have accumulated before migration starts.

**Preconditions:**
- Normal protocol operation before migration naturally accumulates fees in `collectable_fee`
- Any unstake operations before migration add fees to this coin
- Migration is executed following the standard documented flow

**Automatic Occurrence:**
This is not an attack requiring a malicious actor. The incomplete migration logic automatically leaves fees behind whenever the migration process executes with accumulated fees present.

**Detection Difficulty:**
The issue may not be immediately apparent because:
- Migration events don't include `collectable_fee` status
- The v2 pool appears to function normally post-migration
- Only administrators explicitly checking v1 pool state would notice the stranded fees

## Recommendation

Modify the migration flow to include a step that extracts `collectable_fee` before or during the `take_unclaimed_fees` step:

```move
public fun take_unclaimed_fees(
    migration_storage: &mut MigrationStorage,
    migration_cap: &mut MigrationCap,
    recipient: address,
    native_pool: &mut NativePool,
    ctx: &mut TxContext
) {
    // First, extract the actual collectable_fee coin
    let collectable_fee_value = coin::value(&native_pool.collectable_fee);
    if (collectable_fee_value > 0) {
        let fee_coin = coin::split(&mut native_pool.collectable_fee, collectable_fee_value, ctx);
        transfer::public_transfer(fee_coin, recipient);
    };
    
    // Then handle the collected_rewards counter as before
    let unclaimed_fees = native_pool.mut_collected_rewards();
    let fee_amount = *unclaimed_fees;
    let fees = migration_storage.sui_balance.split(fee_amount);
    transfer::public_transfer(fees.into_coin(ctx), recipient);
    *unclaimed_fees = 0;
    migration_cap.fees_taken = true;
    
    // Emit event with both amounts
    event::emit(UnclaimedFeesEvent {
        amount: fee_amount + collectable_fee_value,
    });
}
```

Alternatively, add a dedicated migration step before `take_unclaimed_fees` to extract `collectable_fee`.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Operating v1 NativePool with unstake operations to accumulate fees in `collectable_fee`
2. Executing the migration flow following the documented 6 steps
3. After migration completes, verifying that `collectable_fee` in v1 NativePool still contains the accumulated fees
4. Verifying that v2 StakePool did not receive these fees

The proof is in the code structure itself: searching the entire migration module shows zero references to `collectable_fee`, confirming it is never accessed during migration.

### Citations

**File:** liquid_staking/sources/volo_v1/native_pool.move (L124-155)
```text
    public struct NativePool has key {
        id: UID,

        pending: Coin<SUI>, // pending SUI that should be staked
        collectable_fee: Coin<SUI>, // owner fee
        validator_set: ValidatorSet, // pool validator set
        ticket_metadata: unstake_ticket::Metadata,

        /* Store active stake of each epoch */
        total_staked: Table<u64, u64>,
        staked_update_epoch: u64,

        /* Fees */
        base_unstake_fee: u64, // percent of fee per 1 SUI
        unstake_fee_threshold: u64, // percent of active stake
        base_reward_fee: u64, // percent of rewards

        /* Access */
        version: u64,
        paused: bool,

        /* Limits */
        min_stake: u64, // all stakes should be greater than

        /* General stats */
        total_rewards: u64, // current rewards of pool, we can't calculate them, because it's impossible to do on current step
        collected_rewards: u64, // rewards that stashed as protocol fee

        /* Thresholds */
        rewards_threshold: u64, // percent of rewards that possible to increase
        rewards_update_ts: u64, // timestamp when we updated rewards last time
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L243-257)
```text
    public entry fun change_min_stake(self: &mut NativePool, _owner_cap: &OwnerCap, value: u64) {
        abort E_DEPRECATED
    }

    public entry fun change_unstake_fee_threshold(self: &mut NativePool, _owner_cap: &OwnerCap, value: u64) {
        abort E_DEPRECATED
    }

    public entry fun change_base_unstake_fee(self: &mut NativePool, _owner_cap: &OwnerCap, value: u64) {
        abort E_DEPRECATED
    }

    public entry fun change_base_reward_fee(self: &mut NativePool, _owner_cap: &OwnerCap, value: u64) {
        abort E_DEPRECATED
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L478-481)
```text
        // extract our fees
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
