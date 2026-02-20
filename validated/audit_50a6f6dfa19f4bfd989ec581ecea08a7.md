# Audit Report

## Title
Incomplete Migration: Protocol Fees (collectable_fee) Not Migrated from V1 to V2

## Summary
The v1 to v2 migration flow fails to migrate accumulated protocol fees stored in the `collectable_fee` Coin<SUI> field of the NativePool object. While the migration handles the `collected_rewards` counter for accounting purposes, it does not extract the actual fee coins, leaving protocol revenue in the deprecated v1 contract and requiring manual administrative recovery.

## Finding Description

The NativePool struct contains two distinct fee-related fields: `collectable_fee: Coin<SUI>` which holds actual accumulated SUI fee coins, and `collected_rewards: u64` which is a counter for accounting. [1](#0-0) 

During unstaking operations, protocol fees (both unstake fees and reward fees) are accumulated into the `collectable_fee` coin object. The `unstake_amount_from_validators` function extracts fees and joins them to this coin. [2](#0-1) 

The migration flow implements a documented multi-step process. In step 2 (`export_stakes`), the migration extracts staked SUI from validators and pending SUI, storing them in `migration_storage.sui_balance`. Crucially, this step does not touch `collectable_fee`. [3](#0-2) 

The critical issue occurs in step 3 (`take_unclaimed_fees`), which only handles the `collected_rewards` counter. This function reads the counter value and splits that amount from `migration_storage.sui_balance` (which came from exported stakes and pending SUI, NOT from `collectable_fee`). The actual `collectable_fee` Coin<SUI> object is never accessed or migrated. [4](#0-3) 

The `export_stakes_from_v1` function called by the migration only withdraws staked assets from validators, not the fee coin. [5](#0-4) 

Grep search confirms that the entire migration module contains no reference to `collectable_fee` at all.

## Impact Explanation

**Direct Fund Custody Impact:**
- All protocol fees accumulated in `collectable_fee` before migration remain in the deprecated v1 NativePool object
- These fees represent actual protocol revenue from unstake fees and reward fees collected during normal v1 operations
- The migration appears complete but protocol funds remain in the wrong contract location
- This creates a fund custody issue where protocol revenue is stranded in a deprecated contract

**Operational Risk:**
- Protocol administrators may not realize fees were left behind since migration events don't track `collectable_fee` status
- The v2 pool functions normally post-migration, masking the incomplete asset transfer
- Creates confusion about which contract holds protocol revenue

**Recovery Requirements:**
While technically recoverable via the `collect_fee` function: [6](#0-5) 

This recovery path requires:
1. Awareness that fees were left behind (non-obvious from migration events)
2. Unpausing the v1 pool (migration pauses it)
3. Calling `collect_fee` on the deprecated v1 contract
4. Additional transactions and gas costs

Unlike most v1 functions which abort with `E_DEPRECATED`, `collect_fee` does NOT have the deprecation check, allowing recovery but requiring manual administrative intervention. [7](#0-6) 

## Likelihood Explanation

**Probability: High** - This occurs automatically on every migration where fees have accumulated before migration starts.

**Preconditions:**
- Normal protocol operation before migration naturally accumulates fees in `collectable_fee`
- Any unstake operations before migration add fees to this coin
- Migration is executed following the standard documented flow

**Automatic Occurrence:**
This is not an attack requiring a malicious actor. The incomplete migration logic automatically leaves fees behind whenever the migration process executes with accumulated fees present. There is no code path in the migration that extracts or migrates the `collectable_fee` coin.

**Detection Difficulty:**
The issue may not be immediately apparent because:
- Migration events don't include `collectable_fee` status or balance
- The v2 pool appears to function normally post-migration
- Only administrators explicitly checking v1 pool state would notice the stranded fees

## Recommendation

Modify the migration flow to explicitly extract and transfer the `collectable_fee` coin from the v1 NativePool. Add a new migration step after `take_unclaimed_fees`:

```move
// New step: extract collectable_fee coin
public fun extract_collectable_fee(
    migration_storage: &mut MigrationStorage,
    _: &MigrationCap,
    native_pool: &mut NativePool,
    ctx: &mut TxContext
) {
    // Extract the actual fee coin (not just the counter)
    let fee_coin = native_pool.extract_collectable_fee_for_migration();
    migration_storage.sui_balance.join(fee_coin.into_balance());
    
    event::emit(CollectableFeeExtractedEvent {
        amount: fee_coin.value(),
    });
}
```

Add a corresponding package-visible function in `native_pool.move`:

```move
public(package) fun extract_collectable_fee_for_migration(
    self: &mut NativePool
): Coin<SUI> {
    let value = coin::value(&self.collectable_fee);
    coin::split(&mut self.collectable_fee, value, ctx)
}
```

This ensures all protocol assets, including accumulated fees, are properly migrated from v1 to v2.

## Proof of Concept

The vulnerability is demonstrated by the migration flow itself. A test would verify:

1. Accumulate fees in v1 NativePool's `collectable_fee` field through unstaking operations
2. Execute the migration flow
3. Verify that `collectable_fee` balance in v1 NativePool is non-zero post-migration
4. Verify that migration_storage did not receive these fees
5. Confirm fees remain stranded in v1 contract

The code evidence shows this is guaranteed to occur as the migration module has zero references to `collectable_fee` and only handles the `collected_rewards` counter.

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

**File:** liquid_staking/sources/volo_v1/native_pool.move (L425-495)
```text
    fun unstake_amount_from_validators(
        self: &mut NativePool,
        wrapper: &mut SuiSystemState,
        amount_to_unstake: u64,
        fee: u64,
        validators: vector<address>,
        ctx: &mut TxContext
    ): Coin<SUI> {

        assert!(vector::length(&validators) > 0, E_NOTHING_TO_UNSTAKE);
        let mut i = vector::length(&validators) - 1;

        let mut total_removed_value = coin::value(&self.pending);
        let mut total_removed_balance = coin::into_balance(coin::split(&mut self.pending, total_removed_value, ctx));

        let mut collectable_reward = 0;

        while (total_removed_value < amount_to_unstake) {
            let vldr_address = *vector::borrow(&validators, i);

            let (removed_from_validator, principals, rewards) = validator_set::remove_stakes(
                &mut self.validator_set,
                wrapper,
                vldr_address,
                amount_to_unstake - total_removed_value,
                ctx,
            );

            sub_total_staked_unsafe(self, principals, ctx);
            let reward_fee = calculate_reward_fee(self, rewards);
            collectable_reward = collectable_reward + reward_fee;
            sub_rewards_unsafe(self, rewards);

            balance::join(&mut total_removed_balance, removed_from_validator);

            // sub collectable reward from total removed
            total_removed_value = balance::value(&total_removed_balance) - collectable_reward;

            if (i == 0) {
                break
            };
            i = i - 1;
        };

        // check that we don't plan to charge more fee than needed
        if (collectable_reward > self.collected_rewards) {
            // all rewards was collected
            collectable_reward = self.collected_rewards;
            self.collected_rewards = 0;
        } else {
            self.collected_rewards = self.collected_rewards - collectable_reward;
        };

        // extract our fees
        assert!(balance::value(&total_removed_balance) >= fee + collectable_reward, E_NOT_ENOUGH_BALANCE);
        let fee_balance = balance::split(&mut total_removed_balance, fee + collectable_reward);
        coin::join(&mut self.collectable_fee, coin::from_balance(fee_balance, ctx));

        // restake excess amount
        if (total_removed_value > amount_to_unstake) {
            let stake_value = total_removed_value - amount_to_unstake;
            let balance_to_stake = balance::split(&mut total_removed_balance, stake_value);
            let coin_to_stake = coin::from_balance(balance_to_stake, ctx);
            coin::join(&mut self.pending, coin_to_stake);

            // restake is possible
            stake_pool(self, wrapper, ctx);
        };

        coin::from_balance(total_removed_balance, ctx)
    }
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

**File:** liquid_staking/sources/migration/migrate.move (L67-75)
```text
    public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {

        // ensure this function is only called once
        native_pool.mark_cap_created();

        // sanity check to avoid double migration
        // collected_rewards will be set to 0 in the first migration
        assert!(native_pool.mut_collected_rewards() != 0, 0);
        native_pool.set_pause(owner_cap, true);
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
