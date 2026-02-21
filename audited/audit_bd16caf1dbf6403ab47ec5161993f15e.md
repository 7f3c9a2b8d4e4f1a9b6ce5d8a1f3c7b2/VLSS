# Audit Report

## Title
Protocol Fee Loss on Accrued Rewards During V1 to V2 Migration

## Summary
During the V1 to V2 migration, the protocol loses its entitled 10% reward fees on all staking rewards accrued after `update_rewards()` was deprecated. The migration flow withdraws all SUI (principal + rewards) but only collects fees based on the stale `collected_rewards` value, permanently transferring unfee'd rewards to users through V2.

## Finding Description

The V1 NativePool tracks a 10% reward fee through the `collected_rewards` field [1](#0-0) , which is updated when rewards are calculated. However, `update_rewards()` is deprecated and aborts immediately [2](#0-1) , freezing the `collected_rewards` value.

**Normal V1 Operations (Before Deprecation):**
During unstaking, the system separates principals and rewards, calculates fees on rewards, and updates accounting [3](#0-2) .

**Broken Migration Flow:**

1. **Export Phase**: The migration calls `export_stakes()` which withdraws all StakedSui objects [4](#0-3) . This uses `request_withdraw_stake_non_entry()` which returns the complete balance (principal + all accumulated rewards) [5](#0-4) . Unlike normal operations, the export function does NOT track principals separately and does NOT calculate fees on newly earned rewards [6](#0-5) .

2. **Fee Collection**: The `take_unclaimed_fees()` function only extracts fees equal to the frozen `collected_rewards` value [7](#0-6) . This value was calculated before deprecation and does not include fees on rewards earned after deprecation.

3. **Import Phase**: The remaining balance (including unfee'd rewards) is imported to V2 via `join_to_sui_pool()` [8](#0-7) , which simply adds the balance to the pool without any fee calculation [9](#0-8) .

**Root Cause Comparison:**
- Normal unstaking: Tracks `(total_withdrawn, principals, rewards)` tuple and calculates fees on `rewards` [10](#0-9) 
- Migration export: Only returns total balance, no principal/reward separation, no fee calculation on newly accrued rewards

## Impact Explanation

**Direct Financial Loss:**
The protocol permanently loses 10% of all staking rewards earned between `update_rewards()` deprecation and migration execution. If R_new SUI in rewards accrued during this period, the protocol loses 0.10 × R_new SUI that should have been collected as fees. These unfee'd rewards are transferred to users through the V2 pool.

**Severity: Medium** - This is a guaranteed loss of protocol revenue (not user principal). The amount is bounded by the staking reward rate and time between deprecation and migration, but the loss is certain and irreversible.

## Likelihood Explanation

**Certainty: 100%**

This will occur during migration because:

1. `update_rewards()` is already deprecated in the deployed code and cannot be called [2](#0-1) 
2. StakedSui objects continue earning rewards on-chain through Sui's staking system regardless of V1 deprecation
3. The migration is a planned administrative operation that will execute
4. Any time between deprecation and migration guarantees new reward accrual
5. The code provides no mechanism to recalculate fees on newly accrued rewards [11](#0-10) 

This is not an attack - even honest administrators executing the documented migration flow cannot prevent this loss without code changes.

## Recommendation

Add a fee calculation step during migration to account for rewards earned after deprecation:

1. Before `export_stakes()`, record the total principal staked from V1
2. After `export_stakes()`, calculate: `new_rewards = exported_balance - recorded_principal - pending_balance`
3. Calculate and deduct: `additional_fees = new_rewards × base_reward_fee / MAX_PERCENT`
4. In `take_unclaimed_fees()`, collect `collected_rewards + additional_fees` instead of just `collected_rewards`

Alternatively, calculate the fee based on the difference between exported balance and expected principal:
```move
// In take_unclaimed_fees()
let total_exported = migration_storage.sui_balance.value();
let expected_principal = calculate_v1_total_principal(native_pool); // Track this value
let total_rewards = total_exported - expected_principal;
let total_fees = calculate_reward_fee(total_rewards);
let fees = migration_storage.sui_balance.split(total_fees);
```

## Proof of Concept

A PoC would require:
1. Deploying V1 NativePool with stakes
2. Calling `update_rewards()` to calculate initial `collected_rewards`
3. Advancing time to earn additional rewards
4. Executing migration flow: `export_stakes()` → `take_unclaimed_fees()` → `import_stakes()`
5. Verifying that `take_unclaimed_fees()` only collected the initial `collected_rewards` value, not fees on newly earned rewards
6. Confirming the unfee'd rewards were imported to V2

The vulnerability is evident from code inspection: the migration export does not track rewards separately (unlike normal operations), and fee collection only uses the pre-calculated frozen value.

## Notes

This vulnerability stems from the architectural difference between normal V1 operations (which track principals/rewards separately and calculate fees dynamically) and the migration export (which treats everything as a single lump sum). The deprecation of `update_rewards()` freezes the `collected_rewards` value, but StakedSui objects continue earning rewards on-chain. The migration code has no mechanism to recalculate fees on this gap.

### Citations

**File:** liquid_staking/sources/volo_v1/native_pool.move (L170-170)
```text
            base_reward_fee: 10_00, // 10.00%
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L269-271)
```text
    public entry fun update_rewards(self: &mut NativePool, clock: &Clock, value: u64, _operator_cap: &OperatorCap) {
        abort E_DEPRECATED
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L445-456)
```text
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
```

**File:** liquid_staking/sources/migration/migrate.move (L112-117)
```text
        let validator_set = native_pool.mut_validator_set();
        let (exported_sui, exported_count, exported_sui_amount)
        = export_stakes_from_v1(validator_set, system_state, max_iterations, ctx);

        migration_storage.sui_balance.join(exported_sui);
        migration_storage.exported_count = migration_storage.exported_count + exported_count;
```

**File:** liquid_staking/sources/migration/migrate.move (L137-185)
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

    // 4. import stakes
    public fun import_stakes(
        migration_storage: &mut MigrationStorage,
        _: &MigrationCap,
        admin_cap: &AdminCap,
        stake_pool: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        import_amount: u64,
        min_ratio: u64,
        ctx: &mut TxContext
    ) {
        let amount = import_amount.min(migration_storage.sui_balance.value());

        // temporarily unpause the pool to allow import
        stake_pool.set_paused(admin_cap, false);
        stake_pool.join_to_sui_pool(migration_storage.sui_balance.split(amount));
        stake_pool.rebalance(metadata, system_state, ctx);
        stake_pool.set_paused(admin_cap, true);

        // sanity check
        let ratio = stake_pool.get_ratio(metadata);
        assert!(ratio <= min_ratio, 0);

        event::emit(ImportedEvent {
            imported_amount: amount,
            ratio
        });
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L256-282)
```text
        let withdrawn_reward = balance::value(&total_withdrawn) - total_withdrawn_principal_value;
        vault_mut_ref.total_staked = vault_mut_ref.total_staked - total_withdrawn_principal_value;

        // prune validator if possbile
        if (vault_mut_ref.gap == vault_mut_ref.length) {
            // when gap == length we don't have stakes on validator
            assert!(vault_mut_ref.total_staked == 0, E_BAD_CONDITION);
        
            let prior = *vec_map::get(&self.validators, &validator);
            if (prior == 0) {
                // priority is zero, it means that validator can be removed
                let v = table::remove(&mut self.vaults, validator);
                destroy_vault(v);

                vec_map::remove<address, u64>(&mut self.validators, &validator);
                let (exist, index) = vector::index_of(&self.sorted_validators, &validator);
                assert!(exist, E_NOT_FOUND);
                // we can do swap_revert, because it can be swapped only with inactive validator
                vector::swap_remove(&mut self.sorted_validators, index);
            } else {
                // table is empty, but validator still active => we can reset vault
                vault_mut_ref.gap = 0;
                vault_mut_ref.length = 0;
            };
        };

        (total_withdrawn, total_withdrawn_principal_value, withdrawn_reward)
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L344-365)
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
```

**File:** liquid_staking/sources/validator_pool.move (L531-533)
```text
    public(package) fun join_to_sui_pool(self: &mut ValidatorPool, sui: Balance<SUI>) {
        self.total_sui_supply = self.total_sui_supply + sui.value();
        self.sui_pool.join(sui);
```
