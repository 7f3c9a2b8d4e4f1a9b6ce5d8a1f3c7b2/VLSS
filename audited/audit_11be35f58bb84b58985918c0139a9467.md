# Audit Report

## Title
Protocol Fee Loss on Accrued Rewards During V1 to V2 Migration

## Summary
The V1 to V2 migration contains a design flaw that causes permanent loss of protocol fees. The V1 `update_rewards()` function is deprecated and cannot update the `collected_rewards` field that tracks accrued fee obligations. During migration, all SUI including newly earned validator rewards is withdrawn and transferred to V2, but the protocol only collects fees based on the stale `collected_rewards` value, resulting in loss of the 10% protocol fee on all rewards earned after the last `update_rewards()` call.

## Finding Description

The vulnerability stems from the interaction between deprecated V1 accounting and the migration withdrawal flow.

**Root Cause:** The V1 `update_rewards()` function aborts immediately with `E_DEPRECATED` [1](#0-0) , preventing any updates to the `collected_rewards` field. However, StakedSui objects continue earning validator rewards on-chain through the Sui staking system regardless of this code deprecation.

**Vulnerable Migration Flow:**

1. **Export Phase:** The `export_stakes()` function calls `export_stakes_from_v1()` [2](#0-1) , which invokes `export_stakes()` that withdraws StakedSui objects via `request_withdraw_stake_non_entry()` [3](#0-2) . This withdrawal returns ALL accumulated SUI including principal and all rewards (both tracked and newly accrued).

2. **Balance Accumulation:** All withdrawn SUI is accumulated in `migration_storage.sui_balance` [4](#0-3) .

3. **Fee Collection:** The `take_unclaimed_fees()` function only extracts the stale `collected_rewards` amount [5](#0-4) .

4. **Import to V2:** The remaining balance is imported to V2 via `join_to_sui_pool()` [6](#0-5) , which performs no fee calculation [7](#0-6) .

**Why Protections Fail:**

The V1 system's fee mechanism relies on the `update_rewards()` function to track accumulated rewards and populate `collected_rewards` with the calculated 10% protocol fee [8](#0-7)  using the reward fee calculation [9](#0-8) . 

In normal V1 unstaking, fees on withdrawn rewards are calculated and capped at the `collected_rewards` value [10](#0-9) . This logic ensures the protocol collects fees tracked in `collected_rewards`.

However, the migration flow bypasses this normal unstake logic entirely. The `export_stakes()` function directly withdraws all SUI without any fee calculation, and no subsequent step in the migration flow calculates fees on the newly accrued rewards.

## Impact Explanation

**Direct Financial Loss:** The protocol permanently loses its 10% reward fee on all rewards accrued between when `update_rewards()` was last successfully called and when migration executes.

**Quantified Impact:** If validator stakes earned R SUI in rewards after the last `update_rewards()` call:
- Expected protocol fee: 0.10 × R SUI  
- Actual protocol fee collected: 0 SUI (on new rewards)
- Protocol loss: 0.10 × R SUI

This lost fee is transferred to users through the V2 pool instead of being collected by the protocol treasury.

**Affected Parties:**
- Protocol treasury loses entitled fees
- Users gain unintended benefit (rewards that should have incurred fees)

**Severity: Medium** - This represents direct loss of protocol fees (fee under-collection), but does not affect user principal stakes or system solvency. The loss is bounded by the validator reward rate and the time window between deprecation and migration execution.

## Likelihood Explanation

**Certainty of Occurrence:** This issue will occur during migration with 100% certainty because:

1. `update_rewards()` is already deprecated in the codebase and cannot be called
2. StakedSui objects continue earning rewards on-chain through the Sui validator system regardless of code deprecation  
3. Migration is a one-time administrative operation that will definitely be executed
4. Any time gap between deprecation and migration ensures rewards will accrue

**No Attacker Required:** This is a protocol design flaw, not an attack vector. It occurs through the normal migration flow executed by trusted administrators. The migration caller cannot prevent this loss—the code provides no mechanism to collect fees on newly accrued rewards.

**Feasibility: 100%** - The issue manifests through standard migration execution following the documented flow.

## Recommendation

Modify the migration flow to calculate and collect fees on all withdrawn rewards, not just the stale `collected_rewards` value. 

**Recommended Fix:**

In the `export_stakes_from_v1()` function, track the principal vs reward amounts separately during withdrawal (similar to the normal V1 `remove_stakes()` logic). Calculate the 10% fee on total withdrawn rewards and subtract it from the migration balance before import.

Alternatively, add a fee calculation step in `take_unclaimed_fees()` that:
1. Compares the total withdrawn SUI against expected principal amounts
2. Identifies the reward portion
3. Calculates and extracts 10% of total rewards (not just `collected_rewards`)

## Proof of Concept

```move
// Conceptual PoC showing the fee gap
// Given:
// - Last update_rewards() call recorded 100 SUI rewards → collected_rewards = 10 SUI (10%)
// - After deprecation, stakes earn additional 50 SUI rewards
// - Total rewards at migration: 150 SUI
// - Total withdrawn at migration: principal + 150 SUI rewards

// Migration flow:
// 1. export_stakes() withdraws: principal + 150 SUI rewards
// 2. take_unclaimed_fees() extracts: 10 SUI (only stale collected_rewards)
// 3. import_stakes() transfers to V2: principal + 140 SUI
// 
// Result: Protocol loses 5 SUI fee (10% of 50 SUI new rewards)
// Users receive 140 SUI instead of 135 SUI they should receive
```

## Notes

This vulnerability is specific to the one-time V1→V2 migration and does not affect normal V2 operations. The V2 system has its own fee accounting via `FeeConfig` that calculates fees on-demand. The issue arises solely from the mismatch between V1's deprecated reward tracking and the migration's direct withdrawal approach.

The loss amount is deterministic and bounded by: `0.10 × validator_reward_rate × time_between_deprecation_and_migration`.

### Citations

**File:** liquid_staking/sources/volo_v1/native_pool.move (L170-170)
```text
            base_reward_fee: 10_00, // 10.00%
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L214-216)
```text
    fun calculate_reward_fee(self: &NativePool, value: u64): u64 {
        math::mul_div(value, self.base_reward_fee, MAX_PERCENT)
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L269-271)
```text
    public entry fun update_rewards(self: &mut NativePool, clock: &Clock, value: u64, _operator_cap: &OperatorCap) {
        abort E_DEPRECATED
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L454-476)
```text
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
```

**File:** liquid_staking/sources/migration/migrate.move (L113-114)
```text
        let (exported_sui, exported_count, exported_sui_amount)
        = export_stakes_from_v1(validator_set, system_state, max_iterations, ctx);
```

**File:** liquid_staking/sources/migration/migrate.move (L116-123)
```text
        migration_storage.sui_balance.join(exported_sui);
        migration_storage.exported_count = migration_storage.exported_count + exported_count;

        // take pending
        let pending = native_pool.mut_pending();
        let pending_sui = pending.balance_mut().withdraw_all();
        let pending_sui_amount = pending_sui.value();
        migration_storage.sui_balance.join(pending_sui);
```

**File:** liquid_staking/sources/migration/migrate.move (L144-148)
```text
        let unclaimed_fees = native_pool.mut_collected_rewards();
        let fee_amount = *unclaimed_fees;
        let fees = migration_storage.sui_balance.split(fee_amount);
        transfer::public_transfer(fees.into_coin(ctx), recipient);
        *unclaimed_fees = 0;
```

**File:** liquid_staking/sources/migration/migrate.move (L173-173)
```text
        stake_pool.join_to_sui_pool(migration_storage.sui_balance.split(amount));
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L357-357)
```text
            let withdrawn = sui_system::request_withdraw_stake_non_entry(system_state, staked_sui_to_withdraw, ctx);
```

**File:** liquid_staking/sources/validator_pool.move (L531-533)
```text
    public(package) fun join_to_sui_pool(self: &mut ValidatorPool, sui: Balance<SUI>) {
        self.total_sui_supply = self.total_sui_supply + sui.value();
        self.sui_pool.join(sui);
```
