# Audit Report

## Title
Protocol Fee Loss on Accrued Rewards During V1 to V2 Migration

## Summary
During the V1 to V2 migration, the protocol permanently loses its reward fees (10% by default) on all rewards accrued after the `update_rewards()` function was deprecated. The `take_unclaimed_fees()` function only collects fees based on the stale `collected_rewards` value, while `export_stakes()` withdraws all accumulated SUI including newly earned rewards. These unfee'd rewards are then imported into V2 without any fee calculation, resulting in a direct financial loss to the protocol treasury.

## Finding Description

The V1 NativePool's `update_rewards()` function is deprecated and immediately aborts, preventing any updates to the `collected_rewards` field which tracks protocol fees. [1](#0-0) 

However, StakedSui objects continue to earn rewards on-chain through the Sui validator system regardless of this deprecation. The V1 system tracks a 10% reward fee. [2](#0-1) [3](#0-2) 

**Vulnerable Migration Flow:**

1. **Export Phase**: The `export_stakes()` function calls `export_stakes_from_v1()` which withdraws all StakedSui objects. [4](#0-3) 

2. **Withdrawal Returns All SUI**: The `export_stakes()` helper uses `request_withdraw_stake_non_entry()` which returns the complete balance including principal AND all accumulated rewards. [5](#0-4) 

3. **Fee Collection Gap**: The `take_unclaimed_fees()` function only splits fees based on the frozen `collected_rewards` value, with no mechanism to calculate fees on newly accrued rewards. [6](#0-5) 

4. **Import Without Fee Calculation**: The remaining balance (including unfee'd rewards) is imported to V2 via `join_to_sui_pool()` which performs no fee calculation. [7](#0-6) [8](#0-7) [9](#0-8) 

The protocol has no mechanism to recalculate or collect fees on rewards earned between when `update_rewards()` was deprecated and when migration executes.

## Impact Explanation

**Direct Financial Loss to Protocol:**
- The protocol permanently loses its entitled reward fee (10%) on all rewards accrued after the last `update_rewards()` call
- If stakes earned R SUI in rewards after deprecation: Expected protocol fee = 0.10 × R SUI, Actual collected = 0 SUI on new rewards, Protocol loss = 0.10 × R SUI
- These unfee'd rewards are transferred to users through the V2 pool instead of being collected by the protocol treasury

**Affected Parties:**
- Protocol treasury loses entitled fees
- Users gain unintended benefit (keeping rewards that should have incurred 10% fees)

**Severity: Medium** - Direct loss of protocol fees (not principal stakes). The loss is bounded by the reward rate and migration timing, but is certain to occur during normal migration operations.

## Likelihood Explanation

**Certainty: 100%**

This issue WILL occur during migration because:

1. **Cannot Be Prevented**: `update_rewards()` is already deprecated in the codebase and cannot be called. [1](#0-0) 

2. **Automatic Reward Accrual**: StakedSui continues earning rewards on-chain through Sui validators regardless of V1 code deprecation

3. **Migration Will Execute**: This is a planned one-time administrative operation that will definitely be executed following the documented flow [10](#0-9) 

4. **Time Gap Guarantees Accrual**: Any time gap between deprecation and migration ensures rewards will accrue

**No Attacker Required:**
This is a protocol design flaw in the migration logic, not an attack. It occurs through normal migration flow without any malicious action. Even a trusted admin executing the migration cannot prevent this loss - the code provides no mechanism to collect fees on newly accrued rewards.

## Recommendation

Before calling `take_unclaimed_fees()`, calculate and add protocol fees on newly accrued rewards:

1. **Calculate Total Withdrawn Value**: Track the total SUI amount withdrawn during `export_stakes()` (principal + rewards)
2. **Determine New Rewards**: Subtract known principal amounts from withdrawn totals to get rewards earned after deprecation
3. **Apply Fee Rate**: Calculate 10% protocol fee on these new rewards
4. **Update collected_rewards**: Add the calculated fee to `collected_rewards` before calling `take_unclaimed_fees()`

Suggested fix in `export_stakes()`:
```move
// After exporting all stakes, calculate fees on newly accrued rewards
let total_withdrawn = migration_storage.sui_balance.value();
let expected_principal = /* sum of all principal values */;
let new_rewards = total_withdrawn - expected_principal;
let new_fees = (new_rewards * 10) / 100; // 10% fee
*native_pool.mut_collected_rewards() = *native_pool.mut_collected_rewards() + new_fees;
```

This ensures the protocol collects its entitled fees on all rewards, including those earned after `update_rewards()` deprecation.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize V1 NativePool with staked SUI
2. Deprecate `update_rewards()` (already done in code)
3. Advance epochs to allow rewards to accrue on StakedSui
4. Execute migration: `init_objects()` → `create_stake_pool()` → `export_stakes()` → `take_unclaimed_fees()` → `import_stakes()`
5. Verify: `collected_rewards` value before export vs. actual withdrawn rewards
6. Confirm: Protocol fee collected < 10% of actual total rewards

The discrepancy proves the protocol loses fees on rewards accrued between deprecation and migration.

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

**File:** liquid_staking/sources/migration/migrate.move (L1-10)
```text
/// Module: Migration
/// migrate from volo v1 to volo v2
/// migration will be only executed once
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
/// 6. unpause the pool (after migration)
```

**File:** liquid_staking/sources/migration/migrate.move (L113-116)
```text
        let (exported_sui, exported_count, exported_sui_amount)
        = export_stakes_from_v1(validator_set, system_state, max_iterations, ctx);

        migration_storage.sui_balance.join(exported_sui);
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

**File:** liquid_staking/sources/volo_v1/validator_set.move (L357-363)
```text
            let withdrawn = sui_system::request_withdraw_stake_non_entry(system_state, staked_sui_to_withdraw, ctx);

            *exported_sui_amount = *exported_sui_amount + withdrawn.value();
            *exported_count = *exported_count + 1;
            *iterations = *iterations - 1;

            exported_sui.join(withdrawn);
```

**File:** liquid_staking/sources/stake_pool.move (L552-553)
```text
    public(package) fun join_to_sui_pool(self: &mut StakePool, sui: Balance<SUI>) {
        self.validator_pool.join_to_sui_pool(sui);
```

**File:** liquid_staking/sources/validator_pool.move (L531-533)
```text
    public(package) fun join_to_sui_pool(self: &mut ValidatorPool, sui: Balance<SUI>) {
        self.total_sui_supply = self.total_sui_supply + sui.value();
        self.sui_pool.join(sui);
```
