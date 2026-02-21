# Audit Report

## Title
Liquidated Users Lose Incentive V2 Rewards Due to Incorrect Address Update in Liquidation Functions

## Summary
The `entry_liquidation()` and `liquidation()` functions in incentive_v3 incorrectly update rewards for address `@0x0` instead of `liquidate_user` in the incentive_v2 system. This causes liquidated users to permanently lose unclaimed rewards proportional to their liquidated balance, as the reward calculation applies their post-liquidation balance retroactively across a reward period where they held a larger balance.

## Finding Description

The liquidation functions exhibit a critical inconsistency in their reward update pattern compared to all other protocol entry functions.

**Vulnerable Pattern in Liquidation:**

In `entry_liquidation()`, the function updates rewards for `@0x0` in incentive_v2, not the `liquidate_user`: [1](#0-0) 

However, it correctly updates `liquidate_user` in incentive_v3: [2](#0-1) 

This same bug exists in the non-entry `liquidation()` function: [3](#0-2) 

**Correct Pattern in All Other Operations:**

Every other entry function correctly updates the actual user in both incentive systems. For example, `entry_deposit()`: [4](#0-3) 

Similarly, `entry_withdraw()`: [5](#0-4) 

And `entry_borrow()`: [6](#0-5) 

**Why This Causes Fund Loss:**

When `update_reward_all(@0x0)` is called, the `update_reward()` function advances the global `index_reward` based on elapsed time and updates the tracking data for `@0x0`: [7](#0-6) 

Since `@0x0` has zero balance, no rewards accrue to it, but the global index advances. The reward calculation for any user is: [8](#0-7) 

**The Loss Mechanism:**

1. User has balance `B` at time T0, with last tracked `index_rewards_paid` at `I0`
2. At liquidation time T1:
   - `update_reward_all(@0x0)` advances global `pool.index_reward` from `I0` to `I1`
   - User's `index_rewards_paids[liquidate_user]` remains at `I0` (not updated)
   - Liquidation reduces user's balance from `B` to `B'`
3. At next user interaction T2:
   - User's reward calculated as: `(I2 - I0) × B'`
   - Should have been: `(I1 - I0) × B + (I2 - I1) × B'`
   - **Loss = `(I1 - I0) × (B - B')`**

This is the index increase during liquidation multiplied by the liquidated amount.

## Impact Explanation

**High Severity - Direct User Fund Loss**

This vulnerability causes permanent loss of user funds (unclaimed rewards) with the following characteristics:

- **100% Occurrence Rate:** Affects every liquidation without exception when incentive_v2 pools are active
- **No User Mitigation:** Users cannot force-update their rewards before being liquidated by others
- **Quantifiable Loss:** Lost rewards = (Index increase at liquidation) × (Balance liquidated)
- **Permanent:** Rewards are lost to the system, not recoverable by any party

The loss magnitude depends on:
- Time elapsed since user's last interaction (longer = higher index increase)
- Amount of balance liquidated (larger liquidations = more loss)
- Configured reward rate in active incentive_v2 pools (higher rate = more loss)

Users who remain inactive for extended periods before liquidation suffer the most significant losses. This violates the protocol's accounting invariant that users should receive rewards proportional to their time-weighted balance.

## Likelihood Explanation

**High Likelihood - Automatic on Every Liquidation**

This vulnerability triggers automatically without any special conditions:

- **Public Function:** `entry_liquidation()` is a public entry function callable by anyone
- **Natural Trigger:** Liquidations occur naturally when users become undercollateralized due to market price movements
- **Economic Incentive:** Liquidators are strongly incentivized to liquidate for profit (liquidation bonus), ensuring frequent occurrence
- **No Preconditions:** No special setup required beyond normal liquidation conditions (user undercollateralized, liquidator has debt tokens)
- **100% Reproducible:** Happens deterministically on every liquidation call where incentive_v2 has active reward pools

The bug occurs as an unavoidable side effect of normal protocol operations, not requiring any attacker effort beyond calling the standard liquidation function.

## Recommendation

Update both liquidation functions to pass `liquidate_user` instead of `@0x0` to the incentive_v2 reward update calls:

```move
// In entry_liquidation() - lines 1077-1078
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, liquidate_user);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, liquidate_user);

// In liquidation() - lines 1130-1131
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, liquidate_user);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, liquidate_user);
```

This matches the pattern used in all other entry functions and ensures the liquidated user's reward state is properly updated before their balance changes.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. User deposits collateral and borrows debt, with active incentive_v2 pools for both assets
2. Time passes (e.g., 30 days), allowing rewards to accrue (global index increases)
3. Price movement causes user to become undercollateralized
4. Liquidator calls `entry_liquidation()`, which:
   - Updates `@0x0` rewards (advances global index, updates `@0x0` tracking)
   - Does NOT update `liquidate_user` rewards in incentive_v2
   - Reduces user's collateral/debt balances
5. When user next interacts (or checks rewards):
   - Reward calculation uses (current_index - old_index) × new_reduced_balance
   - User has lost: (index_increase_during_liquidation) × (liquidated_amount)

The existing test infrastructure in the codebase can be used to verify this by:
- Setting up incentive_v2 pools with rewards
- Performing a liquidation
- Comparing the liquidated user's actual rewards vs. expected rewards based on their pre-liquidation balance and time held [9](#0-8) 

**Notes:**
- This vulnerability is distinct from incentive_v3, which correctly updates `liquidate_user`
- The bug affects both collateral and debt asset rewards
- The loss is proportional to reward rate, time since last update, and liquidation size
- This is a logic error, not an access control or external dependency issue

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L792-793)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L845-846)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L910-910)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L1077-1078)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L1080-1081)
```text
        update_reward_state_by_asset<DebtCoinType>(clock, incentive_v3, storage, liquidate_user);
        update_reward_state_by_asset<CollateralCoinType>(clock, incentive_v3, storage, liquidate_user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L1130-1131)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L372-416)
```text
    public(friend) fun update_reward_all(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, asset_id: u8, user: address) {
        update_reward(clock, incentive, storage, asset_id, constants::option_type_supply(), user);
        update_reward(clock, incentive, storage, asset_id, constants::option_type_withdraw(), user);
        update_reward(clock, incentive, storage, asset_id, constants::option_type_repay(), user);
        update_reward(clock, incentive, storage, asset_id, constants::option_type_borrow(), user);
    }

    fun update_reward(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, asset_id: u8, option: u8, user: address) {
        version_verification(incentive);

        let now = clock::timestamp_ms(clock);
        let (_, _, pool_objs) = get_pool_from_asset_and_option(incentive, asset_id, option);
        let pool_length = vector::length(&pool_objs);
        let (user_supply_balance, user_borrow_balance) = storage::get_user_balance(storage, asset_id, user);
        let (total_supply_balance, total_borrow_balance) = storage::get_total_supply(storage, asset_id);
        if (option == constants::option_type_borrow()) {
            total_supply_balance = total_borrow_balance
        };

        
        while(pool_length > 0) {
            let pool = table::borrow_mut(
                &mut incentive.pools,
                *vector::borrow(&pool_objs, pool_length-1)
            );

            let user_effective_amount = calculate_user_effective_amount(option, user_supply_balance, user_borrow_balance, pool.factor);
            let (index_reward, total_rewards_of_user) = calculate_one(pool, now, total_supply_balance, user, user_effective_amount);

            pool.index_reward = index_reward;
            pool.last_update_at = now;
            
            if (table::contains(&pool.index_rewards_paids, user)) {
                table::remove(&mut pool.index_rewards_paids, user);
            };
            table::add(&mut pool.index_rewards_paids, user, index_reward);

            if (table::contains(&pool.total_rewards_of_users, user)) {
                table::remove(&mut pool.total_rewards_of_users, user);
            };
            table::add(&mut pool.total_rewards_of_users, user, total_rewards_of_user);

            pool_length = pool_length - 1;
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L452-453)
```text
        let reward_increase = (index_reward - index_rewards_paid) * user_balance;
        total_rewards_of_user = total_rewards_of_user + reward_increase;
```
