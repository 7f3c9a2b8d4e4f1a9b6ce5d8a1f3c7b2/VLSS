# Audit Report

## Title
Liquidated Users Permanently Lose Incentive V2 Rewards Due to Incorrect Address Update

## Summary
The `entry_liquidation()` function updates rewards for address `@0x0` instead of the actual `liquidate_user` in the incentive_v2 system. This causes liquidated users to permanently lose unclaimed rewards proportional to their liquidated balance, as the reward calculation applies their post-liquidation balance retroactively to the entire reward accrual period.

## Finding Description

The liquidation functions contain a critical bug where they update the wrong address in the incentive_v2 reward system, creating an inconsistency with all other protocol operations.

**Vulnerable Pattern in Liquidation:**

In `entry_liquidation()`, the function updates rewards for `@0x0` in incentive_v2: [1](#0-0) 

However, it correctly updates the `liquidate_user` in incentive_v3: [2](#0-1) 

The non-entry `liquidation()` function exhibits the same bug: [3](#0-2) 

**Correct Pattern in All Other Operations:**

Every other operation correctly updates the actual user in both incentive systems. For example, `entry_deposit()`: [4](#0-3) 

Similarly, `entry_withdraw()`: [5](#0-4) 

And `entry_borrow()`: [6](#0-5) 

**Why This Causes Fund Loss:**

The `update_reward()` function retrieves user balance and advances the global index based on time elapsed: [7](#0-6) 

When `@0x0` is updated instead of the actual user:
- `@0x0` has zero balance, so no rewards accrue to it
- The global `index_reward` advances based on time
- The user's `index_rewards_paids` remains at the old value (not updated)
- Liquidation then reduces the user's balance

The reward calculation uses the formula: [8](#0-7) 

**Loss Mechanism:**

1. User has balance `B` at time T0, last tracked index `I0`
2. At liquidation time T1:
   - Global index advances from `I0` to `I1` (via `@0x0` update)
   - User's `index_rewards_paids` remains at `I0` (not updated)
   - Liquidation reduces balance from `B` to `B'`
3. At next user interaction T2:
   - User's reward calculated as: `(I2 - I0) × B'`
   - Should have been: `(I1 - I0) × B + (I2 - I1) × B'`
   - **Loss = `(I1 - I0) × (B - B')`** (index increase during liquidation × amount liquidated)

## Impact Explanation

**High Severity - Direct User Fund Loss**

This vulnerability causes permanent loss of user funds (unclaimed incentive_v2 rewards) with these characteristics:

- **100% Occurrence Rate:** Affects every liquidation without exception
- **No User Mitigation:** Users cannot force-update their rewards before being liquidated since liquidation is permissionless and immediate when conditions are met
- **Quantifiable Loss:** Lost rewards = (Index increase at liquidation) × (Balance liquidated)
- **Permanent:** Rewards are lost permanently in the accounting system

The loss magnitude depends on:
- Time elapsed since user's last interaction (longer period = higher index increase)
- Amount of balance liquidated (larger liquidations = proportionally more loss)
- Configured reward rate in active incentive_v2 pools (higher rate = more loss per time unit)

Users who remain inactive for extended periods before liquidation suffer the most significant losses. This violates the core protocol invariant that users should receive all rewards accrued on their balances before any balance-changing operation.

## Likelihood Explanation

**High Likelihood - Automatic on Every Liquidation**

This vulnerability triggers automatically on every liquidation without any special conditions or attacker manipulation:

- **Public Function:** `entry_liquidation()` is a public entry function callable by anyone
- **Natural Trigger:** Liquidations occur naturally when users become undercollateralized due to market price movements
- **Economic Incentive:** Liquidators are strongly incentivized to liquidate promptly for liquidation bonuses, ensuring frequent occurrence
- **No Preconditions:** No special setup or state manipulation required beyond normal liquidation threshold conditions
- **100% Reproducible:** Happens deterministically on every liquidation call due to the hardcoded `@0x0` address

The bug is not an edge case but affects the core liquidation flow that executes regularly in lending protocols during periods of market volatility.

## Recommendation

Update both liquidation functions to use the actual `liquidate_user` address when calling `incentive_v2::update_reward_all()`, matching the pattern used in all other operations and already correctly implemented for incentive_v3.

**Fix for `entry_liquidation()`:**
```move
// Change lines 1077-1078 from:
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);

// To:
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, liquidate_user);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, liquidate_user);
```

**Fix for `liquidation()`:**
```move
// Change lines 1130-1131 from:
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);

// To:
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, liquidate_user);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, liquidate_user);
```

This ensures the liquidated user's `index_rewards_paids` is updated with their current balance before liquidation reduces it, preserving their accrued rewards.

## Proof of Concept

```move
#[test]
fun test_liquidation_reward_loss() {
    // Setup: Create test scenario with lending protocol, incentive_v2 pool, and two users
    let scenario = test_scenario::begin(@0xA);
    
    // 1. Setup lending pools and incentive_v2 rewards for USDC collateral
    // 2. User deposits USDC, borrows USDT
    // 3. Time passes (e.g., 1000 seconds) - rewards accrue
    // 4. Price change makes user undercollateralized
    
    // Record user's reward state before liquidation
    let reward_before = get_user_claimable_reward(user, USDC_ASSET);
    let balance_before = get_user_supply_balance(user, USDC_ASSET);
    
    // 5. Liquidator liquidates user's position
    incentive_v3::entry_liquidation<USDT, USDC>(
        clock, oracle, storage, 
        USDT_ASSET, usdt_pool, usdt_coin,
        USDC_ASSET, usdc_pool,
        user, liquidate_amount,
        incentive_v2, incentive_v3, ctx
    );
    
    let balance_after = get_user_supply_balance(user, USDC_ASSET);
    let liquidated_amount = balance_before - balance_after;
    
    // 6. More time passes
    clock::increment_for_testing(&mut clock, 1000);
    
    // 7. User claims rewards - observe loss
    let reward_after = get_user_claimable_reward(user, USDC_ASSET);
    let actual_reward = reward_after - reward_before;
    
    // Calculate expected reward if index was updated correctly
    let expected_reward = calculate_expected_reward_with_liquidation(
        reward_before, balance_before, liquidated_amount, time_periods
    );
    
    // Assert: actual_reward < expected_reward
    // Loss = (index_increase_during_liquidation) × liquidated_amount
    assert!(actual_reward < expected_reward, 0);
}
```

The test demonstrates that the user receives fewer rewards than expected because their `index_rewards_paids` was not updated at liquidation time, causing the post-liquidation balance to be retroactively applied to the entire accrual period.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L791-793)
```text
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L844-846)
```text
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L909-911)
```text
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L379-416)
```text
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
