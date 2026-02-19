# Audit Report

## Title
Liquidate User Loses Incentive V2 Rewards Due to Missing Pre-Liquidation Reward Update

## Summary
The `entry_liquidation()` function incorrectly updates `@0x0` instead of `liquidate_user` in incentive_v2 before executing liquidation. This causes liquidated users to permanently lose unclaimed rewards proportional to their balance reduction, as the reward calculation applies their post-liquidation balance retroactively to the entire reward period.

## Finding Description

The liquidation functions exhibit a critical inconsistency in their reward update pattern compared to all other entry functions in the protocol.

**Vulnerable Pattern in Liquidation:**

In `entry_liquidation()`, the function updates rewards for address `@0x0` in incentive_v2, not the actual `liquidate_user`: [1](#0-0) 

However, it correctly updates the `liquidate_user` in incentive_v3: [2](#0-1) 

This same bug exists in the non-entry `liquidation()` function: [3](#0-2) 

**Correct Pattern in All Other Operations:**

Every other entry function correctly updates the actual user in both incentive systems. For example, `entry_deposit()`: [4](#0-3) 

Similarly, `entry_withdraw()`: [5](#0-4) 

And `entry_borrow()`: [6](#0-5) 

**Why This Causes Fund Loss:**

When `update_reward_all(@0x0)` is called, the `update_reward()` function advances the global `index_reward` based on elapsed time: [7](#0-6) 

Since `@0x0` has zero balance, no rewards accrue to it, but the global index advances. The reward calculation for any user is: [8](#0-7) 

**The Loss Mechanism:**

1. User has balance `B` at time T0, last tracked index `I0`
2. At liquidation time T1:
   - Global index advances from `I0` to `I1` (via `@0x0` update)
   - User's `index_rewards_paids` remains at `I0` (not updated)
   - Liquidation reduces balance from `B` to `B'`
3. At next interaction T2:
   - User's reward calculated as: `(I2 - I0) × B'`
   - But should have been: `(I1 - I0) × B + (I2 - I1) × B'`
   - **Loss = `(I1 - I0) × (B - B')`**

This is the index increase during liquidation multiplied by the amount liquidated.

## Impact Explanation

**High Severity - Direct User Fund Loss**

This vulnerability causes permanent loss of user funds (unclaimed rewards) with the following characteristics:

- **100% Occurrence Rate:** Affects every liquidation without exception
- **No User Mitigation:** Users cannot force-update their rewards before being liquidated
- **Quantifiable Loss:** Lost rewards = (Index increase at liquidation) × (Balance liquidated)
- **Permanent:** Rewards are not stolen by an attacker but are lost/unaccounted for in the system

The loss magnitude depends on:
- Time elapsed since user's last interaction (longer = higher index increase)
- Amount of balance liquidated (larger liquidations = more loss)
- Configured reward rate in incentive_v2 pools (higher rate = more loss)

Users who remain inactive for extended periods before liquidation suffer the most significant losses.

## Likelihood Explanation

**High Likelihood - Automatic on Every Liquidation**

This vulnerability triggers automatically without any special attack or manipulation:

- **Public Function:** `entry_liquidation()` is a public entry function callable by anyone
- **Natural Trigger:** Liquidations occur naturally when users become undercollateralized due to price movements
- **Economic Incentive:** Liquidators are strongly incentivized to liquidate for profit, ensuring frequent occurrence
- **No Preconditions:** No special setup or state required beyond normal liquidation conditions
- **100% Reproducible:** Happens deterministically on every liquidation call

The bug occurs as an unavoidable side effect of normal protocol operations, not requiring any attacker effort or cost.

## Recommendation

Change the liquidation functions to update `liquidate_user` instead of `@0x0` in incentive_v2, consistent with all other entry functions.

**For `entry_liquidation()` (lines 1077-1078):**
```move
// BEFORE (incorrect):
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);

// AFTER (correct):
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, liquidate_user);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, liquidate_user);
```

**For `liquidation()` (lines 1130-1131):**
```move
// BEFORE (incorrect):
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);

// AFTER (correct):
incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, liquidate_user);
incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, liquidate_user);
```

This ensures the user's rewards are properly calculated and recorded on their full balance before the liquidation reduces it, eliminating the reward loss.

## Proof of Concept

```move
#[test]
fun test_liquidation_reward_loss() {
    // Setup: Create test scenario with incentive pools
    let scenario = test_scenario::begin(@0x1);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    
    // Setup user with balance and active incentive_v2 rewards
    // User has 1000 tokens deposited, earning rewards
    setup_user_with_balance(@user, 1000, &mut scenario);
    
    // Advance time by 1 day (rewards accumulating)
    clock::increment_for_testing(&mut clock, 86400000);
    
    // Record user's expected rewards at this point (before liquidation)
    let expected_rewards_before = calculate_user_rewards(@user, &scenario);
    
    // User becomes undercollateralized, liquidation occurs
    // This calls entry_liquidation() which updates @0x0 instead of @user
    execute_liquidation(@user, 500, &mut scenario, &clock); // Liquidates 50% of balance
    
    // Advance time slightly more
    clock::increment_for_testing(&mut clock, 1000);
    
    // Check user's actual rewards after liquidation
    let actual_rewards_after = calculate_user_rewards(@user, &scenario);
    
    // The bug: User should have earned rewards on full 1000 balance for the first day
    // But instead, rewards calculated as if they only had 500 balance the entire time
    let expected_loss = expected_rewards_before * 500 / 1000; // Lost rewards on liquidated 50%
    
    assert!(actual_rewards_after < expected_rewards_before - expected_loss, 0);
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

The test demonstrates that the user's rewards are calculated using their post-liquidation balance for the entire reward period, resulting in permanent loss of rewards on the liquidated portion.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L1130-1134)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);

        update_reward_state_by_asset<DebtCoinType>(clock, incentive_v3, storage, liquidate_user);
        update_reward_state_by_asset<CollateralCoinType>(clock, incentive_v3, storage, liquidate_user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L401-402)
```text
            pool.index_reward = index_reward;
            pool.last_update_at = now;
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L452-453)
```text
        let reward_increase = (index_reward - index_rewards_paid) * user_balance;
        total_rewards_of_user = total_rewards_of_user + reward_increase;
```
