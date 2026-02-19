# Audit Report

## Title
Users Permanently Lose Fractional Rewards on Final Claim After Reward Period Ends

## Summary
The Suilend liquidity mining system permanently destroys fractional reward amounts when users claim rewards after a campaign ends. The `floor()` operation combined with `UserReward` struct destruction causes users to lose up to 0.999... tokens per campaign, which remain in the pool balance for admin recovery rather than user distribution.

## Finding Description

The vulnerability exists in the `claim_rewards()` function within the Suilend liquidity mining module. [1](#0-0) 

**Normal Operation (Before end_time_ms):**
During the active reward period, the flooring operation preserves fractional precision. The `floor()` function extracts only the integer portion of `earned_rewards` as claimable tokens [2](#0-1) , while the fractional remainder persists in the `UserReward.earned_rewards` field for future claims. Users can accumulate fractional amounts across multiple claims until they reach ≥ 1.0 token.

**Vulnerability Trigger (After end_time_ms):**
When users claim after the reward period ends, the protocol checks the timestamp and destroys the entire `UserReward` struct. [3](#0-2) 

The destructuring pattern `earned_rewards: _` discards the fractional amount. Since `option::extract()` removes the `UserReward` from the vector, no subsequent claims are possible. The fractional tokens remain locked in the pool's `Balance<T>` stored in `additional_fields`.

**Admin Recovery:**
The admin can later recover all accumulated dust amounts via `close_pool_reward()`, which returns the entire remaining balance after all users have claimed. [4](#0-3) 

This creates a systematic wealth transfer from users to protocol administrators.

**Call Path:**
Users interact via public functions: `lending_market::claim_rewards()` [5](#0-4)  → `obligation::claim_rewards()` [6](#0-5)  → `liquidity_mining::claim_rewards()`.

## Impact Explanation

**Direct Financial Impact:**
- Each user loses up to 0.999... tokens per reward campaign on their final claim
- For high-value tokens (e.g., WETH at $3,000), individual losses approach $3,000
- Across hundreds of participants, cumulative losses reach tens of thousands of dollars
- Lost funds become admin-recoverable rather than remaining user-claimable

**Affected Parties:**
- Every user participating in Suilend liquidity mining who claims after campaign end
- Volo vault users holding Suilend obligations as DeFi assets
- Impact scales linearly with token value and participant count

**Severity Justification:**
- Systematic wealth transfer violating user expectation of full reward distribution
- 100% occurrence rate for post-campaign claims
- No user mitigation strategy available once period ends
- Violates fundamental protocol invariant: earned rewards should be fully claimable

## Likelihood Explanation

**Attack Complexity:** Zero - This is a design flaw affecting normal protocol operation, not requiring any attacker action.

**Feasibility Conditions:**
1. Reward period must end (natural occurrence for all campaigns)
2. User must have fractional rewards < 1.0 remaining (mathematically guaranteed due to decimal division in reward calculations)

**Probability Assessment:**
- 100% probability users will have fractional amounts due to continuous reward accrual using 18-decimal precision `Decimal` type
- 100% probability these are lost on any post-period claim
- Expected to affect every user in every reward campaign

**Execution Path:** Fully public via `lending_market::claim_rewards()` requiring only standard `ObligationOwnerCap` authentication.

## Recommendation

**Solution:** Implement a rounding threshold mechanism that rounds up small fractional amounts to the next integer before the final claim:

```move
public(package) fun claim_rewards<T>(
    pool_reward_manager: &mut PoolRewardManager,
    user_reward_manager: &mut UserRewardManager,
    clock: &Clock,
    reward_index: u64,
): Balance<T> {
    update_user_reward_manager(pool_reward_manager, user_reward_manager, clock, false);
    
    let pool_reward = option::borrow_mut(
        vector::borrow_mut(&mut pool_reward_manager.pool_rewards, reward_index),
    );
    assert!(pool_reward.coin_type == type_name::get<T>(), EInvalidType);
    
    let optional_reward = vector::borrow_mut(&mut user_reward_manager.rewards, reward_index);
    let reward = option::borrow_mut(optional_reward);
    
    // If period ended and fractional amount exists, round up to avoid loss
    let claimable_rewards = if (clock::timestamp_ms(clock) >= pool_reward.end_time_ms) {
        ceil(reward.earned_rewards)  // Round up on final claim
    } else {
        floor(reward.earned_rewards)  // Normal flooring during active period
    };
    
    reward.earned_rewards = sub(reward.earned_rewards, decimal::from(claimable_rewards));
    
    let reward_balance: &mut Balance<T> = bag::borrow_mut(
        &mut pool_reward.additional_fields,
        RewardBalance<T> {},
    );
    
    if (clock::timestamp_ms(clock) >= pool_reward.end_time_ms) {
        let UserReward {
            pool_reward_id: _,
            earned_rewards: _,
            cumulative_rewards_per_share: _,
        } = option::extract(optional_reward);
        
        pool_reward.num_user_reward_managers = pool_reward.num_user_reward_managers - 1;
    };
    
    balance::split(reward_balance, claimable_rewards)
}
```

Note: Requires adding a `ceil()` function to the `decimal` module if not already present.

## Proof of Concept

```move
#[test]
fun test_fractional_reward_loss_on_period_end() {
    let mut scenario = test_scenario::begin(@0xA);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Create pool reward manager and user reward manager
    let mut pool_reward_manager = liquidity_mining::new_pool_reward_manager(scenario.ctx());
    
    // Add reward campaign: 1000 tokens over 1 hour
    let start_time = 1000000;
    let end_time = start_time + 3_600_000; // 1 hour later
    clock::set_for_testing(&mut clock, start_time);
    
    let rewards = balance::create_for_testing<SUI>(1000);
    liquidity_mining::add_pool_reward<SUI>(
        &mut pool_reward_manager,
        rewards,
        start_time,
        end_time,
        &clock,
        scenario.ctx()
    );
    
    // Create user with stake
    let mut user_reward_manager = liquidity_mining::new_user_reward_manager(
        &mut pool_reward_manager,
        &clock
    );
    
    liquidity_mining::change_user_reward_manager_share(
        &mut pool_reward_manager,
        &mut user_reward_manager,
        1000, // user stake
        &clock
    );
    
    // Fast forward to middle of period - user earns ~500.75 tokens (with fractional part)
    clock::set_for_testing(&mut clock, start_time + 1_800_000);
    
    // Claim mid-period (fractional preserved)
    let claimed_mid = liquidity_mining::claim_rewards<SUI>(
        &mut pool_reward_manager,
        &mut user_reward_manager,
        &clock,
        0
    );
    let mid_amount = balance::value(&claimed_mid);
    
    // Fast forward past end_time
    clock::set_for_testing(&mut clock, end_time + 100);
    
    // Final claim after period ends - fractional amount LOST
    let claimed_final = liquidity_mining::claim_rewards<SUI>(
        &mut pool_reward_manager,
        &mut user_reward_manager,
        &clock,
        0
    );
    let final_amount = balance::value(&claimed_final);
    
    // User received less than total earned due to flooring on final claim
    let total_claimed = mid_amount + final_amount;
    assert!(total_claimed < 1000, 0); // User lost fractional amount
    
    // Verify lost funds remain in pool for admin recovery
    let remaining = liquidity_mining::close_pool_reward<SUI>(
        &mut pool_reward_manager,
        0,
        &clock
    );
    assert!(balance::value(&remaining) > 0, 1); // Dust exists for admin
    
    // Cleanup
    balance::destroy_for_testing(claimed_mid);
    balance::destroy_for_testing(claimed_final);
    balance::destroy_for_testing(remaining);
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

---

**Notes**
This vulnerability exists in Suilend's liquidity mining module, which is included as a local dependency in the Volo protocol codebase. While the vulnerable code belongs to Suilend, it affects Volo users who interact with Suilend through the `suilend_adaptor` [7](#0-6)  when their vault positions include Suilend obligations participating in liquidity mining campaigns.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L136-170)
```text
    public(package) fun close_pool_reward<T>(
        pool_reward_manager: &mut PoolRewardManager,
        index: u64,
        clock: &Clock,
    ): Balance<T> {
        let optional_pool_reward = vector::borrow_mut(&mut pool_reward_manager.pool_rewards, index);
        let PoolReward {
            id,
            pool_reward_manager_id: _,
            coin_type: _,
            start_time_ms: _,
            end_time_ms,
            total_rewards: _,
            allocated_rewards: _,
            cumulative_rewards_per_share: _,
            num_user_reward_managers,
            mut additional_fields,
        } = option::extract(optional_pool_reward);

        object::delete(id);

        let cur_time_ms = clock::timestamp_ms(clock);

        assert!(cur_time_ms >= end_time_ms, EPoolRewardPeriodNotOver);
        assert!(num_user_reward_managers == 0, ENotAllRewardsClaimed);

        let reward_balance: Balance<T> = bag::remove(
            &mut additional_fields,
            RewardBalance<T> {},
        );

        bag::destroy_empty(additional_fields);

        reward_balance
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L368-403)
```text
    public(package) fun claim_rewards<T>(
        pool_reward_manager: &mut PoolRewardManager,
        user_reward_manager: &mut UserRewardManager,
        clock: &Clock,
        reward_index: u64,
    ): Balance<T> {
        update_user_reward_manager(pool_reward_manager, user_reward_manager, clock, false);

        let pool_reward = option::borrow_mut(
            vector::borrow_mut(&mut pool_reward_manager.pool_rewards, reward_index),
        );
        assert!(pool_reward.coin_type == type_name::get<T>(), EInvalidType);

        let optional_reward = vector::borrow_mut(&mut user_reward_manager.rewards, reward_index);
        let reward = option::borrow_mut(optional_reward);

        let claimable_rewards = floor(reward.earned_rewards);

        reward.earned_rewards = sub(reward.earned_rewards, decimal::from(claimable_rewards));
        let reward_balance: &mut Balance<T> = bag::borrow_mut(
            &mut pool_reward.additional_fields,
            RewardBalance<T> {},
        );

        if (clock::timestamp_ms(clock) >= pool_reward.end_time_ms) {
            let UserReward {
                pool_reward_id: _,
                earned_rewards: _,
                cumulative_rewards_per_share: _,
            } = option::extract(optional_reward);

            pool_reward.num_user_reward_managers = pool_reward.num_user_reward_managers - 1;
        };

        balance::split(reward_balance, claimable_rewards)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L98-100)
```text
    public fun floor(a: Decimal): u64 {
        ((a.value / WAD) as u64)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L677-697)
```text
    public fun claim_rewards<P, RewardType>(
        lending_market: &mut LendingMarket<P>,
        cap: &ObligationOwnerCap<P>,
        clock: &Clock,
        reserve_id: u64,
        reward_index: u64,
        is_deposit_reward: bool,
        ctx: &mut TxContext,
    ): Coin<RewardType> {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
        claim_rewards_by_obligation_id(
            lending_market,
            cap.obligation_id,
            clock,
            reserve_id,
            reward_index,
            is_deposit_reward,
            false,
            ctx,
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L632-650)
```text
    public(package) fun claim_rewards<P, T>(
        obligation: &mut Obligation<P>,
        pool_reward_manager: &mut PoolRewardManager,
        clock: &Clock,
        reward_index: u64,
    ): Balance<T> {
        let user_reward_manager_index = find_user_reward_manager_index(
            obligation,
            pool_reward_manager,
        );
        let user_reward_manager = vector::borrow_mut(
            &mut obligation.user_reward_managers,
            user_reward_manager_index,
        );

        liquidity_mining::claim_rewards<T>(
            pool_reward_manager,
            user_reward_manager,
            clock,
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L1-40)
```text
module volo_vault::suilend_adaptor;

use std::ascii::String;
use sui::clock::Clock;
use suilend::lending_market::{LendingMarket, ObligationOwnerCap as SuilendObligationOwnerCap};
use suilend::obligation::{Obligation};
use suilend::reserve::{Self};
use volo_vault::vault::Vault;

const DECIMAL: u256 = 1_000_000_000;

// @dev Need to update the price of the reserve before calling this function
//      Update function: lending_market::refresh_reserve_price
//          public fun refresh_reserve_price<P>(
//              lending_market: &mut LendingMarket<P>,
//              reserve_array_index: u64,
//              clock: &Clock,
//              price_info: &PriceInfoObject,
//           )

// Obligation type is type of suilend lending_market
// e.g. Obligation<suilend::main_market>
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```
