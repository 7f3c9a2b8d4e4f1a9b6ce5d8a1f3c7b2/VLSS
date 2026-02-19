### Title
Permanent Lock of Pool Rewards Due to Unclaimed UserReward Objects Preventing Campaign Closure

### Summary
The `close_pool_reward()` function requires `num_user_reward_managers` to be zero before allowing closure of an expired reward campaign. However, this counter can only be decremented when users explicitly claim rewards after the period ends. If any user fails to claim their rewards (due to negligence, uneconomical gas costs, or lost account access), the counter remains non-zero indefinitely, permanently preventing the admin from closing the campaign and recovering dust rewards.

### Finding Description [1](#0-0) 

The `close_pool_reward()` function enforces a strict check at line 160 that `num_user_reward_managers == 0`. This counter tracks the number of users who have active `UserReward` objects for this pool reward campaign.

**Counter Increment Path:** [2](#0-1) 

The counter increments when a new `UserReward` is created for a user during the `update_user_reward_manager()` call, which happens automatically when users deposit or borrow during an active reward campaign.

**Counter Decrement Path:** [3](#0-2) 

The counter can ONLY be decremented in `claim_rewards()` at line 399, and only when `clock::timestamp_ms(clock) >= pool_reward.end_time_ms`. This requires explicit user action to claim rewards after the period has ended.

**Critical Issue - No Automatic Cleanup:** [4](#0-3) 

When users fully repay their borrows, the `Borrow` struct is removed but the `UserRewardManager` (and its internal `UserReward` objects) persists indefinitely in the obligation's `user_reward_managers` vector. The same occurs for deposits: [5](#0-4) 

There is no mechanism to force cleanup or allow admins to bypass the check. Even the `cancel_pool_reward()` function only sets the end time to current time but doesn't destroy the PoolReward object: [6](#0-5) 

### Impact Explanation

**Operational Denial of Service:**
- Admins cannot close expired reward campaigns if any user fails to claim
- Dust rewards (unallocated or rounding errors) remain permanently locked in the PoolReward object
- Protocol accumulates "zombie" PoolReward objects that can never be cleaned up

**Affected Parties:**
- Protocol administrators lose ability to reclaim unclaimed rewards and manage campaigns
- Future users may encounter confusion with uncloseable campaigns
- Gas inefficiency as PoolReward slots remain occupied indefinitely

**Severity Justification:**
This is HIGH severity because:
1. It's a permanent state - no recovery mechanism exists
2. It affects core protocol functionality (reward distribution management)
3. Economic loss occurs (locked dust rewards)
4. The issue compounds over time as more campaigns become uncloseable

### Likelihood Explanation

**High Probability Scenario:**
Users frequently fail to claim rewards for various reasons:
1. **Negligence:** Users forget to claim after fully exiting positions
2. **Economic Irrationality:** Gas costs exceed reward value for small positions
3. **Lost Access:** Users lose access to wallets/accounts
4. **Technical Issues:** Users may not understand they need to claim post-exit

**Attack Complexity:** None required - this occurs through normal protocol operation. Even a single user with $0.01 in unclaimed rewards can permanently lock a campaign.

**Feasibility:** 100% - No special permissions or timing required. Users deposit/borrow during reward period, exit positions, and simply don't claim.

**Economic Rationality:** Completely rational for users to not claim small reward amounts when gas costs are higher than reward value.

### Recommendation

**Solution 1: Add Admin Override Function**
```move
public(package) fun force_close_pool_reward<T>(
    pool_reward_manager: &mut PoolRewardManager,
    index: u64,
    clock: &Clock,
): Balance<T> {
    // Similar to close_pool_reward but without num_user_reward_managers check
    // Can only be called after a grace period (e.g., 30 days after end_time_ms)
    // Sends remaining balance to protocol treasury
}
```

**Solution 2: Auto-cleanup on Zero Share**
Modify `change_user_reward_manager_share()` to automatically destroy UserReward objects and decrement counter when share is set to 0 and period has ended.

**Solution 3: Implement Claim Deadline**
Add a `claim_deadline_ms` field. After this deadline, admins can force-close regardless of counter, with unclaimed rewards going to protocol treasury.

**Test Cases:**
1. Verify force closure works after grace period
2. Verify auto-cleanup triggers on full withdrawal after period end
3. Verify users can still claim before deadline
4. Verify protocol treasury receives unclaimed funds correctly

### Proof of Concept

**Initial State:**
- Admin creates pool reward campaign for deposit rewards
- Campaign runs from T=0 to T=100
- Total rewards: 1000 tokens

**Transaction Sequence:**

1. **T=10:** User Alice deposits 100 tokens
   - `find_or_add_deposit()` creates Deposit
   - `update_user_reward_manager()` creates UserReward
   - `num_user_reward_managers` incremented from 0 to 1

2. **T=50:** User Bob deposits 50 tokens  
   - Same process
   - `num_user_reward_managers` incremented from 1 to 2

3. **T=110:** Campaign period ends

4. **T=120:** Bob claims his rewards and exits
   - Calls `claim_rewards()` 
   - UserReward destroyed, counter decremented to 1
   - Withdraws all deposits

5. **T=130:** Alice fully withdraws deposits WITHOUT claiming
   - Calls `withdraw()` until `deposited_ctoken_amount == 0`
   - Deposit struct removed at line 1116
   - BUT UserRewardManager persists with unclaimed UserReward
   - `num_user_reward_managers` remains at 1

6. **T=140:** Admin attempts to close campaign
   - Calls `close_pool_reward()`
   - **Transaction ABORTS** at line 160: `assert!(num_user_reward_managers == 0, ENotAllRewardsClaimed)`

**Expected Result:** Campaign closes successfully, admin recovers dust rewards

**Actual Result:** Transaction fails with `ENotAllRewardsClaimed` error. Campaign permanently locked. Dust rewards unrecoverable.

**Success Condition for Attack:** Alice simply needs to never call `claim_rewards()` after exiting. This requires zero effort and is economically rational if her unclaimed reward is less than gas cost.

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L174-202)
```text
    public(package) fun cancel_pool_reward<T>(
        pool_reward_manager: &mut PoolRewardManager,
        index: u64,
        clock: &Clock,
    ): Balance<T> {
        update_pool_reward_manager(pool_reward_manager, clock);

        let pool_reward = option::borrow_mut(
            vector::borrow_mut(&mut pool_reward_manager.pool_rewards, index),
        );
        let cur_time_ms = clock::timestamp_ms(clock);

        let unallocated_rewards = floor(
            sub(
                decimal::from(pool_reward.total_rewards),
                pool_reward.allocated_rewards,
            ),
        );

        pool_reward.end_time_ms = cur_time_ms;
        pool_reward.total_rewards = 0;

        let reward_balance: &mut Balance<T> = bag::borrow_mut(
            &mut pool_reward.additional_fields,
            RewardBalance<T> {},
        );

        balance::split(reward_balance, unallocated_rewards)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L293-316)
```text
            if (option::is_none(optional_reward)) {
                if (user_reward_manager.last_update_time_ms <= pool_reward.end_time_ms) {
                    option::fill(
                        optional_reward,
                        UserReward {
                            pool_reward_id: object::id(pool_reward),
                            earned_rewards: {
                                if (
                                    user_reward_manager.last_update_time_ms <= pool_reward.start_time_ms
                                ) {
                                    mul(
                                        pool_reward.cumulative_rewards_per_share,
                                        decimal::from(user_reward_manager.share),
                                    )
                                } else {
                                    decimal::from(0)
                                }
                            },
                            cumulative_rewards_per_share: pool_reward.cumulative_rewards_per_share,
                        },
                    );

                    pool_reward.num_user_reward_managers = pool_reward.num_user_reward_managers + 1;
                };
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L491-500)
```text
        if (eq(borrow.borrowed_amount, decimal::from(0))) {
            let Borrow {
                coin_type: _,
                reserve_array_index: _,
                borrowed_amount: _,
                cumulative_borrow_rate: _,
                market_value: _,
                user_reward_manager_index: _,
            } = vector::remove(&mut obligation.borrows, borrow_index);
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L1108-1117)
```text
        if (deposit.deposited_ctoken_amount == 0) {
            let Deposit {
                coin_type: _,
                reserve_array_index: _,
                deposited_ctoken_amount: _,
                market_value: _,
                attributed_borrow_value: _,
                user_reward_manager_index: _,
            } = vector::remove(&mut obligation.deposits, deposit_index);
        };
```
