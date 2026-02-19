### Title
Users Permanently Lose Fractional Rewards on Final Claim After Reward Period Ends

### Summary
When users claim rewards after the reward period ends, any fractional amount (< 1.0 token) remaining in their `earned_rewards` is permanently lost due to the flooring operation combined with destruction of the `UserReward` struct. While precision loss does not accumulate during the active reward period (fractional amounts persist and compound), the final claim after `end_time_ms` destroys unclaimed fractional rewards that remain in the pool balance for admin recovery rather than user claims.

### Finding Description

The vulnerability exists in the `claim_rewards()` function's handling of decimal precision at the end of reward campaigns. [1](#0-0) 

During normal claims (before `end_time_ms`), the flooring operation preserves fractional rewards:
- The `floor()` function extracts only the integer portion as `claimable_rewards`
- The fractional remainder persists in `reward.earned_rewards` for future claims
- Users can accumulate fractional amounts until they reach ≥ 1.0 and become claimable [2](#0-1) 

However, when a user claims after the reward period ends, the protocol destroys their `UserReward` struct: [3](#0-2) 

The `earned_rewards` field containing the fractional amount is destructured and dropped. Since `option::extract()` removes the `UserReward` from the vector, subsequent claims are impossible. The fractional tokens remain in the pool's balance but are unclaimable by the user.

The admin can later recover these accumulated dust amounts via `close_pool_reward()`: [4](#0-3) 

This represents a systematic transfer of user-earned rewards to the admin.

### Impact Explanation

**Direct Fund Impact:**
- Each user loses up to 0.999... tokens per reward campaign on their final claim
- For high-value reward tokens (e.g., WETH at $3,000/token), a single user could lose ~$2,997
- Across hundreds of users in a campaign, total lost value could reach tens of thousands of dollars
- The lost funds remain in the pool balance and become admin-recoverable dust rather than user-claimable rewards

**Who Is Affected:**
- Every user participating in liquidity mining who claims rewards after the campaign ends
- Impact scales with token value and number of participants

**Severity Justification:**
- Systematic wealth transfer from users to protocol admin
- 100% occurrence rate for post-campaign claims
- No user action can prevent the loss once the period ends
- Violates user expectation that earned rewards are fully claimable

### Likelihood Explanation

**Attacker Capabilities:**
- No attacker needed - this is a design flaw affecting normal protocol operation
- Every user who claims after `end_time_ms` is affected automatically

**Attack Complexity:**
- Zero - happens during standard claim flow
- No special timing or state manipulation required

**Feasibility Conditions:**
- Reward period must end (`clock::timestamp_ms(clock) >= pool_reward.end_time_ms`)
- User must have fractional rewards < 1.0 remaining
- Both conditions occur naturally in normal usage

**Probability:**
- 100% probability that users will have fractional amounts due to decimal division in reward calculations
- 100% probability these are lost on post-period claims
- Expected to affect every user in every reward campaign

### Recommendation

**Mitigation Strategy:**
Implement a grace period or final settlement mechanism to ensure users can claim fractional rewards:

**Option 1 - Ceiling on Final Claim:**
Modify the claim logic to use `ceil()` instead of `floor()` when the reward period has ended and the user is making their final claim. This ensures fractional amounts are rounded up and fully paid to the user.

**Option 2 - Fractional Claim Period:**
Add a configurable grace period after `end_time_ms` during which users can still claim without their `UserReward` being destroyed. Only destroy the struct after both the period ends AND the grace period expires.

**Option 3 - Dust Redistribution:**
Track cumulative dust amounts and proportionally redistribute them to users in their final claims based on their share of total rewards.

**Invariant Check:**
Add assertion that when a `UserReward` is destroyed, `earned_rewards < decimal::from(1)` to ensure only minimal dust is lost.

**Test Cases:**
1. Test that user with 10.7 earned rewards claims 10, then claims remaining 0.7 in second transaction before period ends
2. Test that user with 0.3 earned rewards after period ends receives 1 token (via ceiling) or receives redistribution
3. Verify total claimed + dust equals total_rewards with minimal error margin

### Proof of Concept

**Initial State:**
- Pool reward campaign with 1000 USDC, 100 total shares
- User A has 33 shares (33% of pool)
- Campaign runs 100 time units
- Due to division: User A earns 330.333... USDC over the period

**Execution Steps:**

1. **During Campaign (time = 50):**
   - User A calls `claim_rewards()`
   - `earned_rewards` = 165.166... USDC (in Decimal form)
   - `claimable_rewards = floor(165.166...)` = 165 USDC
   - User receives 165 USDC
   - `earned_rewards` updated to 0.166... USDC (fractional part preserved)

2. **Campaign Continues (time = 100, period ends):**
   - User A's rewards continue accruing
   - `earned_rewards` = 165.166... USDC (additional rewards + previous fraction)

3. **Post-Period Claim (time = 105):**
   - User A calls `claim_rewards()`
   - `earned_rewards` = 165.166... USDC
   - `claimable_rewards = floor(165.166...)` = 165 USDC
   - User receives 165 USDC
   - Remaining `earned_rewards` = 0.166... USDC
   - **UserReward struct is destroyed** (lines 392-400)
   - **0.166... USDC permanently lost to User A**

4. **Admin Recovery (time = 200):**
   - All users have claimed
   - Admin calls `close_pool_reward()`
   - Receives accumulated dust including User A's 0.166... USDC

**Expected vs Actual:**
- **Expected:** User A receives full 330.333... USDC earned
- **Actual:** User A receives 330 USDC, loses 0.333... USDC to admin-recoverable dust

**Success Condition:**
The vulnerability is confirmed if fractional `earned_rewards` < 1.0 are unrecoverable by users after the `UserReward` is destroyed post-campaign.

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L384-386)
```text
        let claimable_rewards = floor(reward.earned_rewards);

        reward.earned_rewards = sub(reward.earned_rewards, decimal::from(claimable_rewards));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L392-400)
```text
        if (clock::timestamp_ms(clock) >= pool_reward.end_time_ms) {
            let UserReward {
                pool_reward_id: _,
                earned_rewards: _,
                cumulative_rewards_per_share: _,
            } = option::extract(optional_reward);

            pool_reward.num_user_reward_managers = pool_reward.num_user_reward_managers - 1;
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L98-100)
```text
    public fun floor(a: Decimal): u64 {
        ((a.value / WAD) as u64)
    }
```
