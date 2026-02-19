### Title
Incomplete Reward Share Re-synchronization After Unlooping Causes Permanent Loss of Rewards

### Summary
The `zero_out_rewards()` function sets all reward manager shares to 0 when an obligation becomes looped. However, when the user becomes unlooped by repaying a borrow or withdrawing a deposit, only the specific position's reward manager share is updated. Other positions remain with share=0, causing the user to permanently lose rewards on those untouched positions until they perform another operation on them.

### Finding Description

The vulnerability exists in the interaction between `zero_out_rewards()` and the individual deposit/borrow/repay/withdraw operations. [1](#0-0) 

When `zero_out_rewards()` is called, it iterates through ALL deposits and borrows, setting each corresponding UserRewardManager's share to 0. Each deposit/borrow has its own `user_reward_manager_index` pointing to a specific UserRewardManager. [2](#0-1) 

The function is called via `zero_out_rewards_if_looped()` after deposit, borrow, repay, withdraw, and liquidate operations to deny rewards to looped positions. [3](#0-2) 

However, individual operations only update the reward share for the specific position being modified:
- `deposit()` updates only the deposit being added to [4](#0-3) 

- `repay()` updates only the borrow being repaid [5](#0-4) 

- `withdraw_unchecked()` updates only the deposit being withdrawn [6](#0-5) 

When a user becomes unlooped by repaying a borrow, that operation updates only the borrow's UserRewardManager. If the user has multiple deposits in other reserves, their UserRewardManagers remain at share=0 even though the user is no longer looped, causing permanent loss of rewards until those positions are touched.

### Impact Explanation

**Direct Fund Impact:** Users lose reward tokens that should have been earned on their deposits/borrows.

**Quantification:** The loss equals `reward_rate × deposit_amount × time_until_next_interaction`. For a user with 100,000 USDC deposited at 5% APR who doesn't interact for 30 days after becoming unlooped, they lose approximately 411 USDC in rewards (100,000 × 0.05 × 30/365).

**Who is Affected:** Any user with multiple deposit/borrow positions who becomes looped and then unlooped. The impact is greater for:
- Users with large deposits in multiple reserves
- Users who don't frequently interact with their positions
- Passive liquidity providers

**Severity Justification:** Medium severity because rewards are permanently lost (not just delayed), but requires specific multi-position setup and affects a subset of users rather than causing systemic protocol failure.

### Likelihood Explanation

**Attacker Capabilities:** No special capabilities needed - any regular user can encounter this through normal protocol usage.

**Attack Complexity:** Low - naturally occurs through normal operations:
1. User deposits to Reserve A and Reserve B
2. User borrows from Reserve A (becomes looped)
3. User repays borrow from Reserve A (becomes unlooped)
4. User's deposit in Reserve B stops earning rewards

**Feasibility Conditions:**
- User must have deposits/borrows in multiple reserves (common for diversified users)
- User must become looped (deposit + borrow same asset, or specific disabled pairs) - moderately common
- User must become unlooped by repaying/withdrawing one position - very common

**Detection/Operational Constraints:** The issue is not easily detected by users, as they may not realize they're not earning rewards on untouched positions. Active traders would quickly trigger re-sync, but passive investors could go weeks or months without noticing.

**Probability:** Medium - requires multi-position setup and loop/unloop cycle, but all steps are realistic normal user behavior.

### Recommendation

**Code-level Mitigation:** After checking `is_looped()` in `zero_out_rewards_if_looped()`, if the obligation is NOT looped but any UserRewardManager has share=0 while corresponding deposits/borrows exist, re-synchronize all shares:

```move
public(package) fun zero_out_rewards_if_looped<P>(
    obligation: &mut Obligation<P>,
    reserves: &mut vector<Reserve<P>>,
    clock: &Clock,
) {
    if (is_looped(obligation)) {
        zero_out_rewards(obligation, reserves, clock);
    } else {
        // Re-sync all shares if previously zeroed but now unlooped
        resync_all_reward_shares(obligation, reserves, clock);
    }
}

fun resync_all_reward_shares<P>(
    obligation: &mut Obligation<P>,
    reserves: &mut vector<Reserve<P>>,
    clock: &Clock,
) {
    // Resync deposits
    let mut i = 0;
    while (i < vector::length(&obligation.deposits)) {
        let deposit = vector::borrow(&obligation.deposits, i);
        let reserve = vector::borrow_mut(reserves, deposit.reserve_array_index);
        let user_reward_manager = vector::borrow_mut(
            &mut obligation.user_reward_managers,
            deposit.user_reward_manager_index,
        );
        liquidity_mining::change_user_reward_manager_share(
            reserve::deposits_pool_reward_manager_mut(reserve),
            user_reward_manager,
            deposit.deposited_ctoken_amount,
            clock,
        );
        i = i + 1;
    };
    
    // Resync borrows
    let mut i = 0;
    while (i < vector::length(&obligation.borrows)) {
        let borrow = vector::borrow(&obligation.borrows, i);
        let reserve = vector::borrow_mut(reserves, borrow.reserve_array_index);
        let user_reward_manager = vector::borrow_mut(
            &mut obligation.user_reward_managers,
            borrow.user_reward_manager_index,
        );
        liquidity_mining::change_user_reward_manager_share(
            reserve::borrows_pool_reward_manager_mut(reserve),
            user_reward_manager,
            liability_shares(borrow),
            clock,
        );
        i = i + 1;
    };
}
```

**Invariant Check:** After any operation, verify: `for all deposits/borrows with non-zero amounts, corresponding UserRewardManager.share must match the actual position size (unless currently looped)`.

**Test Cases:**
1. User with deposits in Reserve A and B, borrows from A (looped), repays A (unlooped) → verify both deposits earn rewards
2. User with deposit in A, borrows from A and B (looped), repays A (unlooped) → verify deposit A and borrow B still earn rewards
3. Monitor reward accumulation before/after unlooping to ensure no gaps

### Proof of Concept

**Initial State:**
- User has 1000 cToken deposited in Reserve A (USDC)
  - UserRewardManager[0].share = 1000
- User has 500 cToken deposited in Reserve B (ETH)
  - UserRewardManager[1].share = 500

**Execution Steps:**

1. User calls `borrow()` to borrow 100 tokens from Reserve A
   - Creates loop (deposit + borrow same asset)
   - `zero_out_rewards_if_looped()` called
   - `is_looped()` returns true
   - `zero_out_rewards()` executes:
     - UserRewardManager[0].share = 0
     - UserRewardManager[1].share = 0
     - UserRewardManager[2].share = 0 (new borrow)

2. User calls `repay()` to repay entire borrow from Reserve A
   - `repay()` updates UserRewardManager[2] with `liability_shares(borrow)` = 0
   - Borrow removed from obligation.borrows
   - `zero_out_rewards_if_looped()` called
   - `is_looped()` returns false (no borrow from A anymore)
   - `zero_out_rewards()` NOT called

3. Time passes (30 days)
   - Reserve B accumulates rewards
   - User's share in Reserve B pool = 0
   - User earns ZERO rewards despite having 500 cToken deposited

**Expected Result:** User earns rewards on both deposits after becoming unlooped

**Actual Result:** User has 500 cToken in Reserve B with UserRewardManager[1].share = 0, permanently losing all rewards until they perform another deposit/withdraw on Reserve B

**Success Condition:** Verify UserRewardManager[1].share remains 0 after step 2, and user's earned_rewards for Reserve B deposit pool does not increase during step 3.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L85-102)
```text
    public struct Deposit has store {
        coin_type: TypeName,
        reserve_array_index: u64,
        deposited_ctoken_amount: u64,
        market_value: Decimal,
        user_reward_manager_index: u64,
        /// unused
        attributed_borrow_value: Decimal,
    }

    public struct Borrow has store {
        coin_type: TypeName,
        reserve_array_index: u64,
        borrowed_amount: Decimal,
        cumulative_borrow_rate: Decimal,
        market_value: Decimal,
        user_reward_manager_index: u64,
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L335-344)
```text
        let user_reward_manager = vector::borrow_mut(
            &mut obligation.user_reward_managers,
            deposit.user_reward_manager_index,
        );
        liquidity_mining::change_user_reward_manager_share(
            reserve::deposits_pool_reward_manager_mut(reserve),
            user_reward_manager,
            deposit.deposited_ctoken_amount,
            clock,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L480-489)
```text
        let user_reward_manager = vector::borrow_mut(
            &mut obligation.user_reward_managers,
            borrow.user_reward_manager_index,
        );
        liquidity_mining::change_user_reward_manager_share(
            reserve::borrows_pool_reward_manager_mut(reserve),
            user_reward_manager,
            liability_shares(borrow),
            clock,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L866-874)
```text
    public(package) fun zero_out_rewards_if_looped<P>(
        obligation: &mut Obligation<P>,
        reserves: &mut vector<Reserve<P>>,
        clock: &Clock,
    ) {
        if (is_looped(obligation)) {
            zero_out_rewards(obligation, reserves, clock);
        };
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L942-990)
```text
    fun zero_out_rewards<P>(
        obligation: &mut Obligation<P>,
        reserves: &mut vector<Reserve<P>>,
        clock: &Clock,
    ) {
        {
            let mut i = 0;
            while (i < vector::length(&obligation.deposits)) {
                let deposit = vector::borrow(&obligation.deposits, i);
                let reserve = vector::borrow_mut(reserves, deposit.reserve_array_index);

                let user_reward_manager = vector::borrow_mut(
                    &mut obligation.user_reward_managers,
                    deposit.user_reward_manager_index,
                );

                liquidity_mining::change_user_reward_manager_share(
                    reserve::deposits_pool_reward_manager_mut(reserve),
                    user_reward_manager,
                    0,
                    clock,
                );

                i = i + 1;
            };
        };

        {
            let mut i = 0;
            while (i < vector::length(&obligation.borrows)) {
                let borrow = vector::borrow(&obligation.borrows, i);
                let reserve = vector::borrow_mut(reserves, borrow.reserve_array_index);

                let user_reward_manager = vector::borrow_mut(
                    &mut obligation.user_reward_managers,
                    borrow.user_reward_manager_index,
                );

                liquidity_mining::change_user_reward_manager_share(
                    reserve::borrows_pool_reward_manager_mut(reserve),
                    user_reward_manager,
                    0,
                    clock,
                );

                i = i + 1;
            };
        };
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L1097-1106)
```text
        let user_reward_manager = vector::borrow_mut(
            &mut obligation.user_reward_managers,
            deposit.user_reward_manager_index,
        );
        liquidity_mining::change_user_reward_manager_share(
            reserve::deposits_pool_reward_manager_mut(reserve),
            user_reward_manager,
            deposit.deposited_ctoken_amount,
            clock,
        );
```
