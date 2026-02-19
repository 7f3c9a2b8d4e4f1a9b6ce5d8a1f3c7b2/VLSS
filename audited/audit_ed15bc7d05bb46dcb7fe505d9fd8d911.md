### Title
Permissionless Reward Claiming Can Permanently Destroy Future Reward Accrual via Disabled Pairing Creation

### Summary
The `claim_rewards_and_deposit()` function allows anyone to claim and auto-deposit rewards for any obligation after the reward period ends. When this forced deposit creates a disabled reserve pairing (e.g., borrowing from reserve 1 while depositing into reserve 2), the `zero_out_rewards_if_looped()` mechanism permanently sets all reward manager shares to zero across ALL reserves, causing the victim to lose all future reward accrual from all active reward programs.

### Finding Description

The Suilend lending market provides two reward claiming functions with different access controls:

1. `claim_rewards()` requires `ObligationOwnerCap` and has no time restrictions [1](#0-0) 

2. `claim_rewards_and_deposit()` is permissionless but requires the reward period to have ended [2](#0-1) 

The time restriction is enforced via the `fail_if_reward_period_not_over` check [3](#0-2) 

The critical issue occurs when `claim_rewards_and_deposit()` deposits rewards into a reserve that creates a disabled pairing. After depositing ctokens into the obligation, the function calls `zero_out_rewards_if_looped()` [4](#0-3) 

The `is_looped()` function checks for disabled pairings between specific reserve indices [5](#0-4) 

For example, if an obligation borrows from reserve 1 and deposits into reserve 2, this is a disabled pairing. When detected, `zero_out_rewards()` is called, which sets all user reward manager shares to zero across ALL deposits and borrows [6](#0-5) 

This share zeroing is done via `change_user_reward_manager_share()` with `new_share = 0` [7](#0-6) 

Once shares are set to zero, no new rewards accrue regardless of position size, and this persists until the victim restructures their entire position.

### Impact Explanation

**Financial Impact:**
- The victim loses ALL future reward accrual from ALL active reward programs across the obligation
- This is not limited to the reward that was claimed, but affects all deposits and borrows in the obligation
- If multiple reward programs are active with significant APYs, the cumulative loss can be substantial over time

**Affected Parties:**
- Obligation owners with specific borrow/deposit combinations that can form disabled pairings
- Particularly impacts users who have borrowed from reserves 1, 2, 5, 7, 19, 20, 3, or 9, and earn rewards in tokens corresponding to their disabled pairs

**Severity Justification:**
Medium severity because:
- The attack doesn't steal existing funds, but destroys future value accrual
- The claimed rewards are still in the obligation (as deposited ctokens), but future rewards across all reserves are lost
- The victim must completely restructure their position to restart reward accrual
- The impact compounds over time as multiple reward programs are affected

### Likelihood Explanation

**Attacker Capabilities:**
- Any user can execute this attack (permissionless function)
- Attacker only needs to know the obligation_id and wait for reward period to end
- No special privileges or assets required beyond gas fees

**Attack Complexity:**
- Simple: single transaction calling `claim_rewards_and_deposit()`
- Attacker can identify vulnerable obligations by querying those with borrows in target reserves that are earning rewards in disabled pairing tokens
- Front-running opportunity exists when owner attempts to claim after period ends

**Feasibility Conditions:**
- Victim must have borrowed from a target reserve (1, 2, 5, 7, 19, 20, 3, or 9)
- Victim must be earning rewards in a token type corresponding to a disabled pairing reserve
- Victim must NOT already have a deposit in that reward token's reserve (otherwise pairing already exists)
- Reward period must end before victim claims

**Detection and Constraints:**
- Attack is on-chain visible but difficult to prevent once reward period ends
- Victim could avoid by claiming before period ends using `claim_rewards()`, but this requires continuous monitoring and knowledge of disabled pairings
- No economic disincentive for attacker (only gas costs)

**Probability:**
Medium-High for affected obligations, as attackers can systematically identify and target vulnerable positions after reward periods end.

### Recommendation

**Code-Level Mitigation:**
Add a check in `claim_rewards_and_deposit()` to prevent creating newly disabled pairings:

```move
// Before depositing, check if this would create a disabled pairing
let obligation = object_table::borrow(&lending_market.obligations, obligation_id);
let would_create_disabled_pairing = check_would_create_disabled_pairing(
    obligation, 
    deposit_reserve_id
);
assert!(!would_create_disabled_pairing, EWouldCreateDisabledPairing);
```

**Invariant Checks:**
- Ensure `claim_rewards_and_deposit()` cannot change an obligation from non-looped to looped state
- Add event emission when rewards are force-deposited to alert obligation owners
- Consider adding a whitelist or owner approval mechanism for permissionless reward claiming

**Alternative Approach:**
Only allow permissionless claiming if the rewards will be used to repay debt (which improves position health) or if depositing won't create a disabled pairing. Otherwise, require ObligationOwnerCap.

**Test Cases:**
1. Test that `claim_rewards_and_deposit()` reverts when it would create a disabled pairing
2. Test that non-looped obligations cannot be converted to looped via permissionless claiming
3. Test that reward accrual continues after permissionless claiming when no disabled pairing is created

### Proof of Concept

**Initial State:**
- Obligation O has borrowed 1000 tokens from reserve index 1
- Obligation O has deposited 2000 tokens in reserve index 5 (NOT reserve 2)
- Obligation O is earning rewards in token type corresponding to reserve 2
- Reserve 2 is in the disabled pairings list for reserve 1
- Reward program for reserve 2 ends at timestamp T
- Obligation O has other active reward programs ongoing

**Attack Sequence:**
1. Time reaches T (reward period ends)
2. Before owner can claim, attacker calls:
   ```
   claim_rewards_and_deposit(
       lending_market,
       obligation_id: O,
       reward_reserve_id: 2,
       reward_index: X,
       is_deposit_reward: true,
       deposit_reserve_id: 2
   )
   ```
3. Rewards are claimed and deposited as ctokens into reserve 2
4. `deposit_ctokens_into_obligation_by_id()` is called
5. `zero_out_rewards_if_looped()` executes
6. `is_looped()` returns true (borrow reserve 1 + deposit reserve 2 = disabled pairing)
7. All user_reward_manager shares across ALL reserves set to 0

**Expected vs Actual Result:**
- Expected (owner intent): Claim rewards as liquid tokens, maintain reward accrual
- Actual (after attack): Rewards deposited as ctokens, ALL future rewards across ALL reserves permanently stopped until position restructured

**Success Condition:**
After attack, checking the obligation's user_reward_managers shows all shares = 0, and no new rewards accrue in subsequent blocks despite active reward programs.

### Citations

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L699-773)
```text
    /// Permissionless function. Anyone can call this function to claim the rewards
    /// and deposit into the same obligation. This is useful to "crank" rewards for users
    public fun claim_rewards_and_deposit<P, RewardType>(
        lending_market: &mut LendingMarket<P>,
        obligation_id: ID,
        clock: &Clock,
        // array index of reserve that is giving out the rewards
        reward_reserve_id: u64,
        reward_index: u64,
        is_deposit_reward: bool,
        // array index of reserve with type RewardType
        deposit_reserve_id: u64,
        ctx: &mut TxContext,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let mut rewards = claim_rewards_by_obligation_id<P, RewardType>(
            lending_market,
            obligation_id,
            clock,
            reward_reserve_id,
            reward_index,
            is_deposit_reward,
            true,
            ctx,
        );

        let obligation = object_table::borrow(&lending_market.obligations, obligation_id);
        if (gt(obligation::borrowed_amount<P, RewardType>(obligation), decimal::from(0))) {
            repay<P, RewardType>(
                lending_market,
                deposit_reserve_id,
                obligation_id,
                clock,
                &mut rewards,
                ctx,
            );
        };

        let deposit_reserve = vector::borrow_mut(&mut lending_market.reserves, deposit_reserve_id);
        let expected_ctokens = {
            assert!(
                reserve::coin_type(deposit_reserve) == type_name::get<RewardType>(),
                EWrongType,
            );

            floor(
                div(
                    decimal::from(coin::value(&rewards)),
                    reserve::ctoken_ratio(deposit_reserve),
                ),
            )
        };

        if (expected_ctokens == 0) {
            reserve::join_fees<P, RewardType>(deposit_reserve, coin::into_balance(rewards));
        } else {
            let ctokens = deposit_liquidity_and_mint_ctokens<P, RewardType>(
                lending_market,
                deposit_reserve_id,
                clock,
                rewards,
                ctx,
            );

            deposit_ctokens_into_obligation_by_id<P, RewardType>(
                lending_market,
                deposit_reserve_id,
                obligation_id,
                clock,
                ctokens,
                ctx,
            );
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1246-1246)
```text
        obligation::zero_out_rewards_if_looped(obligation, &mut lending_market.reserves, clock);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1282-1290)
```text
        if (fail_if_reward_period_not_over) {
            let pool_reward = option::borrow(
                liquidity_mining::pool_reward(pool_reward_manager, reward_index),
            );
            assert!(
                clock::timestamp_ms(clock) >= liquidity_mining::end_time_ms(pool_reward),
                ERewardPeriodNotOver,
            );
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L877-940)
```text
    public(package) fun is_looped<P>(obligation: &Obligation<P>): bool {
        let target_reserve_array_indices = vector[1, 2, 5, 7, 19, 20, 3, 9];

        // The vector target_reserve_array_indices maps to disabled_pairings_map
        // by corresponding indices of each element
        // target_reserve_index --> pairings disabled
        let disabled_pairings_map = vector[
            vector[2, 5, 7, 19, 20], // 1 --> [2, 5, 7, 19, 20]
            vector[1, 5, 7, 19, 20], // 2 --> [1, 5, 7, 19, 20]
            vector[1, 2, 7, 19, 20], // 5 --> [1, 2, 7, 19, 20]
            vector[1, 2, 5, 19, 20], // 7 --> [1, 2, 5, 19, 20]
            vector[1, 2, 5, 7, 20], // 19 --> [1, 2, 5, 7, 20]
            vector[1, 2, 5, 7, 19], // 20 --> [1, 2, 5, 7, 19]
            vector[9], // 3 --> [9]
            vector[3], // 9 --> [3]
        ];

        let mut i = 0;
        while (i < vector::length(&obligation.borrows)) {
            let borrow = vector::borrow(&obligation.borrows, i);

            // Check if borrow-deposit reserve match
            let deposit_index = find_deposit_index_by_reserve_array_index(
                obligation,
                borrow.reserve_array_index,
            );

            if (deposit_index < vector::length(&obligation.deposits)) {
                return true
            };

            let (has_target_borrow_idx, target_borrow_idx) = vector::index_of(
                &target_reserve_array_indices,
                &borrow.reserve_array_index,
            );

            // If the borrowing is over a targetted reserve
            // we check if the deposit reserve is a disabled pair
            if (has_target_borrow_idx) {
                let disabled_pairs = vector::borrow(&disabled_pairings_map, target_borrow_idx);
                let pair_count = vector::length(disabled_pairs);
                let mut i = 0;

                while (i < pair_count) {
                    let disabled_reserve_array_index = *vector::borrow(disabled_pairs, i);

                    let deposit_index = find_deposit_index_by_reserve_array_index(
                        obligation,
                        disabled_reserve_array_index,
                    );

                    if (deposit_index < vector::length(&obligation.deposits)) {
                        return true
                    };

                    i = i +1;
                };
            };

            i = i + 1;
        };

        false
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/liquidity_mining.move (L355-366)
```text
    public(package) fun change_user_reward_manager_share(
        pool_reward_manager: &mut PoolRewardManager,
        user_reward_manager: &mut UserRewardManager,
        new_share: u64,
        clock: &Clock,
    ) {
        update_user_reward_manager(pool_reward_manager, user_reward_manager, clock, false);

        pool_reward_manager.total_shares =
            pool_reward_manager.total_shares - user_reward_manager.share + new_share;
        user_reward_manager.share = new_share;
    }
```
