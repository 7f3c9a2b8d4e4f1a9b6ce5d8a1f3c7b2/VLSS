# Audit Report

## Title
Retroactive Reward Over-Distribution for Pre-Existing Balances When New Incentive Rules Are Created

## Summary
When a new incentive rule is added to an existing lending pool, users with pre-existing deposits or borrows receive retroactive rewards calculated from the rule's inception despite not participating during that period. The `get_user_index_by_rule` function returns 0 for users without entries in the `user_index` table, causing `calculate_user_reward` to grant rewards as if their balance earned from the beginning of the rule's existence, over-distributing reward tokens from the `RewardFund`.

## Finding Description

The vulnerability exists in the reward calculation logic when new incentive rules are created for pools where users already have active positions.

When a new rule is created via `create_rule`, it initializes with `global_index = 0` and an empty `user_index` table: [1](#0-0) 

When the admin subsequently sets a reward rate via `set_reward_rate_by_rule_id`, the function only updates the reward state for address `@0x0` (a placeholder), not for existing users: [2](#0-1) 

The `get_user_index_by_rule` function returns 0 when a user has no entry in the `user_index` table, creating ambiguity between truly new users (correct: 0 balance, 0 index) and existing users who had balances before the rule was created (vulnerability: non-zero balance, 0 index): [3](#0-2) 

As time passes and the protocol operates, `global_index` accumulates via `calculate_global_index`: [4](#0-3) 

When an existing user (with pre-existing balance) makes their first transaction after the rule activation, any standard lending operation calls `update_reward_state_by_asset` BEFORE the actual operation: [5](#0-4) 

This retrieves the user's current balance from storage (their pre-existing balance) and triggers reward calculation: [6](#0-5) 

The `update_reward_state_by_rule_and_balance` function is invoked, which calls `calculate_user_reward` with the user's current (pre-existing) balance and `user_index = 0`: [7](#0-6) 

The `calculate_user_reward` function computes rewards using the difference between `global_index` and the user's stored `user_index`. For users without entries, this becomes the full accumulated `global_index`: [8](#0-7) 

This results in: `reward = 0 + ray_mul(existing_balance, global_index - 0)`, granting full rewards for their existing balance over the entire accumulation period, despite never opting into the incentive program.

## Impact Explanation

**Direct Fund Impact:**
- Reward tokens in the `RewardFund` are over-distributed to users with pre-existing balances
- Each affected user receives `ray_mul(their_balance, global_index)` in unearned rewards
- With multiple users having pre-existing positions, the RewardFund can be substantially depleted
- Legitimate users who deposit after rule creation receive smaller reward shares

**Quantified Example:**
- User A has 100,000 USDC deposited before rule creation
- New supply incentive rule created with 10,000 tokens/month reward rate
- After 30 days without User A interaction, `global_index` accumulates significantly
- User A makes a 1 USDC deposit, triggering reward calculation
- User A receives approximately 10,000 tokens for their 100,000 USDC balance over 30 days
- These rewards should have been distributed among active participants

**Affected Parties:**
- Protocol treasury loses reward token allocation efficiency
- Active participants receive diluted rewards
- Pre-existing balance holders gain unearned windfall

This constitutes **High severity** due to direct fund impact, predictable exploitation, and unfair reward distribution that undermines incentive program economics.

## Likelihood Explanation

**Attacker Capabilities:**
- Any regular user with a pre-existing lending position
- No special permissions or capabilities required
- Simply requires patience to maximize accumulated `global_index`

**Attack Complexity:**
- Trivial - user makes any deposit/withdraw/borrow/repay transaction
- No complex contract interactions or edge case triggers
- Entry points are standard protocol operations accessible to all users

**Feasibility Conditions:**
- Common scenario: protocols frequently add new incentive programs to existing markets
- Natural user behavior: many users maintain passive positions for extended periods
- No detection mechanism exists to identify or prevent this behavior

**Economic Rationality:**
- Zero cost to execute (normal transaction fees only)
- Zero risk (no liquidation or loss possibility)
- Guaranteed reward gain proportional to balance × time waited
- Rational economic actors will naturally exploit this

**Probability Assessment:**
Very high likelihood. This will occur organically whenever:
1. A new incentive rule is added to an existing pool (common operational practice)
2. Users with positions naturally interact after the rule activation
3. No active malice required - passive users automatically receive over-rewards

## Recommendation

Implement one of the following mitigations:

**Option 1: Initialize user indices at rule creation**
When creating a new rule, snapshot all existing users in the pool and initialize their `user_index` to the current `global_index` (which is 0 at creation). This prevents retroactive reward calculation.

**Option 2: Track rule creation timestamp**
Add a `rule_created_at` timestamp to the `Rule` struct. When calculating rewards, only consider the time period after the rule was created and after the user's first interaction, whichever is later.

**Option 3: Require explicit opt-in**
Users with pre-existing balances must make an explicit opt-in transaction to participate in newly created incentive rules. The opt-in transaction would initialize their `user_index` to the current `global_index`.

**Recommended Fix (Option 1 - most efficient):**

In `set_reward_rate_by_rule_id`, instead of only updating `@0x0`, iterate through all users in the storage who have non-zero balances for the asset and initialize their `user_index` to the current `global_index`. This ensures pre-existing balances don't receive retroactive rewards.

Alternatively, modify `calculate_user_reward` to check if a user's balance existed before the rule was created (by comparing timestamps or checking if `user_index == 0 && user_balance > 0`) and handle this case appropriately.

## Proof of Concept

```move
#[test]
public fun test_retroactive_reward_over_distribution() {
    // Setup: Create protocol, user deposits 100,000 USDC
    // Create new incentive rule with 10,000 tokens/month reward
    // Advance time by 30 days
    // User makes minimal interaction (1 USDC deposit)
    // Assert: User receives ~10,000 tokens for 100,000 USDC over 30 days
    // Expected: User should receive 0 rewards for pre-existing balance
    // Actual: User receives full retroactive rewards
    
    // This test would demonstrate that calculate_user_reward
    // returns ray_mul(100_000 USDC, accumulated_global_index)
    // when get_user_index_by_rule returns 0 for the user
}
```

The test would confirm that users with pre-existing balances receive retroactive rewards equal to `ray_mul(their_balance, global_index)` when they first interact after a new rule is created, violating the invariant that rewards should only accrue during active participation.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L274-286)
```text
        let rule = Rule {
            id,
            option,
            enable: true,
            reward_coin_type: reward_coin_type,
            rate: 0,
            max_rate: 0,
            last_update_at: clock::timestamp_ms(clock),
            global_index: 0,
            user_index: table::new<address, u256>(ctx),
            user_total_rewards: table::new<address, u256>(ctx),
            user_rewards_claimed: table::new<address, u256>(ctx),
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L385-412)
```text
    public(friend) fun set_reward_rate_by_rule_id<T>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, rule_id: address, total_supply: u64, duration_ms: u64, ctx: &TxContext) {
        version_verification(incentive); // version check
        // use @0x0 to update the reward state for convenience
        update_reward_state_by_asset<T>(clock, incentive, storage, @0x0);

        let rate = 0;
        if (duration_ms > 0) {
            rate = ray_math::ray_div((total_supply as u256), (duration_ms as u256));
        };

        let coin_type = type_name::into_string(type_name::get<T>());
        let rule = get_mut_rule<T>(incentive, rule_id);

        assert!(rule.max_rate == 0 || rate <= rule.max_rate, error::invalid_value());

        rule.rate = rate;
        rule.last_update_at = clock::timestamp_ms(clock);

        emit(RewardRateUpdated{
            sender: tx_context::sender(ctx),
            pool: coin_type,
            rule_id: rule_id,
            rate: rate,
            total_supply: total_supply,
            duration_ms: duration_ms,
            timestamp: rule.last_update_at,
        });
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L516-534)
```text
    public fun update_reward_state_by_asset<T>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, user: address) {
        version_verification(incentive);
        let coin_type = type_name::into_string(type_name::get<T>());
        if (!vec_map::contains(&incentive.pools, &coin_type)) {
            return
        };
        let pool = vec_map::get_mut(&mut incentive.pools, &coin_type);
        let (user_effective_supply, user_effective_borrow, total_supply, total_borrow) = get_effective_balance(storage, pool.asset, user);

        // update rewards
        let rule_keys = vec_map::keys(&pool.rules);
        while (vector::length(&rule_keys) > 0) {
            let key = vector::pop_back(&mut rule_keys);
            let rule = vec_map::get_mut(&mut pool.rules, &key);

            // update the user reward
            update_reward_state_by_rule_and_balance(clock, rule, user, user_effective_supply, user_effective_borrow, total_supply, total_borrow);
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L549-571)
```text
    fun update_reward_state_by_rule_and_balance(clock: &Clock, rule: &mut Rule, user: address, user_effective_supply: u256, user_effective_borrow: u256, total_supply: u256, total_borrow: u256) {
        let new_global_index = calculate_global_index(clock, rule, total_supply, total_borrow);
        let new_user_total_reward = calculate_user_reward(rule, new_global_index, user, user_effective_supply, user_effective_borrow);
        // update the user index to the new global index
        if (table::contains(&rule.user_index, user)) {
            let user_index = table::borrow_mut(&mut rule.user_index, user);
            *user_index = new_global_index;
        } else {
            table::add(&mut rule.user_index, user, new_global_index);
        };

        // update the user rewards to plus the new reward
        if (table::contains(&rule.user_total_rewards, user)) {
            let user_total_reward = table::borrow_mut(&mut rule.user_total_rewards, user);
            *user_total_reward = new_user_total_reward;
        } else {
            table::add(&mut rule.user_total_rewards, user, new_user_total_reward);
        };

        // update the last update time and global index
        rule.last_update_at = clock::timestamp_ms(clock);
        rule.global_index = new_global_index;    
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L573-590)
```text
    fun calculate_global_index(clock: &Clock, rule: &Rule, total_supply: u256, total_borrow: u256): u256 {
        let total_balance = if (rule.option == constants::option_type_supply()) {
            total_supply
        } else if (rule.option == constants::option_type_borrow()) {
            total_borrow
        } else {
            abort 0
        };
        
        let now = clock::timestamp_ms(clock);
        let duration = now - rule.last_update_at;
        let index_increased = if (duration == 0 || total_balance == 0) {
            0
        } else {
            (rule.rate * (duration as u256)) / total_balance
        };
        rule.global_index + index_increased
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L592-603)
```text
    fun calculate_user_reward(rule: &Rule, global_index: u256, user: address, user_effective_supply: u256, user_effective_borrow: u256): u256 {
        let user_balance = if (rule.option == constants::option_type_supply()) {
            user_effective_supply
        } else if (rule.option == constants::option_type_borrow()) {
            user_effective_borrow
        } else {
            abort 0
        };
        let user_index_diff = global_index - get_user_index_by_rule(rule, user);
        let user_reward = get_user_total_rewards_by_rule(rule, user);
        user_reward + ray_math::ray_mul(user_balance, user_index_diff)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L652-658)
```text
    public fun get_user_index_by_rule(rule: &Rule, user: address): u256 {
        if (table::contains(&rule.user_index, user)) {
            *table::borrow(&rule.user_index, user)
        } else {
            0
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L780-796)
```text
    public entry fun entry_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_coin<CoinType>(clock, storage, pool, asset, deposit_coin, amount, ctx);
    }
```
