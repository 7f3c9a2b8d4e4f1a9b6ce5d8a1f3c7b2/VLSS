### Title
Retroactive Reward Over-Distribution for Pre-Existing Balances When New Incentive Rules Are Created

### Summary
When a new incentive rule is added to an existing lending pool, users with pre-existing deposits or borrows receive retroactive rewards from `global_index` inception despite not participating in the incentive program during that period. The `get_user_index_by_rule` function returns 0 for users without an entry, causing `calculate_user_reward` to compute rewards as if their balance earned from the beginning of the rule's existence, over-distributing reward tokens.

### Finding Description

The vulnerability exists in the reward calculation logic when new incentive rules are created for pools where users already have active positions. [1](#0-0) 

The `calculate_user_reward` function computes rewards using the difference between `global_index` and the user's stored `user_index`: [2](#0-1) 

The `get_user_index_by_rule` function returns 0 when a user has no entry in the `user_index` table. This creates ambiguity between two distinct scenarios:
1. Truly new users who join after the rule exists (0 balance, 0 index) - **Correct behavior**
2. Existing users who had balances before the rule was created (non-zero balance, 0 index) - **Vulnerability**

When a new rule is created via `create_rule`, it initializes with `global_index = 0` and an empty `user_index` table: [3](#0-2) 

When the admin subsequently sets a reward rate: [4](#0-3) 

The function only updates state for address `@0x0` (a placeholder), not for existing users. As time passes and other users interact, `global_index` accumulates via: [5](#0-4) 

When an existing user (with pre-existing balance) makes their first transaction after the rule activation, `update_reward_state_by_rule_and_balance` is invoked: [6](#0-5) 

At line 551, `calculate_user_reward` is called with their current (pre-existing) balance and `user_index = 0`, resulting in:
```
reward = 0 + ray_mul(existing_balance, global_index - 0)
```

This grants full rewards for their existing balance over the entire accumulation period, despite never opting into the incentive program.

### Impact Explanation

**Direct Fund Impact:**
- Reward tokens in the `RewardFund` are over-distributed to users with pre-existing balances
- Each affected user receives: `ray_mul(their_balance, global_index)` in unearned rewards
- With multiple users having pre-existing positions, the RewardFund can be substantially depleted
- Legitimate users who deposit after rule creation receive smaller reward shares

**Quantified Example:**
- User A has 100,000 USDC deposited before rule creation
- New supply incentive rule created with 10,000 tokens/month reward rate
- After 30 days without User A interaction, `global_index` accumulates significantly
- User A makes a 1 USDC deposit, triggering reward calculation
- User A receives ~10,000 tokens for their 100,000 USDC balance over 30 days
- These were rewards that should have been distributed among active participants

**Affected Parties:**
- Protocol treasury loses reward token allocation efficiency
- Active participants receive diluted rewards
- Pre-existing balance holders gain unearned windfall

**Severity Justification:**
High severity due to direct fund impact, predictable exploitation, and unfair reward distribution that undermines incentive program economics.

### Likelihood Explanation

**Attacker Capabilities:**
- Any regular user with a pre-existing lending position
- No special permissions or capabilities required
- Simply requires patience to maximize accumulated `global_index`

**Attack Complexity:**
- Trivial - user makes any deposit/withdraw/borrow/repay transaction
- No complex contract interactions or edge case triggers
- Entry points are standard protocol operations: [7](#0-6) 

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

### Recommendation

**Immediate Fix:**
Modify `set_reward_rate_by_rule_id` to snapshot the current `global_index` and initialize all existing users' `user_index` to this value when activating rewards:

```move
// When setting rate > 0 for the first time or after being 0
if (previous_rate == 0 && rate > 0) {
    // Initialize user_index for all existing users to current global_index
    // This requires tracking active users or processing at first interaction
}
```

**Better Design:**
1. Track rule activation timestamp separately from `last_update_at`
2. In `calculate_user_reward`, use `max(user_index, rule_activation_global_index)` instead of raw `user_index`
3. Store the `global_index` value when a rule is activated with `rate > 0`

**Invariant Checks:**
- Assert that `user_index` for new entries equals current `global_index` when rule is active
- Add event emission when initializing user rewards to track first participation
- Validate reward calculations don't exceed theoretical maximum based on activation time

**Test Cases:**
1. Create rule, set rate, verify pre-existing users get 0 retroactive rewards on first interaction
2. Create rule, users deposit, verify only post-activation balance earns rewards
3. Multiple users with various entry times, verify proportional reward distribution

### Proof of Concept

**Initial State:**
- Lending pool exists with User A having 10,000 tokens deposited at T0
- No incentive rules exist yet for this asset

**Transaction 1 (T1 = Day 0, Block 100):**
Admin calls `create_rule<ASSET, REWARD_TOKEN>` with `option = SUPPLY`
- `rule.global_index = 0`
- `rule.user_index` table is empty (User A not in table)
- `rule.rate = 0`

**Transaction 2 (T2 = Day 0, Block 200):**
Admin calls `set_reward_rate_by_rule_id` with `total_supply = 100_000 tokens`, `duration = 30 days`
- `rule.rate = 100_000 / (30 * 86400000)` per millisecond
- `rule.last_update_at = T2`
- User A's `user_index` still not in table

**Time Passes (T2 → T3 = 30 days):**
Other users interact, causing `global_index` to accumulate through normal deposits/withdraws
- Assume `global_index` reaches value X (proportional to time × rate / total_balance)

**Transaction 3 (T3 = Day 30, Block 5000):**
User A makes a small 1 token deposit
- `update_reward_state_by_asset` is called for User A
- `get_effective_balance` returns User A's balance = 10,001 tokens
- `get_user_index_by_rule(rule, User_A)` returns 0 (not in table)
- `user_index_diff = X - 0 = X`
- `new_user_total_reward = 0 + ray_mul(10,001, X)` = **Full rewards for 10,000 tokens over 30 days**

**Expected vs Actual Result:**
- **Expected:** User A should receive rewards only for the 1 token deposited at T3, prorated for remaining time
- **Actual:** User A receives rewards for full 10,001 token balance as if held from T2, obtaining ~10,000 tokens worth of rewards they never earned

**Success Condition:**
User A's claimed reward balance exceeds the theoretical maximum based on their actual participation period, confirming over-distribution from the RewardFund.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L260-296)
```text
    public(friend) fun create_rule<T, RewardCoinType>(clock: &Clock, incentive: &mut Incentive, option: u8, ctx: &mut TxContext) {
        version_verification(incentive); // version check
        assert!(option == constants::option_type_supply() || option == constants::option_type_borrow(), error::invalid_option());

        let coin_type = type_name::into_string(type_name::get<T>());
        assert!(vec_map::contains(&incentive.pools, &coin_type), error::pool_not_found());

        let pool = vec_map::get_mut(&mut incentive.pools, &coin_type);

        let reward_coin_type = type_name::into_string(type_name::get<RewardCoinType>());
        assert!(!contains_rule(pool, option, reward_coin_type), error::duplicate_config());

        let id = object::new(ctx);
        let addr = object::uid_to_address(&id);
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

        vec_map::insert(&mut pool.rules, addr, rule);
        emit(RuleCreated{
            sender: tx_context::sender(ctx),
            pool: coin_type,
            rule_id: addr,
            option: option,
            reward_coin_type: reward_coin_type,
        });
    }
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
