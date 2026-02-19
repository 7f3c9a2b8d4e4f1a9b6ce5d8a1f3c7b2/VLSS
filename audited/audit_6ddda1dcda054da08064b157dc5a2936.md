### Title
Improper State Management in Rule Disable/Re-enable Allows Unintended Reward Accrual During Disabled Period

### Summary
The `disable_incentive_v3_by_rule_id()` function only sets the `enable` flag to `false` without updating the `last_update_at` timestamp or clearing the reward `rate`. When a rule is subsequently re-enabled, the stale `last_update_at` value causes the reward calculation to include the entire disabled period, resulting in unintended reward distribution to users for a time when rewards should have been paused.

### Finding Description

The vulnerability exists in the interaction between three key functions:

**1. Incomplete Disable Logic:** [1](#0-0) 

The `disable_incentive_v3_by_rule_id()` function only calls `set_enable_by_rule_id()` which exclusively modifies the `enable` boolean: [2](#0-1) 

Critical fields remain unchanged:
- `last_update_at` is NOT updated to the disable timestamp
- `rate` remains at its active value (not cleared/frozen)
- `global_index` continues from its previous state

**2. Enable Flag Only Gates Claiming, Not Reward Accrual:**

The `enable` flag is checked only in the claim path to return early: [3](#0-2) 

However, the critical `update_reward_state_by_asset()` function (called on every deposit/withdraw/borrow/repay operation) iterates through ALL rules WITHOUT checking the `enable` flag: [4](#0-3) 

This unconditionally calls `update_reward_state_by_rule_and_balance()` which calculates rewards: [5](#0-4) 

**3. Stale Timestamp Causes Incorrect Duration Calculation:**

The `calculate_global_index()` function computes the reward accumulation duration as the difference between current time and `last_update_at`: [6](#0-5) 

When a rule is disabled and later re-enabled without `last_update_at` being updated, the duration calculation spans the entire period including when the rule was disabled, causing rewards to accrue as if the rule was never disabled.

**Root Cause:**
The protocol conflates two distinct concepts:
1. Eligibility to claim (controlled by `enable` flag)  
2. Active reward accrual (should be controlled by `enable` flag but is not)

The `Rule` struct maintains these critical timing fields: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**
When a rule is disabled and re-enabled, the protocol distributes rewards for the disabled period, causing:
- Protocol reward fund depletion beyond intended allocation
- Users receive more rewards than entitled (theft from reward fund)
- Breaks the fundamental invariant that disabled rules should not distribute rewards

**Concrete Impact Quantification:**
If a rule with rate R is disabled for time period T:
- Intended rewards during T: 0
- Actual rewards accrued: R × T × (user_balance / total_balance)
- Loss to protocol: The full amount of rewards for period T

For example, if a 1000 USDT/day reward rule is disabled for 30 days then re-enabled, users will receive 30,000 USDT that should not have been distributed.

**Who Is Affected:**
- Protocol reward funds are depleted
- Users who were active during and after the disabled period receive unearned rewards
- Creates unfair distribution compared to users who only participated during intended active periods

**Severity Justification - Medium:**
This is not a direct theft by an attacker but a protocol logic flaw that causes systematic reward over-distribution whenever rules are disabled and re-enabled, which is a normal operational pattern for reward management.

### Likelihood Explanation

**Reachable Entry Point:**
This issue manifests through the standard admin workflow:
1. Admin calls `disable_incentive_v3_by_rule_id()` (authorized operation)
2. Time passes
3. Admin calls `enable_incentive_v3_by_rule_id()` (authorized operation)
4. Any user performs deposit/withdraw/borrow/repay triggering reward calculation [8](#0-7) 

**Attack Complexity:**
No attacker action required - this is an inherent protocol flaw. The vulnerability triggers through legitimate admin operations.

**Feasibility Conditions:**
Occurs whenever:
- An admin temporarily disables a rule (common for reward adjustments, funding issues, or strategic pauses)
- The rule is later re-enabled
- Users interact with the protocol afterward

**Probability:**
HIGH - Disabling and re-enabling rules is a standard operational pattern for incentive management. The existing test suite does not cover this scenario (tests only disable but never re-enable): [9](#0-8) 

### Recommendation

**Immediate Mitigation:**

1. Update `set_enable_by_rule_id()` to properly manage state on disable:

```move
public(friend) fun set_enable_by_rule_id<T>(
    clock: &Clock,  // Add clock parameter
    incentive: &mut Incentive, 
    storage: &mut Storage,  // Add storage parameter
    rule_id: address, 
    enable: bool, 
    ctx: &TxContext
) {
    version_verification(incentive);
    
    // Update reward state BEFORE changing enable flag
    update_reward_state_by_asset<T>(clock, incentive, storage, @0x0);
    
    let rule = get_mut_rule<T>(incentive, rule_id);
    rule.enable = enable;
    
    // Update last_update_at to prevent stale timestamp
    rule.last_update_at = clock::timestamp_ms(clock);
    
    emit(RewardStateUpdated{
        sender: tx_context::sender(ctx),
        rule_id: rule_id,
        enable: enable,
    });
}
```

2. Add `enable` check in `update_reward_state_by_asset()`:

```move
while (vector::length(&rule_keys) > 0) {
    let key = vector::pop_back(&mut rule_keys);
    let rule = vec_map::get_mut(&mut pool.rules, &key);
    
    // Skip disabled rules during reward updates
    if (!rule.enable) {
        // Update last_update_at to current time to prevent stale timestamp
        rule.last_update_at = clock::timestamp_ms(clock);
        continue
    };
    
    update_reward_state_by_rule_and_balance(...);
}
```

**Test Cases to Add:**

1. Test disable → time passage → re-enable → verify no rewards accrue for disabled period
2. Test disable → user operations → re-enable → verify correct reward boundaries
3. Test multiple disable/enable cycles with varying durations

### Proof of Concept

**Initial State:**
- Rule created at T0 with rate = 1000 tokens/day
- User deposits 100 USDT at T0
- Total pool = 1000 USDT
- `last_update_at` = T0

**Step 1 (T1 = Day 10):** Admin disables rule
- `disable_incentive_v3_by_rule_id<USDT>()` called
- `rule.enable` = false
- `rule.last_update_at` = T0 (UNCHANGED)
- `rule.rate` = 1000 tokens/day (UNCHANGED)

**Step 2 (T1 to T2):** 20 days pass with rule disabled
- Intended reward accrual: 0 tokens
- Users cannot claim (blocked by enable check)

**Step 3 (T2 = Day 30):** Admin re-enables rule
- `enable_incentive_v3_by_rule_id<USDT>()` called  
- `rule.enable` = true
- `rule.last_update_at` = T0 (STILL STALE!)

**Step 4 (T3 = Day 31):** User makes deposit
- `update_reward_state_by_asset()` called
- `calculate_global_index()` computes:
  - `duration` = T3 - T0 = 31 days (includes 20 disabled days!)
  - `index_increased` = (1000 tokens/day × 31 days) / 1000 USDT = 31 tokens per USDT
- User's reward includes 20,000 tokens from disabled period

**Expected Result:** User should receive ~11,000 tokens (10 days before disable + 1 day after re-enable)

**Actual Result:** User receives ~31,000 tokens (includes 20 days of disabled period)

**Success Condition:** Protocol distributes 20,000 extra tokens that should not have been rewarded, depleting the reward fund beyond intended allocation.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L132-134)
```text
    public fun enable_incentive_v3_by_rule_id<T>(_: &IncentiveOwnerCap, incentive: &mut IncentiveV3, rule_id: address, ctx: &mut TxContext) {
        incentive_v3::set_enable_by_rule_id<T>(incentive, rule_id, true, ctx)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L136-138)
```text
    public fun disable_incentive_v3_by_rule_id<T>(_: &IncentiveOwnerCap, incentive: &mut IncentiveV3, rule_id: address, ctx: &mut TxContext) {
        incentive_v3::set_enable_by_rule_id<T>(incentive, rule_id, false, ctx)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L49-61)
```text
    struct Rule has key, store {
        id: UID,
        option: u8,
        enable: bool,
        reward_coin_type: String,
        rate: u256, // RAY number,ray_div(total_release, duration) --> 20usdt in 1month = ray_div(20 * 1e6, (86400 * 30 * 1000)) = 7.716049575617284e+24
        max_rate: u256, // rate limit to prevent operation errors --> 0 means no limit
        last_update_at: u64, // milliseconds
        global_index: u256,
        user_index: Table<address, u256>,
        user_total_rewards: Table<address, u256>, // total rewards of the user
        user_rewards_claimed: Table<address, u256>, // total rewards of the user claimed
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L359-369)
```text
    public(friend) fun set_enable_by_rule_id<T>(incentive: &mut Incentive, rule_id: address, enable: bool, ctx: &TxContext) {
        version_verification(incentive); // version check
        let rule = get_mut_rule<T>(incentive, rule_id);
        rule.enable = enable;

        emit(RewardStateUpdated{
            sender: tx_context::sender(ctx),
            rule_id: rule_id,
            enable: enable,
        });
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L453-456)
```text
        // continue if the rule is not enabled
        if (!rule.enable) {
            return (rule.global_index, balance::zero<RewardCoinType>())
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L525-533)
```text
        // update rewards
        let rule_keys = vec_map::keys(&pool.rules);
        while (vector::length(&rule_keys) > 0) {
            let key = vector::pop_back(&mut rule_keys);
            let rule = vec_map::get_mut(&mut pool.rules, &key);

            // update the user reward
            update_reward_state_by_rule_and_balance(clock, rule, user, user_effective_supply, user_effective_borrow, total_supply, total_borrow);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/incentive_v3_tests/incentive_v3_integration.test.move (L619-630)
```text
        // 11. Disable the USDC->USDC borrow rule for user A
        test_scenario::next_tx(scenario_mut, OWNER);
        {
            let owner_cap = test_scenario::take_from_sender<IncentiveOwnerCap>(scenario_mut);
            let incentive = test_scenario::take_shared<Incentive_V3>(scenario_mut);
            
            let (addr, _, _, _, _) = incentive_v3::get_rule_params_for_testing<USDC_TEST_V2, COIN_TEST_V2>(&incentive, 3);
            manage::disable_incentive_v3_by_rule_id<USDC_TEST_V2>(&owner_cap, &mut incentive, addr, test_scenario::ctx(scenario_mut));

            test_scenario::return_shared(incentive);
            test_scenario::return_to_sender(scenario_mut, owner_cap);
        };
```
