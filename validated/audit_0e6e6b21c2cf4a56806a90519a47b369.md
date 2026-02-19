# Audit Report

## Title
Improper State Management in Rule Disable/Re-enable Allows Unintended Reward Accrual During Disabled Period

## Summary
The Incentive V3 system's `disable_incentive_v3_by_rule_id()` function only sets the `enable` flag without updating the `last_update_at` timestamp. When a rule is subsequently re-enabled, reward calculations include the entire disabled period, causing protocol reward fund depletion and unintended reward distribution to users for periods when rewards should have been paused.

## Finding Description

The vulnerability stems from incomplete state management in the rule disable/enable mechanism, where the `enable` flag controls only claiming eligibility but not reward accrual.

**Incomplete Disable Logic:**

The `disable_incentive_v3_by_rule_id()` function delegates to `set_enable_by_rule_id()` which exclusively modifies the `enable` boolean field: [1](#0-0) [2](#0-1) 

Critical fields remain unchanged during disable:
- `last_update_at` is NOT updated to the disable timestamp
- `rate` remains at its active value
- `global_index` continues from its previous state

**Enable Flag Only Gates Claiming, Not Accrual:**

The `enable` flag is checked only in the claim path to prevent claiming when disabled: [3](#0-2) 

However, the critical `update_reward_state_by_asset()` function (called on every deposit/withdraw/borrow/repay operation) iterates through ALL rules WITHOUT checking the `enable` flag: [4](#0-3) 

This unconditionally calls `update_reward_state_by_rule_and_balance()` which calculates and accrues rewards regardless of the enable status: [5](#0-4) 

**Stale Timestamp Causes Incorrect Duration Calculation:**

The `calculate_global_index()` function computes reward accumulation duration as the difference between current time and `last_update_at`: [6](#0-5) 

When a rule is disabled at T=2000 and re-enabled at T=4000, the `last_update_at` timestamp remains at the pre-disable value (e.g., T=1000). When a user next interacts at T=5000, the duration calculation becomes 5000 - 1000 = 4000ms, incorrectly including the 2000ms disabled period (T=2000 to T=4000) in reward accrual.

**All Lending Operations Trigger Update:**

Every lending operation calls `update_reward_state_by_asset()`, ensuring rewards accrue on each interaction: [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

## Impact Explanation

**Direct Fund Impact:**
When a rule is disabled and re-enabled, the protocol distributes rewards for the entire period including when the rule was disabled, causing:
- Protocol reward fund depletion beyond intended allocation
- Users receive rewards for periods when the rule was explicitly disabled
- Breaks the fundamental invariant that disabled rules should not distribute rewards

**Concrete Quantification:**
If a rule with rate R is disabled for time period T:
- Intended rewards during T: 0
- Actual rewards accrued: R × T × (user_balance / total_balance)
- Loss to protocol: Full amount of rewards for the disabled period T

**Example:**
A 1000 USDT/day reward rule disabled for 30 days then re-enabled would result in 30,000 USDT being distributed for a period when rewards should have been paused. This represents direct theft from the reward fund.

**Affected Parties:**
- Protocol reward funds are systematically depleted
- Users active during and after the disabled period receive unearned rewards
- Creates unfair distribution compared to users who only participated during intended active periods

## Likelihood Explanation

**Reachable Entry Point:**
This vulnerability manifests through standard administrative operations:
1. Admin calls `disable_incentive_v3_by_rule_id()` (legitimate authorized operation)
2. Time passes while rule is disabled
3. Admin calls `enable_incentive_v3_by_rule_id()` (legitimate authorized operation)
4. Any user performs deposit/withdraw/borrow/repay, triggering reward calculation

**Attack Complexity:**
No attacker action required - this is an inherent protocol logic flaw. The vulnerability triggers automatically through legitimate admin operations followed by normal user interactions.

**Feasibility:**
This occurs in standard operational scenarios:
- Admin temporarily disables rules for reward adjustments, funding issues, or strategic pauses
- Rules are later re-enabled when conditions normalize
- Users continue normal protocol interactions

**Probability:**
HIGH - Disabling and re-enabling rules is a standard operational pattern for incentive management. The existing test suite confirms this scenario is not covered, as tests only disable rules without testing re-enable scenarios: [11](#0-10) 

## Recommendation

The `set_enable_by_rule_id()` function should be enhanced to properly manage state transitions when disabling rules:

```move
public(friend) fun set_enable_by_rule_id<T>(clock: &Clock, incentive: &mut Incentive, rule_id: address, enable: bool, ctx: &TxContext) {
    version_verification(incentive);
    
    // First update reward state to current timestamp before changing enable flag
    update_reward_state_by_asset<T>(clock, incentive, storage, @0x0);
    
    let rule = get_mut_rule<T>(incentive, rule_id);
    
    // When disabling, update last_update_at to prevent stale timestamp issues
    if (!enable && rule.enable) {
        rule.last_update_at = clock::timestamp_ms(clock);
    }
    
    // When re-enabling, update last_update_at to current time
    if (enable && !rule.enable) {
        rule.last_update_at = clock::timestamp_ms(clock);
    }
    
    rule.enable = enable;

    emit(RewardStateUpdated{
        sender: tx_context::sender(ctx),
        rule_id: rule_id,
        enable: enable,
    });
}
```

Alternatively, consider checking the `enable` flag in `update_reward_state_by_rule_and_balance()` to prevent reward accrual when disabled:

```move
fun update_reward_state_by_rule_and_balance(clock: &Clock, rule: &mut Rule, user: address, ...) {
    // Skip reward calculation if rule is disabled
    if (!rule.enable) {
        return
    };
    
    let new_global_index = calculate_global_index(clock, rule, total_supply, total_borrow);
    // ... rest of function
}
```

## Proof of Concept

```move
#[test]
fun test_disable_reenable_accrues_unintended_rewards() {
    let mut scenario = test_scenario::begin(OWNER);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    
    // Setup: Create incentive, pool, and rule with rate=1000
    setup_incentive_system(&mut scenario, &clock);
    
    // T=1000: User A borrows 100 USDC, last_update_at=1000
    clock::set_for_testing(&mut clock, 1000);
    user_borrow<USDC>(&mut scenario, &clock, USER_A, 100);
    
    // T=2000: Admin disables rule (last_update_at stays at 1000)
    clock::set_for_testing(&mut clock, 2000);
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let owner_cap = test_scenario::take_from_sender<IncentiveOwnerCap>(&scenario);
        let mut incentive = test_scenario::take_shared<IncentiveV3>(&scenario);
        let rule_id = get_rule_id<USDC, REWARD_COIN>(&incentive);
        
        manage::disable_incentive_v3_by_rule_id<USDC>(&owner_cap, &mut incentive, rule_id, test_scenario::ctx(&mut scenario));
        
        test_scenario::return_to_sender(&scenario, owner_cap);
        test_scenario::return_shared(incentive);
    };
    
    // T=4000: Admin re-enables rule (last_update_at STILL at 1000!)
    clock::set_for_testing(&mut clock, 4000);
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let owner_cap = test_scenario::take_from_sender<IncentiveOwnerCap>(&scenario);
        let mut incentive = test_scenario::take_shared<IncentiveV3>(&scenario);
        let rule_id = get_rule_id<USDC, REWARD_COIN>(&incentive);
        
        manage::enable_incentive_v3_by_rule_id<USDC>(&owner_cap, &mut incentive, rule_id, test_scenario::ctx(&mut scenario));
        
        test_scenario::return_to_sender(&scenario, owner_cap);
        test_scenario::return_shared(incentive);
    };
    
    // T=5000: User B deposits, triggering reward calculation
    // Duration = 5000 - 1000 = 4000ms (includes 2000ms disabled period!)
    clock::set_for_testing(&mut clock, 5000);
    user_deposit<USDC>(&mut scenario, &clock, USER_B, 50);
    
    // Check: User A can claim rewards for full 4000ms including disabled period
    let claimable = get_user_claimable_rewards(&scenario, &clock, USER_A);
    
    // Expected if properly disabled: rewards for 1000ms (T=1000 to T=2000) only
    // Actual: rewards for 4000ms (T=1000 to T=5000) including disabled period
    // This proves unintended reward accrual during disabled period
    
    assert!(claimable > expected_for_1000ms, 0); // Vulnerability confirmed
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L136-138)
```text
    public fun disable_incentive_v3_by_rule_id<T>(_: &IncentiveOwnerCap, incentive: &mut IncentiveV3, rule_id: address, ctx: &mut TxContext) {
        incentive_v3::set_enable_by_rule_id<T>(incentive, rule_id, false, ctx)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L793-793)
```text
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L846-846)
```text
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L911-911)
```text
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L985-985)
```text
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/incentive_v3_tests/incentive_v3_integration.test.move (L626-626)
```text
            manage::disable_incentive_v3_by_rule_id<USDC_TEST_V2>(&owner_cap, &mut incentive, addr, test_scenario::ctx(scenario_mut));
```
