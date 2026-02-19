# Audit Report

## Title
Unbounded Reward Accumulation Allows Early Users to Drain Reward Pool, Causing DoS for Later Claimants

## Summary
The `incentive_v3` reward distribution mechanism lacks a critical balance check before splitting rewards from the reward fund. This allows users to accumulate rewards that collectively exceed the available fund balance, causing later claimants to experience permanent transaction failures when attempting to claim their legitimately earned rewards.

## Finding Description

The vulnerability exists in the reward claiming flow within the `incentive_v3` module. When users claim rewards, the function directly attempts to split the reward amount from the reward fund without verifying sufficient balance exists. [1](#0-0) 

The reward calculation itself is unbounded, computing rewards as the user's balance multiplied by the index difference, with no cap to ensure the sum of all user rewards stays within the reward fund capacity. [2](#0-1) 

While the protocol has a `max_rate` field, it only limits the rate of reward accrual, not the total accumulated rewards that can be claimed. [3](#0-2) 

This design contrasts sharply with the protocol's own `incentive_v2` implementation, which explicitly caps rewards by checking if distributed rewards plus the new reward exceed the total supply, and limits the reward accordingly. [4](#0-3) 

Similarly, the protocol's `reward_manager` module demonstrates the correct pattern by asserting that the reward amount does not exceed the available balance before attempting to split. [5](#0-4) 

The vulnerability is reachable through multiple public entry points that allow any user to claim their accumulated rewards. [6](#0-5) 

## Impact Explanation

**HIGH Severity** - This vulnerability results in direct loss of user funds and permanent denial of service:

1. **Direct Fund Loss**: Users who legitimately earned rewards by supplying or borrowing assets will permanently lose access to their rewards once the fund is depleted by early claimants.

2. **Permanent DoS**: When the reward fund balance is insufficient, the Sui Move `balance::split` operation will abort the transaction. Later users cannot claim their rewards until administrators manually deposit additional funds.

3. **Bank Run Dynamic**: Once users realize the fund may be depleted, this creates a race condition where users rush to claim first, exacerbating the problem.

4. **Quantifiable Impact**: If a reward fund contains 10,000 tokens but total calculated user rewards equal 15,000 tokens, the first claimants will succeed in claiming up to 10,000 tokens, while the remaining 5,000 tokens worth of legitimate claims will fail permanently.

## Likelihood Explanation

**HIGH Likelihood** - This occurs through normal protocol usage without any malicious intent:

1. **Natural Occurrence**: The vulnerability triggers when:
   - Admin sets a reward rate via `set_reward_rate_by_rule_id`
   - Users supply/borrow assets normally, accumulating rewards over time
   - Total accumulated rewards exceed the reward fund balance
   - Users attempt to claim their rewards

2. **No Attack Required**: This is not an exploit requiring special knowledge or malicious actions. It happens naturally if the reward rate is set too high relative to fund deposits, or if the fund is not topped up regularly.

3. **No Privilege Required**: Any user participating in the lending protocol can trigger this by simply using the protocol normally and claiming their earned rewards.

4. **Realistic Preconditions**: All preconditions are standard operational scenarios for a lending protocol with incentive rewards.

## Recommendation

Implement a balance check before attempting to split rewards from the reward fund. The fix should follow the same pattern used in `incentive_v2` or `reward_manager`:

**Option 1**: Cap the reward to available balance before splitting:
```move
let available_balance = balance::value(&reward_fund.balance);
let actual_reward = std::u64::min((reward as u64), available_balance);
if (actual_reward > 0) {
    return (rule.global_index, balance::split(&mut reward_fund.balance, actual_reward))
}
```

**Option 2**: Assert sufficient balance and revert with a clear error:
```move
if (reward > 0) {
    assert!(balance::value(&reward_fund.balance) >= (reward as u64), ERR_INSUFFICIENT_REWARD_FUND);
    return (rule.global_index, balance::split(&mut reward_fund.balance, (reward as u64)))
}
```

**Option 3**: Implement a `distributed` vs `total_supply` tracking system similar to `incentive_v2` to prevent over-distribution at the protocol level rather than at claim time.

Additionally, consider implementing:
- On-chain tracking of total pending rewards vs available fund balance
- Events or view functions to alert administrators when the fund is running low
- Grace period mechanisms to allow administrators to top up funds before DoS occurs

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::balance::ENotEnough)]
fun test_reward_fund_depletion_causes_dos() {
    // Setup: Create incentive system with limited reward fund
    let mut scenario = test_scenario::begin(OWNER);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Initialize storage and incentive_v3
    base::init_for_testing(scenario.ctx());
    create_incentive_v3(&mut scenario);
    create_incentive_fund<USDT_TEST>(&mut scenario);
    create_incentive_pool<USDT_TEST>(&mut scenario, 2);
    create_incentive_rule<USDT_TEST, USDT_TEST>(&mut scenario, &clock, 1);
    
    // Deposit limited reward fund: only 1000 tokens
    deposit_reward_fund<USDT_TEST>(&mut scenario, 1000);
    
    // Set high reward rate that will accumulate more than fund capacity
    set_reward_rate<USDT_TEST, USDT_TEST>(&mut scenario, &clock, 1, 2000, 1000);
    
    // User A deposits and accumulates rewards
    scenario.next_tx(USERA);
    {
        let mut incentive_v3 = scenario.take_shared<IncentiveV3>();
        let mut storage = scenario.take_shared<Storage>();
        let mut pool = scenario.take_shared<Pool<USDT_TEST>>();
        let mut incentive_v2 = scenario.take_shared<IncentiveV2>();
        
        let deposit = coin::mint_for_testing<USDT_TEST>(10000, scenario.ctx());
        incentive_v3::entry_deposit(&clock, &mut storage, &mut pool, 2, deposit, 10000, 
                                    &mut incentive_v2, &mut incentive_v3, scenario.ctx());
        
        scenario.return_shared(incentive_v3);
        scenario.return_shared(storage);
        scenario.return_shared(pool);
        scenario.return_shared(incentive_v2);
    };
    
    // Advance time for rewards to accumulate beyond fund capacity
    clock.increment_for_testing(2000);
    
    // User A claims successfully (drains most/all of fund)
    scenario.next_tx(USERA);
    {
        let mut incentive_v3 = scenario.take_shared<IncentiveV3>();
        let mut storage = scenario.take_shared<Storage>();
        let mut reward_fund = scenario.take_shared<RewardFund<USDT_TEST>>();
        
        let claimable = incentive_v3::get_user_claimable_rewards(&clock, &mut storage, &incentive_v3, USERA);
        let (_, _, _, _, rule_ids_vec) = incentive_v3::parse_claimable_rewards(claimable);
        let rule_ids = *vector::borrow(&rule_ids_vec, 0);
        
        incentive_v3::claim_reward_entry<USDT_TEST>(&clock, &mut incentive_v3, &mut storage, 
                                                     &mut reward_fund, vector[ascii::string(b"USDT_TEST")], 
                                                     rule_ids, scenario.ctx());
        
        scenario.return_shared(incentive_v3);
        scenario.return_shared(storage);
        scenario.return_shared(reward_fund);
    };
    
    // User B deposits and accumulates rewards
    scenario.next_tx(USERB);
    {
        let mut incentive_v3 = scenario.take_shared<IncentiveV3>();
        let mut storage = scenario.take_shared<Storage>();
        let mut pool = scenario.take_shared<Pool<USDT_TEST>>();
        let mut incentive_v2 = scenario.take_shared<IncentiveV2>();
        
        let deposit = coin::mint_for_testing<USDT_TEST>(5000, scenario.ctx());
        incentive_v3::entry_deposit(&clock, &mut storage, &mut pool, 2, deposit, 5000,
                                    &mut incentive_v2, &mut incentive_v3, scenario.ctx());
        
        scenario.return_shared(incentive_v3);
        scenario.return_shared(storage);
        scenario.return_shared(pool);
        scenario.return_shared(incentive_v2);
    };
    
    clock.increment_for_testing(1000);
    
    // User B attempts to claim but FAILS due to insufficient reward fund
    // This will abort with ENotEnough from balance::split
    scenario.next_tx(USERB);
    {
        let mut incentive_v3 = scenario.take_shared<IncentiveV3>();
        let mut storage = scenario.take_shared<Storage>();
        let mut reward_fund = scenario.take_shared<RewardFund<USDT_TEST>>();
        
        let claimable = incentive_v3::get_user_claimable_rewards(&clock, &mut storage, &incentive_v3, USERB);
        let (_, _, _, _, rule_ids_vec) = incentive_v3::parse_claimable_rewards(claimable);
        let rule_ids = *vector::borrow(&rule_ids_vec, 0);
        
        // This call will ABORT with balance::ENotEnough
        incentive_v3::claim_reward_entry<USDT_TEST>(&clock, &mut incentive_v3, &mut storage,
                                                     &mut reward_fund, vector[ascii::string(b"USDT_TEST")],
                                                     rule_ids, scenario.ctx());
        
        scenario.return_shared(incentive_v3);
        scenario.return_shared(storage);
        scenario.return_shared(reward_fund);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

**Notes:**
- This vulnerability exists because `incentive_v3` does not implement the same protective checks present in the protocol's own `incentive_v2` and `reward_manager` modules.
- The issue is compounded by the lack of on-chain monitoring or warning mechanisms to alert administrators when reward funds are running low.
- This is a systemic issue affecting all reward distributions using the `incentive_v3` mechanism, not isolated to a specific reward token or pool.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L398-398)
```text
        assert!(rule.max_rate == 0 || rate <= rule.max_rate, error::invalid_value());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L475-477)
```text
        if (reward > 0) {
            return (rule.global_index, balance::split(&mut reward_fund.balance, (reward as u64)))
        } else {
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L765-778)
```text
    public fun claim_reward<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, ctx: &mut TxContext): Balance<RewardCoinType> {
        base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, tx_context::sender(ctx))
    }

    #[allow(lint(self_transfer))]
    public entry fun claim_reward_entry<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, ctx: &mut TxContext) {
        let balance = base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, tx_context::sender(ctx));
        transfer::public_transfer(coin::from_balance(balance, ctx), tx_context::sender(ctx))
    }

    public fun claim_reward_with_account_cap<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, account_cap: &AccountCap): Balance<RewardCoinType> {
        let sender = account::account_owner(account_cap);
        base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, sender)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L323-325)
```text
            if ((pool.distributed + reward) > pool.total_supply) {
                reward = pool.total_supply - pool.distributed
            };
```

**File:** volo-vault/sources/reward_manager.move (L628-628)
```text
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);
```
