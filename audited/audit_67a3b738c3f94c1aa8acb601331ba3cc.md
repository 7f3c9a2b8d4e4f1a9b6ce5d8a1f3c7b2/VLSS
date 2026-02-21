# Audit Report

## Title
Incentive V3 Reward Claims Fail When Reward Fund Balance Is Insufficient, Causing Denial of Service

## Summary
The `base_claim_reward_by_rule()` function in `incentive_v3` attempts to split rewards from the `RewardFund` without validating that sufficient balance exists. When calculated rewards exceed available funds, the `balance::split()` operation aborts, preventing users from claiming legitimately earned rewards and creating a race condition where early claimers drain the fund while later claimers face transaction failures.

## Finding Description

The vulnerability exists in the reward claiming logic where the protocol calculates user rewards independently from the actual `RewardFund` balance. After computing the claimable reward amount through reward rate accrual calculations, the function directly attempts to split this amount from the fund balance without any validation. [1](#0-0) 

In Sui Move's standard library, `balance::split()` will abort if attempting to split more than the available balance. The reward calculation tracks user accruals in separate state variables (`user_total_rewards` and `user_rewards_claimed`), creating an insolvency scenario where:

1. Rewards accrue to users based on rates, time, and supply/borrow balances
2. `RewardFund` balance is managed independently via deposits and withdrawals
3. No mechanism ensures the fund balance covers all accrued reward obligations [2](#0-1) 

**Comparison with Protected Functions:**

The codebase demonstrates awareness of this exact issue. The `withdraw_reward_fund()` function properly handles insufficient balance by capping withdrawals to the minimum of the requested amount and available balance: [3](#0-2) 

Furthermore, the predecessor `incentive_v2` system includes explicit protection against this scenario by capping rewards at `total_supply - distributed`: [4](#0-3) 

The v2 system prevents claims that exceed available funds through this cap. **Incentive_v3 removed this critical protection.**

The vulnerability is directly reachable through the public entry function: [5](#0-4) 

## Impact Explanation

**Direct Operational Impact:**
- Users with legitimately accrued rewards cannot claim them, resulting in **denial of service** for the reward claiming functionality
- All users attempting to claim when `reward_fund.balance < calculated_reward` will have their transactions abort with no recovery path
- Users remain unable to claim until an admin manually deposits more funds into the reward pool

**Race Condition and Fund Insolvency:**
- Creates a "first-come-first-served" scenario where early claimers successfully drain the reward fund
- Later claimers are denied rewards they have legitimately earned through protocol participation
- No mechanism exists to fairly distribute limited funds among eligible claimers
- The protocol can accrue more reward obligations than it has funds to pay, breaking the fundamental guarantee that earned rewards are claimable

**Who Is Affected:**
- All users with accrued rewards in any asset pool using `incentive_v3`
- Particularly affects users who: (a) accrue rewards during high-rate periods, (b) attempt to claim after others have drained the fund, or (c) participate in pools where reward rates exceed fund deposit rates

**Severity: HIGH** because:
1. **Concrete financial harm**: Users lose access to earned rewards representing real value
2. **Widespread impact**: Affects all reward claimers when the fund becomes underfunded
3. **No user mitigation**: Users cannot prevent or work around this issue through alternative claim strategies
4. **Protocol integrity violation**: The system cannot guarantee payment of reward obligations it has accrued

## Likelihood Explanation

**Feasible Preconditions:**

The vulnerability triggers under realistic operational conditions that require no attacker capabilities:

1. **Reward Rate Misconfiguration**: Admin sets reward rates via `set_reward_rate_by_rule_id()` without ensuring adequate fund deposits exist or will be made
2. **Admin Withdrawal**: Admin withdraws from reward fund via `withdraw_reward_fund()` while rewards continue accruing to users
3. **Natural Accumulation**: Rewards accrue faster than the fund is replenished during normal operation
4. **Multiple Simultaneous Claims**: Race condition where multiple users claim concurrently, with later transactions failing [6](#0-5) 

The rate-setting function performs no validation that sufficient funds exist to cover the configured reward schedule.

**Execution Practicality:**
- No special attacker capabilities required - any user calling `claim_reward_entry()` can trigger the abort
- No exploitation complexity - the issue happens automatically when `reward > balance`
- Executable under standard Sui Move semantics - the `balance::split()` abort behavior is standard Move functionality

**Economic Rationality:**
- Users calling claim functions are acting rationally to collect their earned rewards
- No cost barrier prevents the issue - claiming is a normal, expected protocol operation
- Not economically irrational for users to claim when rewards show as available

**Probability: HIGH** because:
- Reward accrual is continuous and automatic based on time and user balances
- Fund deposits are manual administrative actions that may lag behind accrual
- Time gaps between reward accrual and fund deposits create vulnerability windows
- Multiple independent users can trigger claims simultaneously, depleting funds

## Recommendation

Implement balance validation before attempting to split rewards, similar to the protection in `withdraw_reward_fund()` and `incentive_v2`:

```move
fun base_claim_reward_by_rule<RewardCoinType>(
    clock: &Clock,
    storage: &mut Storage,
    incentive: &mut Incentive,
    reward_fund: &mut RewardFund<RewardCoinType>,
    coin_type: String,
    rule_id: address,
    user: address
): (u256, Balance<RewardCoinType>) {
    // ... existing validation and reward calculation ...
    
    if (reward > 0) {
        // Cap reward at available balance
        let available_balance = balance::value(&reward_fund.balance);
        let actual_reward = std::u64::min((reward as u64), available_balance);
        
        // Update claimed amount to reflect what was actually paid
        *user_reward_claimed = *user_reward_claimed + (actual_reward as u256);
        
        return (rule.global_index, balance::split(&mut reward_fund.balance, actual_reward))
    } else {
        return (rule.global_index, balance::zero<RewardCoinType>())
    }
}
```

Additionally, consider:
1. Emitting events when partial payments occur due to insufficient funds
2. Adding a view function to check if sufficient funds exist before claiming
3. Implementing fund balance monitoring to alert admins when reserves are low

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Admin creates an incentive pool with reward rate set to distribute 1000 tokens over 30 days
2. Admin deposits only 500 tokens into the RewardFund
3. Users accrue 600 tokens worth of rewards through normal participation
4. First user claims 500 tokens successfully (drains the fund)
5. Second user's claim transaction with 100 tokens accrued ABORTS due to insufficient balance in RewardFund
6. Second user cannot claim their legitimately earned 100 tokens until admin deposits more funds

This scenario requires no malicious actors - it occurs through normal protocol operations when reward accrual rates exceed funding rates.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L202-204)
```text
    public(friend) fun withdraw_reward_fund<T>(reward_fund: &mut RewardFund<T>, amount: u64, ctx: &TxContext): Balance<T> {
        let amt = std::u64::min(amount, balance::value(&reward_fund.balance));
        let withdraw_balance = balance::split(&mut reward_fund.balance, amt);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L458-479)
```text
        // update the user reward
        update_reward_state_by_rule(clock, storage, pool.asset, rule, user);

        let user_total_reward = *table::borrow(&rule.user_total_rewards, user);

        if (!table::contains(&rule.user_rewards_claimed, user)) {
            table::add(&mut rule.user_rewards_claimed, user, 0);
        };
        let user_reward_claimed = table::borrow_mut(&mut rule.user_rewards_claimed, user);

        let reward = if (user_total_reward > *user_reward_claimed) {
            user_total_reward - *user_reward_claimed
        } else {
            0
        };
        *user_reward_claimed = user_total_reward;

        if (reward > 0) {
            return (rule.global_index, balance::split(&mut reward_fund.balance, (reward as u64)))
        } else {
            return (rule.global_index, balance::zero<RewardCoinType>())
        }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L770-773)
```text
    public entry fun claim_reward_entry<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, ctx: &mut TxContext) {
        let balance = base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, tx_context::sender(ctx));
        transfer::public_transfer(coin::from_balance(balance, ctx), tx_context::sender(ctx))
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L322-325)
```text
            let reward = ((total_rewards_of_user - total_claimed_of_user) / ray_math::ray() as u64);
            if ((pool.distributed + reward) > pool.total_supply) {
                reward = pool.total_supply - pool.distributed
            };
```
