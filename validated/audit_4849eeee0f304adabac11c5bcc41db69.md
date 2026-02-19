# Audit Report

## Title
Reward Claim DoS Due to Missing Balance Validation in base_claim_reward_by_rule()

## Summary
The `base_claim_reward_by_rule()` function in the Navi Protocol Incentive V3 system (integrated by Volo) attempts to split reward amounts from the RewardFund without verifying sufficient balance exists, causing transaction aborts when the fund is depleted or underfunded. This creates a denial-of-service condition where all users are blocked from claiming earned rewards until the administrator deposits additional funds.

## Finding Description

The vulnerability exists in the reward claiming flow where users withdraw their accrued incentive rewards through the Navi Protocol integration.

In the `base_claim_reward_by_rule()` function, after calculating the claimable reward amount and updating the user's claimed balance state, the code directly calls `balance::split(&mut reward_fund.balance, (reward as u64))` without first checking if the RewardFund contains sufficient balance. [1](#0-0) 

Sui Move's `balance::split()` function aborts with error code when the requested amount exceeds available balance, causing the entire transaction to revert.

The execution path flows through three public entry points:
- `claim_reward_entry()` [2](#0-1) 
- `claim_reward()` [3](#0-2) 
- `claim_reward_with_account_cap()` [4](#0-3) 

These functions call `base_claim_reward_by_rules()` which loops through multiple rules [5](#0-4) , and for each rule invokes `base_claim_reward_by_rule()` which attempts the unprotected balance split.

In contrast, the administrative `withdraw_reward_fund()` function properly protects against this scenario by using `std::u64::min(amount, balance::value(&reward_fund.balance))` to cap withdrawals at available balance. [6](#0-5) 

The claiming functions lack this defensive check, creating an inconsistency where administrative withdrawals are protected but user claims are not.

## Impact Explanation

**Operational DoS Impact**: When the RewardFund balance is insufficient to cover any user's accrued rewards, ANY attempt by ANY user to claim rewards will cause transaction abort. This blocks all users from claiming rewards, not just those with amounts exceeding the remaining balance. The protocol's reward claiming functionality becomes completely non-operational until an administrator deposits sufficient funds via the friend-only `deposit_reward_fund()` function. [7](#0-6) 

**Affected Parties**: All users who have earned rewards through supply/borrow activities on Navi Protocol (integrated by Volo) are denied access to their legitimate reward entitlements tracked in the system's `user_total_rewards` tables.

**Recovery Requirement**: The DoS persists until a trusted administrator deposits additional funds. There is no self-healing mechanism or user-accessible workaround.

**Trust Assumption Violation**: The system allows administrators to configure reward rates and manages reward accrual automatically, creating legitimate user entitlements. However, it places no enforcement on administrators to maintain adequate RewardFund balances to honor these entitlements.

**Severity Classification**: HIGH (not Critical) because:
- No permanent fund loss occurs (Sui Move transaction atomicity ensures state rollback)
- No state corruption (aborted transactions fully revert)
- No fund theft or misrouting
- Condition is recoverable through admin action
- Requires operational misconfiguration rather than exploitable logic flaw

## Likelihood Explanation

**Reachable Entry Points**: The vulnerability is triggered through public functions accessible to all users without special privileges.

**Precondition Feasibility**: The underfunding condition can arise through realistic operational scenarios:
1. Administrator sets reward rates but fails to deposit proportional funds to the RewardFund
2. Administrator withdraws funds from RewardFund prematurely
3. Reward accrual rate exceeds funding deposit rate over time
4. Multiple reward rules compete for limited RewardFund balance

**Execution Practicality**: Any user with non-zero accrued rewards can trigger the abort by calling claim functions when the fund is depleted. No special privileges, timing manipulation, or complex transaction sequences are required.

**Probability**: MEDIUM to HIGH probability in practice, as reward rate configuration and fund management are separate administrative actions with no programmatic linkage or validation enforcing adequate balance.

## Recommendation

Add defensive balance checking in `base_claim_reward_by_rule()` consistent with the pattern used in `withdraw_reward_fund()`:

```move
if (reward > 0) {
    let available_balance = balance::value(&reward_fund.balance);
    let claim_amount = std::u64::min((reward as u64), available_balance);
    return (rule.global_index, balance::split(&mut reward_fund.balance, claim_amount))
} else {
    return (rule.global_index, balance::zero<RewardCoinType>())
}
```

This allows partial claims when funds are insufficient, preventing DoS while maintaining operational continuity.

Additionally, consider implementing:
1. Monitoring alerts when RewardFund balance falls below outstanding entitlements
2. Administrative functions to query total outstanding reward liabilities
3. Validation during reward rate configuration to ensure adequate funding

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::balance::ENotEnough)]
public fun test_claim_reward_insufficient_balance_dos() {
    let scenario = test_scenario::begin(OWNER);
    let scenario_mut = &mut scenario;
    let alice = @0xaaaaaaaa;
    let clock = clock::create_for_testing(test_scenario::ctx(scenario_mut));
    
    // Initialize protocol with minimal RewardFund deposit
    {
        incentive_v3_util::init_protocol(scenario_mut);
    };
    
    // Withdraw most funds from RewardFund to simulate underfunding
    test_scenario::next_tx(scenario_mut, OWNER);
    {
        let owner_cap = test_scenario::take_from_sender<IncentiveOwnerCap>(scenario_mut);
        let sui_funds = test_scenario::take_shared<RewardFund<SUI_TEST_V2>>(scenario_mut);
        
        // Withdraw most of the reward fund
        let withdraw_amount = incentive_v3::get_balance_value_by_reward_fund(&sui_funds) - 1_000000000; // Leave only 1 SUI
        manage::withdraw_incentive_v3_reward_fund(&owner_cap, &mut sui_funds, withdraw_amount, test_scenario::ctx(scenario_mut));
        
        test_scenario::return_shared(sui_funds);
        test_scenario::return_to_sender(scenario_mut, owner_cap);
    };
    
    // User deposits and accrues rewards beyond remaining RewardFund balance
    test_scenario::next_tx(scenario_mut, alice);
    {
        incentive_v3_util::user_deposit<SUI_TEST_V2>(scenario_mut, alice, 0, 1000_000000000, &clock);
    };
    
    // Advance time to accrue significant rewards (> 1 SUI remaining in fund)
    clock::increment_for_testing(&mut clock, 86400 * 1000); // 1 day
    
    // Attempt to claim rewards - this will abort due to insufficient RewardFund balance
    test_scenario::next_tx(scenario_mut, alice);
    {
        let incentive = test_scenario::take_shared<Incentive_V3>(scenario_mut);
        let storage = test_scenario::take_shared<Storage>(scenario_mut);
        let sui_funds = test_scenario::take_shared<RewardFund<SUI_TEST_V2>>(scenario_mut);
        
        let rule_ids = vector::empty<address>();
        let (addr, _, _, _, _) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
        vector::push_back(&mut rule_ids, addr);
        
        // This call will abort with ENotEnough because RewardFund has only 1 SUI but user earned ~100 SUI
        incentive_v3::claim_reward_entry<SUI_TEST_V2>(&clock, &mut incentive, &mut storage, &mut sui_funds, 
            vector::singleton(type_name::into_string(type_name::get<SUI_TEST_V2>())), rule_ids, test_scenario::ctx(scenario_mut));
        
        test_scenario::return_shared(incentive);
        test_scenario::return_shared(storage);
        test_scenario::return_shared(sui_funds);
    };
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L191-200)
```text
    public(friend) fun deposit_reward_fund<T>(reward_fund: &mut RewardFund<T>, reward_balance: Balance<T>, ctx: &TxContext) {
        let amount = balance::value(&reward_balance);
        balance::join(&mut reward_fund.balance, reward_balance);

        emit(RewardFundDeposited{
            sender: tx_context::sender(ctx),
            reward_fund_id: object::uid_to_address(&reward_fund.id),
            amount: amount,
        });
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L202-213)
```text
    public(friend) fun withdraw_reward_fund<T>(reward_fund: &mut RewardFund<T>, amount: u64, ctx: &TxContext): Balance<T> {
        let amt = std::u64::min(amount, balance::value(&reward_fund.balance));
        let withdraw_balance = balance::split(&mut reward_fund.balance, amt);

        emit(RewardFundWithdrawn{
            sender: tx_context::sender(ctx),
            reward_fund_id: object::uid_to_address(&reward_fund.id),
            amount: amt,
        });

        withdraw_balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L414-441)
```text
    fun base_claim_reward_by_rules<RewardCoinType>(clock: &Clock, storage: &mut Storage, incentive: &mut Incentive, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, user: address): Balance<RewardCoinType> {
        version_verification(incentive);
        assert!(vector::length(&coin_types) == vector::length(&rule_ids), error::invalid_coin_type());
        let reward_balance = balance::zero<RewardCoinType>();
        let rule_indices = vector::empty<u256>();
        let i = 0;
        let len = vector::length(&coin_types);
        while (i < len) {
            let rule_id = *vector::borrow(&rule_ids, i);
            let coin_type = *vector::borrow(&coin_types, i);
            let (index, _balance) = base_claim_reward_by_rule<RewardCoinType>(clock, storage, incentive, reward_fund, coin_type,  rule_id, user);
            vector::push_back(&mut rule_indices, index);

            _ = balance::join(&mut reward_balance, _balance);
            i = i + 1;
        };

        let reward_balance_value = balance::value(&reward_balance);
        emit(RewardClaimed{
            user: user,
            total_claimed: reward_balance_value,
            coin_type: type_name::into_string(type_name::get<RewardCoinType>()),
            rule_ids: rule_ids,
            rule_indices: rule_indices,
        });

        reward_balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L475-476)
```text
        if (reward > 0) {
            return (rule.global_index, balance::split(&mut reward_fund.balance, (reward as u64)))
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L765-767)
```text
    public fun claim_reward<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, ctx: &mut TxContext): Balance<RewardCoinType> {
        base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, tx_context::sender(ctx))
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L770-773)
```text
    public entry fun claim_reward_entry<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, ctx: &mut TxContext) {
        let balance = base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, tx_context::sender(ctx));
        transfer::public_transfer(coin::from_balance(balance, ctx), tx_context::sender(ctx))
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L775-778)
```text
    public fun claim_reward_with_account_cap<RewardCoinType>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, reward_fund: &mut RewardFund<RewardCoinType>, coin_types: vector<String>, rule_ids: vector<address>, account_cap: &AccountCap): Balance<RewardCoinType> {
        let sender = account::account_owner(account_cap);
        base_claim_reward_by_rules<RewardCoinType>(clock, storage, incentive, reward_fund, coin_types, rule_ids, sender)
    }
```
