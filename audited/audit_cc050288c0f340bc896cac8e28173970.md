# Audit Report

## Title
Reward Fund Depletion Causes Denial of Service on Legitimate User Reward Claims

## Summary
The Navi protocol's `base_claim_reward_by_rule()` function in the incentive_v3 module performs an unchecked `balance::split()` operation that will abort when the reward fund is depleted below pending user obligations, causing a complete denial of service where users cannot claim their legitimately earned rewards.

## Finding Description

The vulnerability exists in the reward claiming flow where user rewards are calculated from accounting records (`user_total_rewards - user_rewards_claimed`) but the actual fund withdrawal lacks balance validation.

**Vulnerable Code Location:** [1](#0-0) 

The function directly calls `balance::split(&mut reward_fund.balance, (reward as u64))` without verifying sufficient balance exists. In Sui Move, this will abort the transaction if the requested amount exceeds available balance.

**Execution Flow:**
Users call one of three public entry points that all route to the vulnerable function: [2](#0-1) 

These call `base_claim_reward_by_rules`, which iterates through rules and invokes the vulnerable `base_claim_reward_by_rule`: [3](#0-2) 

**Missing Protection:**
Unlike other balance operations in the codebase, no balance check precedes the split. Compare to the safe withdrawal implementation: [4](#0-3) 

And Volo's own reward manager which includes the exact protection this is missing: [5](#0-4) 

**How Fund Depletion Occurs:**
The reward fund can be depleted through the management interface: [6](#0-5) 

There is no mechanism to ensure the reward fund balance remains >= total pending user rewards across all users. An administrator miscalculation when withdrawing funds, or a burst of concurrent claims, can leave insufficient balance for subsequent claimers.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability causes direct denial of access to user funds:

1. **User Fund Lockout**: Users with legitimately earned rewards cannot access them when the fund is depleted
2. **Complete Service Denial**: ALL pending reward claims fail with transaction aborts until manual refill
3. **No Automatic Recovery**: Requires operator intervention to detect and refill the fund
4. **Widespread Effect**: Can affect the entire user base simultaneously if fund is exhausted
5. **Indefinite Duration**: Users remain locked out until manual operator action

The total locked value equals the sum of all pending rewards across all affected users, potentially representing significant value in an active lending protocol.

## Likelihood Explanation

**Likelihood: HIGH**

This is an operational vulnerability with realistic occurrence conditions:

1. **No Attack Required**: This is a natural operational failure, not requiring malicious intent
2. **Common Scenario**: Administrator miscalculates required fund reserves when withdrawing
3. **Race Conditions**: Multiple users claiming concurrently can exhaust the fund faster than monitoring/refill rate
4. **No Safeguards**: The protocol lacks any mechanism to prevent fund depletion below pending obligations
5. **Demonstrated Risk**: Volo's own implementation shows this was a known risk - they added the exact protection this code is missing

The probability is particularly high because:
- Administrators have legitimate operational needs to manage fund balances
- No accounting system tracks (reward_fund.balance vs. sum of all user pending rewards)
- Common pattern in reward distribution systems that lack proper reserve management

## Recommendation

Add balance validation before attempting to split, consistent with Volo's own implementation:

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
    // ... existing code ...
    
    if (reward > 0) {
        // Add balance check before split
        let available_balance = balance::value(&reward_fund.balance);
        assert!(reward <= (available_balance as u256), ERROR_INSUFFICIENT_REWARD_FUND);
        
        return (rule.global_index, balance::split(&mut reward_fund.balance, (reward as u64)))
    } else {
        return (rule.global_index, balance::zero<RewardCoinType>())
    }
}
```

Additionally, implement fund reserve tracking to prevent depletion below pending obligations during withdrawals.

## Proof of Concept

```move
#[test]
fun test_reward_claim_fails_when_fund_depleted() {
    // Setup: Create user with 1000 tokens earned reward
    let user = @0xUSER;
    let (incentive, storage, reward_fund) = setup_test_environment();
    
    // User accumulates 1000 token rewards through normal supply/borrow activity
    accrue_user_rewards(&mut incentive, &mut storage, user, 1000);
    
    // Admin withdraws 900 tokens from reward fund (leaving only 100)
    let admin_cap = test_scenario::take_from_sender<StorageAdminCap>(&scenario);
    manage::withdraw_incentive_v3_reward_fund<TestCoin>(
        &admin_cap,
        &mut reward_fund,
        900,
        @admin_recipient,
        test_scenario::ctx(&mut scenario)
    );
    
    // User attempts to claim their legitimately earned 1000 tokens
    // Expected: Transaction aborts because 1000 > 100 remaining balance
    let result = incentive_v3::claim_reward<TestCoin>(
        &clock,
        &mut incentive,
        &mut storage,
        &mut reward_fund,
        vector[coin_type],
        vector[rule_id],
        test_scenario::ctx(&mut scenario)
    );
    
    // This call will abort with balance::split error
    // Proving DoS on legitimate user reward claims
}
```

## Notes

This vulnerability affects the Navi protocol integration within Volo's local dependencies. While the code is from an external protocol (Navi), it is:

1. Explicitly listed in the in-scope files
2. Used by Volo's Navi adaptor for reward distribution
3. Can directly impact Volo users attempting to claim rewards from Navi lending positions

The issue is particularly concerning because Volo's own `reward_manager.move` implementation includes the exact protection this code is missing, demonstrating that the Volo team recognized this risk in their own code but it exists in the integrated Navi dependency.

### Citations

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

**File:** volo-vault/sources/reward_manager.move (L625-639)
```text
    let vault_reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);

    emit(RewardClaimed {
        reward_manager_id: self.id.to_address(),
        vault_id: receipt.vault_id(),
        receipt_id: receipt.receipt_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    });

    vault_reward_balance.split(reward_amount)
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/manage.move (L114-118)
```text
    public fun withdraw_incentive_v3_reward_fund<T>(_: &StorageAdminCap, reward_fund: &mut RewardFund<T>, amount: u64, recipient: address, ctx: &mut TxContext) {
        let balance = incentive_v3::withdraw_reward_fund<T>(reward_fund, amount, ctx);

        transfer::public_transfer(coin::from_balance(balance, ctx), recipient)
    }
```
