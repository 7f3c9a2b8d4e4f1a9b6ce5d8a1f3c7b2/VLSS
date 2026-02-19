### Title
Insufficient Reward Fund Check Causes Denial of Service for All Reward Claimants

### Summary
The `base_claim_reward_by_rule()` function calls `balance::split()` on the reward fund without verifying sufficient balance exists. When the reward fund is depleted or underfunded, any claim transaction will abort, preventing all users from claiming their legitimately earned rewards until the fund is replenished by administrators.

### Finding Description

The vulnerability exists in the `base_claim_reward_by_rule()` function at line 476: [1](#0-0) 

The function calculates the user's claimable reward amount and attempts to split it from the reward fund without checking if sufficient balance exists: [2](#0-1) 

In Sui Move, the `balance::split()` operation will abort the entire transaction if the requested amount exceeds the available balance. No validation is performed to ensure `reward_fund.balance >= reward` before the split operation.

The function is called from public entry points accessible to any user: [3](#0-2) [4](#0-3) [5](#0-4) 

Notably, the codebase demonstrates awareness of this issue - the `withdraw_reward_fund()` function properly protects against insufficient balance: [6](#0-5) 

This function uses `std::u64::min(amount, balance::value(&reward_fund.balance))` to ensure only available balance is withdrawn. However, this same protection is absent in `base_claim_reward_by_rule()`.

### Impact Explanation

**Operational DoS for Legitimate Claimants**: When the reward fund balance is insufficient to fulfill a claim request, the transaction aborts, preventing the user from claiming their earned rewards. This affects all subsequent claimants until administrators replenish the fund.

**Concrete Scenario**: 
- Rules are configured with reward rates and users accumulate rewards over time
- Reward fund contains 1000 tokens
- User A claims 600 tokens successfully (400 remaining)
- User B has earned 500 tokens and attempts to claim
- Transaction aborts at line 476 when trying to split 500 from 400 available balance
- User B and all other users with pending claims are blocked until admin deposits more tokens

**Affected Users**: All users with claimable rewards in any rule associated with the depleted reward fund. This could span multiple asset pools if they share the same reward token type.

**Severity Justification**: This is a High severity issue because:
1. Users lose access to legitimately earned rewards through no fault of their own
2. The DoS persists until administrative intervention
3. No on-chain mechanism exists for users to verify fund sufficiency before claiming
4. The impact scales with the number of affected claimants and reward pools

### Likelihood Explanation

**High Likelihood - Realistic Operational Scenario**:

The vulnerability can be triggered through normal protocol operation without any malicious intent:

1. **Underfunding by Administrators**: Administrators may miscalculate required reward deposits or delay replenishment, causing the fund to be depleted before all claims are processed.

2. **Accrual-Deposit Mismatch**: Rewards accrue continuously based on user supply/borrow positions and configured rates, but fund deposits are discrete admin actions. A timing mismatch is inevitable.

3. **First-Come-First-Served Race**: Early claimants can deplete the fund, leaving later legitimate claimants blocked. No fair distribution mechanism exists.

4. **No Preventive Checks**: The protocol lacks any mechanism to:
   - Warn administrators when fund balance is low
   - Prevent rule activation when fund is insufficient
   - Limit reward rate based on available funds

**Attacker Capabilities**: Not required - any legitimate user claiming earned rewards can trigger this.

**Attack Complexity**: None - this is normal protocol usage.

**Detection Constraints**: The issue may go undetected until users start reporting failed claim transactions.

**Economic Rationality**: N/A - this is not an attack but a protocol design flaw affecting normal operations.

### Recommendation

Implement a balance sufficiency check before calling `balance::split()`, similar to the pattern used in `withdraw_reward_fund()`:

```move
fun base_claim_reward_by_rule<RewardCoinType>(...) {
    // ... existing code ...
    
    if (reward > 0) {
        let available_balance = balance::value(&reward_fund.balance);
        let claimable_amount = std::u64::min((reward as u64), available_balance);
        return (rule.global_index, balance::split(&mut reward_fund.balance, claimable_amount))
    } else {
        return (rule.global_index, balance::zero<RewardCoinType>())
    }
}
```

**Additional Recommendations**:
1. Update `user_rewards_claimed` only by the actual amount claimed, not the full calculated reward
2. Add event emission when partial claim occurs due to insufficient funds
3. Implement administrative monitoring for low reward fund balances
4. Consider adding a minimum reserve requirement before enabling reward rules
5. Add test cases covering scenarios with insufficient reward fund balance

### Proof of Concept

**Initial State**:
- IncentiveV3 configured with asset pool and reward rule
- RewardFund contains 100 tokens
- User A has earned 60 tokens (not yet claimed)
- User B has earned 80 tokens (not yet claimed)

**Execution Steps**:
1. User A calls `claim_reward_entry()` with their rule parameters
   - Function calculates reward = 60
   - Successfully splits 60 tokens from fund
   - RewardFund balance now = 40 tokens
   - Transaction succeeds

2. User B calls `claim_reward_entry()` with their rule parameters
   - Function calculates reward = 80
   - Attempts `balance::split(&mut reward_fund.balance, 80)`
   - Fund only has 40 tokens available
   - **Transaction aborts with insufficient balance error**
   - User B receives no tokens and gas is consumed

**Expected Result**: User B should receive either 40 tokens (partial claim) or a clear indication that the fund is depleted.

**Actual Result**: User B's transaction aborts, they receive nothing, and all subsequent claimants are blocked until admin deposits more tokens.

**Success Condition for Exploit**: Any scenario where `(reward as u64) > balance::value(&reward_fund.balance)` causes immediate DoS for that user and all subsequent claimants.

## Notes

This vulnerability is particularly concerning because it can occur through entirely legitimate protocol usage without any malicious actor. The protocol's reward accrual mechanism is independent of the reward fund deposit mechanism, creating an inevitable window for this issue to manifest. The existence of proper balance checking in `withdraw_reward_fund()` indicates the developers were aware of this pattern but failed to apply it consistently to user-facing claim functions.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L468-479)
```text
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
