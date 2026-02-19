### Title
Reward Buffer Update Can Permanently Fail Due to Overflow When Time Interval Exceeds Hardcoded Day Assumption

### Summary
The `set_reward_rate()` function validates that the rate won't overflow by checking `rate < max_u256 / 86_400_000`, assuming updates occur within one day. However, if `update_reward_buffer()` is not called for more than 86,400,000 milliseconds (24 hours), the multiplication of rate by the actual time difference can overflow, causing permanent DoS of the reward distribution system with no recovery mechanism.

### Finding Description

The constraint at line 428 in `set_reward_rate()` only protects against overflow for time intervals up to exactly one day (86,400,000 milliseconds). [1](#0-0) 

When `update_reward_buffer()` calculates new rewards, it multiplies the rate by the actual elapsed time without bounds checking. [2](#0-1) 

If a rate is set to just below the maximum allowed value and more than one day passes between updates, the calculation `reward_rate * (now - last_update_time)` will exceed `max_u256` and abort. This creates a deadlock because `set_reward_rate()` attempts to update the buffer before changing the rate. [3](#0-2) 

The test suite only validates behavior up to exactly one day intervals and never tests what happens when updates are delayed beyond this assumption. [4](#0-3) [5](#0-4) 

### Impact Explanation

When overflow occurs, all reward buffer updates for that reward type permanently fail. Users cannot claim rewards that were already earned. [6](#0-5) 

The reward balance remains locked in the contract with no recovery mechanism since changing the rate also requires updating the buffer first. The protocol would require migration or emergency intervention to restore functionality.

This affects all users holding receipts expecting rewards from the affected reward type, potentially representing significant value depending on the buffer balance.

### Likelihood Explanation

This scenario requires:
1. Operator setting a reward rate near the maximum allowed threshold (within valid bounds)
2. System experiencing no buffer updates for over 24 hours due to maintenance, network issues, or simply no user activity calling update functions

While the operator is a trusted role, this isn't about compromise—they're making a legitimate configuration choice. The issue is inadequate safeguards for operational realities where update intervals can vary. During planned maintenance, chain congestion, or low activity periods, 24+ hour gaps are plausible.

The probability is low but non-zero, and the irreversible impact justifies the Low severity rating.

### Recommendation

1. Add validation that enforces a maximum safe time interval or dynamically calculate the maximum allowed rate based on potential time gaps:

```move
// In set_reward_rate(), add check:
let max_expected_interval = 86_400_000 * 7; // Allow up to 1 week
assert!(rate < std::u256::max_value!() / max_expected_interval, ERR_INVALID_REWARD_RATE);
```

2. Add a recovery mechanism that allows resetting the `last_updated` timestamp if the buffer cannot be updated due to overflow, sacrificing some reward accuracy to restore functionality.

3. Add invariant checks in `update_reward_buffer()`:
```move
let time_diff = now - last_updated;
assert!(time_diff <= max_safe_interval, ERR_UPDATE_INTERVAL_TOO_LONG);
```

4. Add test cases validating behavior with multi-day gaps and near-maximum rates.

### Proof of Concept

**Initial State:**
- Vault has 1,000,000,000 shares
- Reward buffer created for SUI rewards

**Step 1:** Operator sets maximum allowed rate:
```
rate = (max_u256 / 86_400_000) - 1
set_reward_rate(rate)  // Passes validation
```

**Step 2:** Add reward buffer:
```
add_reward_to_buffer(1000 SUI)
```

**Step 3:** 48 hours (172,800,000 ms) pass without any calls to `update_reward_buffer()`

**Step 4:** User attempts to claim rewards:
```
claim_reward() → calls update_reward_buffers() → calls update_reward_buffer()
```

**Expected:** Rewards distributed proportionally for elapsed time
**Actual:** Transaction aborts with arithmetic overflow in `new_reward = reward_rate * 172_800_000`, which exceeds max_u256

**Result:** All subsequent attempts to update buffer or change rate fail permanently, locking rewards.

### Citations

**File:** volo-vault/sources/reward_manager.move (L428-428)
```text
    assert!(rate < std::u256::max_value!() / 86_400_000, ERR_INVALID_REWARD_RATE);
```

**File:** volo-vault/sources/reward_manager.move (L433-433)
```text
    self.update_reward_buffer<PrincipalCoinType>(vault, clock, reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L498-498)
```text
            let new_reward = reward_rate * ((now - last_update_time) as u256);
```

**File:** volo-vault/sources/reward_manager.move (L596-639)
```text
public fun claim_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt: &mut Receipt,
): Balance<RewardCoinType> {
    self.check_version();
    vault.assert_enabled();
    vault.assert_vault_receipt_matched(receipt);
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    let receipt_id = receipt.receipt_id();

    let vault_receipt = vault.vault_receipt_info(receipt_id);
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Update all reward buffers
    self.update_reward_buffers<PrincipalCoinType>(vault, clock);
    // Update the pending reward for the receipt
    self.update_receipt_reward(vault, receipt_id);

    let reward_type = type_name::get<RewardCoinType>();

    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;

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

**File:** volo-vault/tests/reward/reward_manager.test.move (L1621-1621)
```text
        clock::set_for_testing(&mut clock, 86_400_000 + 1);
```

**File:** volo-vault/tests/reward/reward_manager.test.move (L1776-1776)
```text
        clock::set_for_testing(&mut clock, 86_400_000 + 1);
```
