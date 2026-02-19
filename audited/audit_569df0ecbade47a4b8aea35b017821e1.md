### Title
Reward Loss Due to Premature Reset and Decimal Rounding in claim_reward()

### Summary
The `claim_reward()` function resets unclaimed rewards to zero before applying decimal conversion, causing users with accumulated rewards less than 1e9 (1 unit in 9-decimal representation) to permanently lose those rewards. The `from_decimals()` function rounds down to zero for values below the DECIMALS threshold, and no minimum claim check prevents this loss.

### Finding Description

In `claim_reward()`, the sequence of operations causes permanent fund loss: [1](#0-0) 

The function calls `reset_unclaimed_rewards()` which returns the accumulated reward amount and immediately resets the stored value to zero: [2](#0-1) 

The `from_decimals()` function performs integer division that rounds down: [3](#0-2) 

**Root Cause**: The reset occurs before the decimal conversion. When `unclaimed_rewards < DECIMALS` (i.e., < 1_000_000_000), the division rounds to zero. Since the rewards were already reset to zero, the user permanently loses these funds.

**Why Protections Fail**: The only check is that `reward_amount <= vault_reward_balance.value()`: [4](#0-3) 

This check passes when `reward_amount = 0`, allowing the function to complete successfully while the user receives nothing.

**Execution Path**:
1. User accumulates rewards tracked in `unclaimed_rewards` (stored in 9 decimals)
2. Rewards calculated via `mul_with_oracle_price()` accumulate small amounts: [5](#0-4) 
3. User calls `claim_reward()` when `unclaimed_rewards < 1e9`
4. `reset_unclaimed_rewards()` sets balance to 0 and returns original value
5. `from_decimals()` divides by 1e9, resulting in 0
6. User receives Balance with value 0, rewards permanently lost

### Impact Explanation

**Harm**: Users with accumulated rewards below 1_000_000_000 (in 9-decimal representation, equivalent to 1 unit of the reward token) permanently lose those rewards when attempting to claim.

**Quantified Damage**: 
- For each claim attempt with rewards < 1e9, users lose up to 999,999,999 units (0.999... tokens in 9-decimal format)
- Affects all reward types added to the vault
- No recovery mechanism exists once rewards are reset to zero

**Affected Parties**: All vault users who accumulate small amounts of rewards, particularly:
- Users with small share balances
- Users claiming rewards frequently
- Early claimers in low-TVL conditions
- Any reward token regardless of type

**Severity Justification**: HIGH - Direct, permanent fund loss affecting regular user operations. While individual losses may be small, the aggregate impact across all users and claim attempts is significant, and the vulnerability violates the core invariant that users should receive all accumulated rewards.

### Likelihood Explanation

**Attacker Capabilities**: None required - this affects normal users performing legitimate claim operations. No special permissions or manipulation needed.

**Attack Complexity**: Trivial - occurs naturally when users with small reward balances attempt to claim. Steps:
1. Accumulate rewards < 1e9 through normal vault participation
2. Call `claim_reward()` 
3. Rewards are lost

**Feasibility Conditions**: 
- User has accumulated rewards less than 1_000_000_000 
- Occurs naturally for users with small share amounts or those claiming frequently
- No preconditions beyond normal vault usage

**Detection Constraints**: Users may not notice small reward losses, especially if they don't track exact unclaimed amounts. The `RewardClaimed` event emits `reward_amount: 0`, which appears as a successful but zero-value claim.

**Probability**: HIGH - Will occur regularly in production:
- Small shareholders naturally accumulate sub-1e9 rewards
- Users claiming rewards promptly to compound will trigger this
- Lower TVL periods increase likelihood

### Recommendation

**Code-Level Mitigation**:

1. Add a minimum claim check before resetting unclaimed rewards:
   ```move
   let unclaimed_amount = vault_receipt_mut.get_receipt_reward(reward_type);
   let reward_amount = vault_utils::from_decimals(unclaimed_amount) as u64;
   
   // Only reset if reward_amount > 0
   if (reward_amount > 0) {
       vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>();
   } else {
       // Revert with ERR_REWARD_AMOUNT_TOO_SMALL or allow zero-value claims
       // without resetting unclaimed rewards
       assert!(false, ERR_REWARD_AMOUNT_TOO_SMALL);
   }
   ```

2. Alternative: Accumulate rewards until they exceed minimum threshold:
   ```move
   let minimum_claimable = vault_utils::to_decimals(1); // 1e9
   assert!(unclaimed_amount >= minimum_claimable, ERR_REWARD_AMOUNT_TOO_SMALL);
   ```

**Invariant Checks**:
- Before resetting unclaimed rewards, verify that `from_decimals(amount) > 0`
- Add assertion that actual claimed amount matches expected amount after conversion
- Consider tracking lost dust amounts separately for later recovery

**Test Cases**:
1. Test claiming rewards with `unclaimed_rewards = 999_999_999` (should fail or accumulate)
2. Test claiming rewards with `unclaimed_rewards = 1_000_000_000` (should succeed with 1 unit)
3. Test multiple small claims don't compound the loss
4. Verify event emissions accurately reflect actual transfers

### Proof of Concept

**Required Initial State**:
- Vault deployed and operational
- User has receipt with small share balance
- Rewards have accumulated to amount < 1_000_000_000 in 9-decimal representation

**Transaction Steps**:
1. User deposits small amount (e.g., 0.1 principal tokens)
2. Operator adds reward balance causing small reward accumulation
3. `update_receipt_reward()` calculates: `acc_reward = (index_delta * shares) / 1e18`
   - Example: shares = 100_000_000, index_delta = 1e15
   - Result: acc_reward = (1e15 * 1e8) / 1e18 = 100_000 (well below 1e9)
4. User calls `claim_reward<PrincipalCoinType, RewardCoinType>()`
5. Function executes line 622: `reset_unclaimed_rewards()` returns 100_000 and sets storage to 0
6. Function executes line 621: `from_decimals(100_000) = 100_000 / 1_000_000_000 = 0`
7. Function executes line 638: `split(0)` returns empty Balance

**Expected Result**: User receives rewards proportional to their accumulated unclaimed amount (100_000 in internal accounting)

**Actual Result**: 
- User receives Balance with value 0
- `unclaimed_rewards` storage is now 0
- Rewards permanently lost
- Event emits `reward_amount: 0`

**Success Condition**: User's reward balance increases by 0 instead of expected amount, and subsequent claims show unclaimed_rewards remains at 0, confirming permanent loss.

### Notes

While the protocol implements minimum reward checks for operators adding rewards to the vault (`ERR_REWARD_AMOUNT_TOO_SMALL` at line 357), no corresponding protection exists for user claims. The comment at line 354-355 acknowledges that small rewards can be lost, but this refers to operator actions, not user claims where the loss is permanent and affects end users directly.

### Citations

**File:** volo-vault/sources/reward_manager.move (L619-623)
```text
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;
```

**File:** volo-vault/sources/reward_manager.move (L628-628)
```text
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);
```

**File:** volo-vault/sources/vault_receipt_info.move (L144-151)
```text
public(package) fun reset_unclaimed_rewards<RewardCoinType>(self: &mut VaultReceiptInfo): u256 {
    let reward_type = type_name::get<RewardCoinType>();
    // always call after update_reward to ensure key existed
    let reward = self.unclaimed_rewards.borrow_mut(reward_type);
    let reward_amount = *reward;
    *reward = 0;
    reward_amount
}
```

**File:** volo-vault/sources/vault_receipt_info.move (L177-181)
```text
        let acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares);

        // set reward and index
        *pre_idx = new_reward_idx;
        *unclaimed_reward = *unclaimed_reward + acc_reward;
```

**File:** volo-vault/sources/utils.move (L48-50)
```text
public fun from_decimals(v: u256): u256 {
    v / DECIMALS
}
```
