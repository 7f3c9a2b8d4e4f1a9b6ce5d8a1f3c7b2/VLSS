### Title
Permanent Reward Loss Due to Index Update on Zero-Share Receipts During Deposit Execution

### Summary
The `update_reward()` function unconditionally updates a receipt's reward index even when the receipt has zero shares, causing `acc_reward` to be calculated as zero. This creates permanent reward loss for users because `update_receipt_reward()` is called before shares are added during deposit execution, causing receipts to skip reward accrual for the period between when rewards were distributed and when their deposit was executed.

### Finding Description

The vulnerability exists in the `update_reward()` function where the reward index is updated unconditionally regardless of whether the receipt has any shares: [1](#0-0) 

When `self.shares` is 0, the calculation `acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares)` results in 0, but line 180 still executes `*pre_idx = new_reward_idx`, advancing the receipt's index without accruing any rewards.

This becomes exploitable due to the execution flow in deposit operations. In `execute_deposit`, the reward update occurs BEFORE shares are added to the receipt: [2](#0-1) 

The critical timing issue is:
1. Line 396: `update_receipt_reward()` is called while receipt still has 0 shares
2. Line 398-403: `vault.execute_deposit()` adds shares to the receipt via `update_after_execute_deposit()` [3](#0-2) 

The shares are only added AFTER the reward update completes, meaning any rewards that accrued between the last reward buffer update and deposit execution are permanently lost.

### Impact Explanation

**Direct Fund Impact - Permanent Reward Loss:**
Users suffer permanent loss of rewards they should have earned. When a user requests a deposit and the operator executes it later, any rewards distributed during that waiting period are lost because:
- The receipt had 0 shares when `update_receipt_reward()` was called
- The reward index advanced without accruing rewards (acc_reward = 0)
- Once shares are added, future rewards only accrue from the new index
- The index delta during the waiting period is permanently lost

**Quantified Impact:**
If global reward index increases from 100 to 200 during the deposit waiting period, and the user deposits to receive 1000 shares:
- Expected reward: (200-100) × 1000 = 100,000 reward units
- Actual reward: 0 (index updated with 0 shares)
- Permanent loss: 100,000 reward units per user per deposit

**Affected Parties:**
ALL users depositing into the vault are affected on EVERY deposit execution. This is not limited to edge cases - it's the standard deposit flow.

### Likelihood Explanation

**Reachable Entry Point:**
Any user can trigger this via the standard deposit flow through `user_entry::deposit()` followed by operator calling `execute_deposit()`.

**Feasible Preconditions:**
- User creates receipt and requests deposit (normal operation)
- Rewards accrue globally during the waiting period between request and execution
- Operator executes the deposit (standard protocol operation)

**Execution Practicality:**
This occurs automatically in the normal deposit execution flow. No special conditions or attack setup required. The vulnerability triggers on every single deposit execution where rewards have accrued during the waiting period.

**Economic Rationality:**
Users lose rewards proportional to:
- The time delay between deposit request and execution
- The rate of reward distribution
- The size of their deposit

Longer operator delays between request and execution amplify the reward loss. This is not an attack - it's a defect in the reward accrual logic that systematically disadvantages all depositors.

**Probability:** Near 100% - occurs on every deposit execution when rewards are active.

### Recommendation

**Code-level Mitigation:**
Modify `update_reward()` to only update the index when shares > 0, or defer index updates until shares are acquired:

```move
public(package) fun update_reward(
    self: &mut VaultReceiptInfo,
    reward_type: TypeName,
    new_reward_idx: u256,
): u256 {
    // ... existing initialization code ...
    
    if (new_reward_idx > *pre_idx) {
        // Only update if receipt has shares
        if (self.shares > 0) {
            let acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares);
            *pre_idx = new_reward_idx;
            *unclaimed_reward = *unclaimed_reward + acc_reward;
            emit(VaultReceiptInfoUpdated { new_reward: acc_reward, unclaimed_reward: *unclaimed_reward });
            acc_reward
        } else {
            // Don't update index if no shares - preserve the delta for when shares are added
            0
        }
    } else {
        0
    }
}
```

**Invariant Checks:**
Add assertion: "Reward index updates must only occur when shares > 0 OR when explicitly setting initial index on receipt creation"

**Test Cases:**
1. Create receipt with 0 shares
2. Accrue rewards globally (increase reward index from 100 to 200)
3. Call update_receipt_reward (should NOT update receipt's index)
4. Execute deposit to add shares
5. Call update_receipt_reward again with index 200
6. Verify receipt receives full reward for 0-200 index delta, not just from execution point

### Proof of Concept

**Initial State:**
- Global reward index for token X: 100
- User creates new receipt: shares = 0, reward_index[X] = 100
- User requests deposit of 1000 USDC (expected to receive ~1000 shares)

**Transaction Sequence:**

**T1:** User requests deposit
- Receipt state: shares = 0, reward_index[X] = 100, pending_deposit_balance = 1000

**T2:** Rewards accrue (time passes, reward buffers update)
- Global reward index increases: 100 → 200
- Receipt state unchanged: shares = 0, reward_index[X] = 100

**T3:** Operator executes deposit
- Step 1: `update_reward_buffers()` - global index confirmed at 200
- Step 2: `update_receipt_reward()` calls `update_reward()`
  - Calculation: acc_reward = (200-100) × 0 = 0
  - Receipt index updated: reward_index[X] = 100 → 200
  - Unclaimed reward: 0
- Step 3: `execute_deposit()` adds shares
  - Receipt state: shares = 1000, reward_index[X] = 200

**T4:** More rewards accrue
- Global reward index: 200 → 250
- User calls claim_reward
  - Calculation: acc_reward = (250-200) × 1000 = 50,000
  - User receives only 50,000 units

**Expected vs Actual:**
- **Expected:** User should receive rewards for full index delta 100-250 = (250-100) × 1000 = 150,000 units
- **Actual:** User receives only (250-200) × 1000 = 50,000 units
- **Loss:** 100,000 reward units permanently lost (66% of entitled rewards)

**Success Condition:**
The vulnerability is confirmed if the receipt's reward index advances from 100 to 200 in T3 while shares = 0, causing the user to miss the 100-200 delta when shares are subsequently added.

### Citations

**File:** volo-vault/sources/vault_receipt_info.move (L175-191)
```text
    if (new_reward_idx > *pre_idx) {
        // get new reward
        let acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares);

        // set reward and index
        *pre_idx = new_reward_idx;
        *unclaimed_reward = *unclaimed_reward + acc_reward;

        emit(VaultReceiptInfoUpdated {
            new_reward: acc_reward,
            unclaimed_reward: *unclaimed_reward,
        });

        acc_reward
    } else {
        return 0
    }
```

**File:** volo-vault/sources/operation.move (L393-403)
```text
    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
```

**File:** volo-vault/sources/volo_vault.move (L864-869)
```text
    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );
```
