# Audit Report

## Title
Reward Buffer Timestamp Stall Causes Permanent Loss of Sub-Minimum Rewards

## Summary
The `update_reward_buffer()` function contains a critical control flow flaw where timestamp updates are conditional on `actual_reward_amount > 0`. When remaining buffer rewards fall below the minimum threshold (`total_shares / 1e18`), the timestamp never advances, permanently locking these rewards and preventing their distribution to users.

## Finding Description

The vulnerability exists in the `update_reward_buffer()` function where three control flow branches handle different scenarios, but only Branch 3 has a flawed timestamp update mechanism. [1](#0-0) 

**Branch 1** (rate == 0): Timestamp is updated unconditionally at line 484, ensuring time progression even with no active distribution. [2](#0-1) 

**Branch 2** (remaining_reward_amount == 0): Timestamp is updated unconditionally at line 505 when the buffer is fully depleted. [3](#0-2) 

**Branch 3** (rate != 0 AND remaining != 0): This is the problematic branch. The timestamp update at line 536 is **inside** the conditional block that starts at line 523 (`if (actual_reward_amount > 0)`). When `actual_reward_amount == 0` (because remaining rewards are below the minimum threshold), this entire block is skipped and the timestamp is never updated. [4](#0-3) [5](#0-4) 

The minimum reward amount is calculated as `total_shares * 1 / ORACLE_DECIMALS` where `ORACLE_DECIMALS = 1e18`, meaning any remaining reward amount below `total_shares / 1e18` results in `actual_reward_amount = 0`, triggering the timestamp stall.

**Execution Path:**
1. Buffer has remaining rewards below `total_shares / 1e18` with non-zero rate
2. `new_reward = rate * (now - last_updated)` grows over time (line 498)
3. `reward_amount = min(remaining_reward_amount, new_reward)` caps at remaining amount (line 512)
4. `actual_reward_amount = 0` since reward_amount < minimum_reward_amount (lines 515-519)
5. Timestamp NOT updated (line 536 skipped because it's inside the if block at line 523)
6. On next call, `(now - last_updated)` is even larger, but reward_amount still capped at remaining
7. Loop continues indefinitely - rewards permanently stuck [6](#0-5) 

The operator can retrieve stuck funds via `retrieve_undistributed_reward()`, meaning these rewards go to the operator rather than being distributed to vault share holders as intended.

## Impact Explanation

**Direct Harm**: Users permanently lose rewards that should have been distributed to them proportionally based on their vault shares. The core fairness invariant of the reward system - that all deposited rewards should be distributed proportionally to users - is violated.

**Quantified Loss**:
- Any remaining buffer amount below `total_shares / 1e18` becomes permanently unclaimable by users
- For a vault with 1 billion units in total_shares (1e18), rewards below ~1 unit are permanently lost per buffer
- This affects **all** reward buffers as they naturally deplete over time
- Aggregate loss across multiple reward types and time periods compounds the impact

**Affected Parties**: All vault participants lose proportional rewards during the buffer's lifetime.

## Likelihood Explanation

**Reachability**: The vulnerable code path is reached through multiple public functions: [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

All of these functions call `update_reward_buffer()`, making the vulnerable code path highly accessible.

**Preconditions** (Inevitable in Normal Operations):
1. Reward buffer exists with non-zero rate (standard operational state)
2. Buffer has been distributing rewards over time (normal operation)
3. Remaining buffer amount depletes below `total_shares / 1e18` (inevitable as buffers empty)
4. Vault has non-zero shares (normal state)

**Execution Practicality**: This occurs **automatically** during normal reward distribution. No attacker action is required - it's a natural consequence of reward buffers depleting over time as they distribute rewards to users.

**Economic Reality**:
- Zero cost to trigger (happens passively during normal operations)
- Affects every reward buffer eventually as they drain
- Probability of occurrence approaches 100% for long-running buffers
- No special conditions or attacker involvement needed

## Recommendation

Move the timestamp update outside the `if (actual_reward_amount > 0)` conditional block in Branch 3. The timestamp should be updated unconditionally whenever the function processes a non-zero rate with remaining rewards, similar to how Branch 1 and Branch 2 handle their timestamp updates:

```move
} else {
    let reward_amount = std::u256::min(remaining_reward_amount, new_reward);
    let minimum_reward_amount = vault_utils::mul_with_oracle_price(total_shares, 1);

    let actual_reward_amount = if (reward_amount >= minimum_reward_amount) {
        reward_amount
    } else {
        0
    };

    if (actual_reward_amount > 0) {
        if (total_shares > 0) {
            self.update_reward_indices(vault, reward_type, actual_reward_amount);
            *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
                remaining_reward_amount - actual_reward_amount;
        };
    };
    
    // Move timestamp update outside the conditional block
    self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;

    emit(RewardBufferUpdated {
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: actual_reward_amount,
    });
}
```

## Proof of Concept

The following test demonstrates the timestamp stall:

```move
#[test]
public fun test_reward_buffer_timestamp_stall() {
    // Setup: Create vault with 1e18 total_shares and reward buffer
    // Add rewards to buffer with non-zero rate
    // Let buffer distribute until remaining < total_shares / 1e18
    
    // Call update_reward_buffer()
    // Assert: timestamp NOT updated despite time passing
    // Assert: remaining rewards unchanged
    
    // Advance time further
    // Call update_reward_buffer() again
    // Assert: timestamp STILL not updated
    // Assert: rewards remain stuck in buffer
    
    // Assert: Users cannot claim stuck rewards
    // Assert: Operator CAN retrieve via retrieve_undistributed_reward()
}
```

### Citations

**File:** volo-vault/sources/reward_manager.move (L379-412)
```text
public fun add_reward_to_buffer<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    reward: Balance<RewardCoinType>,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    let reward_type = type_name::get<RewardCoinType>();
    let reward_amount = vault_utils::to_decimals(reward.value() as u256);

    // Update reward buffer's current distribution
    self.update_reward_buffer(vault, clock, reward_type);

    let buffer_reward_amount = self.reward_buffer.reward_amounts[reward_type];
    *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
        buffer_reward_amount + reward_amount;

    // New reward balance is not stored in the buffer
    let reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    reward_balance.join(reward);

    emit(RewardAddedWithBuffer {
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    });
}
```

**File:** volo-vault/sources/reward_manager.move (L483-489)
```text
        if (distribution.rate == 0) {
            self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;
            emit(RewardBufferUpdated {
                vault_id: vault.vault_id(),
                coin_type: reward_type,
                reward_amount: 0,
            });
```

**File:** volo-vault/sources/reward_manager.move (L504-510)
```text
            if (remaining_reward_amount == 0) {
                self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;
                emit(RewardBufferUpdated {
                    vault_id: vault.vault_id(),
                    coin_type: reward_type,
                    reward_amount: 0,
                });
```

**File:** volo-vault/sources/reward_manager.move (L511-544)
```text
            } else {
                let reward_amount = std::u256::min(remaining_reward_amount, new_reward);
                let minimum_reward_amount = vault_utils::mul_with_oracle_price(total_shares, 1);

                let actual_reward_amount = if (reward_amount >= minimum_reward_amount) {
                    reward_amount
                } else {
                    0
                };

                // If there is enough reward in the buffer, add the reward to the vault
                // Otherwise, add all the remaining reward to the vault (remaining reward = balance::zero)
                if (actual_reward_amount > 0) {
                    if (total_shares > 0) {
                        // If the vault has no shares, only update the last update time
                        // i.e. It means passing this period of time
                        // Miminum reward amount that will make the index increase
                        // e.g. If the reward amount is too small and the add_index is 0,
                        //      this part of reward should not be updated now (or the funds will be lost).
                        self.update_reward_indices(vault, reward_type, actual_reward_amount);

                        *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
                            remaining_reward_amount - actual_reward_amount;
                    };

                    self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;
                };

                emit(RewardBufferUpdated {
                    vault_id: vault.vault_id(),
                    coin_type: reward_type,
                    reward_amount: actual_reward_amount,
                });
            }
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

**File:** volo-vault/sources/reward_manager.move (L664-699)
```text
public fun retrieve_undistributed_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    amount: u64,
    clock: &Clock,
): Balance<RewardCoinType> {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    let reward_type = type_name::get<RewardCoinType>();

    self.update_reward_buffer(vault, clock, reward_type);

    let remaining_reward_amount = self.reward_buffer.reward_amounts[reward_type];
    let amount_with_decimals = vault_utils::to_decimals(amount as u256);
    assert!(remaining_reward_amount >= amount_with_decimals, ERR_INSUFFICIENT_REWARD_AMOUNT);

    *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
        remaining_reward_amount - amount_with_decimals;

    let reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);

    emit(UndistributedRewardRetrieved {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        reward_type,
        amount,
    });

    reward_balance.split(amount)
}
```

**File:** volo-vault/sources/utils.move (L10-10)
```text
const ORACLE_DECIMALS: u256 = 1_000_000_000_000_000_000; // 10^18
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/operation.move (L393-393)
```text
    reward_manager.update_reward_buffers(vault, clock);
```

**File:** volo-vault/sources/operation.move (L462-462)
```text
    reward_manager.update_reward_buffers(vault, clock);
```
