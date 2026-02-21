# Audit Report

## Title
Missing Timestamp Update in Zero-Reward Scenarios Violates Linear Reward Distribution Invariant

## Summary
The `update_reward_buffer` function fails to update the `last_updated` timestamp when calculated rewards fall below the minimum distribution threshold (`actual_reward_amount == 0`). This causes subsequent reward calculations to include previously skipped time periods, violating the protocol's linear reward distribution invariant and causing rewards to be distributed faster than the configured rate.

## Finding Description

The vulnerability exists in the `update_reward_buffer` function where timestamp updates are conditionally executed based on whether rewards are distributed. [1](#0-0) 

When the reward buffer has a non-zero rate and remaining rewards, but the calculated reward amount falls below the minimum threshold, the following sequence occurs:

1. The minimum reward amount is calculated as `total_shares / 1e18` [2](#0-1) 

2. If `reward_amount < minimum_reward_amount`, then `actual_reward_amount` is set to 0 [3](#0-2) 

3. The timestamp update is inside the `if (actual_reward_amount > 0)` block [4](#0-3) 

4. When `actual_reward_amount == 0`, the condition at line 523 evaluates to FALSE, skipping the timestamp update at line 536

5. The function emits an event and exits, leaving `last_updated` at its stale value [5](#0-4) 

On subsequent calls, the calculation `new_reward = reward_rate * ((now - last_update_time) as u256)` uses the stale timestamp [6](#0-5) , causing `time_elapsed` to include the previously skipped period. This results in a "catch-up" distribution that violates the linear rate.

The vulnerability is easily triggered through public interfaces. The `claim_reward` function is publicly accessible [7](#0-6)  and calls `update_reward_buffers` [8](#0-7) , which invokes the vulnerable function [9](#0-8) . Additionally, operator-triggered deposit and withdraw operations also call this function [10](#0-9) [11](#0-10) [12](#0-11) [13](#0-12) .

## Impact Explanation

This vulnerability breaks a core protocol invariant: **linear reward distribution at a configured rate**. 

The reward buffer mechanism guarantees that rewards are distributed smoothly over time according to the configured rate. When the timestamp is not updated during zero-reward periods, the protocol allows "deferred" time periods to be retroactively included in future distributions. This causes:

1. **Violated Distribution Schedule**: Rewards that should have been distributed linearly are instead distributed in bursts, breaking the vesting mechanism
2. **Accelerated Buffer Depletion**: The reward buffer is depleted faster than intended by the configured rate
3. **Unpredictable User Rewards**: Users receive irregular reward distributions rather than the expected steady stream

While the total distributed amount cannot exceed the buffer balance (due to the `min` check), the RATE at which rewards are distributed is violated, which undermines the operator's ability to control reward distribution timing.

## Likelihood Explanation

**HIGH Likelihood** - This occurs naturally during normal protocol operations:

1. **High TVL Scenarios**: When `total_shares` is large, `minimum_reward_amount = total_shares / 1e18` becomes substantial, making it easy for rewards to fall below the threshold

2. **Conservative Reward Rates**: Operators setting low rates for gradual distribution will frequently trigger this condition

3. **Short Time Intervals**: Frequent updates (from high-frequency claims or operations) result in small `time_elapsed * rate` values that fall below the minimum

4. **Multiple Trigger Points**: Any user with a receipt can trigger via `claim_reward`, and operators routinely trigger via deposit/withdraw operations

5. **No Special Preconditions**: Requires no compromised keys, special vault state, or malicious intent - happens during ordinary operations

## Recommendation

Update the timestamp unconditionally when time has passed and the rate is non-zero, regardless of whether rewards were distributed:

```move
// After line 519, move the timestamp update outside the actual_reward_amount check
let actual_reward_amount = if (reward_amount >= minimum_reward_amount) {
    reward_amount
} else {
    0
};

// Update timestamp regardless of distribution
self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;

// Only distribute if actual_reward_amount > 0
if (actual_reward_amount > 0 && total_shares > 0) {
    self.update_reward_indices(vault, reward_type, actual_reward_amount);
    *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
        remaining_reward_amount - actual_reward_amount;
};

emit(RewardBufferUpdated {
    vault_id: vault.vault_id(),
    coin_type: reward_type,
    reward_amount: actual_reward_amount,
});
```

This ensures that time periods where rewards are below the minimum threshold are properly "skipped" rather than accumulated for future distribution.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Create a reward buffer with a low rate and high TVL vault
2. Call `update_reward_buffer` at time T1 - rewards fall below minimum, no distribution, timestamp not updated
3. Wait additional time and call again at time T2
4. Verify that rewards calculated = rate * (T2 - T0) instead of rate * (T2 - T1), proving the stale timestamp was used
5. Show that this results in faster buffer depletion than the configured rate intended

### Citations

**File:** volo-vault/sources/reward_manager.move (L460-460)
```text
        self.update_reward_buffer<PrincipalCoinType>(vault, clock, *reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L466-547)
```text
public fun update_reward_buffer<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    reward_type: TypeName,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    assert!(
        self.reward_buffer.reward_amounts.contains(reward_type),
        ERR_REWARD_BUFFER_TYPE_NOT_FOUND,
    );

    let now = clock.timestamp_ms();
    let distribution = &self.reward_buffer.distributions[&reward_type];

    if (now > distribution.last_updated) {
        if (distribution.rate == 0) {
            self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;
            emit(RewardBufferUpdated {
                vault_id: vault.vault_id(),
                coin_type: reward_type,
                reward_amount: 0,
            });
        } else {
            let total_shares = vault.total_shares();

            // Newly generated reward from last update time to current time
            let reward_rate = distribution.rate;
            let last_update_time = distribution.last_updated;

            // New reward amount is with extra 9 decimals
            let new_reward = reward_rate * ((now - last_update_time) as u256);

            // Total remaining reward in the buffer
            // Newly generated reward from last update time to current time
            // Minimum reward amount that will make the index increase (total shares / 1e18)
            let remaining_reward_amount = self.reward_buffer.reward_amounts[reward_type];
            if (remaining_reward_amount == 0) {
                self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;
                emit(RewardBufferUpdated {
                    vault_id: vault.vault_id(),
                    coin_type: reward_type,
                    reward_amount: 0,
                });
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
        }
    }
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

**File:** volo-vault/sources/operation.move (L393-393)
```text
    reward_manager.update_reward_buffers(vault, clock);
```

**File:** volo-vault/sources/operation.move (L418-418)
```text
    reward_manager.update_reward_buffers(vault, clock);
```

**File:** volo-vault/sources/operation.move (L462-462)
```text
    reward_manager.update_reward_buffers(vault, clock);
```

**File:** volo-vault/sources/operation.move (L493-493)
```text
    reward_manager.update_reward_buffers(vault, clock);
```
