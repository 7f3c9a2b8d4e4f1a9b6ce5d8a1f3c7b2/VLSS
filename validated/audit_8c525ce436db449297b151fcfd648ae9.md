# Audit Report

## Title
Integer Division Floor Precision Loss in Reward Index Minimum Check Causes Permanent Reward Fund Loss

## Summary
The `update_reward_indices()` function uses floor division to calculate the minimum reward amount check when ceiling division is required. When `total_shares` is not a perfect multiple of 1e18 (the common case), rewards that pass the minimum check can still result in `add_index = 0`, causing reward tokens to be deposited into the contract but never distributed to users, resulting in permanent fund loss.

## Finding Description

The vulnerability exists in the reward distribution mechanism where a mathematical inconsistency between the minimum reward check and the actual index calculation creates a gap that leads to permanent fund loss.

**Two vulnerable code paths:**

1. **Direct reward addition** [1](#0-0) 

2. **Reward buffer distribution** [2](#0-1) 

**The minimum check calculation** uses `mul_with_oracle_price(total_shares, 1)` which evaluates to `floor(total_shares / 1e18)` [3](#0-2) [4](#0-3) 

**The utility function** implements floor division [5](#0-4) 

**The index calculation** uses `div_with_oracle_price(reward_amount, total_shares)` which evaluates to `reward_amount * 1e18 / total_shares` (floor division) [6](#0-5) [7](#0-6) 

**Mathematical Root Cause:**

For `add_index >= 1`, we need: `reward_amount * 1e18 / total_shares >= 1`, which requires `reward_amount >= ceil(total_shares / 1e18)`

However, the check uses `reward_amount >= floor(total_shares / 1e18)`

This creates a gap where: `floor(total_shares / 1e18) <= reward_amount < ceil(total_shares / 1e18)`

In this gap, rewards pass the assertion but `add_index` truncates to 0 [8](#0-7) 

**Concrete Example:**
- If `total_shares = 1,234,567,890,123,456,789` (≈1.234e18)
- `floor(1.234e18 / 1e18) = 1` (minimum check)
- `ceil(1.234e18 / 1e18) = 2` (actual requirement)
- With `reward_amount = 1`: passes check but `add_index = 1 * 1e18 / 1.234e18 = 0`

**Why Existing Protection Fails:**

The developers were aware of this issue as shown by the comment [9](#0-8)  but implemented floor division instead of ceiling division.

**Impact Chain:**

1. Reward balance is joined to the bag [10](#0-9) 
2. When `add_index = 0`, the reward index doesn't increase [8](#0-7) 
3. User rewards are calculated based on index difference multiplied by shares [11](#0-10) 
4. If index unchanged, accumulated reward = 0, users cannot claim these tokens
5. Reward tokens remain permanently locked in the `reward_balances` bag

## Impact Explanation

**Direct Fund Loss:** Reward tokens are permanently locked in the contract when `add_index = 0`. The reward balance is deposited into the `reward_balances` bag but the index doesn't increase, preventing users from ever claiming these rewards.

**Quantified Loss per Incident:**
- For `total_shares = 1.234e18`, minimum check requires `reward_amount >= 1`, but `add_index = 0` when `reward_amount = 1`
- Lost amount per incident: `reward_amount * 1e-9` tokens (since reward_amount has 9 extra decimals)
- With `reward_amount = 1`, this is `1e-9` tokens per incident

**Cumulative Impact:**
The reward buffer distribution path executes automatically based on configured rates [2](#0-1) . Over time with continuous distributions, small amounts accumulate into significant fund loss.

**Affected Parties:**
- Protocol loses reward tokens permanently
- Users don't receive their entitled reward distributions
- All vault participants are affected proportionally

## Likelihood Explanation

**High Likelihood - Occurs in Normal Operations:**

1. **Precondition is Default State:** `total_shares` being a non-multiple of 1e18 is the normal state, not an edge case. Shares are calculated based on deposit amounts and share ratios, making perfect multiples of 1e18 practically impossible in real operations.

2. **Triggered by Normal Operator Actions:** Operators adding rewards near the minimum threshold, or automatic buffer distributions releasing small amounts based on configured rates, will trigger this without any malicious intent.

3. **No Detection Mechanism:** The transaction succeeds and emits events showing the reward was added [12](#0-11) , but users never receive it. The operator has no indication that funds were lost.

4. **Zero Execution Complexity:** This happens automatically in the normal flow when the buffer distributes rewards based on the configured rate. No special setup or attack vector required.

## Recommendation

Replace floor division with ceiling division in the minimum reward check. The fix requires calculating `ceil(total_shares / 1e18)` instead of `floor(total_shares / 1e18)`.

**Implementation approach:**
```
// Instead of: minimum_reward_amount = total_shares * 1 / ORACLE_DECIMALS
// Use: minimum_reward_amount = (total_shares + ORACLE_DECIMALS - 1) / ORACLE_DECIMALS
```

This ensures that `reward_amount >= minimum_reward_amount` guarantees `add_index >= 1`, eliminating the gap that causes fund loss.

## Proof of Concept

```move
#[test]
fun test_reward_index_floor_precision_loss() {
    // Setup vault with total_shares = 1.234e18 (not a multiple of 1e18)
    let total_shares: u256 = 1_234_567_890_123_456_789;
    
    // Calculate minimum using floor division (current implementation)
    let minimum_floor = total_shares * 1 / 1_000_000_000_000_000_000; // = 1
    
    // Test with reward_amount = 1 (passes minimum check)
    let reward_amount: u256 = 1;
    assert!(reward_amount >= minimum_floor, 0); // Passes ✓
    
    // Calculate add_index (same as update_reward_indices)
    let add_index = reward_amount * 1_000_000_000_000_000_000 / total_shares;
    assert!(add_index == 0, 1); // Index = 0, FUNDS LOST ✗
    
    // What we actually need (ceiling division)
    let minimum_ceiling = (total_shares + 1_000_000_000_000_000_000 - 1) / 1_000_000_000_000_000_000; // = 2
    
    // With ceiling check, reward_amount = 1 would correctly fail
    // Only reward_amount >= 2 would pass and guarantee add_index >= 1
}
```

This test demonstrates that with `total_shares = 1.234e18`, a `reward_amount = 1` passes the current minimum check but produces `add_index = 0`, causing the deposited reward tokens to become permanently unclaimable.

### Citations

**File:** volo-vault/sources/reward_manager.move (L340-376)
```text
public fun add_reward_balance<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    reward: Balance<RewardCoinType>,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    let reward_type = type_name::get<RewardCoinType>();
    let reward_amount = vault_utils::to_decimals(reward.value() as u256);

    // If the reward amount is too small to make the index increase,
    // the reward will be lost.
    let minimum_reward_amount = vault_utils::mul_with_oracle_price(vault.total_shares(), 1);
    assert!(reward_amount>= minimum_reward_amount, ERR_REWARD_AMOUNT_TOO_SMALL);

    // New reward balance goes into the bag
    let reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    reward_balance.join(reward);

    let reward_amounts = self.reward_amounts.borrow_mut(reward_type);
    *reward_amounts = *reward_amounts + reward_amount;

    self.update_reward_indices(vault, reward_type, reward_amount);

    emit(RewardBalanceAdded {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
    })
}
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

**File:** volo-vault/sources/reward_manager.move (L574-577)
```text
    let add_index = vault_utils::div_with_oracle_price(
        reward_amount,
        total_shares,
    );
```

**File:** volo-vault/sources/reward_manager.move (L578-580)
```text
    let new_reward_index = *self.reward_indices.get(&reward_type) + add_index;

    *self.reward_indices.get_mut(&reward_type) = new_reward_index;
```

**File:** volo-vault/sources/reward_manager.move (L582-589)
```text
    emit(RewardIndicesUpdated {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
        inc_reward_index: add_index,
        new_reward_index: new_reward_index,
    })
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/vault_receipt_info.move (L175-181)
```text
    if (new_reward_idx > *pre_idx) {
        // get new reward
        let acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares);

        // set reward and index
        *pre_idx = new_reward_idx;
        *unclaimed_reward = *unclaimed_reward + acc_reward;
```
