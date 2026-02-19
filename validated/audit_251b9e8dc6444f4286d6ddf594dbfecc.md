# Audit Report

## Title
Reward Buffer Timestamp Stall Causes Permanent Loss of Sub-Minimum Rewards

## Summary
The `update_reward_buffer()` function contains a critical control flow flaw where the timestamp update is conditional on `actual_reward_amount > 0`. When remaining buffer rewards fall below the minimum threshold (`total_shares / 1e18`) while the distribution rate is non-zero, the timestamp never advances, permanently locking these rewards and preventing their distribution to users.

## Finding Description

The vulnerability exists in the `update_reward_buffer()` function where three separate control flow branches handle different scenarios, but only one has a flawed timestamp update mechanism. [1](#0-0) 

**Branch 1** (rate == 0): The timestamp is updated unconditionally, ensuring time progression even with no active distribution. [2](#0-1) 

**Branch 2** (remaining_reward_amount == 0): The timestamp is updated unconditionally when the buffer is fully depleted. [3](#0-2) 

**Branch 3** (rate != 0 AND remaining != 0): This is the problematic branch. The `actual_reward_amount` is calculated based on a minimum threshold, and crucially, the timestamp update at line 536 is **inside** the `if (actual_reward_amount > 0)` conditional block at line 523. When `actual_reward_amount == 0` (because remaining rewards are below the minimum threshold), this entire block is skipped, and the timestamp is never updated. [4](#0-3) 

The minimum reward amount is calculated as `total_shares * 1 / ORACLE_DECIMALS` where `ORACLE_DECIMALS = 1e18`. [5](#0-4) 

This means any remaining reward amount below `total_shares / 1e18` will result in `actual_reward_amount = 0`, triggering the timestamp stall.

**Execution Path:**
1. Buffer has small remaining rewards (below `total_shares / 1e18`) with non-zero rate
2. `new_reward = rate * (now - last_updated)` grows over time
3. `reward_amount = min(remaining_reward_amount, new_reward)` caps at remaining amount
4. `actual_reward_amount = 0` (since reward_amount < minimum_reward_amount)
5. Timestamp is NOT updated (line 536 skipped because it's inside the if block)
6. On next call, `(now - last_updated)` is even larger, but reward_amount still capped at remaining
7. Loop continues indefinitely - rewards permanently stuck

## Impact Explanation

**Direct Harm**: Users permanently lose rewards that should have been distributed to them proportionally based on their vault shares. [6](#0-5) 

The operator can retrieve these stuck funds via `retrieve_undistributed_reward()`, meaning the funds go to the operator rather than being distributed to vault share holders as intended.

**Violated Security Guarantee**: The core fairness invariant of the reward system - that all deposited rewards should be distributed proportionally to users - is violated. Rewards become "lost" to users but recoverable by the operator.

**Quantified Loss**:
- Any remaining buffer amount below `total_shares / 1e18` becomes permanently unclaimable by users
- For a vault with 1 billion units in total_shares (1e18), rewards below ~1 unit are permanently lost per buffer
- This affects **all** reward buffers as they naturally deplete over time
- Aggregate loss across multiple reward types and time periods compounds the impact

**Affected Parties**: All vault participants lose proportional rewards that should have been distributed during the buffer's lifetime.

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

Move the timestamp update outside of the `if (actual_reward_amount > 0)` conditional block to ensure consistent timestamp advancement across all three branches. The timestamp should always be updated when `now > distribution.last_updated`, regardless of whether rewards are actually distributed.

**Fixed code structure** (lines 523-537):
```move
if (actual_reward_amount > 0) {
    if (total_shares > 0) {
        self.update_reward_indices(vault, reward_type, actual_reward_amount);
        *self.reward_buffer.reward_amounts.borrow_mut(reward_type) =
            remaining_reward_amount - actual_reward_amount;
    };
};

// MOVE THIS OUTSIDE THE IF BLOCK
self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;

emit(RewardBufferUpdated {
    vault_id: vault.vault_id(),
    coin_type: reward_type,
    reward_amount: actual_reward_amount,
});
```

This ensures that even when `actual_reward_amount == 0` due to insufficient rewards, the timestamp still advances, preventing the permanent stall condition.

## Proof of Concept

A test case demonstrating the vulnerability would:
1. Create a reward buffer with a non-zero rate
2. Add a small amount of rewards (below `total_shares / 1e18`)
3. Advance the clock and call `update_reward_buffer()` multiple times
4. Verify that the `last_updated` timestamp never advances
5. Verify that rewards remain stuck in the buffer
6. Show that operator can retrieve these "stuck" rewards that should have gone to users

The vulnerability is confirmed by code inspection of the control flow logic where the timestamp update at line 536 is inside the conditional block at line 523, creating inconsistent behavior compared to the other two branches (lines 484 and 505) which update the timestamp unconditionally.

### Citations

**File:** volo-vault/sources/reward_manager.move (L379-386)
```text
public fun add_reward_to_buffer<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    reward: Balance<RewardCoinType>,
) {
```

**File:** volo-vault/sources/reward_manager.move (L415-422)
```text
public fun set_reward_rate<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    rate: u256,
) {
```

**File:** volo-vault/sources/reward_manager.move (L449-453)
```text
public fun update_reward_buffers<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
) {
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

**File:** volo-vault/sources/reward_manager.move (L512-537)
```text
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
```

**File:** volo-vault/sources/reward_manager.move (L596-601)
```text
public fun claim_reward<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt: &mut Receipt,
): Balance<RewardCoinType> {
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

**File:** volo-vault/sources/utils.move (L9-10)
```text
const DECIMALS: u256 = 1_000_000_000; // 10^9
const ORACLE_DECIMALS: u256 = 1_000_000_000_000_000_000; // 10^18
```

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```
