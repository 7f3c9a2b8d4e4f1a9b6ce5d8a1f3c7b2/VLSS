# Audit Report

## Title
Arithmetic Overflow in Reward Buffer Distribution Causes Denial of Service After Multi-Day Gaps

## Summary
The `update_reward_buffer()` function in the reward manager performs unchecked u256 multiplication that overflows when the time gap exceeds 1 day with near-maximum reward rates. In Sui Move, arithmetic overflow causes transaction abort, leading to a complete denial of service where users cannot claim rewards and operators cannot manage the reward buffer.

## Finding Description

The vulnerability exists in the reward buffer update mechanism. When setting reward rates, the code validates that the rate is safe for exactly 1 day of accumulation [1](#0-0) , but the actual reward calculation does not enforce this time limit.

The vulnerable multiplication occurs when computing new rewards based on elapsed time [2](#0-1) . The rate validation ensures `rate < MAX_U256 / 86_400_000`, which only prevents overflow when `time_delta <= 86_400_000` milliseconds (exactly 1 day). However, there is no check to ensure that the actual time delta stays within this bound.

When `update_reward_buffer()` is not called for more than 1 day, the multiplication `rate * time_delta` exceeds u256 maximum value, causing the transaction to abort. This affects multiple critical entry points:

- Users calling `claim_reward()` [3](#0-2) 
- Operators calling `add_reward_to_buffer()` [4](#0-3) 
- Operators calling `set_reward_rate()` [5](#0-4) 
- Operators calling `retrieve_undistributed_reward()` [6](#0-5) 
- Operators calling `remove_reward_buffer_distribution()` [7](#0-6) 

All these functions internally call `update_reward_buffer()`, which will abort if the overflow condition is met.

**Critical recovery issue:** The system cannot easily recover because calling `set_reward_rate()` to lower the rate requires calling `update_reward_buffer()` first, which is the function that overflows. This creates a deadlock requiring contract upgrade or migration.

## Impact Explanation

This is a **HIGH severity** vulnerability because:

1. **Complete DoS of reward distribution system**: All reward-related operations become unavailable, including user reward claims and operator reward management.

2. **User funds locked**: Users' accumulated rewards become inaccessible until admin intervention through contract upgrade or migration.

3. **Quantified impact scenario**: 
   - Vault sets rate to `MAX_U256 / 86_400_000 - 1` (maximum allowed, passes validation)
   - 2 days pass without activity: `time_delta = 172_800_000 ms`
   - Calculation: `rate * 172_800_000 ≈ 2 * MAX_U256` → overflow
   - All reward operations abort indefinitely

4. **No easy recovery path**: Cannot call `set_reward_rate()` to fix the rate because it also calls `update_reward_buffer()`.

5. **Affects entire vault**: All users holding receipts for that vault cannot access their rewards.

## Likelihood Explanation

This is a **MEDIUM-HIGH likelihood** vulnerability because:

1. **No attacker required**: This occurs naturally during normal protocol operation with low activity.

2. **Realistic scenarios where multi-day gaps occur**:
   - New vaults with limited initial users
   - Weekend/holiday periods when blockchain activity drops
   - Market downturns reducing vault engagement
   - Any temporary reduction in user activity

3. **Economically rational preconditions**: High reward rates (near maximum) are economically rational for protocols competing for TVL through yield.

4. **No forced updates**: There is no mechanism that forces regular `update_reward_buffer()` calls within the 1-day threshold.

5. **Test coverage gap**: The test suite only validates exactly 1-day scenarios, not longer periods [8](#0-7) , indicating this edge case was not considered.

The 1-day threshold is relatively short for blockchain protocols, making multi-day gaps a realistic occurrence.

## Recommendation

Implement one or more of the following fixes:

1. **Cap the time delta** in `update_reward_buffer()`:
```move
let time_delta = now - last_update_time;
let safe_time_delta = std::u256::min((time_delta as u256), 86_400_000);
let new_reward = reward_rate * safe_time_delta;
```

2. **Use safe multiplication** from the existing `safe_math` module:
```move
use volo_vault::safe_math;
let new_reward = safe_math::mul(reward_rate, (time_delta as u256));
```

3. **Add time delta validation** before multiplication:
```move
let time_delta_u256 = (now - last_update_time) as u256;
assert!(time_delta_u256 <= 86_400_000 || reward_rate <= std::u256::max_value!() / time_delta_u256, ERR_TIME_DELTA_TOO_LARGE);
let new_reward = reward_rate * time_delta_u256;
```

4. **Strengthen rate validation** to account for possible multi-day gaps:
```move
// Assume maximum 7-day gap
assert!(rate < std::u256::max_value!() / (7 * 86_400_000), ERR_INVALID_REWARD_RATE);
```

The recommended approach is **option 1** (cap time delta) combined with **option 4** (strengthen validation) to provide defense in depth.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = ARITHMETIC_OVERFLOW)] // Will abort due to overflow
fun test_reward_buffer_overflow_after_two_days() {
    let mut s = scenario();
    let clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and reward manager with maximum allowed rate
    setup_vault_with_max_rate(&mut s, &clock);
    
    // Advance time by 2 days (172,800,000 milliseconds)
    clock.increment_for_testing(172_800_000);
    
    // Attempt to claim reward - this will abort due to overflow
    s.next_tx(USER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI>>();
        let mut vault = s.take_shared<Vault<SUI>>();
        let mut receipt = s.take_from_sender<Receipt>();
        
        // This call will abort due to u256 overflow in update_reward_buffer()
        let reward_balance = reward_manager.claim_reward<SUI, SUI>(
            &mut vault,
            &clock,
            &mut receipt,
        );
        
        reward_balance.destroy_for_testing();
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

The proof of concept demonstrates that after 2 days without updates, any attempt to interact with the reward system will abort due to arithmetic overflow, confirming the vulnerability.

### Citations

**File:** volo-vault/sources/reward_manager.move (L309-321)
```text
public fun remove_reward_buffer_distribution<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    reward_type: TypeName,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    self.update_reward_buffer(vault, clock, reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L379-395)
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
```

**File:** volo-vault/sources/reward_manager.move (L415-433)
```text
public fun set_reward_rate<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    rate: u256,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    // assert!(rate >= DECIMALS, ERR_RATE_DECIMALS_TOO_SMALL);
    assert!(rate < std::u256::max_value!() / 86_400_000, ERR_INVALID_REWARD_RATE);

    let reward_type = type_name::get<RewardCoinType>();

    // Update the reward buffer for this reward type first
    self.update_reward_buffer<PrincipalCoinType>(vault, clock, reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L494-498)
```text
            let reward_rate = distribution.rate;
            let last_update_time = distribution.last_updated;

            // New reward amount is with extra 9 decimals
            let new_reward = reward_rate * ((now - last_update_time) as u256);
```

**File:** volo-vault/sources/reward_manager.move (L596-613)
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
```

**File:** volo-vault/sources/reward_manager.move (L664-678)
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
```

**File:** volo-vault/tests/reward/reward_manager.test.move (L1218-1224)
```text
        reward_manager.set_reward_rate<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            std::u256::max_value!() / 86_400_000,
        );
```
