# Audit Report

## Title
Arithmetic Overflow in Reward Buffer Distribution Causes Denial of Service After Multi-Day Gaps

## Summary
The `update_reward_buffer()` function performs an unchecked u256 multiplication between the reward rate and time delta that can overflow when the time gap exceeds 1 day with near-maximum reward rates, causing transaction aborts and complete denial of service for the reward system.

## Finding Description

The vulnerability exists in the reward buffer distribution calculation logic where the reward rate validation provides insufficient overflow protection.

The rate constraint only ensures safety for exactly 1-day time intervals: [1](#0-0) 

However, the actual reward calculation uses the dynamically computed time delta without bounds checking: [2](#0-1) 

When `time_delta > 86_400_000` milliseconds (more than 1 day) and the reward rate is set near the maximum allowed value, the multiplication `reward_rate * time_delta` exceeds u256 maximum bounds. In Sui Move, arithmetic overflow causes immediate transaction abort.

Multiple critical entry points trigger this vulnerability by calling `update_reward_buffer()`:
- User-callable `claim_reward()` function [3](#0-2) 
- Operator function `add_reward_to_buffer()` [4](#0-3) 
- Operator function `set_reward_rate()` [5](#0-4) 

The protocol provides no recovery mechanism. The `set_reward_rate()` function itself calls `update_reward_buffer()` before modifying the rate, creating a deadlock where operators cannot lower the rate to fix the overflow condition.

## Impact Explanation

This is **HIGH severity** due to complete denial of service affecting critical protocol functionality:

1. **User Impact**: All vault users with pending rewards become unable to claim them. The `claim_reward()` function will abort before distributing any rewards, making accumulated rewards temporarily inaccessible.

2. **Operator Impact**: Protocol operators lose the ability to manage the reward distribution system. They cannot add new rewards to the buffer, cannot adjust reward rates, and cannot retrieve undistributed rewards.

3. **System State**: The vault's entire reward mechanism becomes partially inoperable. While the vault's core deposit/withdrawal functionality remains operational, the reward system enters an irrecoverable locked state without package upgrade intervention.

4. **No Self-Recovery**: Since `set_reward_rate()` calls `update_reward_buffer()` internally before updating the rate [6](#0-5) , operators cannot lower the rate to fix the condition, creating a permanent DoS until admin performs package upgrade with state migration.

**Quantified Scenario**: If rate is set to `MAX_U256 / 86_400_000 - 1` and 2 days (172,800,000 ms) pass without any `update_reward_buffer()` call, the overflow calculation becomes `rate * 172_800_000 ≈ MAX_U256 * 2`, causing guaranteed abort.

## Likelihood Explanation

The likelihood is **MEDIUM-HIGH** because this occurs through normal protocol operation without requiring any attacker:

1. **Natural Occurrence**: Multi-day gaps without reward buffer updates are realistic during:
   - New vault launches with limited initial users
   - Weekend/holiday periods with reduced activity
   - Market downturns decreasing vault usage
   - Any temporary low engagement period

2. **Economic Incentive**: High reward rates near the validation maximum are economically rational for competitive yield farming, making operators likely to set rates close to the upper bound.

3. **Short Threshold**: The 1-day (86,400,000 ms) safety threshold is relatively short for blockchain protocols where user activity can be sporadic.

4. **No Forcing Mechanism**: The protocol includes no mechanism to force regular `update_reward_buffer()` calls, relying entirely on organic transaction activity.

5. **Test Evidence**: The test suite only validates exactly 1-day scenarios [7](#0-6) , indicating the development team did not consider longer time gaps.

## Recommendation

Implement proper overflow protection for the reward calculation:

```move
public fun update_reward_buffer<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    reward_type: TypeName,
) {
    // ... existing code ...
    
    if (now > distribution.last_updated) {
        if (distribution.rate == 0) {
            // ... existing zero rate handling ...
        } else {
            let total_shares = vault.total_shares();
            let reward_rate = distribution.rate;
            let last_update_time = distribution.last_updated;
            let time_delta = (now - last_update_time) as u256;
            
            // FIX: Cap time_delta to maximum safe value
            let max_safe_time_delta = std::u256::max_value!() / reward_rate;
            let capped_time_delta = std::u256::min(time_delta, max_safe_time_delta);
            
            let new_reward = reward_rate * capped_time_delta;
            
            // ... rest of existing code ...
        }
    }
}
```

Alternatively, strengthen the rate validation to account for maximum expected time gaps:

```move
// In set_reward_rate(), validate against expected maximum gap (e.g., 7 days)
const MAX_EXPECTED_GAP_MS: u64 = 604_800_000; // 7 days
assert!(rate < std::u256::max_value!() / MAX_EXPECTED_GAP_MS, ERR_INVALID_REWARD_RATE);
```

## Proof of Concept

```move
#[test]
fun test_reward_buffer_overflow_dos() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and reward manager
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // Add reward type with buffer
        reward_manager.add_new_reward_type<SUI_TEST_COIN, SUI_TEST_COIN>(
            &operation, &operator_cap, &clock, true
        );
        
        vault.set_total_shares(1_000_000_000);
        
        // Set rate to maximum allowed by validation
        let max_rate = std::u256::max_value!() / 86_400_000 - 1;
        reward_manager.set_reward_rate<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &operator_cap, &clock, max_rate
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
    };
    
    // Advance time by 2 days (172,800,000 ms)
    clock::set_for_testing(&mut clock, 172_800_000);
    
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This will abort due to overflow: rate * 172_800_000 > MAX_U256
        reward_manager.update_reward_buffer(
            &mut vault, &clock, type_name::get<SUI_TEST_COIN>()
        );
        
        // Test should abort here - reward system is now in permanent DoS
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

The test demonstrates that when the reward rate is set to the maximum allowed value and time advances beyond 1 day, any attempt to update the reward buffer causes an arithmetic overflow abort, rendering the reward system inoperable.

### Citations

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

**File:** volo-vault/sources/reward_manager.move (L415-437)
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

    // Update the reward rate
    let distribution = &mut self.reward_buffer.distributions[&reward_type];
    distribution.rate = rate;
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

**File:** volo-vault/tests/reward/reward_manager.test.move (L1621-1621)
```text
        clock::set_for_testing(&mut clock, 86_400_000 + 1);
```
