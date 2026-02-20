# Audit Report

## Title
Reward Buffer Calculation Overflow Causes Permanent Vault DoS

## Summary
The reward buffer update mechanism validates reward rates against one day of elapsed time but does not bound the actual elapsed time used in calculations. When the buffer is not updated for more than one day while the rate is set near the maximum allowed value, the multiplication overflows in Sui Move, causing permanent denial of service for all vault operations with no recovery mechanism.

## Finding Description

The vulnerability exists in the `update_reward_buffer` function's design. The rate validation ensures the rate can be safely multiplied by 86,400,000 milliseconds (one day) without overflow [1](#0-0) , but the actual calculation uses completely unbounded elapsed time [2](#0-1) .

**Mathematical proof of overflow:**
- Maximum allowed rate: `rate < u256::max / 86_400_000`
- If operator sets `rate = (u256::max / 86_400_000) - 1` (valid under the constraint)
- And elapsed time = `86_400_001` milliseconds (just over 1 day)
- Then: `new_reward = rate * elapsed_time ≈ u256::max * (86_400_001/86_400_000) > u256::max`
- Result: Arithmetic overflow → transaction abort

This affects ALL critical vault operations because they call `update_reward_buffers`:
- Deposit execution [3](#0-2) 
- Batch deposit execution [4](#0-3) 
- Withdrawal execution [5](#0-4) 
- Batch withdrawal execution [6](#0-5) 
- Reward claims [7](#0-6) 

**Most critically, there is NO recovery path.** The operator cannot fix the issue by calling `set_reward_rate` to lower the rate because it must update the buffer first [8](#0-7) , which triggers the same overflow. Similarly, `add_reward_to_buffer` [9](#0-8) , `remove_reward_buffer_distribution` [10](#0-9) , and `retrieve_undistributed_reward` [11](#0-10)  all call `update_reward_buffer`, making them equally unusable.

The `last_updated` timestamp can only be modified inside `update_reward_buffer` itself [12](#0-11) , meaning no emergency function can bypass the overflow calculation.

## Impact Explanation

**Operational Impact - Complete Vault DoS:**
- All deposit operations fail permanently, preventing new capital from entering the vault
- All withdrawal operations fail permanently, trapping user funds indefinitely
- All reward claims fail permanently, making accumulated rewards unclaimable
- The operator cannot modify the reward rate to fix the issue (also triggers overflow)
- No emergency functions exist to directly modify the `last_updated` timestamp or bypass the overflow calculation

**Affected Parties:**
- All vault users lose access to their principal deposits and cannot withdraw
- All vault users lose access to accumulated rewards and cannot claim
- Protocol operations are completely halted
- Operator has no recovery mechanism beyond deploying a new contract and migrating all user state and funds

**Severity Justification:**
This is a HIGH severity issue because it causes permanent denial of service for all vault operations with no recovery path. While it requires the operator to set a high reward rate, such rates are legitimate operational parameters within the allowed bounds established by the validation. The overflow is triggered by time passage alone, not malicious action, making this a design flaw rather than an operator error.

## Likelihood Explanation

**Realistic Scenario:**
1. Operator sets a high but legitimate reward rate near the maximum allowed to offer competitive rewards: `rate ≈ (u256::max / 86_400_000) - 1`
2. During a period of low vault activity, scheduled maintenance window, holiday period, or operational delay, the reward buffer is not updated for more than 24 hours
3. The next call to any deposit/withdraw/claim function triggers the overflow and causes permanent abort

**Feasibility:**
- Operators legitimately want to maximize reward rates to attract capital and may set rates near the maximum allowed
- Multi-day periods without vault activity naturally occur during low-usage periods, weekends, holidays, or planned maintenance
- Once triggered, the condition is permanent - every subsequent transaction attempt will fail with arithmetic overflow
- The rate validation creates a false sense of security by checking only 1 day while allowing the vulnerable configuration

**Execution Practicality:**
- No attacker action required - time passage alone triggers the issue
- Standard operator configuration (setting reward rates within documented bounds) combined with normal operational variations creates the condition
- Sui Move's overflow abort behavior makes this deterministic and unrecoverable

**Likelihood Assessment:** MEDIUM to HIGH  
The vulnerability is likely to manifest in real-world operations, particularly for vaults with high reward rates during periods of reduced activity.

## Recommendation

Implement one of the following fixes:

**Option 1: Cap elapsed time in the calculation**
```move
// In update_reward_buffer, replace line 498 with:
let elapsed_time = std::u256::min((now - last_update_time) as u256, 86_400_000);
let new_reward = reward_rate * elapsed_time;
```

**Option 2: Adjust the rate validation to account for maximum expected elapsed time**
```move
// In set_reward_rate, replace line 428 with a more conservative bound:
// Assuming maximum 30 days between updates
assert!(rate < std::u256::max_value!() / (86_400_000 * 30), ERR_INVALID_REWARD_RATE);
```

**Option 3: Add emergency bypass function (recommended in addition to Option 1 or 2)**
```move
public fun emergency_reset_buffer_timestamp<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    admin_cap: &AdminCap, // Requires admin capability
    clock: &Clock,
) {
    let reward_type = type_name::get<RewardCoinType>();
    let now = clock.timestamp_ms();
    self.reward_buffer.distributions.get_mut(&reward_type).last_updated = now;
}
```

Option 1 is the most robust as it prevents the overflow while maintaining reward distribution semantics. Option 3 provides an emergency recovery mechanism if the issue occurs.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = ARITHMETIC_ERROR)] // Sui Move arithmetic overflow abort code
public fun test_reward_buffer_overflow_dos() {
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
        
        // Add reward type with buffer
        reward_manager.add_new_reward_type<SUI_TEST_COIN, SUI_TEST_COIN>(
            &operation, &operator_cap, &clock, true
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
        test_scenario::return_shared(reward_manager);
    };
    
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        
        vault.set_total_shares(1_000_000_000);
        
        // Set rate to maximum allowed value (just below the limit)
        let max_rate = std::u256::max_value!() / 86_400_000 - 1;
        reward_manager.set_reward_rate<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, &clock, max_rate
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
    };
    
    // Advance time by more than 1 day (86,400,001 milliseconds)
    clock.increment_for_testing(86_400_001);
    
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This will trigger overflow: rate * 86_400_001 > u256::max
        // Causes permanent DoS - all vault operations now fail
        reward_manager.update_reward_buffers(&mut vault, &clock);
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability demonstrates a critical design flaw where input validation creates a false sense of security. The rate validation correctly ensures safety for 1-day intervals, but the actual calculation uses unbounded elapsed time from the blockchain clock. The combination of:

1. Legitimate high reward rates (within validated bounds)
2. Natural operational gaps (maintenance, low activity periods)
3. Sui Move's safe arithmetic (overflow abort)
4. No recovery mechanism in the protocol

Creates a permanent denial of service condition with no operator recourse except full contract redeployment and user migration.

### Citations

**File:** volo-vault/sources/reward_manager.move (L321-321)
```text
    self.update_reward_buffer(vault, clock, reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L395-395)
```text
    self.update_reward_buffer(vault, clock, reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L428-428)
```text
    assert!(rate < std::u256::max_value!() / 86_400_000, ERR_INVALID_REWARD_RATE);
```

**File:** volo-vault/sources/reward_manager.move (L433-433)
```text
    self.update_reward_buffer<PrincipalCoinType>(vault, clock, reward_type);
```

**File:** volo-vault/sources/reward_manager.move (L484-536)
```text
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
```

**File:** volo-vault/sources/reward_manager.move (L613-613)
```text
    self.update_reward_buffers<PrincipalCoinType>(vault, clock);
```

**File:** volo-vault/sources/reward_manager.move (L678-678)
```text
    self.update_reward_buffer(vault, clock, reward_type);
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
