# Audit Report

## Title
Reward Buffer Arithmetic Overflow Causes Vault Operations Denial of Service

## Summary
The reward buffer distribution system contains an arithmetic overflow vulnerability when the time between updates exceeds 24 hours and the reward rate is set near its maximum allowed value. This causes all critical vault operations (deposit execution, withdrawal execution, and reward claims) to abort with arithmetic overflow, creating a complete denial of service until operator intervention.

## Finding Description

The vulnerability exists in the `update_reward_buffer` function where reward accumulation is calculated by multiplying the reward rate by the elapsed time. [1](#0-0) 

The `set_reward_rate` function validates that the rate allows safe multiplication only for time deltas up to 86,400,000 milliseconds (24 hours). [2](#0-1) 

However, there is no cap on how long `(now - last_update_time)` can grow. If more than 24 hours elapse without calling `update_reward_buffer`, and the reward_rate is set near `u256::MAX / 86_400_000`, the multiplication will overflow u256 and abort the transaction.

This overflow blocks all critical vault operations because they call `update_reward_buffers` at entry:
- Deposit execution [3](#0-2) 
- Withdrawal execution [4](#0-3) 
- Reward claims [5](#0-4) 

The vulnerability breaks the critical availability invariant: users must be able to execute deposits, withdrawals, and claim rewards at any time under normal operation.

## Impact Explanation

Once triggered, the overflow causes a complete denial of service of the vault:

- **No deposit executions**: Users cannot have their deposit requests processed, locking their funds in the request buffer indefinitely
- **No withdrawal executions**: Users cannot execute withdrawal requests, preventing access to their funds  
- **No reward claims**: Users cannot claim accumulated rewards from any reward type

The vault remains frozen until an operator manually intervenes by either reducing the reward rate or removing the problematic reward distribution. This violates the critical availability guarantee that users can access their funds and execute normal vault operations.

The impact is HIGH because it affects all users and all critical vault operations, requiring privileged operator intervention to restore functionality.

## Likelihood Explanation

**Preconditions**:
1. Operator sets a high reward_rate approaching `u256::MAX / 86_400_000` - this is a legitimate operational decision to incentivize users during promotional periods
2. No transactions call `update_reward_buffer` for more than 24 hours - realistic during:
   - Weekend/holiday periods with low protocol activity
   - After market events causing user caution
   - Early protocol stages with few active users
   - Network congestion or maintenance windows

**Trigger**: Any user or operator attempting to execute a deposit, withdrawal, or claim reward will trigger the overflow

**Feasibility**: HIGH - This requires only normal operator configuration choices combined with a period of low activity, both of which are realistic in production environments. The vulnerability is deterministic once the time threshold is crossed. No malicious intent or actions are required.

## Recommendation

Add a maximum time delta check in the `update_reward_buffer` function before performing the multiplication to prevent overflow:

```move
// Cap the time delta to prevent overflow
let time_delta = now - last_update_time;
let max_safe_time_delta = 86_400_000; // 24 hours in milliseconds
let safe_time_delta = std::u256::min(time_delta as u256, max_safe_time_delta);

// Use the capped time delta for calculation
let new_reward = reward_rate * safe_time_delta;
```

Alternatively, update the reward rate validation to enforce a much lower maximum rate that remains safe even for extended time periods (e.g., 30+ days), or implement automatic periodic updates to prevent long gaps.

## Proof of Concept

```move
#[test]
#[expected_failure(arithmetic_error, location = reward_manager)]
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
        
        // Set reward rate near maximum allowed value
        reward_manager.set_reward_rate<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, &clock,
            std::u256::max_value!() / 86_400_000 - 1000
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
    };
    
    // Advance clock by MORE than 24 hours (e.g., 25 hours)
    clock.increment_for_testing(90_000_000); // 25 hours in milliseconds
    
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This will trigger arithmetic overflow and abort
        reward_manager.update_reward_buffers(&mut vault, &clock);
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that when the reward rate is set near the maximum and more than 24 hours pass, attempting to update reward buffers causes an arithmetic overflow abort, which would block all critical vault operations.

### Citations

**File:** volo-vault/sources/reward_manager.move (L428-428)
```text
    assert!(rate < std::u256::max_value!() / 86_400_000, ERR_INVALID_REWARD_RATE);
```

**File:** volo-vault/sources/reward_manager.move (L494-498)
```text
            let reward_rate = distribution.rate;
            let last_update_time = distribution.last_updated;

            // New reward amount is with extra 9 decimals
            let new_reward = reward_rate * ((now - last_update_time) as u256);
```

**File:** volo-vault/sources/reward_manager.move (L613-613)
```text
    self.update_reward_buffers<PrincipalCoinType>(vault, clock);
```

**File:** volo-vault/sources/operation.move (L393-393)
```text
    reward_manager.update_reward_buffers(vault, clock);
```

**File:** volo-vault/sources/operation.move (L462-462)
```text
    reward_manager.update_reward_buffers(vault, clock);
```
