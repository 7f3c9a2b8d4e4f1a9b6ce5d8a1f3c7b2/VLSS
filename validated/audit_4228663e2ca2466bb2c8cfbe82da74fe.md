# Audit Report

## Title
Arithmetic Overflow in Reward Buffer Update Causes Permanent DoS and Reward Lock

## Summary
The `update_reward_buffer()` function contains an unchecked multiplication that overflows when reward rates are set near maximum allowed values and time passes beyond 1 day. This causes permanent denial-of-service for the entire reward system with no recovery mechanism, locking all reward funds indefinitely.

## Finding Description

The core vulnerability exists in the reward buffer calculation where the reward rate is multiplied by elapsed time without bounds checking on the time delta. [1](#0-0) 

The rate validation constraint only ensures safety for time deltas up to exactly 86,400,000 milliseconds (1 day): [2](#0-1) 

However, the time delta calculation has no upper bound enforcement: [3](#0-2) 

**Mathematical Analysis:**
- If operator sets `rate = (u256::max / 86_400_000) - ε` where ε is small (passes validation)
- And `time_delta = 86_400_001 ms` (1 day + 1 ms)
- Then `rate * 86_400_001 ≈ u256::max * (86_400_001 / 86_400_000) > u256::max`
- In Sui Move, integer overflow causes transaction abort (not wraparound), as confirmed by the safe_math implementation in the codebase [4](#0-3) 

**Why No Recovery Path Exists:**

All administrative functions that could fix the state call `update_reward_buffer()` first:

1. `set_reward_rate()` calls it before updating rate: [5](#0-4) 

2. `remove_reward_buffer_distribution()` calls it early: [6](#0-5) 

3. `add_reward_to_buffer()` calls it first: [7](#0-6) 

4. `retrieve_undistributed_reward()` calls it first: [8](#0-7) 

**Cascading User Impact:**

Users cannot claim rewards because `claim_reward()` calls `update_reward_buffers()`: [9](#0-8) 

Which iterates through ALL reward types: [10](#0-9) 

A single overflowing reward type aborts the entire loop, blocking ALL reward claims across ALL reward tokens.

## Impact Explanation

**Critical Fund Lock:**
All rewards stored become permanently inaccessible:
- Actual coin balances in `reward_balances` (Bag of Balance<T>)
- Pending distribution amounts in `reward_buffer.reward_amounts` (Table)

The locked value could be substantial on high-TVL vaults with active reward programs.

**Complete System DoS:**
Once overflow occurs, the reward system enters permanent deadlock:
- Users cannot claim any accumulated rewards (past or future)
- Operators cannot add new rewards to maintain distributions
- Operators cannot adjust rates to prevent overflow
- Operators cannot remove the problematic reward distribution
- Operators cannot retrieve undistributed rewards

The protocol guarantees users can claim accrued rewards and operators can manage distributions. This vulnerability breaks both guarantees with **no emergency recovery mechanism**.

## Likelihood Explanation

**High Likelihood Due to Natural Occurrence:**

This vulnerability does NOT require an attacker. It occurs through legitimate operational patterns:

1. **Operator Sets High Rate (Legitimate Action):**
   - Operators may set rates near `u256::max / 86_400_000` for high-yield reward campaigns
   - The validation allows this, as it's designed for 24-hour distribution windows
   - This is **within permitted bounds** and operationally reasonable

2. **Natural Inactivity Period (Common Scenario):**
   - New vaults during initial launch often have low activity
   - Bear market conditions reduce overall DeFi engagement
   - Weekends/holidays see reduced blockchain activity
   - Small vaults may not have daily user interactions
   - No system enforces daily update requirements

3. **Overflow Trigger (Inevitable):**
   - For maximum rate: overflow after 1 day + 1 millisecond
   - For rates designed for 30-day distributions: overflow after 30 days
   - Time is the only requirement - **no user action needed**

**Detection Difficulty:**
Operators configuring reward distributions would reasonably interpret the validation constraint as providing complete overflow protection. The implicit "1-day assumption" is not documented or enforced, making this a subtle operational trap evident only after permanent lock.

## Recommendation

**Option 1: Add Time Delta Cap (Recommended)**
Add an upper bound check on the time delta in `update_reward_buffer()`:

```move
let time_delta = now - last_update_time;
assert!(time_delta <= 86_400_000, ERR_TIME_DELTA_TOO_LARGE);
let new_reward = reward_rate * (time_delta as u256);
```

**Option 2: Use Safe Math**
Replace unchecked multiplication with safe math operations from the existing safe_math module to catch overflow and handle it gracefully.

**Option 3: Add Emergency Circuit Breaker**
Implement an admin-only emergency function that can reset buffer state without calling `update_reward_buffer()`, allowing recovery from deadlock scenarios.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = <OVERFLOW_ABORT_CODE>)]
public fun test_reward_buffer_overflow_dos() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and reward manager
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Add reward type with buffer
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        
        // Set rate near maximum allowed value
        let max_rate = std::u256::max_value!() / 86_400_000 - 1;
        reward_manager.set_reward_rate<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            max_rate,
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
    };
    
    // Advance time beyond 1 day (86_400_000 ms + 2 ms)
    clock::set_for_testing(&mut clock, 86_400_002);
    
    // Attempt to update reward buffer - this will overflow and abort
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This call will cause overflow: max_rate * 86_400_002 > u256::max
        reward_manager.update_reward_buffer(
            &mut vault,
            &clock,
            type_name::get<SUI_TEST_COIN>()
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

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

**File:** volo-vault/sources/reward_manager.move (L449-462)
```text
public fun update_reward_buffers<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    let buffer_reward_types = self.reward_buffer.distributions.keys();

    buffer_reward_types.do_ref!(|reward_type| {
        self.update_reward_buffer<PrincipalCoinType>(vault, clock, *reward_type);
    });
}
```

**File:** volo-vault/sources/reward_manager.move (L479-498)
```text
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
```

**File:** volo-vault/sources/reward_manager.move (L613-613)
```text
    self.update_reward_buffers<PrincipalCoinType>(vault, clock);
```

**File:** volo-vault/sources/reward_manager.move (L678-678)
```text
    self.update_reward_buffer(vault, clock, reward_type);
```

**File:** volo-vault/local_dependencies/protocol/math/sources/safe_math.move (L25-34)
```text
    public fun mul(a: u256, b: u256): u256 {
        if (a == 0) {
            return 0
        };

        let c = a * b;
        assert!(c / a == b, SAFE_MATH_MULTIPLICATION_OVERFLOW);

        return c
    }
```
