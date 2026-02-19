### Title
Reward Buffer Arithmetic Overflow Causes Vault Operations Denial of Service

### Summary
The reward buffer distribution system in `volo-vault` contains an unchecked multiplication that can overflow when the time delta between updates exceeds 24 hours and the reward rate is set near its maximum allowed value. This overflow causes all critical vault operations (deposit execution, withdrawal execution, and reward claims) to abort, creating a complete denial of service until admin intervention.

### Finding Description

The vulnerability exists in the `update_reward_buffer` function where reward accumulation is calculated based on time elapsed: [1](#0-0) 

The reward rate validation in `set_reward_rate` only checks that the rate allows safe multiplication for up to 24 hours: [2](#0-1) 

However, there is no cap on how long `(now - last_update_time)` can grow. If more than 86,400,000 milliseconds (24 hours) elapse without calling `update_reward_buffer`, and the reward_rate is set near `u256::MAX / 86_400_000`, the multiplication `reward_rate * ((now - last_update_time) as u256)` will overflow u256 and abort the transaction.

This overflow blocks all critical vault operations because they call `update_reward_buffers` at entry: [3](#0-2) [4](#0-3) [5](#0-4) 

The vulnerability is analogous to the external report where unchecked multiplication of user/time-controlled values causes transaction abort, preventing legitimate operations.

### Impact Explanation

Once triggered, the overflow causes a complete denial of service of the vault:
- **No deposit executions**: Users cannot have their deposit requests processed, locking their funds in the request buffer indefinitely
- **No withdrawal executions**: Users cannot execute withdrawal requests, preventing access to their funds
- **No reward claims**: Users cannot claim accumulated rewards from any reward type

The vault remains frozen until an operator manually removes the problematic reward distribution or reduces the reward rate, requiring privileged intervention. This violates the critical availability invariant for protocol operations.

### Likelihood Explanation

**Preconditions**:
1. Operator sets a high reward_rate approaching `u256::MAX / 86_400_000` (a legitimate operational decision to incentivize users)
2. No transactions call `update_reward_buffer` for more than 24 hours (realistic during low activity periods, weekends, holidays, or network issues)

**Trigger**: Any user attempting to execute a deposit, withdrawal, or claim reward will trigger the overflow and abort

**Feasibility**: High - this requires only normal operator configuration choices and a period of inactivity, both of which are realistic in production environments. The vulnerability is deterministic once the time threshold is crossed.

### Recommendation

Add a maximum time delta check in `update_reward_buffer` before the multiplication:

```move
let time_delta = (now - last_update_time) as u256;
let max_safe_delta = 86_400_000; // 24 hours in milliseconds
let capped_time_delta = std::u256::min(time_delta, max_safe_delta);
let new_reward = reward_rate * capped_time_delta;
```

Alternatively, validate the multiplication result won't overflow before performing it, or use the `math::safe_math::mul()` utility that performs checked multiplication and aborts with a descriptive error.

### Proof of Concept

**Setup**:
1. Deploy vault with reward manager
2. Operator creates reward buffer distribution with `create_reward_buffer_distribution<PrincipalCoin, RewardCoin>`
3. Operator sets reward_rate to `(std::u256::max_value!() / 86_400_000) - 1` via `set_reward_rate`
4. Add reward balance to buffer with `add_reward_to_buffer`

**Exploit Steps**:
1. Wait or simulate 86,400,001 milliseconds (just over 24 hours) without any calls to `update_reward_buffer`
2. User attempts to execute any operation:
   - Call `execute_deposit` for a pending deposit request, OR
   - Call `execute_withdraw` for a pending withdrawal request, OR  
   - Call `claim_reward` to claim accumulated rewards

**Result**: Transaction aborts with arithmetic overflow at line 498 of reward_manager.move. All subsequent attempts to execute deposits, withdrawals, or claim rewards fail with the same overflow error, effectively bricking the vault until admin removes the distribution or lowers the rate.

### Citations

**File:** volo-vault/sources/reward_manager.move (L428-428)
```text
    assert!(rate < std::u256::max_value!() / 86_400_000, ERR_INVALID_REWARD_RATE);
```

**File:** volo-vault/sources/reward_manager.move (L498-498)
```text
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
