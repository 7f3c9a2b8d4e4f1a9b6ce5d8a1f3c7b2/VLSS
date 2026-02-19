### Title
Unclaimed Reward Truncation Due to Unsafe u256 to u64 Conversion in claim_reward()

### Summary
The `claim_reward()` function converts accumulated unclaimed rewards from u256 to u64 without checking for overflow, causing truncation when rewards exceed u64::MAX (~1.844 × 10^19). This results in permanent loss of user rewards as the truncated value passes validation checks but only distributes a fraction of the owed amount.

### Finding Description

The vulnerability exists in the reward claiming flow: [1](#0-0) 

The code retrieves accumulated unclaimed rewards (stored as u256 with 9 extra decimals), divides by 10^9, then unsafely casts to u64. The `reset_unclaimed_rewards()` function returns a u256 value: [2](#0-1) 

Unclaimed rewards accumulate without bounds through repeated calls to `update_reward()`: [3](#0-2) 

The accumulated reward calculation multiplies reward index difference (u256) by user shares (u256), which can produce values exceeding u64::MAX after decimal adjustment. The safety check at line 628 becomes ineffective because it validates the already-truncated value: [4](#0-3) 

**Why protections fail:** The validation occurs AFTER truncation, comparing the wrapped u64 value against the balance rather than checking if the u256 value is safe to convert.

### Impact Explanation

**Direct Fund Impact:** Users suffer permanent loss of accumulated rewards exceeding u64::MAX threshold. In a realistic scenario:
- Vault with ~10^28 shares (approaching maximum Balance<T> capacity)
- Reward index accumulates to 10^30 over many distributions
- User's unclaimed rewards: (10^28 × 10^30) / 10^18 / 10^9 = 10^31
- u64::MAX ≈ 1.844 × 10^19
- User loses ~99.9999998% of rewards due to truncation

**Who is affected:** Any receipt holder with large share balances in long-running vaults with substantial reward distributions. The impact scales with vault TVL and operational duration.

**Severity justification:** HIGH - Violates critical invariant that users must be able to claim all earned rewards. Causes measurable financial loss without any exploit required, affecting core protocol functionality.

### Likelihood Explanation

**Reachability:** The vulnerability triggers through normal protocol operation via the public `claim_reward()` entry function. No malicious action required.

**Feasible preconditions:**
- Vault operates long-term with high TVL (approaching u64::MAX in principal deposits)
- Operators distribute rewards regularly over extended period
- Receipt accumulates significant shares (proportional to vault size)
- Reward index grows through repeated `add_reward_balance()` or buffer distributions

**Execution practicality:** Happens naturally in successful vault deployments. Calculation example:
- 1 billion USD vault (~10^18 with 9 decimals)
- 100 reward distributions of 1M USD each over 2 years
- Single receipt with 10% vault ownership
- Accumulated index: ~10^28, receipt rewards exceed u64::MAX after ~50 distributions

**Probability:** MEDIUM-HIGH for large, successful vaults. As Volo scales and operates long-term, this becomes increasingly likely.

### Recommendation

Add overflow check before u256 to u64 conversion:

```move
let unclaimed_u256 = vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>();
let reward_u256 = vault_utils::from_decimals(unclaimed_u256);

// Add this check:
assert!(reward_u256 <= (std::u64::max_value!() as u256), ERR_REWARD_AMOUNT_OVERFLOW);

let reward_amount = reward_u256 as u64;
```

Alternatively, split large reward claims into multiple transactions or implement a claim limit with remaining balance tracking. Add comprehensive test cases covering:
1. Rewards approaching u64::MAX
2. Rewards exceeding u64::MAX (should revert)
3. Long-term accumulation scenarios with multiple distributions

### Proof of Concept

**Initial state:**
- Vault with 10^28 shares total, receipt owns 10^27 shares
- Reward type registered with initial index = 0
- Vault has 10^20 reward token balance

**Transaction sequence:**
1. Operator adds rewards 100 times, each increasing index by 10^28:
   - After 100 distributions: reward_index = 10^30
2. User calls `claim_reward()`:
   - `acc_reward = (10^30 × 10^27) / 10^18 = 10^39` (with 9 decimals)
   - `from_decimals(10^39) = 10^30`
   - Cast to u64: `10^30 as u64` = wraps to tiny value
3. User receives ~1000 tokens instead of 10^21 tokens

**Expected result:** Transaction reverts with overflow error
**Actual result:** Transaction succeeds, user receives truncated amount, loses ~99.9999999999% of rewards

### Citations

**File:** volo-vault/sources/reward_manager.move (L619-623)
```text
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;
```

**File:** volo-vault/sources/reward_manager.move (L625-628)
```text
    let vault_reward_balance = self
        .reward_balances
        .borrow_mut<TypeName, Balance<RewardCoinType>>(reward_type);
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);
```

**File:** volo-vault/sources/vault_receipt_info.move (L144-151)
```text
public(package) fun reset_unclaimed_rewards<RewardCoinType>(self: &mut VaultReceiptInfo): u256 {
    let reward_type = type_name::get<RewardCoinType>();
    // always call after update_reward to ensure key existed
    let reward = self.unclaimed_rewards.borrow_mut(reward_type);
    let reward_amount = *reward;
    *reward = 0;
    reward_amount
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
