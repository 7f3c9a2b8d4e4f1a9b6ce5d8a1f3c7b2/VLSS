### Title
Unchecked u256 to u64 Cast in Reward Claiming Causes Permanent Reward Lock for Large Accumulations

### Summary
The `claim_reward()` function performs an unchecked cast from u256 to u64 when converting accumulated rewards to claimable amounts. When rewards accumulate to values exceeding u64::max after decimal conversion, the transaction aborts, permanently locking user rewards in their receipt. This vulnerability contradicts the defensive overflow checking patterns implemented elsewhere in the codebase.

### Finding Description

**Exact Location:** [1](#0-0) 

The vulnerability occurs in the reward claiming flow where:

1. User's accumulated rewards are stored as u256 with 9 extra decimals in `VaultReceiptInfo.unclaimed_rewards` [2](#0-1) 

2. The `reset_unclaimed_rewards()` function returns this u256 value [3](#0-2) 

3. The value is converted via `from_decimals()` which divides by 1e9 (DECIMALS constant) [4](#0-3) 

4. **Critical Issue**: The result is directly cast to u64 without checking if it fits within u64::max (18,446,744,073,709,551,615)

**Why Protections Fail:**

The only validation occurs AFTER the cast at line 628, checking if `reward_amount <= vault_reward_balance.value()`. However, this check is unreachable if the cast aborts: [5](#0-4) 

**Contradicts Codebase Patterns:**

Other modules properly implement overflow checks before casting:

- Oracle utilities check `amplitude > (U64MAX as u256)` before casting: [6](#0-5) 

- Liquid staking math enforces `assert!(value <= U64_MAX, E_U64_OVERFLOW)` before all casts: [7](#0-6) 

**Execution Path:**

Rewards accumulate via the index-based mechanism where: [8](#0-7) 

The accumulated reward formula `(new_reward_idx - pre_idx) × shares` can produce arbitrarily large u256 values over time with high APY or large share positions.

### Impact Explanation

**Direct Harm:**
When accumulated rewards (after dividing by 1e9) exceed u64::max, users cannot claim their legitimately earned rewards. The transaction aborts in Move's type system, and the rewards remain permanently locked in the receipt's `unclaimed_rewards` table.

**Quantified Damage:**
- For tokens with 9 decimals: ~18.4 billion tokens worth of accumulated rewards triggers the issue
- For tokens with 6 decimals (like USDC): ~18.4 trillion USDC equivalent triggers the issue
- While these are large absolute values, they can accumulate through:
  - High APY rates over extended periods
  - Large share positions (vault can hold u256 shares)
  - Reward index increases of magnitude 1e28 or higher

**Who Is Affected:**
Any user who accumulates rewards over time without regular claiming, particularly:
- Whale depositors with large share positions
- Long-term vault participants during high-reward periods
- Users of vaults with high-decimal reward tokens

**Severity Justification:**
HIGH severity because:
1. Results in permanent loss of user funds (rewards)
2. No recovery mechanism exists once unclaimed_rewards exceeds threshold
3. Violates critical invariant of fund custody and reward claimability
4. Contradicts defensive patterns used elsewhere in the codebase

### Likelihood Explanation

**User Capabilities:**
Any legitimate vault user can be affected simply by:
1. Depositing funds and receiving shares
2. Allowing rewards to accumulate over time
3. Attempting to claim when accumulated value is large

**Complexity:**
No attack needed - this is a protocol flaw affecting normal operations. The condition triggers naturally when:
- Time × APY × Shares produces large accumulated rewards
- Reward indices grow through repeated `update_reward_indices()` calls [9](#0-8) 

**Feasibility Conditions:**
- High reward distribution rates set by operators
- Long periods between user claims
- Large total share positions in the vault
- All of these are expected in normal vault operations

**Probability:**
MEDIUM-HIGH likelihood because:
- Vaults are designed for long-term staking
- Reward buffers can distribute continuously at high rates [10](#0-9) 
- No maximum reward accumulation limits exist in the protocol
- Users may rationally delay claiming to save on transaction fees

### Recommendation

**Code-Level Mitigation:**

Add an explicit overflow check before casting in `claim_reward()`:

```move
// At line 620-623, replace with:
let reward_amount_u256 = vault_utils::from_decimals(
    vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
);

const U64_MAX: u256 = 18_446_744_073_709_551_615;
assert!(reward_amount_u256 <= U64_MAX, ERR_REWARD_AMOUNT_OVERFLOW);

let reward_amount = reward_amount_u256 as u64;
```

**Invariant Checks:**
1. Add error constant: `const ERR_REWARD_AMOUNT_OVERFLOW: u64 = 3_013;`
2. Consider adding a maximum reward per claim limit in vault configuration
3. Add monitoring/alerts for rewards approaching u64 thresholds

**Test Cases:**
```move
#[test]
#[expected_failure(abort_code = ERR_REWARD_AMOUNT_OVERFLOW)]
public fun test_claim_reward_overflow_u64() {
    // Setup vault with shares
    // Manually set unclaimed_rewards to value that exceeds u64 after from_decimals
    // Attempt claim_reward
    // Verify abort with correct error code
}
```

### Proof of Concept

**Initial State:**
1. Vault is initialized with reward manager
2. User deposits and receives 1e18 shares (1 billion tokens with 9 decimals)
3. Reward type is added and reward buffer is configured

**Transaction Steps:**

Step 1: Set high reward rate over extended period
```
- Operator calls set_reward_rate with rate = 1e18 per millisecond
- Time progresses for 1 billion milliseconds (~11.5 days)
```

Step 2: Rewards accumulate in receipt
```
- update_reward_buffer distributes: 1e18 * 1e9 = 1e27 (with 9 decimals)
- User's share of rewards: (1e18 shares / 1e18 total) * 1e27 = 1e27
- unclaimed_rewards[RewardCoinType] = 1e27 (u256 with 9 extra decimals)
```

Step 3: User attempts to claim
```
- User calls claim_reward<PrincipalCoin, RewardCoin>()
- from_decimals(1e27) = 1e27 / 1e9 = 1e18
- Cast to u64: 1e18 (1,000,000,000,000,000,000) fits in u64
```

Step 4: Extend scenario for overflow
```
- Increase rate or time: unclaimed_rewards = 1e30 (with 9 decimals)
- from_decimals(1e30) = 1e30 / 1e9 = 1e21
- u64::max = 1.844... × 1e19
- 1e21 > u64::max → TRANSACTION ABORTS
```

**Expected vs Actual Result:**
- Expected: User claims rewards or receives clear error about exceeding limits
- Actual: Transaction aborts with type cast failure, rewards permanently locked in receipt

**Success Condition:**
The vulnerability is confirmed when attempting to claim rewards with `unclaimed_rewards / 1e9 > 18446744073709551615` causes transaction abort rather than graceful handling.

### Citations

**File:** volo-vault/sources/reward_manager.move (L492-499)
```text

            // Newly generated reward from last update time to current time
            let reward_rate = distribution.rate;
            let last_update_time = distribution.last_updated;

            // New reward amount is with extra 9 decimals
            let new_reward = reward_rate * ((now - last_update_time) as u256);

```

**File:** volo-vault/sources/reward_manager.move (L574-578)
```text
    let add_index = vault_utils::div_with_oracle_price(
        reward_amount,
        total_shares,
    );
    let new_reward_index = *self.reward_indices.get(&reward_type) + add_index;
```

**File:** volo-vault/sources/reward_manager.move (L619-623)
```text
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;
```

**File:** volo-vault/sources/reward_manager.move (L628-628)
```text
    assert!(reward_amount <= vault_reward_balance.value(), ERR_REWARD_EXCEED_LIMIT);
```

**File:** volo-vault/sources/vault_receipt_info.move (L28-28)
```text
    unclaimed_rewards: Table<TypeName, u256>, // store unclaimed rewards, decimal: reward coin
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

**File:** volo-vault/sources/vault_receipt_info.move (L177-181)
```text
        let acc_reward = vault_utils::mul_with_oracle_price(new_reward_idx - *pre_idx, self.shares);

        // set reward and index
        *pre_idx = new_reward_idx;
        *unclaimed_reward = *unclaimed_reward + acc_reward;
```

**File:** volo-vault/sources/utils.move (L48-50)
```text
public fun from_decimals(v: u256): u256 {
    v / DECIMALS
}
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move (L52-56)
```text
        if (amplitude > (U64MAX as u256)) {
            return U64MAX
        };

        (amplitude as u64)
```

**File:** liquid_staking/sources/volo_v1/math.move (L16-18)
```text
        let r = (x as u128) * (y as u128) / (z as u128);
        assert!(r <= U64_MAX, E_U64_OVERFLOW);
        (r as u64)
```
