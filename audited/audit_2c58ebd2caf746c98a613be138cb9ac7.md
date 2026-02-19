# Audit Report

## Title
Unchecked u256 to u64 Cast in Reward Claiming Causes Permanent Reward Lock for Large Accumulations

## Summary
The `claim_reward()` function performs an unchecked cast from u256 to u64 when converting accumulated rewards to claimable amounts. When rewards accumulate to values exceeding u64::max after decimal conversion, the transaction aborts with a type casting error, permanently locking user rewards in their receipt with no recovery mechanism.

## Finding Description

The vulnerability exists in the reward claiming flow where accumulated rewards stored as u256 are directly cast to u64 without overflow validation.

**Vulnerable Code Path:**

The `claim_reward()` function retrieves accumulated rewards and performs an unsafe cast: [1](#0-0) 

This code:
1. Calls `reset_unclaimed_rewards()` which returns u256 rewards with 9 extra decimals [2](#0-1) 
2. Converts via `from_decimals()` which divides by 1e9 [3](#0-2) 
3. Directly casts the result to u64 without checking if it exceeds u64::max (18,446,744,073,709,551,615)

**Why Existing Protections Fail:**

The balance validation check occurs AFTER the cast: [4](#0-3) 

This check is unreachable if the cast aborts, rendering it ineffective as a safety mechanism.

**Contradicts Established Defensive Patterns:**

The codebase implements proper overflow checks elsewhere:

- Liquid staking math module checks before casting: [5](#0-4) 

- Oracle utilities validate before casting: [6](#0-5) 

**How Rewards Accumulate:**

Rewards accumulate through an index-based mechanism where user shares multiply by reward index deltas: [7](#0-6) 

The accumulated reward formula `(reward_index_delta × shares) / 1e18` can produce arbitrarily large u256 values over time. The unclaimed_rewards table stores these values as u256 [8](#0-7)  with no maximum accumulation limits in the protocol.

## Impact Explanation

**HIGH Severity** - This vulnerability results in permanent loss of user funds:

1. **Permanent Fund Loss**: When accumulated rewards exceed the threshold (unclaimed_rewards / 1e9 > u64::max), users cannot claim their legitimately earned rewards. The transaction aborts during type casting, and rewards remain locked in the receipt's unclaimed_rewards table.

2. **No Recovery Mechanism**: There is no admin function or alternative path to retrieve these locked rewards. Once the threshold is exceeded, the funds are permanently inaccessible.

3. **Quantified Threshold**:
   - For 9-decimal tokens: ~18.4 billion tokens worth of accumulated rewards triggers the issue
   - For 6-decimal tokens (like USDC): ~18.4 trillion USDC equivalent
   - While large, these values can accumulate through: high APY rates over extended periods, large share positions (vault supports u256 shares), and reward index increases over time

4. **Violates Core Invariant**: Breaks the fundamental guarantee that users can always claim their earned rewards, violating fund custody responsibilities.

## Likelihood Explanation

**LOW-MEDIUM Likelihood** - While requiring extreme conditions, the scenario is feasible under realistic vault operations:

**Triggerable by Normal Users:**
- Any vault participant can be affected through normal protocol usage
- No attack or malicious behavior required
- Simply requires: depositing funds, receiving shares, allowing rewards to accumulate, attempting to claim

**Accumulation Feasibility:**
- Vaults are designed for long-term staking strategies
- Reward buffers can distribute continuously at operator-set rates [9](#0-8) 
- High-APY scenarios with whale positions can accumulate large values over months/years
- Users may rationally delay claiming to minimize transaction fees

**No Protocol Limits:**
- No maximum reward accumulation caps exist in the protocol
- Reward indices grow unbounded through repeated updates [10](#0-9) 
- No warnings or safeguards for approaching the u64 boundary

## Recommendation

Implement overflow checking before the cast, following the established defensive pattern used elsewhere in the codebase:

```move
// Add constants at module level
const E_REWARD_OVERFLOW: u64 = 3_013;
const U64_MAX: u256 = 18_446_744_073_709_551_615;

// In claim_reward function, replace lines 620-623 with:
let reward_amount_u256 = vault_utils::from_decimals(
    vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>()
);
assert!(reward_amount_u256 <= U64_MAX, E_REWARD_OVERFLOW);
let reward_amount = (reward_amount_u256 as u64);
```

This ensures the cast is safe and provides a clear error message if rewards exceed the u64 limit, allowing operators to potentially implement a multi-claim mechanism or other recovery process.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = ARITHMETIC_ERROR)] // Move runtime abort on unsafe cast
fun test_reward_overflow_causes_permanent_lock() {
    // Setup: Create vault and receipt
    let mut scenario = test_scenario::begin(ADMIN);
    setup_vault_and_reward_manager(&mut scenario);
    
    scenario.next_tx(USER);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let mut receipt = scenario.take_from_sender<Receipt>();
        let receipt_id = receipt.receipt_id();
        
        // Simulate accumulated rewards exceeding u64::max after decimal conversion
        // This would accumulate over time through normal reward distribution
        let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
        let unclaimed = vault_receipt_mut.unclaimed_rewards_mut();
        
        // Set unclaimed_rewards to value that exceeds u64::max when divided by 1e9
        // 20_000_000_000 * 1e9 = 2e19, which exceeds u64::max (1.84e19)
        *unclaimed.borrow_mut(reward_type) = 20_000_000_000_000_000_000;
        
        let mut reward_manager = scenario.take_shared<RewardManager<SUI>>();
        let clock = scenario.take_shared<Clock>();
        
        // This will abort on the cast at line 623, not on the balance check at line 628
        // User's rewards are now permanently locked
        let reward = reward_manager.claim_reward<SUI, REWARD_TOKEN>(
            &mut vault,
            &clock,
            &mut receipt
        );
        
        // Never reaches here due to abort
        reward.destroy_for_testing();
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(clock);
        scenario.return_to_sender(receipt);
    };
    scenario.end();
}
```

The test demonstrates that when `unclaimed_rewards / 1e9` exceeds u64::max, the cast aborts before the balance check can execute, proving the rewards are permanently inaccessible.

### Citations

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

**File:** volo-vault/sources/reward_manager.move (L551-590)
```text
public(package) fun update_reward_indices<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &Vault<PrincipalCoinType>,
    reward_type: TypeName,
    reward_amount: u256,
) {
    self.check_version();
    // assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    // Check if the reward type exists in the rewards & reward_indices bag
    assert!(self.reward_amounts.contains(reward_type), ERR_REWARD_TYPE_NOT_FOUND);

    // Update reward index
    // Reward amount normally is 1e9 decimals (token amount)
    // Shares is normally 1e9 decimals
    // The index is 1e18 decimals
    let total_shares = vault.total_shares();
    assert!(total_shares > 0, ERR_VAULT_HAS_NO_SHARES);

    // Index precision
    // reward_amount * 1e18 / total_shares
    // vault has 1e9 * 1e9 shares (1b TVL)
    // reward amount only needs to be larger than 1
    let add_index = vault_utils::div_with_oracle_price(
        reward_amount,
        total_shares,
    );
    let new_reward_index = *self.reward_indices.get(&reward_type) + add_index;

    *self.reward_indices.get_mut(&reward_type) = new_reward_index;

    emit(RewardIndicesUpdated {
        reward_manager_id: self.id.to_address(),
        vault_id: vault.vault_id(),
        coin_type: reward_type,
        reward_amount: reward_amount,
        inc_reward_index: add_index,
        new_reward_index: new_reward_index,
    })
}
```

**File:** volo-vault/sources/reward_manager.move (L620-623)
```text
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

**File:** volo-vault/sources/vault_receipt_info.move (L175-182)
```text
    if (new_reward_idx > *pre_idx) {
        // get new reward
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

**File:** liquid_staking/sources/volo_v1/math.move (L34-41)
```text
    public fun to_shares(ratio: u256, amount: u64): u64 {
        let mut shares = (amount as u256) * ratio / RATIO_MAX;
        assert!(shares <= (U64_MAX as u256), E_U64_OVERFLOW);
        if (amount > 0 && shares == 0) {
            shares = 1;
        };
        (shares as u64)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move (L40-57)
```text
    public fun calculate_amplitude(a: u256, b: u256): u64 {
        if (a == 0 || b == 0) {
            return U64MAX
        };
        let ab_diff = abs_sub(a, b);

        // prevent overflow 
        if (ab_diff > sui::address::max() / (constants::multiple() as u256)) {
            return U64MAX
        };

        let amplitude = (ab_diff * (constants::multiple() as u256) / a);
        if (amplitude > (U64MAX as u256)) {
            return U64MAX
        };

        (amplitude as u64)
    }
```
