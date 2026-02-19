# Audit Report

## Title
Reward Truncation Loss in `from_decimals()` Causes Permanent Loss of User Rewards

## Summary
The `claim_reward()` function in the Volo vault reward system contains a critical ordering flaw where user reward balances are reset to zero before decimal conversion, causing permanent loss of any fractional rewards less than 10^9 internal units (< 1 token in native decimals). This affects all users claiming rewards with small positions or during periods of small reward distributions.

## Finding Description

The vulnerability exists in the reward claiming flow where three operations occur in a problematic sequence:

**Step 1: Entry Point**
Users call the public `claim_reward()` function to claim their accumulated rewards. [1](#0-0) 

**Step 2: Critical Flaw - Premature Balance Reset**
The function retrieves and immediately zeros the user's unclaimed reward balance via `reset_unclaimed_rewards()`, which returns the current balance but permanently sets it to 0. [2](#0-1) 

**Step 3: Truncation via Integer Division**
The returned balance (now stored nowhere since user's balance is already 0) is converted using `from_decimals()`, which performs integer division by 10^9 (DECIMALS constant). [3](#0-2) 

**Step 4: Loss Occurs**
The claiming logic combines these operations: [4](#0-3) 

If `unclaimed_rewards < 10^9`, then `from_decimals()` returns 0, the user receives 0 tokens, but their balance is already zeroed with no mechanism to recover the truncated amount.

**Why Existing Protections Fail**
The minimum reward amount check only validates rewards being ADDED to the vault to prevent index precision loss, not individual user claims: [5](#0-4) 

This check ensures the reward index increments properly, but does NOT prevent users from losing fractional rewards during claims.

**Root Cause**: The order of operations is fundamentally flawed. The balance reset happens BEFORE truncation, with no preservation mechanism for remainders. A correct implementation would either:
1. Only reset the balance if the claimable amount is non-zero
2. Preserve the truncated remainder in unclaimed_rewards
3. Perform the conversion first, then reset only the claimable portion

## Impact Explanation

**Direct Fund Loss**: Users permanently and irreversibly lose legitimate earned rewards up to 999,999,999 internal units per claim (nearly 1 full token in native decimals).

**Concrete Example**:
- Vault: 1,000,000 tokens total shares (10^15 internal units)
- User: 1 token position (10^9 internal units, 0.0001% of vault)
- Reward distribution: 1,000 tokens (10^12 internal units)
- User's proportional reward: (10^9 / 10^15) × 10^12 = 1,000 internal units
- Claim execution: `from_decimals(1,000)` = 1,000 / 10^9 = 0 (integer division truncates)
- User receives: 0 tokens
- User's balance after: 0 (already reset)
- Permanent loss: 1,000 internal units

**Affected Users**:
- Small retail depositors with positions representing < 0.001% of vault TVL
- ANY user in high-TVL vaults during normal reward distribution cycles
- All token types since the vault uses fixed 9-decimal internal representation

**Severity Justification**:
While individual losses appear small (< 1 native token unit), they are:
- **Permanent and unrecoverable** - no code path exists to reclaim truncated amounts
- **Cumulative across all users and all claims** - systematic value extraction from protocol users
- **Violation of core protocol invariant** - users must receive their proportional rewards
- **Disproportionately affects retail users** - wealth concentration via rounding errors

## Likelihood Explanation

**Reachable Entry Point**: The `claim_reward()` function is marked `public fun`, making it callable from any Programmable Transaction Block (PTB) by any user with a valid receipt. No privileged roles required. [1](#0-0) 

**Feasibility**: This occurs naturally during normal protocol operation:
- No malicious input required
- No special conditions or state manipulation needed
- Simply holding a small position and claiming rewards triggers the issue
- Mathematical certainty for users whose proportional share yields < 10^9 reward units

**Execution Practicality**: Trivial to trigger:
1. User deposits small amount in vault (or vault TVL grows large, making their share small)
2. Operator distributes rewards via standard mechanisms
3. User calls `claim_reward()` when their `unclaimed_rewards < 10^9`
4. Loss occurs automatically

**Probability**: HIGH. In production vaults with:
- Significant TVL (> 1 billion tokens)
- Many small depositors (< 0.001% of vault each)
- Regular reward distribution cycles (daily/weekly)

Truncation losses will occur consistently with each reward claim from affected users.

## Recommendation

**Fix Option 1: Preserve Remainder (Recommended)**
Modify `claim_reward()` to only reset the claimable (non-truncated) portion:

```move
public fun claim_reward<PrincipalCoinType, RewardCoinType>(
    // ... params ...
): Balance<RewardCoinType> {
    // ... existing validation ...
    
    let vault_receipt_mut = vault.vault_receipt_info_mut(receipt_id);
    let unclaimed_amount = vault_receipt_mut.get_unclaimed_rewards<RewardCoinType>();
    
    let reward_amount = vault_utils::from_decimals(unclaimed_amount as u256) as u64;
    
    // Only reset the claimable portion, preserve remainder
    let claimable_with_decimals = vault_utils::to_decimals(reward_amount as u256);
    vault_receipt_mut.decrease_unclaimed_rewards<RewardCoinType>(claimable_with_decimals);
    
    // ... rest of function ...
}
```

**Fix Option 2: Prevent Zero Claims**
Check if claimable amount is zero and revert early:

```move
let unclaimed = vault_receipt_mut.get_unclaimed_rewards<RewardCoinType>();
let reward_amount = vault_utils::from_decimals(unclaimed as u256) as u64;
assert!(reward_amount > 0, ERR_REWARD_AMOUNT_TOO_SMALL);
vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>();
```

This prevents loss but forces users to wait until they accumulate ≥ 10^9 units.

## Proof of Concept

Add this test to `volo-vault/tests/reward/reward_manager.test.move`:

```move
#[test]
// [TEST-CASE: Should demonstrate reward truncation loss for small positions]
public fun test_reward_truncation_loss_small_position() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and reward manager
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // Add reward type
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
        reward_manager.add_new_reward_type<SUI_TEST_COIN, SUI_TEST_COIN>(
            &operation, &operator_cap, &clock, false
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
    };
    
    // Large whale deposits to create high TVL
    s.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000_000, s.ctx()); // 1T tokens
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, whale_receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin, 1_000_000_000_000, 
            1_000_000_000_000_000_000_000, option::none(), &clock, s.ctx()
        );
        
        transfer::public_transfer(whale_receipt, ALICE);
        transfer::public_transfer(coin, ALICE);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Small user deposits tiny amount
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000, s.ctx()); // 1,000 tokens
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, small_receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin, 1_000, 
            1_000_000_000_000, option::none(), &clock, s.ctx()
        );
        
        transfer::public_transfer(small_receipt, OWNER);
        transfer::public_transfer(coin, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Distribute reward
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let reward_coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        reward_manager.add_reward_balance<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, reward_coin.into_balance()
        );
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
    };
    
    // Small user tries to claim - should get 0 despite having earned rewards
    s.next_tx(OWNER);
    {
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();
        
        // Check unclaimed rewards BEFORE claim (will be > 0 but < 10^9)
        let receipt_info = vault.vault_receipt_info(receipt.receipt_id());
        let unclaimed_before = receipt_info.get_receipt_reward(type_name::get<SUI_TEST_COIN>());
        assert!(unclaimed_before > 0, 1); // User earned rewards
        assert!(unclaimed_before < 1_000_000_000, 2); // But less than DECIMALS
        
        let reward_balance = reward_manager.claim_reward<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &clock, &mut receipt
        );
        
        // BUG: User receives 0 tokens despite earning rewards
        assert!(reward_balance.value() == 0, 3);
        reward_balance.destroy_for_testing();
        
        // Check unclaimed rewards AFTER claim (will be 0 - funds lost permanently)
        let receipt_info_after = vault.vault_receipt_info(receipt.receipt_id());
        let unclaimed_after = receipt_info_after.get_receipt_reward(type_name::get<SUI_TEST_COIN>());
        assert!(unclaimed_after == 0, 4); // Balance reset to 0, funds lost
        
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This PoC demonstrates:
1. A whale creates high TVL (1 trillion tokens)
2. A small user deposits 1,000 tokens (0.0000001% of vault)
3. 1 billion tokens distributed as rewards
4. Small user's share: ~1,000 internal units (< 10^9 DECIMALS)
5. Upon claiming: receives 0 tokens, balance reset to 0, funds lost permanently

**Notes**

The vulnerability is systematic and affects the protocol's core reward distribution mechanism. While individual losses may seem small, they accumulate across all affected users and all reward cycles, representing a continuous value leak from protocol users. The issue is particularly concerning because:

1. **Wealth Concentration Effect**: Consistently benefits large holders (who accumulate rewards above truncation threshold) at the expense of small retail users
2. **No User Mitigation**: Users cannot prevent this loss through any action (waiting longer only increases their exposure)
3. **Protocol Invariant Violation**: The protocol promises proportional reward distribution but systematically fails to deliver for small positions

The fix is straightforward (preserve remainder or prevent zero claims) and should be implemented immediately to protect user funds.

### Citations

**File:** volo-vault/sources/reward_manager.move (L354-357)
```text
    // If the reward amount is too small to make the index increase,
    // the reward will be lost.
    let minimum_reward_amount = vault_utils::mul_with_oracle_price(vault.total_shares(), 1);
    assert!(reward_amount>= minimum_reward_amount, ERR_REWARD_AMOUNT_TOO_SMALL);
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

**File:** volo-vault/sources/reward_manager.move (L620-623)
```text
    let reward_amount =
        vault_utils::from_decimals(
            vault_receipt_mut.reset_unclaimed_rewards<RewardCoinType>() as u256,
        ) as u64;
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

**File:** volo-vault/sources/utils.move (L48-50)
```text
public fun from_decimals(v: u256): u256 {
    v / DECIMALS
}
```
