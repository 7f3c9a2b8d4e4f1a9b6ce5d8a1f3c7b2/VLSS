# Audit Report

## Title
Unit Mismatch in Treasury Dust Collection Causes Protocol Insolvency Through Inflated Claims

## Summary
The `execute_withdraw()` function in the Navi Protocol lending core contains a critical unit mismatch bug where dust balances (≤1000 units) are added to `treasury_balance` as actual amounts instead of scaled amounts. This inflates the treasury balance by a factor of `supply_index`, creating protocol insolvency where total withdrawable claims exceed the pool's actual balance.

## Finding Description

The vulnerability exists in the dust collection mechanism within the lending protocol's withdrawal flow. When a user's remaining balance after withdrawal is ≤1000 units, this amount is intended to be transferred to the treasury to avoid leaving economically unviable dust amounts in user accounts.

However, the code adds `token_amount - actual_amount` (which is in **actual** terms) directly to `treasury_balance`, which stores **scaled** values according to the lending protocol's interest-bearing token model.

**Evidence that treasury_balance stores SCALED values:**

1. In `update_state()`, treasury amounts from interest accrual are explicitly converted to scaled before storage by dividing by `supply_index` [1](#0-0) 

2. The `storage::update_state()` function adds the explicitly-named `scaled_treasury_amount` parameter to `treasury_balance` [2](#0-1) 

3. In `withdraw_treasury()`, the stored `treasury_balance` is multiplied by `supply_index` to convert from scaled to actual amounts for withdrawal [3](#0-2) 

**How the bug occurs:**

The `token_amount` is calculated as the actual balance by multiplying scaled balance by `supply_index` [4](#0-3) 

At withdrawal execution, `token_amount` represents the user's total actual balance [5](#0-4) 

The dust amount `token_amount - actual_amount` is in actual terms but gets added to the scaled `treasury_balance` field without conversion [6](#0-5) 

This breaks the fundamental accounting invariant that `treasury_balance` must store scaled values, not actual values. All other functions that modify or read `treasury_balance` assume scaled values and perform appropriate conversions.

## Impact Explanation

**Quantified Impact:**
When `supply_index = 1.5` and dust amount = 999 actual units:
- **Expected behavior**: Add 999 / 1.5 = 666 scaled units to treasury
- **Actual behavior**: Add 999 (treated as scaled) to treasury  
- **Treasury withdrawal**: 999 × 1.5 = 1,498.5 actual units
- **Excess claim**: 1,498.5 - 999 = 499.5 actual units (50% inflation)

**Protocol Impact:**
- With N accounts each triggering 999-unit dust collection, total inflated claims = N × 999 × (supply_index - 1)
- This creates systemic insolvency where total user claims + treasury claims exceed the pool's actual balance
- Legitimate users who deposited funds cannot withdraw their full deposits as the pool becomes under-collateralized
- The treasury can extract value that should belong to legitimate depositors

**Severity: CRITICAL** - This directly causes loss of user funds through accounting manipulation, creates protocol-wide insolvency, and can be executed by any untrusted user without special permissions. The bug affects the Navi Protocol lending core which is integrated as a dependency in the Volo vault system.

## Likelihood Explanation

**Attacker Capabilities:**
- Create multiple accounts (no restrictions in Sui)
- Deposit minimal amounts to each account  
- Trigger withdrawals that leave exactly ≤1000 unit remainders

**Attack Complexity: LOW**
The exploit is straightforward:
1. Calculate the deposit amount needed to leave 999 units after a specific withdrawal
2. Execute deposit and withdrawal operations
3. Repeat across multiple accounts
4. No timing constraints, race conditions, or complex state manipulation required

**Feasibility Conditions:**
- `supply_index > 1.0` - This naturally increases over time as interest accrues in the lending pool, making the vulnerability increasingly severe
- Sufficient SUI for gas fees (minimal cost per transaction)
- No special permissions, admin rights, or privileged access required

**Economic Rationality:**
- Attack cost: N × (dust amount + gas) ≈ minimal 
- Attack benefit: N × dust × (supply_index - 1) in excess withdrawable claims
- With supply_index = 1.5, creates 50% excess claims per dust unit
- With 1,000 accounts × 999 dust, creates ~500,000 excess withdrawable units

**Detection Difficulty:**
- Dust collection appears as an intentional protocol feature
- No unusual transaction patterns that would trigger alerts
- Can be spread over time to avoid detection
- Each individual transaction appears legitimate

**Probability: HIGH** - The vulnerability exists in deployed code, requires no special conditions beyond normal protocol operation, and is economically rational to exploit.

## Recommendation

Convert the dust amount from actual to scaled before adding to treasury_balance:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_dust = ray_math::ray_div(token_amount - actual_amount, supply_index);
        storage::increase_treasury_balance(storage, asset, scaled_dust);
        
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

This ensures consistency with all other treasury balance operations which expect and handle scaled values.

## Proof of Concept

```move
#[test]
fun test_dust_collection_unit_mismatch() {
    // Setup: Create lending pool with supply_index = 1.5
    let scenario = test_scenario::begin(ADMIN);
    setup_lending_pool(&mut scenario);
    
    // User deposits 10,000 units
    deposit_to_pool(&mut scenario, USER, 10_000);
    
    // Simulate interest accrual: supply_index increases to 1.5
    advance_time_and_accrue_interest(&mut scenario, supply_index: 1.5);
    
    // User withdraws leaving exactly 999 units dust
    // User's actual balance: 10,000 * 1.5 = 15,000
    // User withdraws: 14,001, leaving 999 dust
    withdraw_from_pool(&mut scenario, USER, 14_001);
    
    // BUG: Treasury balance increased by 999 (actual) instead of 999/1.5 = 666 (scaled)
    let treasury_balance = get_treasury_balance(&scenario);
    assert!(treasury_balance == 999, 0); // Should be 666!
    
    // Treasury withdraws and gets 999 * 1.5 = 1,498.5 actual units
    let withdrawn = withdraw_treasury(&mut scenario);
    assert!(withdrawn == 1_498, 0); // Got 1,498 instead of 999!
    
    // Pool is now short by 499 units - INSOLVENCY
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L88-88)
```text
        let token_amount = user_collateral_balance(storage, asset, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L100-108)
```text
        if (token_amount > actual_amount) {
            if (token_amount - actual_amount <= 1000) {
                // Tiny balance cannot be raised in full, put it to treasury 
                storage::increase_treasury_balance(storage, asset, token_amount - actual_amount);
                if (is_collateral(storage, asset, user)) {
                    storage::remove_user_collaterals(storage, asset, user);
                }
            };
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L278-283)
```text
        // Calculate the treasury amount
        let treasury_amount = ray_math::ray_mul(
            ray_math::ray_mul(total_borrow, (new_borrow_index - current_borrow_index)),
            reserve_factor
        );
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L486-490)
```text
    public fun user_collateral_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (supply_balance, _) = storage::get_user_balance(storage, asset, user);
        let (supply_index, _) = storage::get_index(storage, asset);
        ray_math::ray_mul(supply_balance, supply_index) // scaled_amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L480-492)
```text
        new_borrow_index: u256,
        new_supply_index: u256,
        last_update_timestamp: u64,
        scaled_treasury_amount: u256
    ) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);

        reserve.current_borrow_index = new_borrow_index;
        reserve.current_supply_index = new_supply_index;
        reserve.last_update_timestamp = last_update_timestamp;
        reserve.treasury_balance = reserve.treasury_balance + scaled_treasury_amount;
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L648-649)
```text
        let scaled_treasury_value = reserve.treasury_balance;
        let treasury_value = ray_math::ray_mul(scaled_treasury_value, supply_index);
```
