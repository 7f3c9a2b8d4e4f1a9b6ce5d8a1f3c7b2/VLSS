# Audit Report

## Title
Treasury Balance Inflation Through Unbalanced Tiny Balance Transfer

## Summary
The `execute_withdraw()` function in `lending_core::logic` inflates `treasury_balance` without corresponding `total_supply` adjustment when handling tiny user balance remainders (≤1000 units). This breaks the fundamental accounting invariant and creates phantom treasury claims that either cause treasury withdrawal failures or enable extraction of funds belonging to other protocol users.

## Finding Description

The vulnerability exists in the withdrawal flow's handling of tiny balance remainders. When a user withdraws funds, their balance is first decreased by the `actual_amount` withdrawn. [1](#0-0) 

Subsequently, if a tiny remainder exists (≤1000 units), the code transfers it to the treasury by calling `storage::increase_treasury_balance()`. [2](#0-1) 

The critical flaw is that `increase_treasury_balance()` only increments the `treasury_balance` field without adjusting `total_supply`. [3](#0-2) 

In contrast, when treasury fees accumulate through normal protocol operations in `update_state()`, the code correctly calls BOTH `storage::update_state()` (which increases treasury_balance) AND `storage::increase_total_supply_balance()` to maintain the accounting invariant. [4](#0-3) 

The protocol maintains the invariant: `total_supply = sum(all user balances) + treasury_balance`. After the tiny balance transfer, the user still retains the tiny remainder in their balance (since only `actual_amount` was deducted), but treasury_balance is also increased by this amount. The `total_supply` is only decreased by `actual_amount`, not accounting for the additional treasury credit. This creates a double-counting scenario where the same funds exist as claims in both the user's account and the treasury.

When the treasury later attempts withdrawal via `withdraw_treasury()`, it calls `decrease_total_supply_balance()` to reduce total_supply. [5](#0-4)  Since the treasury's inflated balance was never added to total_supply, this operation either causes arithmetic underflow (transaction abort) or incorrectly reduces total_supply below the sum of legitimate user claims, effectively stealing from other users.

## Impact Explanation

**Fund Conservation Violation:**
The vulnerability directly violates the protocol's core accounting invariant. Each withdrawal leaving a tiny balance inflates treasury_balance by up to 1000 units without corresponding backing in total_supply or pool liquidity.

**Exploitable Damage Scenarios:**

1. **Treasury DoS**: If an attacker repeatedly creates tiny balances to inflate treasury_balance beyond legitimate total_supply, any treasury withdrawal attempt will trigger arithmetic underflow and permanently fail.

2. **Fund Theft from Users**: If sufficient legitimate treasury fees exist in total_supply, withdrawing the inflated treasury_balance succeeds but incorrectly reduces total_supply. This leaves other users with valid claims exceeding the reduced total_supply, causing their withdrawals to eventually fail when pool liquidity is exhausted.

**Quantified Impact:**
- Each withdrawal with tiny remainder ≤1000 units inflates treasury by up to 1000 units
- An attacker can repeat this operation cheaply (only gas costs)
- With 1000 operations, treasury_balance inflates by up to 1,000,000 units
- This phantom balance either blocks treasury operations or enables extraction of users' funds

## Likelihood Explanation

**Trivial Attack Path:**
The vulnerability is triggered through normal user operations without requiring special privileges. Any user can:
1. Deposit funds into the lending pool
2. Withdraw an amount that leaves a remainder ≤1000 units
3. Repeat to accumulate inflated treasury_balance

**Low Preconditions:**
- No admin capabilities required
- Any withdrawal amount works (just needs to leave tiny remainder)
- No time-based constraints or complex state requirements
- Bypasses all existing validation checks [6](#0-5) 

**Economic Feasibility:**
- Attack cost is minimal (only transaction gas fees)
- Benefit is disruption of protocol accounting or potential fund extraction
- Can be automated across multiple transactions
- Detection is difficult as treasury increases appear as legitimate fee accumulation

**High Probability:**
This will occur naturally during normal protocol operation whenever users withdraw amounts leaving tiny balances, without any malicious intent. The accounting corruption accumulates over time, making it a systemic issue rather than requiring a deliberate attack.

## Recommendation

Add a call to `increase_total_supply_balance()` after increasing treasury_balance for tiny balances, mirroring the pattern used in normal treasury fee accumulation:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let tiny_amount = token_amount - actual_amount;
        // Convert to scaled amount
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_tiny_amount = ray_math::ray_div(tiny_amount, supply_index);
        
        // Properly account for tiny balance transfer
        storage::increase_treasury_balance(storage, asset, tiny_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_tiny_amount);
        
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

Alternatively, call `decrease_supply_balance()` to properly remove the tiny amount from the user's account before crediting it to treasury, ensuring the funds don't exist in both places simultaneously.

## Proof of Concept

```move
#[test]
fun test_treasury_inflation_exploit() {
    // Setup: Create lending pool with initial liquidity
    let (clock, oracle, storage, pool) = setup_test_environment();
    
    // User deposits 10,500 units
    let user = @0xABCD;
    execute_deposit<USDT>(&clock, &mut storage, ASSET_USDT, user, 10500);
    
    // Record initial treasury balance
    let treasury_before = storage::get_treasury_balance(&storage, ASSET_USDT);
    let total_supply_before = storage::get_total_supply(&storage, ASSET_USDT);
    
    // User withdraws 10,000 units, leaving 500 unit remainder
    execute_withdraw<USDT>(&clock, &oracle, &mut storage, ASSET_USDT, user, 10000);
    
    // Verify accounting corruption
    let treasury_after = storage::get_treasury_balance(&storage, ASSET_USDT);
    let total_supply_after = storage::get_total_supply(&storage, ASSET_USDT);
    let user_balance = user_collateral_balance(&storage, ASSET_USDT, user);
    
    // Treasury increased by 500
    assert!(treasury_after == treasury_before + 500, 0);
    
    // Total supply only decreased by 10,000 (not 10,500)
    assert!(total_supply_after == total_supply_before - 10000, 1);
    
    // User still has 500 units balance
    assert!(user_balance == 500, 2);
    
    // INVARIANT BROKEN: total_supply should equal sum(user_balances) + treasury_balance
    // But: total_supply = original - 10000
    // While: user_balance (500) + treasury_balance (500) = 1000
    // The 500 units are double-counted!
    
    // Demonstrate impact: Treasury withdrawal will fail or steal from other users
    // (Test would show underflow or insufficient pool balance for all claims)
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L88-90)
```text
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L278-286)
```text
        // Calculate the treasury amount
        let treasury_amount = ray_math::ray_mul(
            ray_math::ray_mul(total_borrow, (new_borrow_index - current_borrow_index)),
            reserve_factor
        );
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);

        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_treasury_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L565-568)
```text
    public(friend) fun increase_treasury_balance(storage: &mut Storage, asset: u8, amount: u256) {
        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.treasury_balance = reserve.treasury_balance + amount;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L653-656)
```text
            // decrease treasury balance
            let scaled_withdrawable_value = ray_math::ray_div(withdrawable_value, supply_index);
            reserve.treasury_balance = scaled_treasury_value - scaled_withdrawable_value;
            decrease_total_supply_balance(storage, asset, scaled_withdrawable_value);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L35-46)
```text
    public fun validate_withdraw<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_supply_balance >= scale_borrow_balance + amount, error::insufficient_balance())
    }
```
