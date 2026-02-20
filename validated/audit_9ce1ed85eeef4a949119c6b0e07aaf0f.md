# Audit Report

## Title
Loans List-Balance Inconsistency Due to Price Conversion Rounding in Full Liquidations

## Summary
During full liquidations in the NAVI lending protocol integration, integer division rounding in bidirectional price conversions (token→USD→token) creates a critical accounting inconsistency where dust debt remains in user balances while assets are removed from the loans tracking list. This breaks the fundamental protocol invariant that the loans list must accurately reflect all non-zero debt, causing health factor miscalculations and preventing further liquidation of remaining debt.

## Finding Description

The vulnerability exists in the liquidation flow where the decision to remove an asset from a user's loans list uses USD value comparisons, while actual debt reduction uses token amounts converted back from USD values through non-invertible integer division.

**Root Cause:**

In `calculate_liquidation`, the system calculates `loan_value` by converting the user's token balance to USD: [1](#0-0) 

This internally calls `user_loan_value` which uses `calculate_value` with formula `amount * price / decimal`: [2](#0-1) 

The function then determines full liquidation based on USD comparison: [3](#0-2) 

However, the actual debt reduction amount is calculated by converting USD value back to tokens using `calculate_amount` with inverse formula `value * decimal / price`: [4](#0-3) [5](#0-4) 

**The Critical Inconsistency:**

These conversions are NOT perfect inverses due to integer division. Example:
- User has 1001 tokens debt, price=7, decimal=1 (10^1=10)
- Forward: `loan_value = 1001 * 7 / 10 = 700` USD (rounded down)
- Backward: `liquidable_amount = 700 * 10 / 7 = 1000` tokens (rounded down)
- Dust remaining: 1 token

In `execute_liquidate`, the balance is reduced by the converted amount: [6](#0-5) 

But if `is_max_loan_value` is true, the asset is removed from loans list: [7](#0-6) [8](#0-7) 

The `decrease_balance` function simply subtracts without verifying list consistency: [9](#0-8) 

## Impact Explanation

**Health Factor Miscalculation:**

The `user_health_loan_value()` function calculates total loan value by iterating ONLY over assets in the loans list: [10](#0-9) 

When dust debt exists but the asset is not in the list, this debt is completely excluded from health factor calculations, making the user appear healthier than reality. This breaks the fundamental protocol invariant that health factor must accurately reflect all outstanding debt.

**Liquidation Prevention:**

Future liquidation attempts for dust debt will fail because `execute_liquidate` requires `is_loan()` to return true: [11](#0-10) 

The `is_loan()` check verifies if the asset exists in the loans vector: [12](#0-11) 

After the asset is removed from the list, this check will fail, permanently preventing liquidation of remaining debt.

**Permanent Untracked Debt:**

The dust debt continues to accrue interest through the index-based accounting system, cannot be liquidated due to the `is_loan()` check, artificially inflates user borrowing capacity by excluding it from health calculations, and can only be repaid voluntarily if the user notices it. Multiple liquidations across different assets or users can accumulate significant untracked debt in the protocol.

## Likelihood Explanation

**Occurrence Frequency: High**

This issue occurs during every full liquidation where price and decimal values don't divide evenly, which is virtually guaranteed given the variety of oracle prices and token decimal configurations in production. The integer division rounding is a mathematical certainty, not a rare edge case.

**Preconditions: Minimal**

Only requires: (1) A user position being liquidated, (2) `liquidable_value >= loan_value` triggering full liquidation, (3) Price conversion rounding from integer division. All three conditions are part of normal protocol operation.

**Execution Complexity: None**

The vulnerability triggers automatically during normal liquidations - no attacker action required. Any liquidator calling the standard liquidation function will trigger this inconsistency when performing full loan repayment. The issue is inherent in the mathematical operations, not dependent on adversarial manipulation.

## Recommendation

Before removing an asset from the loans list, verify the actual token balance is zero (or below dust threshold):

```move
// In execute_liquidate, replace lines 228-230:
let remaining_balance = user_loan_balance(storage, debt_asset, user);
if (is_max_loan_value && remaining_balance == 0) {
    storage::remove_user_loans(storage, debt_asset, user);
};
```

Alternatively, modify `calculate_liquidation` to compare token amounts instead of USD values when determining `is_max_loan_value`:

```move
// In calculate_liquidation, replace lines 598-602:
let liquidable_amount_in_debt = calculator::calculate_amount(clock, oracle, liquidable_value, debt_asset_oracle_id);
let user_debt_balance = user_loan_balance(storage, debt_asset, user);
if (liquidable_amount_in_debt >= user_debt_balance) {
    is_max_loan_value = true;
    liquidable_value = calculator::calculate_value(clock, oracle, user_debt_balance, debt_asset_oracle_id);
    liquidable_amount_in_debt = user_debt_balance;
    excess_value = repay_value - liquidable_value;
};
```

## Proof of Concept

```move
#[test]
public fun test_liquidation_dust_debt_inconsistency() {
    // Setup: User has 1001 tokens borrowed with price=7, decimal=1
    // This configuration guarantees rounding: 1001*7/10=700 USD, 700*10/7=1000 tokens
    // After full liquidation:
    // - is_max_loan_value = true (because 700 >= 700 USD)
    // - Asset removed from loans list
    // - Balance reduced by 1000 tokens
    // - 1 token dust remains but is not in loans list
    // - user_health_loan_value() excludes this debt
    // - Further liquidation fails on is_loan() check
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L203-203)
```text
        assert!(is_loan(storage, debt_asset, user), error::user_have_no_loan());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L224-224)
```text
        decrease_borrow_balance(storage, debt_asset, user, liquidable_amount_in_debt);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L228-230)
```text
        if (is_max_loan_value) {
            storage::remove_user_loans(storage, debt_asset, user);
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L446-458)
```text
    public fun user_health_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): u256 {
        let (_, loans) = storage::get_user_assets(storage, user);
        let len = vector::length(&loans);
        let value = 0;
        let i = 0;
        while (i < len) {
            let asset = vector::borrow(&loans, i);
            let loan_value = user_loan_value(clock, oracle, storage, *asset, user);
            value = value + loan_value;
            i = i + 1;
        };
        value
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L515-518)
```text
    public fun is_loan(storage: &mut Storage, asset: u8, user: address): bool {
        let (_, loans) = storage::get_user_assets(storage, user);
        vector::contains(&loans, &asset)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L538-538)
```text
        let loan_value = user_loan_value(clock, oracle, storage, debt_asset, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L598-602)
```text
        if (liquidable_value >= loan_value) {
            is_max_loan_value = true;
            liquidable_value = loan_value;
            excess_value = repay_value - loan_value;
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L619-619)
```text
        let total_liquidable_amount_in_debt = calculator::calculate_amount(clock, oracle, liquidable_value, debt_asset_oracle_id);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L103-107)
```text
    public fun calculate_amount(clock: &Clock, oracle: &PriceOracle, value: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        value * (sui::math::pow(10, decimal) as u256) / price
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L553-563)
```text
    fun decrease_balance(_balance: &mut TokenBalance, user: address, amount: u256) {
        let current_amount = 0;

        if (table::contains(&_balance.user_state, user)) {
            current_amount = table::remove(&mut _balance.user_state, user)
        };
        assert!(current_amount >= amount, error::insufficient_balance());

        table::add(&mut _balance.user_state, user, current_amount - amount);
        _balance.total_supply = _balance.total_supply - amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L595-601)
```text
    public(friend) fun remove_user_loans(storage: &mut Storage, asset: u8, user: address) {
        let user_info = table::borrow_mut(&mut storage.user_info, user);
        let (exist, index) = vector::index_of(&user_info.loans, &asset);
        if (exist) {
            _ = vector::remove(&mut user_info.loans, index)
        }
    }
```
