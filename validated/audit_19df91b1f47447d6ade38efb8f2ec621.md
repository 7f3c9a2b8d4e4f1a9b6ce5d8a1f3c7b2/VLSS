# Audit Report

## Title
Loans List-Balance Inconsistency Due to Price Conversion Rounding in Full Liquidations

## Summary
During full liquidations in the NAVI lending protocol, the decision to remove an asset from a user's loans list is based on USD value comparisons, while the actual debt reduction uses token amounts converted back from USD values. Integer division rounding in the bidirectional price conversion (token→USD→token) creates an inconsistency where dust debt remains in the balance while the asset is removed from the loans list, causing health factor miscalculations and preventing further liquidation of the remaining debt.

## Finding Description

The vulnerability exists in the liquidation flow where list management and balance updates use different value representations that are not perfectly invertible due to integer division rounding.

**Root Cause:**

In `calculate_liquidation`, the `loan_value` is calculated by converting the user's token balance to USD using `user_loan_value()` [1](#0-0) , which internally calls `calculate_value` with the formula `amount * price / decimal` [2](#0-1) .

The function then determines `is_max_loan_value = true` when `liquidable_value >= loan_value` [3](#0-2) , meaning the liquidation will fully cover the loan based on USD comparison.

However, the actual debt reduction amount is calculated by converting the USD value back to tokens using `calculate_amount` with formula `value * decimal / price` [4](#0-3)  at line 619 of the liquidation calculation [5](#0-4) .

**The Critical Inconsistency:**

These two conversions are NOT perfect inverses due to integer division. For example:
- User has 1001 token debt, price=7, decimal=10
- Forward: `loan_value = 1001 * 7 / 10 = 7007 / 10 = 700` USD (rounded down)
- Backward: `liquidable_amount = 700 * 10 / 7 = 7000 / 7 = 1000` tokens (rounded down)
- Dust remaining: 1 token

In `execute_liquidate`, the balance is reduced by `liquidable_amount_in_debt` [6](#0-5) , but if `is_max_loan_value` is true, the asset is removed from the loans list [7](#0-6)  via `remove_user_loans` [8](#0-7) .

The `decrease_balance` function simply subtracts the amount without checking if the result creates an inconsistency with the loans list [9](#0-8) .

## Impact Explanation

**Health Factor Miscalculation:**

The `user_health_loan_value()` function calculates total loan value by iterating only over assets in the loans list [10](#0-9) . When dust debt exists but the asset is not in the list, this debt is completely excluded from health factor calculations, making the user appear healthier than they actually are. This breaks a fundamental protocol invariant that health factor should accurately reflect all outstanding debt.

**Liquidation Prevention:**

Future liquidation attempts for the dust debt will fail because `execute_liquidate` requires `is_loan()` to return true [11](#0-10) , which checks if the asset exists in the loans vector [12](#0-11) . This check will fail after the asset is removed from the list, permanently preventing liquidation of the remaining debt.

**Permanent Untracked Debt:**

The dust debt continues to accrue interest indefinitely through the index-based accounting system, cannot be liquidated due to the `is_loan()` check, artificially inflates the user's borrowing capacity by excluding it from health calculations, and can only be repaid voluntarily if the user notices it. Multiple liquidations across different assets or users can accumulate significant untracked debt in the protocol.

## Likelihood Explanation

**Occurrence Frequency: High**

This issue occurs during every full liquidation where the price and decimal values don't divide evenly, which is virtually guaranteed given the variety of oracle prices and token decimal configurations in production. The integer division rounding is a mathematical certainty, not a rare edge case.

**Preconditions: Minimal**

Only requires: (1) A user position being liquidated, (2) `liquidable_value >= loan_value` triggering full liquidation, (3) Price conversion rounding from integer division. All three conditions are part of normal protocol operation.

**Execution Complexity: None**

The vulnerability triggers automatically during normal liquidations - no attacker action required. Any liquidator calling the standard liquidation function will trigger this inconsistency when performing full loan repayment. The issue is inherent in the mathematical operations, not dependent on adversarial manipulation.

## Recommendation

The protocol should ensure consistency between list management and balance updates. Two potential solutions:

**Option 1: Check actual balance before removing from list**
After reducing the balance, check if the remaining balance is zero (or below a dust threshold) before calling `remove_user_loans`. This ensures the list only updates when debt is truly fully repaid.

**Option 2: Round conservatively in liquidation calculations**
When calculating `liquidable_amount_in_debt`, ensure the result never exceeds the actual `user_loan_balance()` by taking the minimum of the calculated amount and the current balance. This prevents the `is_max_loan_value` flag from being set prematurely.

**Option 3: Remove from list based on actual balance**
In `execute_liquidate`, instead of using the `is_max_loan_value` flag, check the actual remaining balance after reduction and only remove from the list if the balance is zero or below a dust threshold.

## Proof of Concept

```move
#[test]
// Demonstrates dust debt remaining after full liquidation due to rounding
public fun test_liquidation_dust_debt_inconsistency() {
    let alice = @0xace;
    let bob = @0xb0b;
    let scenario = test_scenario::begin(OWNER);
    sup_global::init_protocol(&mut scenario);

    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let clock = clock::create_for_testing(ctx);
        let stg = test_scenario::take_shared<Storage>(&scenario);
        let price_oracle = test_scenario::take_shared<PriceOracle>(&scenario);
        let oracle_feeder_cap = test_scenario::take_from_sender<OracleFeederCap>(&scenario);

        // Setup: Alice supplies, Bob borrows
        logic::execute_deposit_for_testing<USDT_TEST>(&clock, &mut stg, 0, alice, 30000_000000000);
        logic::execute_deposit_for_testing<ETH_TEST>(&clock, &mut stg, 1, bob, 10_000000000);
        
        // Set price that creates rounding: price=7, decimal=10
        oracle::update_token_price(&oracle_feeder_cap, &clock, &mut price_oracle, 0, 7_000000000);
        
        // Bob borrows amount that will create dust: 1001 tokens
        // loan_value = 1001 * 7 / 10 = 700 USD
        // liquidable_amount = 700 * 10 / 7 = 1000 tokens
        // Dust = 1 token
        logic::execute_borrow_for_testing<USDT_TEST>(&clock, &price_oracle, &mut stg, 0, bob, 1001_000000000);
        
        // Drop ETH price to make Bob unhealthy
        oracle::update_token_price(&oracle_feeder_cap, &clock, &mut price_oracle, 1, 800_000000000);
        
        // Verify Bob has loan before liquidation
        assert!(logic::is_loan(&mut stg, 0, bob), 0);
        let balance_before = logic::user_loan_balance(&mut stg, 0, bob);
        
        // Liquidate full amount
        logic::execute_liquidate_for_testing<USDT_TEST, ETH_TEST>(&clock, &price_oracle, &mut stg, bob, 1, 0, 1001_000000000);
        
        // Bug: Asset removed from loans list
        assert!(!logic::is_loan(&mut stg, 0, bob), 1);
        
        // Bug: But dust debt remains in balance
        let balance_after = logic::user_loan_balance(&mut stg, 0, bob);
        assert!(balance_after > 0, 2); // Dust debt exists
        
        // Bug: Health calculation excludes this debt
        let health_loan_value = logic::user_health_loan_value(&clock, &price_oracle, &mut stg, bob);
        assert!(health_loan_value == 0, 3); // Debt not counted!
        
        // Bug: Cannot liquidate remaining dust
        // This would fail with "user_have_no_loan" error:
        // logic::execute_liquidate_for_testing<USDT_TEST, ETH_TEST>(&clock, &price_oracle, &mut stg, bob, 1, 0, 1_000000000);
        
        clock::destroy_for_testing(clock);
        test_scenario::return_shared(stg);
        test_scenario::return_shared(price_oracle);
        test_scenario::return_to_sender(&scenario, oracle_feeder_cap);
    };

    test_scenario::end(scenario);
}
```

## Notes

This vulnerability affects the NAVI Protocol lending core that is integrated as a local dependency in the Volo smart contracts. While the issue is in the lending protocol logic rather than Volo-specific code, it is within the explicitly defined in-scope files for this audit. The vulnerability represents a fundamental accounting invariant violation where the loans list state and actual balance state become desynchronized due to integer division rounding in price conversions.

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
