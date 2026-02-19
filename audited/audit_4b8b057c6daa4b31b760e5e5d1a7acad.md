### Title
Rounding Loss in Liquidation Repayment Due to Decimal-to-Integer Conversion Mismatch

### Summary
The `liquidate()` function forces liquidators to provide `ceil(required_repay_amount)` coins but only credits the decimal `required_repay_amount` to reduce the borrowed debt, causing liquidators to lose up to 0.999 tokens per liquidation. This excess is added to the reserve's `available_amount` without proportionally reducing `borrowed_amount`, creating an accounting imbalance that inflates the total supply and unfairly benefits ctoken holders at the liquidator's expense.

### Finding Description

The vulnerability occurs in the interaction between `lending_market::liquidate()` and `reserve::repay_liquidity()`: [1](#0-0) 

At line 543, the code splits `ceil(required_repay_amount)` coins from the liquidator's balance. For example, if `required_repay_amount = 100.3`, it splits 101 coins. These coins are then passed to `reserve::repay_liquidity()` along with the decimal `required_repay_amount`. [2](#0-1) 

In `repay_liquidity()`, line 944 enforces that the coin balance equals `ceil(settle_amount)` (101 coins), but line 946 adds the full 101 to `available_amount` while line 947-950 only subtract the decimal 100.3 from `borrowed_amount`. The 0.7 coin difference creates an accounting discrepancy.

The root cause is a type mismatch: `reserve.available_amount` is `u64` while `reserve.borrowed_amount` is `Decimal`: [3](#0-2) 

This affects the `total_supply` calculation, which adds both values: [4](#0-3) 

When `available_amount` increases by 101 but `borrowed_amount` decreases by only 100.3, the `total_supply` incorrectly increases by 0.7, making ctokens more valuable at the liquidator's expense.

The same issue affects the normal `repay()` function: [5](#0-4) 

### Impact Explanation

**Direct Financial Loss:**
- Liquidators lose up to 0.999 tokens per liquidation (the rounding difference between the decimal repay amount and its ceiling)
- For low-value tokens ($1), this is ~$0.001 per liquidation
- For high-value tokens (e.g., WBTC at $100,000), this could be ~$100 per liquidation
- Accumulates across all liquidations and repayments in the protocol

**Accounting Imbalance:**
- The reserve's `total_supply` becomes artificially inflated by the rounding excess
- CToken holders unfairly benefit as their tokens become slightly more valuable
- The protocol's accounting between `available_amount` and `borrowed_amount` becomes inconsistent

**Affected Parties:**
- Liquidators: Direct financial loss on every liquidation
- Borrowers performing repayments: Same issue affects normal `repay()` function
- CToken holders: Unearned gains from inflated total supply

The severity is Medium because while the per-transaction loss is small (< 1 token), it's systematic, affects all liquidations/repayments, and can be substantial for high-value assets.

### Likelihood Explanation

**Certainty: 100% - This is not an exploit, it's inherent behavior**

- **Reachable Entry Point:** `liquidate()` and `repay()` are public functions callable by any user
- **Preconditions:** Happens automatically whenever the repay amount has any decimal places (extremely common in lending protocols due to compound interest)
- **Execution Practicality:** No special actions needed - occurs during normal liquidation/repayment operations
- **Economic Viability:** Liquidators have no choice but to accept this loss when performing liquidations
- **Detection:** The assertion at line 944 explicitly enforces this behavior, indicating it may have been intentional but creates unfairness

This affects every liquidation and repayment where the calculated amount has fractional precision, which is virtually all transactions in a lending protocol with interest accrual.

### Recommendation

**Option 1: Track and Return Excess (Recommended)**
Modify `repay_liquidity()` to calculate and return the rounding difference, then refund it to the caller:

```move
public(package) fun repay_liquidity<P, T>(
    reserve: &mut Reserve<P>, 
    liquidity: Balance<T>,
    settle_amount: Decimal
): Balance<T> {
    let provided = balance::value(&liquidity);
    let required = ceil(settle_amount);
    assert!(provided == required, EInvalidRepayBalance);
    
    reserve.available_amount = reserve.available_amount + required;
    reserve.borrowed_amount = saturating_sub(reserve.borrowed_amount, settle_amount);
    
    // Calculate and split excess
    let excess = provided - floor(settle_amount);
    let excess_balance = balance::split(&mut liquidity, excess);
    
    balance::join(&mut balances.available_amount, liquidity);
    excess_balance // Return to caller for refund
}
```

Update callers in `lending_market.move` to handle the returned excess balance.

**Option 2: Route Excess to Protocol Fees**
If the rounding is intentional as a fee, modify the code to properly account for it:
- Add the excess to `unclaimed_spread_fees` instead of `available_amount`
- Document this as a "rounding fee" in the protocol specification
- Ensure proper fee distribution mechanisms

**Testing:**
Add test cases verifying:
1. Liquidation with `required_repay_amount = 100.3` returns 0.7 coins to liquidator
2. Reserve's `total_supply` changes by exactly `floor(required_repay_amount)`
3. No accounting discrepancy accumulates over multiple transactions

### Proof of Concept

**Initial State:**
- Reserve has `available_amount = 1000`, `borrowed_amount = 500.3`
- Obligation has unhealthy position requiring liquidation
- Liquidator has 200 repay tokens

**Transaction Steps:**

1. Call `liquidate()` with liquidator's 200 tokens
2. `obligation::liquidate()` calculates `required_repay_amount = 100.3` (Decimal)
3. `coin::split(repay_coins, ceil(100.3), ctx)` splits 101 coins
4. `reserve::repay_liquidity()` receives 101 coins and 100.3 decimal amount
5. Reserve state updates:
   - `available_amount = 1000 + 101 = 1101` (increase by 101)
   - `borrowed_amount = 500.3 - 100.3 = 400.0` (decrease by 100.3)
6. `total_supply = 1101 + 400.0 - fees = 1501.0 - fees`

**Expected Result:**
- Liquidator should lose exactly 100.3 tokens
- Total supply should increase by 0 (100.3 added to available, 100.3 removed from borrowed)

**Actual Result:**
- Liquidator loses 101 tokens (0.7 extra loss)
- Total supply increases by 0.7
- CToken ratio increases, benefiting existing depositors unfairly
- Liquidator's remaining balance: 99 tokens instead of 99.7

**Success Condition for Exploit:**
The vulnerability manifests on every single liquidation - no special conditions needed. Simply perform any liquidation where the repay amount has decimal precision.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L543-553)
```text
        let required_repay_coins = coin::split(repay_coins, ceil(required_repay_amount), ctx);
        let repay_reserve = vector::borrow_mut(
            &mut lending_market.reserves,
            repay_reserve_array_index,
        );
        assert!(reserve::coin_type(repay_reserve) == type_name::get<Repay>(), EWrongType);
        reserve::repay_liquidity<P, Repay>(
            repay_reserve,
            coin::into_balance(required_repay_coins),
            required_repay_amount,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L623-624)
```text
        let repay_coins = coin::split(max_repay_coins, ceil(repay_amount), ctx);
        reserve::repay_liquidity<P, T>(reserve, coin::into_balance(repay_coins), repay_amount);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L70-72)
```text
        available_amount: u64,
        ctoken_supply: u64,
        borrowed_amount: Decimal,
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L371-378)
```text
    public fun total_supply<P>(reserve: &Reserve<P>): Decimal {
        sub(
            add(
                decimal::from(reserve.available_amount),
                reserve.borrowed_amount
            ),
            reserve.unclaimed_spread_fees
        )
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L939-955)
```text
    public(package) fun repay_liquidity<P, T>(
        reserve: &mut Reserve<P>, 
        liquidity: Balance<T>,
        settle_amount: Decimal
    ) {
        assert!(balance::value(&liquidity) == ceil(settle_amount), EInvalidRepayBalance);

        reserve.available_amount = reserve.available_amount + balance::value(&liquidity);
        reserve.borrowed_amount = saturating_sub(
            reserve.borrowed_amount, 
            settle_amount
        );

        log_reserve_data(reserve);
        let balances: &mut Balances<P, T> = dynamic_field::borrow_mut(&mut reserve.id, BalanceKey {});
        balance::join(&mut balances.available_amount, liquidity);
    }
```
