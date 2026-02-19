### Title
Liquidator Loss Due to Ceiling Rounding in Repayment Amount Without Proportional Compensation

### Summary
The `liquidate()` function calculates liquidator compensation based on a precise Decimal repayment amount, but forces the liquidator to pay the ceiled integer amount via `coin::split()`. This systematic rounding causes liquidators to lose up to (1 - ε) tokens per liquidation without receiving proportional collateral compensation, as the withdrawal amount is computed only on the exact Decimal value. This reduces liquidation incentives and creates reserve accounting inconsistencies.

### Finding Description

The vulnerability exists in the liquidation flow across multiple function calls:

**Location 1: Liquidation compensation calculation** [1](#0-0) 

The `obligation::liquidate()` function calculates `repay_value` from the exact Decimal `repay_amount`, then computes `withdraw_value` based on this value plus liquidation bonus. The `final_withdraw_amount` (ctokens the liquidator receives) is floored based on the precise Decimal calculation.

**Location 2: Forced ceiling of payment** [2](#0-1) 

The `lending_market::liquidate()` function receives `required_repay_amount` as a Decimal from `obligation::liquidate()`, but immediately applies `ceil()` when splitting coins from the liquidator, forcing payment of the rounded-up integer amount.

**Location 3: Ceiling implementation** [3](#0-2) 

The `ceil()` function rounds up any fractional component, meaning a Decimal of 100.000000000000000001 becomes 101 tokens.

**Location 4: Reserve accounting mismatch** [4](#0-3) 

The `repay_liquidity()` function adds the ceiled coin amount to `available_amount` but only subtracts the exact Decimal `settle_amount` from `borrowed_amount`, creating an accounting discrepancy where the reserve gains the difference.

**Root Cause:**
The compensation calculation happens before the ceiling operation, using the exact Decimal value. The liquidator then pays more than this calculated amount, but receives no additional compensation for the overpayment. This breaks the fundamental liquidation incentive structure.

### Impact Explanation

**Direct Fund Impact:**
- Liquidators systematically lose up to 0.999999999999999999 tokens per liquidation
- For a liquidation of 100 tokens where `required_repay_amount = 100.000000000000000001` Decimal:
  - Liquidator pays: 101 tokens (ceiled)
  - Compensation calculated on: 100.000000000000000001 tokens
  - Loss: ~1 token
  
**Economic Impact Quantification:**
- If liquidation bonus is 5% and token value is $1:
  - Expected profit on 100 token liquidation: $5
  - Loss from ceiling: up to $1
  - Effective profit reduction: 20%
- For high-value tokens (e.g., $1000/token), the loss scales proportionally
- Small liquidations become economically unviable if ceiling loss exceeds bonus

**Reserve Accounting Impact:**
The protocol accumulates the difference between ceiled coins received and Decimal amount deducted from borrows, creating an untracked surplus in `available_amount` that doesn't correspond to actual borrowed amounts.

**Affected Parties:**
- Primary: All liquidators performing liquidations
- Secondary: Protocol health (reduced liquidation activity due to disincentive)
- Tertiary: Borrowers (delayed liquidations increase bad debt risk)

### Likelihood Explanation

**Reachable Entry Point:** [5](#0-4) 

The `liquidate()` function is public and callable by any user when an obligation is unhealthy.

**Feasibility:**
- **Preconditions:** Only requires an unhealthy obligation (standard protocol operation)
- **Frequency:** Occurs on virtually every liquidation since calculations involving multiplications, divisions, and percentage bonuses consistently produce fractional Decimal results
- **Automaticity:** No attacker action needed; this is systematic protocol behavior

**Execution Practicality:**
- No special privileges required
- No complex transaction sequences
- Happens automatically on every standard liquidation
- Probability: ~100% for liquidations (any fractional component in 18 decimal precision triggers the issue)

**Economic Rationality:**
Liquidators will rationally avoid liquidations where:
```
ceiling_loss > (liquidation_bonus_percentage × repay_amount)
```

For small liquidations or high-value tokens, this threshold is easily reached, reducing protocol liquidation coverage.

### Recommendation

**Primary Fix - Adjust compensation for ceiling:**

Modify `lending_market::liquidate()` to calculate compensation based on the ceiled amount:

```move
// After line 543, recalculate based on actual payment
let actual_repay_amount = decimal::from(coin::value(&required_repay_coins));
if (gt(actual_repay_amount, required_repay_amount)) {
    // Recalculate withdraw amount proportionally
    let ratio = div(actual_repay_amount, required_repay_amount);
    withdraw_ctoken_amount = ceil(mul(decimal::from(withdraw_ctoken_amount), ratio));
}
```

**Alternative Fix - Floor instead of ceiling:**

Change to floor the repayment amount and handle the dust amount separately, though this requires more complex obligation accounting updates.

**Invariant Check:**
Add assertion that liquidator compensation value ≥ payment value:
```move
assert!(
    market_value(withdraw_reserve, withdraw_ctoken_amount) >= 
    mul(market_value(repay_reserve, actual_repay_coins), liquidation_bonus),
    EInsufficientLiquidatorCompensation
);
```

**Test Cases:**
1. Liquidation where `required_repay_amount` = X.000000000000000001 (maximum rounding)
2. Liquidation with small amounts where ceiling loss > bonus
3. Verify reserve accounting consistency after liquidations

### Proof of Concept

**Initial State:**
- Obligation with 100 SUI borrowed, becomes unhealthy
- Obligation has 200 USDC collateral (deposited as ctokens)
- Liquidation bonus: 5%
- After liquidation calculation: `required_repay_amount` = 50.000000000000000001 SUI (Decimal)

**Transaction Steps:**
1. Liquidator calls `liquidate()` with 51 SUI coins
2. `obligation::liquidate()` calculates:
   - Repay value: 50.000000000000000001 SUI
   - Withdraw value: 50.000000000000000001 × 1.05 = 52.500000000000000001 USDC equivalent
   - Returns: `(52.5 ctokens, 50.000000000000000001 Decimal)`
3. `lending_market::liquidate()` line 543 executes:
   - `ceil(50.000000000000000001)` = 51
   - Splits 51 SUI from liquidator
4. Liquidator receives: 52.5 ctokens (worth ~52.5 USDC)
5. Liquidator paid: 51 SUI

**Expected Result:**
Liquidator should receive compensation worth 51 × 1.05 = 53.55 SUI equivalent

**Actual Result:**
Liquidator receives compensation worth only 52.5 SUI equivalent (calculated on 50.000000000000000001)

**Loss Calculation:**
- Expected: 53.55 - 51 = 2.55 SUI profit
- Actual: 52.5 - 51 = 1.5 SUI profit  
- Loss: 1.05 SUI (41% reduction in profit)

**Success Condition:**
Transaction completes successfully, but liquidator receives less compensation than economically justified by their actual payment, confirmed by comparing ctoken redemption value against SUI paid.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L568-597)
```text
        let repay_value = reserve::market_value(repay_reserve, repay_amount);
        let bonus = add(
            liquidation_bonus(config(withdraw_reserve)),
            protocol_liquidation_fee(config(withdraw_reserve)),
        );

        let withdraw_value = mul(
            repay_value,
            add(decimal::from(1), bonus),
        );

        // repay amount, but in decimals. called settle amount to keep logic in line with
        // spl-lending
        let final_settle_amount;
        let final_withdraw_amount;

        if (lt(deposit.market_value, withdraw_value)) {
            let repay_pct = div(deposit.market_value, withdraw_value);

            final_settle_amount = mul(repay_amount, repay_pct);
            final_withdraw_amount = deposit.deposited_ctoken_amount;
        } else {
            let withdraw_pct = div(withdraw_value, deposit.market_value);

            final_settle_amount = repay_amount;
            final_withdraw_amount =
                floor(
                    mul(decimal::from(deposit.deposited_ctoken_amount), withdraw_pct),
                );
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L511-519)
```text
    public fun liquidate<P, Repay, Withdraw>(
        lending_market: &mut LendingMarket<P>,
        obligation_id: ID,
        repay_reserve_array_index: u64,
        withdraw_reserve_array_index: u64,
        clock: &Clock,
        repay_coins: &mut Coin<Repay>, // mut because we probably won't use all of it
        ctx: &mut TxContext,
    ): (Coin<CToken<P, Withdraw>>, RateLimiterExemption<P, Withdraw>) {
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L532-543)
```text
        let (withdraw_ctoken_amount, required_repay_amount) = obligation::liquidate<P>(
            obligation,
            &mut lending_market.reserves,
            repay_reserve_array_index,
            withdraw_reserve_array_index,
            clock,
            coin::value(repay_coins),
        );

        assert!(gt(required_repay_amount, decimal::from(0)), ETooSmall);

        let required_repay_coins = coin::split(repay_coins, ceil(required_repay_amount), ctx);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L110-112)
```text
    public fun ceil(a: Decimal): u64 {
        (((a.value + WAD - 1) / WAD) as u64)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L944-950)
```text
        assert!(balance::value(&liquidity) == ceil(settle_amount), EInvalidRepayBalance);

        reserve.available_amount = reserve.available_amount + balance::value(&liquidity);
        reserve.borrowed_amount = saturating_sub(
            reserve.borrowed_amount, 
            settle_amount
        );
```
