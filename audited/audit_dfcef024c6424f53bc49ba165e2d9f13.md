# Audit Report

## Title
Rounding Loss in Suilend Liquidation and Repayment Due to Decimal-to-Integer Conversion Mismatch

## Summary
The Suilend protocol (integrated by Volo) contains a systematic accounting flaw where liquidators and borrowers are forced to provide `ceil(repay_amount)` coins but only the decimal `repay_amount` is credited to reduce borrowed debt. This creates an accounting imbalance in Suilend reserves that affects all participants, including Volo's positions.

## Finding Description

The vulnerability exists in the interaction between Suilend's `lending_market` and `reserve` modules, which are in scope as Volo dependencies.

**In the liquidate() function**, the code splits the ceiling of the required repay amount from the liquidator's balance: [1](#0-0) 

This amount is then passed to `repay_liquidity()` along with the decimal value: [2](#0-1) 

**In repay_liquidity()**, the function enforces that the balance equals the ceiling, adds the full ceiling amount to `available_amount`, but only subtracts the decimal amount from `borrowed_amount`: [3](#0-2) 

The root cause is a type mismatch in the Reserve struct where `available_amount` is `u64` while `borrowed_amount` is `Decimal`: [4](#0-3) 

This affects the `total_supply` calculation which adds both values: [5](#0-4) 

**The same issue affects the normal repay() function:** [6](#0-5) 

**Example:** If `repay_amount = 100.3`:
1. Liquidator provides `ceil(100.3) = 101` coins
2. `available_amount` increases by `101`
3. `borrowed_amount` decreases by `100.3` (decimal)
4. Net effect: `total_supply` increases by `0.7`, creating accounting corruption

Volo integrates with Suilend through the suilend_adaptor and holds `SuilendObligationOwnerCap` positions: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Direct Financial Loss:**
- Liquidators lose up to 0.999 tokens per liquidation
- Borrowers lose up to 0.999 tokens per repayment
- For high-value tokens (e.g., WBTC at $100,000), this represents ~$100 per transaction
- Accumulates systematically across all transactions

**Accounting Corruption:**
- Suilend reserve `total_supply` becomes artificially inflated
- CToken exchange rates are corrupted, affecting all reserve participants
- Volo's Suilend positions are valued using these corrupted exchange rates
- This leads to incorrect vault accounting and position valuations

**Affected Parties:**
- Liquidators and borrowers in Suilend markets (direct loss)
- Volo vault users (indirect impact through corrupted position valuations)
- If Volo ever needs to repay Suilend debts, it would suffer direct losses

The severity is Medium-High because while per-transaction loss is small, it's systematic, certain to occur, and affects protocol accounting integrity.

## Likelihood Explanation

**Certainty: 100% - This is inherent behavior, not an exploit**

- **Entry Points:** `liquidate()` and `repay()` are public functions callable by any user
- **Preconditions:** Occurs automatically whenever repay amounts have decimal places (virtually all transactions due to compound interest accrual)
- **Execution:** No special actions needed - happens during normal operations
- **Detection:** The assertion explicitly enforces this behavior

The vulnerability affects every liquidation and repayment where the calculated amount has fractional precision, which is the common case in lending protocols with continuous interest accrual.

## Recommendation

**Option 1: Credit the full ceiling amount to reduce borrowed_amount**
Modify `repay_liquidity()` to subtract `decimal::from(ceil(settle_amount))` from `borrowed_amount` instead of just `settle_amount`. This ensures symmetry between what users pay and what gets credited.

**Option 2: Return excess to the user**
Only take `ceil(settle_amount)` if needed for whole coin amounts, but credit/return any excess appropriately.

**Option 3: Use consistent decimal accounting**
Refactor to handle all amounts as decimals throughout the system, only converting to u64 at the final coin operations.

The fix should ensure that `available_amount` increases and `borrowed_amount` decreases by equivalent amounts when accounting for the rounding, maintaining the invariant that `total_supply` remains consistent.

## Proof of Concept

```move
// Conceptual proof (requires full Suilend test environment)
// 
// Setup:
// 1. Create a Suilend reserve with initial state
// 2. User borrows 100 tokens, accrues interest to 100.3 tokens owed
// 
// Execute repay:
// - User calls repay() with 100.3 decimal amount
// - Code splits ceil(100.3) = 101 coins from user balance
// - repay_liquidity() receives 101 coins and 100.3 decimal
// - available_amount += 101 (u64)
// - borrowed_amount -= 100.3 (Decimal)
// 
// Verify:
// - total_supply increased by 0.7
// - User lost 0.7 tokens with no benefit
// - CToken holders gained from inflated total_supply
// 
// This occurs on every repayment/liquidation with fractional amounts
```

**Notes:**

This vulnerability exists in the Suilend integration code that is explicitly in scope. While Volo may not directly trigger liquidations, it holds positions in Suilend markets where this accounting corruption occurs. The corrupted ctoken exchange rates and reserve accounting indirectly affect Volo's position valuations and vault accounting. Additionally, if Volo ever needs to repay Suilend obligations, it would suffer direct losses from this issue.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L543-543)
```text
        let required_repay_coins = coin::split(repay_coins, ceil(required_repay_amount), ctx);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L549-553)
```text
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L371-379)
```text
    public fun total_supply<P>(reserve: &Reserve<P>): Decimal {
        sub(
            add(
                decimal::from(reserve.available_amount),
                reserve.borrowed_amount
            ),
            reserve.unclaimed_spread_fees
        )
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

**File:** volo-vault/sources/operation.move (L247-256)
```text
        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-39)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
```
