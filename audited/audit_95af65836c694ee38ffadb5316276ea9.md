# Audit Report

## Title
Integer Division in Price Parsing Can Result in Zero Price, Enabling Unlimited Borrowing Without Liquidation Risk

## Summary
The Suilend oracle's `parse_price_to_decimal()` function performs integer division that can round down to zero when processing Pyth price feeds with large negative exponents (expo ≤ -19) relative to small price magnitudes. When an asset's price is calculated as zero, borrowed amounts of that asset are excluded from debt calculations, completely bypassing liquidation checks and allowing unlimited borrowing while corrupting vault USD valuations.

## Finding Description

The root cause lies in the fixed-point arithmetic implementation used to convert Pyth prices to Suilend's Decimal format.

**Integer Division Zero-Rounding:**

The `parse_price_to_decimal()` function [1](#0-0)  converts Pyth prices using Decimal division. The Decimal type uses WAD (1e18) precision [2](#0-1) , and its `div()` operation performs: `result.value = (a.value * WAD) / b.value` [3](#0-2) .

For negative exponents, the calculation becomes:
- `result.value = (price_mag * 1e18 * 1e18) / (pow(10, expo_magnitude) * 1e18)`
- Simplifies to: `(price_mag * 1e18) / pow(10, expo_magnitude)`

When `price_mag * 1e18 < pow(10, expo_magnitude)`, integer division rounds to **zero**.

**Example**: With `expo = -20` and `price_mag = 50`:
- `(50 * 1e18) / 1e20 = 5e19 / 1e20 = 0`

**Missing Validation:**

The `update_price()` function only validates that the price option is `Some`, not that the value is non-zero [4](#0-3) . There is no minimum price threshold check anywhere in the codebase.

**Propagation Through System:**

1. **Market Value Calculation**: The `market_value()` function multiplies the zero price by the borrowed amount, resulting in zero market value regardless of debt size [5](#0-4) .

2. **Obligation Health**: During `refresh()`, borrows with zero market value contribute zero to `weighted_borrowed_value_usd` [6](#0-5) , making the debt invisible to health calculations.

3. **Liquidation Bypass**: The `is_liquidatable()` check compares the artificially low `weighted_borrowed_value_usd` against collateral thresholds [7](#0-6) , preventing liquidation even when severely undercollateralized.

4. **Borrowing Limits**: The `max_borrow_amount()` calculation excludes zero-priced debt from limits [8](#0-7) , enabling unlimited borrowing.

5. **Vault Mispricing**: The Suilend adaptor calculates position value as `total_deposited_value_usd - total_borrowed_value_usd`, excluding zero-priced borrows and inflating the vault's reported value [9](#0-8) .

## Impact Explanation

**Critical Security Invariant Violations:**

1. **Complete Liquidation Bypass**: Obligations with zero-priced borrows can never be liquidated, as the debt is invisible to health checks. This violates the fundamental lending protocol invariant that undercollateralized positions must be liquidatable.

2. **Unlimited Borrowing**: Attackers can borrow unlimited amounts of zero-priced assets without affecting their borrowing capacity, draining all available liquidity for that asset.

3. **Fund Drainage**: Since zero-priced borrows don't count as debt, attackers can over-leverage their collateral far beyond safe limits, effectively stealing funds from lenders who deposited the zero-priced asset.

4. **Vault Accounting Corruption**: The Suilend adaptor reports artificially inflated position values, corrupting the vault's `total_usd_value` calculations. This can lead to incorrect share pricing and potentially allowing withdrawals that exceed actual vault value.

5. **Protocol Insolvency**: Bad debt accumulates with no mechanism for liquidation, threatening the solvency of the entire lending market and any vaults with Suilend positions.

**Affected Parties:**
- Lenders who deposited the zero-priced asset (funds can be fully drained)
- Vault shareholders (mispriced shares, potential loss)
- Protocol treasury (bad debt accumulation)
- Overall protocol stability and reputation

## Likelihood Explanation

**Required Preconditions:**

For zero-price rounding to occur, the condition `price_mag * 1e18 < pow(10, expo_magnitude)` must be satisfied. This requires:
- `expo_magnitude >= 19` (i.e., `expo <= -19`)
- Price magnitude small enough relative to exponent

**Feasibility Assessment:**

While mainstream assets (BTC, ETH, SOL, USDC) use standard Pyth exponents of -6 to -12 that don't trigger this issue, edge cases exist:

1. **Newly Listed Tokens**: Tokens with many decimal places (18+) or unusual pricing structures may use large negative exponents.

2. **Micro-Cap Assets**: Small market cap tokens with non-standard Pyth configurations could have expo <= -19.

3. **Market Price Collapse**: Even for properly configured feeds, if an asset's market price drops extremely low (below 10^(-18) for expo=-20 assets), it would round to zero.

4. **Configuration Errors**: Honest admins could accidentally configure reserves with vulnerable Pyth feed parameters without realizing the mathematical implications.

**Probability: LOW-MEDIUM**

While unlikely with current well-configured mainstream assets, the complete absence of validation makes this exploitable whenever:
- Any asset with vulnerable parameters is added (accidental misconfiguration)
- Any asset's price drops to near-zero levels (extreme but possible market movement)
- Future protocol expansion includes edge-case tokens

The vulnerability is latent because there are zero safeguards preventing it, and the impact is silent until exploitation occurs.

## Recommendation

Implement zero-price validation at multiple layers:

1. **In `parse_price_to_decimal()`**: Add a check to ensure the resulting Decimal value is non-zero before returning.

2. **In `update_price()`**: After extracting the price, validate it's above a reasonable minimum threshold (e.g., 1 WAD = 10^(-18) USD).

3. **In `market_value()` calculations**: Add assertions to prevent zero-price multiplication from producing zero market values for non-zero amounts.

4. **Reserve configuration**: Validate Pyth feed parameters during reserve creation to ensure `expo_magnitude < 19` or implement safeguards for edge cases.

Example fix for `parse_price_to_decimal()`:
```
fun parse_price_to_decimal(price: Price): Decimal {
    let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
    let expo = price::get_expo(&price);
    
    let result = if (i64::get_is_negative(&expo)) {
        div(
            decimal::from(price_mag),
            decimal::from(std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))),
        )
    } else {
        mul(
            decimal::from(price_mag),
            decimal::from(std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))),
        )
    };
    
    // Ensure price is not zero
    assert!(result.value > 0, EZeroPrice);
    result
}
```

## Proof of Concept

A complete PoC would require:
1. Creating a test lending market with a reserve configured with Pyth feed parameters `expo = -20`, `price_mag = 50`
2. Verifying the parsed price rounds to zero
3. Having a user borrow the zero-priced asset
4. Demonstrating the obligation cannot be liquidated despite being undercollateralized
5. Showing the Suilend adaptor reports incorrect vault value

The mathematical proof is straightforward:
- Given: `expo = -20`, `price_mag = 50`
- Calculation: `(50 * 10^18) / 10^20 = 5 * 10^19 / 10^20 = 0` (integer division)
- Result: Price stored as `Decimal { value: 0 }`
- Impact: All market value calculations return zero for this asset

---

## Notes

This vulnerability represents a fundamental failure to validate a critical invariant in lending protocols: **all asset prices must be positive and meaningful**. While the likelihood is low-medium due to requiring unusual asset parameters, the impact is catastrophic, constituting a complete bypass of the liquidation mechanism. The lack of any validation layer makes this a latent time bomb that could be triggered by honest configuration mistakes or extreme market conditions.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-70)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let expo = price::get_expo(&price);

        if (i64::get_is_negative(&expo)) {
            div(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))),
            )
        } else {
            mul(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))),
            )
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L1-15)
```text
/// fixed point decimal representation. 18 decimal places are kept.
module suilend::decimal {
    // 1e18
    const WAD: u256 = 1000000000000000000;
    const U64_MAX: u256 = 18446744073709551615;

    public struct Decimal has copy, drop, store {
        value: u256,
    }

    public fun from(v: u64): Decimal {
        Decimal {
            value: (v as u256) * WAD,
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L77-81)
```text
    public fun div(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: (a.value * WAD) / b.value,
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L261-272)
```text
    public fun market_value<P>(
        reserve: &Reserve<P>, 
        liquidity_amount: Decimal
    ): Decimal {
        div(
            mul(
                price(reserve),
                liquidity_amount
            ),
            decimal::from(std::u64::pow(10, reserve.mint_decimals))
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-593)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
        reserve.price_last_update_timestamp_s = clock::timestamp_ms(clock) / 1000;
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L234-275)
```text
        while (i < vector::length(&obligation.borrows)) {
            let borrow = vector::borrow_mut(&mut obligation.borrows, i);

            let borrow_reserve = vector::borrow_mut(reserves, borrow.reserve_array_index);
            reserve::compound_interest(borrow_reserve, clock);
            if (!reserve::is_price_fresh(borrow_reserve, clock)) {
                exist_stale_oracles = true;
            };

            compound_debt(borrow, borrow_reserve);

            let market_value = reserve::market_value(borrow_reserve, borrow.borrowed_amount);
            let market_value_upper_bound = reserve::market_value_upper_bound(
                borrow_reserve,
                borrow.borrowed_amount,
            );

            borrow.market_value = market_value;
            unweighted_borrowed_value_usd = add(unweighted_borrowed_value_usd, market_value);
            weighted_borrowed_value_usd =
                add(
                    weighted_borrowed_value_usd,
                    mul(
                        market_value,
                        borrow_weight(config(borrow_reserve)),
                    ),
                );
            weighted_borrowed_value_upper_bound_usd =
                add(
                    weighted_borrowed_value_upper_bound_usd,
                    mul(
                        market_value_upper_bound,
                        borrow_weight(config(borrow_reserve)),
                    ),
                );

            if (isolated(config(borrow_reserve))) {
                borrowing_isolated_asset = true;
            };

            i = i + 1;
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L794-796)
```text
    public fun is_liquidatable<P>(obligation: &Obligation<P>): bool {
        gt(obligation.weighted_borrowed_value_usd, obligation.unhealthy_borrow_value_usd)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L803-819)
```text
    public(package) fun max_borrow_amount<P>(
        obligation: &Obligation<P>,
        reserve: &Reserve<P>,
    ): u64 {
        floor(
            reserve::usd_to_token_amount_lower_bound(
                reserve,
                div(
                    saturating_sub(
                        obligation.allowed_borrow_value_usd,
                        obligation.weighted_borrowed_value_upper_bound_usd,
                    ),
                    borrow_weight(config(reserve)),
                ),
            ),
        )
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L65-89)
```text
    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```
