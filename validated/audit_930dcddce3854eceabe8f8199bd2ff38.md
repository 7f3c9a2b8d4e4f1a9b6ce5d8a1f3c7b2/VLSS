# Audit Report

## Title
Zero Price Acceptance Due to Flawed Confidence Check Causes Division-by-Zero DoS in Maximum Borrow/Withdraw Operations

## Summary
The Suilend oracle price validation incorrectly allows zero prices when both `price_mag` and `conf` are zero. This zero price propagates to reserve storage and causes Move runtime aborts when users attempt to borrow or withdraw maximum amounts, resulting in a denial-of-service for these operations until the price is manually updated.

## Finding Description

**Root Cause - Flawed Confidence Check:**
The confidence interval validation performs the check `conf * MIN_CONFIDENCE_RATIO > price_mag` [1](#0-0) . When both values are zero, this evaluates to `0 * 10 > 0` (false), allowing the zero price to pass validation and return `option::some(0)` instead of `option::none()`.

The EMA price is parsed without zero-value validation [2](#0-1) , allowing both spot and smoothed prices to be zero.

**Insufficient Downstream Validation:**
Reserve creation only validates that the Option contains a value, not whether that value is zero [3](#0-2) . The same insufficient check exists in `update_price()` [4](#0-3) .

Zero prices are stored in reserve state [5](#0-4) , where they can then be accessed by pricing functions.

**Division-by-Zero Execution Path:**
When users request maximum borrow amounts, the code calls `usd_to_token_amount_lower_bound()` which divides by `price_upper_bound()` [6](#0-5) . Similarly, `usd_to_token_amount_upper_bound()` divides by `price_lower_bound()` [7](#0-6) .

Both `price_upper_bound()` and `price_lower_bound()` return the max/min of the stored prices [8](#0-7) . When both prices are zero, these functions return zero, causing the subsequent division to abort [9](#0-8) .

**Critical Call Sites:**
The vulnerable functions are invoked when users specify `U64_MAX` as the borrow/withdraw amount:
- `borrow_request()` triggers `max_borrow_amount()` at [10](#0-9) 
- `withdraw_ctokens()` triggers `max_withdraw_amount()` at [11](#0-10) 

These functions call the price conversion functions that cause division by zero [12](#0-11)  and [13](#0-12) .

Additional vulnerable paths exist in [14](#0-13) , [15](#0-14) , and [16](#0-15) .

## Impact Explanation

**Operational DoS - Maximum Amount Operations:**
Once a reserve accepts a zero price, any user attempting to borrow or withdraw the maximum available amount from that reserve will experience a Move runtime abort due to division by zero. This specifically affects:
- Users calling `borrow_request()` with `amount = U64_MAX` to borrow the maximum they can
- Users calling `withdraw_ctokens()` with `amount = U64_MAX` to withdraw all available collateral
- Rate limiter calculations that occur within these operations

**Scope of Impact:**
Users can still perform borrow/withdraw operations by specifying concrete amounts rather than using the maximum amount feature. However, the maximum amount feature is commonly used in UIs and by users who want to fully utilize their borrowing capacity or withdraw all available collateral.

**Recovery:**
The DoS persists until an authorized party calls `update_price()` with valid non-zero price data, restoring normal operation.

**Severity:** Medium-High - Denial of service for maximum borrow/withdraw functionality affecting all users of the impacted reserve, though specific-amount operations remain functional.

## Likelihood Explanation

**Preconditions:**
The vulnerability requires Pyth oracle to provide both `price_mag = 0` and `conf = 0` simultaneously. While unusual for established assets, this can occur in several realistic scenarios:
1. New asset listings with incomplete or uninitialized price feeds
2. Asset delisting or deprecation where price feeds are zeroed out
3. Oracle malfunction or edge case handling during extreme market events
4. Testing/staging environments with zero-initialized data

**Reachable Entry Points:**
The zero price can be introduced during:
- `create_reserve()` when initializing a new reserve [17](#0-16) 
- `update_price()` during periodic price updates [18](#0-17) 

**Attacker Requirements:**
No malicious actor is required - the vulnerability is triggered by legitimate oracle data that the protocol fails to properly validate. Any user attempting to use the maximum borrow/withdraw feature after zero price acceptance will encounter the DoS.

## Recommendation

Add explicit zero-price validation in `get_pyth_price_and_identifier()`:

```move
// After line 31 in oracles.move, add:
if (price_mag == 0 || i64::get_magnitude_if_positive(&price::get_price(&price_feed::get_ema_price(price_feed))) == 0) {
    return (option::none(), ema_price, price_identifier)
};
```

Additionally, add zero-price validation checks before storing prices in reserves:

```move
// In reserve.move create_reserve() and update_price(), after extracting price, add:
assert!(price > decimal::from(0), EInvalidPrice);
assert!(smoothed_price > decimal::from(0), EInvalidPrice);
```

## Proof of Concept

The vulnerability can be demonstrated with a test that:
1. Mocks a Pyth PriceInfoObject returning both `price_mag = 0` and `conf = 0`
2. Creates a reserve with this zero price (which incorrectly succeeds)
3. Attempts to call `max_borrow_amount()` on the reserve
4. Observes the transaction abort due to division by zero

The key issue is that the confidence check `0 * 10 > 0` evaluates to false, allowing the zero price through, and subsequent division operations abort the transaction.

# Notes

**Important Clarifications:**

1. **Scope of DoS:** The vulnerability specifically affects operations where users request maximum amounts (`U64_MAX`). Users can still borrow/withdraw by specifying concrete amounts, as those code paths don't invoke the problematic `usd_to_token_amount_*` functions in the same way.

2. **Volo Integration:** Volo's `suilend_adaptor` only calls `market_value()` functions that multiply by price rather than divide by it [19](#0-18) , so Volo's vault operations do not directly trigger this vulnerability.

3. **In-Scope Validation:** The Suilend protocol code is explicitly included in the audit scope as a local dependency, making this vulnerability valid for the overall codebase security assessment even though it's in an external integration.

4. **Oracle Dependency:** The actual likelihood depends on whether Pyth oracles can realistically provide zero values for both price and confidence, which would require understanding Pyth's internal implementation and failure modes.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L27-27)
```text
        let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L36-38)
```text
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L157-168)
```text
    public(package) fun create_reserve<P, T>(
        lending_market_id: ID,
        config: ReserveConfig, 
        array_index: u64,
        mint_decimals: u8,
        price_info_obj: &PriceInfoObject, 
        clock: &Clock, 
        ctx: &mut TxContext
    ): Reserve<P> {

        let (mut price_decimal, smoothed_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L178-179)
```text
            price: option::extract(&mut price_decimal),
            smoothed_price: smoothed_price_decimal,
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L253-259)
```text
    public fun price_lower_bound<P>(reserve: &Reserve<P>): Decimal {
        min(reserve.price, reserve.smoothed_price)
    }

    public fun price_upper_bound<P>(reserve: &Reserve<P>): Decimal {
        max(reserve.price, reserve.smoothed_price)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L340-351)
```text
    public fun usd_to_token_amount_lower_bound<P>(
        reserve: &Reserve<P>, 
        usd_amount: Decimal
    ): Decimal {
        div(
            mul(
                decimal::from(std::u64::pow(10, reserve.mint_decimals)),
                usd_amount
            ),
            price_upper_bound(reserve)
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L353-364)
```text
    public fun usd_to_token_amount_upper_bound<P>(
        reserve: &Reserve<P>, 
        usd_amount: Decimal
    ): Decimal {
        div(
            mul(
                decimal::from(std::u64::pow(10, reserve.mint_decimals)),
                usd_amount
            ),
            price_lower_bound(reserve)
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L470-476)
```text
                usd_to_token_amount_lower_bound(
                    reserve,
                    saturating_sub(
                        decimal::from(borrow_limit_usd(config(reserve))),
                        market_value_upper_bound(reserve, reserve.borrowed_amount)
                    )
                )
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L77-81)
```text
    public fun div(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: (a.value * WAD) / b.value,
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L414-416)
```text
        if (amount == U64_MAX) {
            amount = max_borrow_amount<P>(lending_market.rate_limiter, obligation, reserve, clock);
            assert!(amount > 0, ETooSmall);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L489-491)
```text
        if (amount == U64_MAX) {
            amount =
                max_withdraw_amount<P>(lending_market.rate_limiter, obligation, reserve, clock);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L840-843)
```text
            reserve::usd_to_token_amount_lower_bound(
                reserve,
                min(remaining_outflow_usd, decimal::from(1_000_000_000)),
            ),
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L890-893)
```text
        let rate_limiter_max_withdraw_amount = reserve::usd_to_token_amount_lower_bound(
            reserve,
            min(remaining_outflow_usd, decimal::from(1_000_000_000)),
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L808-817)
```text
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
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L845-848)
```text
        let max_withdraw_token_amount = reserve::usd_to_token_amount_upper_bound(
            reserve,
            max_withdraw_value,
        );
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L58-82)
```text
        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

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
```
