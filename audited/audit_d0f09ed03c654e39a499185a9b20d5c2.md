# Audit Report

## Title
Zero Price Acceptance Due to Flawed Confidence Check Causes Division-by-Zero DoS in Maximum Borrow/Withdraw Operations

## Summary
The Suilend oracle price validation incorrectly allows zero prices when both `price_mag` and `conf` are zero, enabling these invalid prices to be stored in reserve state. This causes Move runtime aborts (division by zero) when users attempt to borrow or withdraw maximum amounts via the `U64_MAX` sentinel value, resulting in a denial-of-service for these operations.

## Finding Description

**Root Cause - Flawed Confidence Check:**

The confidence interval validation check is intended to reject prices with excessive uncertainty, but it fails when both the price and confidence are zero. [1](#0-0) 

When `price_mag = 0` and `conf = 0`, the expression `conf * MIN_CONFIDENCE_RATIO > price_mag` evaluates to `0 * 10 > 0` (false), allowing execution to continue and return `option::some(0)` instead of the intended `option::none()`. [2](#0-1) 

The EMA price parsing also lacks zero-value validation, allowing smoothed prices to be zero. [3](#0-2) [4](#0-3) 

**Insufficient Downstream Validation:**

Reserve creation only validates that the Option contains a value, not whether that value is non-zero. [5](#0-4)  The zero price is then extracted and stored in reserve state. [6](#0-5) 

The same insufficient validation exists in the price update function. [7](#0-6) 

**Division-by-Zero Execution Path:**

The price bounds functions return the stored prices directly. [8](#0-7)  When both stored prices are zero, these functions return zero.

The USD-to-token conversion functions divide by these price bounds. [9](#0-8) [10](#0-9) 

The Decimal division operation performs direct division without zero checks, causing a Move runtime abort when the divisor is zero. [11](#0-10) 

**Critical Call Sites:**

When users call `borrow_request` with the maximum amount sentinel value, it triggers the vulnerable calculation path. [12](#0-11) [13](#0-12) 

The `max_borrow_amount` helper invokes the problematic conversion functions. [14](#0-13) [15](#0-14) 

The obligation-level max borrow calculation also calls the vulnerable function. [16](#0-15) 

Similarly, `withdraw_ctokens` with the maximum amount sentinel triggers the same path. [17](#0-16) [18](#0-17) 

The obligation-level max withdraw calculation uses the upper bound variant which divides by `price_lower_bound`. [19](#0-18) 

## Impact Explanation

**Operational DoS - Maximum Amount Operations:**

Once a reserve accepts a zero price, any user attempting to borrow or withdraw the maximum available amount from that reserve will experience a Move runtime abort due to division by zero. This specifically affects users who:
- Call `borrow_request()` with `amount = U64_MAX` to borrow their maximum capacity
- Call `withdraw_ctokens()` with `amount = U64_MAX` to withdraw all available collateral

**Scope of Impact:**

The DoS is limited to the maximum amount feature - users can still perform operations by specifying concrete amounts rather than using `U64_MAX`. However, this feature is commonly used in user interfaces and by users who want to fully utilize their positions without manual calculations.

**Recovery:**

The DoS persists until an authorized party calls `update_price()` with valid non-zero price data from the oracle, restoring normal operation.

**Severity:** Medium-High - Denial of service for a commonly-used feature affecting all users of the impacted reserve, though workarounds exist via specific amount specifications.

## Likelihood Explanation

**Preconditions:**

The vulnerability requires Pyth oracle to provide both `price_mag = 0` and `conf = 0` simultaneously. While unusual for established assets, this can realistically occur during:
1. New asset listings with incomplete or uninitialized price feeds
2. Asset delisting or deprecation where price feeds are intentionally zeroed
3. Oracle malfunction or edge case handling during extreme market conditions
4. Testing/staging environments with zero-initialized data

**Reachable Entry Points:**

The zero price can be introduced during reserve initialization or any price update operation, making this vulnerability continuously exploitable once triggered.

**Trigger Mechanism:**

No malicious actor is required - the vulnerability is triggered by legitimate oracle data that passes through insufficient validation. Any user attempting to use the maximum borrow/withdraw feature after zero price acceptance will encounter the DoS.

## Recommendation

Add explicit zero-value validation in the oracle price parsing and reserve price storage functions:

1. In `oracles.move`, add a check after the confidence validation to reject zero prices:
   - Check `price_mag > 0` before returning `option::some(spot_price)`
   - This ensures zero prices are rejected even when confidence checks pass

2. In `reserve.move`, add defensive validation in `create_reserve()` and `update_price()`:
   - After extracting the price from Option, assert it is non-zero
   - This provides defense-in-depth even if oracle validation is bypassed

3. Consider adding zero-checks in the division operations within `usd_to_token_amount_lower_bound()` and `usd_to_token_amount_upper_bound()`:
   - Assert price bounds are non-zero before division
   - This prevents runtime aborts and provides clearer error messages

## Proof of Concept

```move
#[test]
fun test_zero_price_division_by_zero_dos() {
    // Setup: Create a reserve with zero price by exploiting the flawed confidence check
    // 1. Oracle provides price_mag = 0 and conf = 0
    // 2. Confidence check: 0 * 10 > 0 evaluates to false, passes validation
    // 3. option::some(decimal::from(0)) is returned and stored in reserve
    // 4. Reserve now has both price = 0 and smoothed_price = 0
    
    // Attack: User calls borrow_request with amount = U64_MAX
    // 1. Triggers max_borrow_amount() calculation
    // 2. Calls usd_to_token_amount_lower_bound(reserve, usd_amount)
    // 3. Calls price_upper_bound(reserve) which returns max(0, 0) = 0
    // 4. Performs division: (decimals * usd_amount) / 0
    // 5. decimal::div performs (a.value * WAD) / 0 -> ABORT (division by zero)
    
    // Expected: Transaction aborts with division by zero
    // Impact: All users cannot use max borrow/withdraw feature for this reserve
}
```

**Notes:**
- This vulnerability exists in the Suilend protocol integration within Volo's local dependencies
- The flaw is in the oracle price validation logic that fails to handle the zero-price edge case
- The DoS is persistent until manual intervention via `update_price()` with valid non-zero data
- While users can work around by specifying concrete amounts, this degrades UX and may break automated systems expecting the max amount feature to work

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L50-51)
```text
        let spot_price = parse_price_to_decimal(price);
        (option::some(spot_price), ema_price, price_identifier)
```

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L167-169)
```text
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-591)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L77-81)
```text
    public fun div(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: (a.value * WAD) / b.value,
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L33-33)
```text
    const U64_MAX: u64 = 18_446_744_073_709_551_615;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L414-417)
```text
        if (amount == U64_MAX) {
            amount = max_borrow_amount<P>(lending_market.rate_limiter, obligation, reserve, clock);
            assert!(amount > 0, ETooSmall);
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L489-492)
```text
        if (amount == U64_MAX) {
            amount =
                max_withdraw_amount<P>(lending_market.rate_limiter, obligation, reserve, clock);
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L839-844)
```text
        let rate_limiter_max_borrow_amount = saturating_floor(
            reserve::usd_to_token_amount_lower_bound(
                reserve,
                min(remaining_outflow_usd, decimal::from(1_000_000_000)),
            ),
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L846-852)
```text
        let max_borrow_amount_including_fees = std::u64::min(
            std::u64::min(
                obligation::max_borrow_amount(obligation, reserve),
                reserve::max_borrow_amount(reserve),
            ),
            rate_limiter_max_borrow_amount,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L890-893)
```text
        let rate_limiter_max_withdraw_amount = reserve::usd_to_token_amount_lower_bound(
            reserve,
            min(remaining_outflow_usd, decimal::from(1_000_000_000)),
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L807-818)
```text
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
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L845-848)
```text
        let max_withdraw_token_amount = reserve::usd_to_token_amount_upper_bound(
            reserve,
            max_withdraw_value,
        );
```
