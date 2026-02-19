### Title
Decimal Underflow in Pyth Price Parsing Causes Reserve DoS

### Summary
The `parse_price_to_decimal()` function in the Suilend oracle module can round extremely small prices to zero due to integer division truncation when converting Pyth prices with large negative exponents. Zero prices propagate through the system unchecked and cause division-by-zero aborts in critical reserve operations, rendering affected reserves unusable for borrowing and withdrawing.

### Finding Description

The vulnerability exists in the Pyth price parsing logic: [1](#0-0) 

When the exponent is negative (representing very small prices), the function performs:
```
(price_mag * 1e18) / 10^|expo|
```

For this division to round to zero: `price_mag < 10^(|expo| - 18)`

**Example scenarios:**
- price_mag = 1, expo = -19: (1 × 10^18) / 10^19 = 0.1 → rounds to 0
- price_mag = 99, expo = -20: (99 × 10^18) / 10^20 = 0.99 → rounds to 0
- Minimum non-zero: price_mag = 1, expo = -18: (1 × 10^18) / 10^18 = 1

The Decimal type uses 18 decimal places of precision: [2](#0-1) 

**No validation prevents zero prices:**

The `get_pyth_price_and_identifier` function performs confidence and staleness checks but never validates against zero: [3](#0-2) 

Critically, the EMA price (line 27) is always parsed and returned without any validation. The spot price is only rejected if confidence or staleness checks fail, not if it equals zero.

**Division by zero occurs in critical operations:**

Zero prices cause aborts when used in USD-to-token conversions: [4](#0-3) 

These functions use `price_lower_bound` and `price_upper_bound`: [5](#0-4) 

When either price (spot or EMA) is zero, `price_lower_bound` returns zero. The `div` function then performs division by zero: [6](#0-5) 

With `b.value = 0`, this causes a Move VM abort.

**Affected operations:**

1. **Obligation borrow limits:** [7](#0-6) 

2. **Obligation withdrawal limits:** [8](#0-7) 

3. **Rate limiter calculations:** [9](#0-8) 

4. **Volo vault Suilend position valuation:** [10](#0-9) 

The adaptor calls `reserve::ctoken_market_value` and `reserve::market_value` which depend on the reserve's price field set through the vulnerable parsing function.

### Impact Explanation

**Operational DoS Impact:**
- Any reserve with a zero price becomes completely unusable for lending operations
- All attempts to calculate max borrow/withdraw amounts abort with division by zero
- Rate limiters fail, preventing any borrowing or withdrawing regardless of limits
- Volo vault's Suilend position updates fail, preventing vault operations that depend on Suilend asset valuation

**Affected parties:**
- Users with positions in the affected reserve cannot borrow or withdraw
- Volo vault operators cannot update positions or execute operations involving the affected Suilend reserve
- Liquidators cannot liquidate underwater positions if any collateral or debt uses the affected reserve

**Severity justification:**
Medium severity - this is a reserve-level DoS (not protocol-wide) that requires specific price conditions but has severe operational impact when triggered. The reserve becomes completely frozen for all lending activity.

### Likelihood Explanation

**Trigger conditions:**
- Requires Pyth to report price_mag and expo such that `price_mag < 10^(|expo| - 18)`
- Example: price_mag = 1 with expo = -19 or more negative
- This represents prices below 10^-18 USD (0.000000000000000001 USD)

**Realistic scenarios:**
1. **Microcap tokens**: Tokens with extremely low USD values could legitimately have such prices
2. **Crashed tokens**: Tokens experiencing hyperinflationary collapse or total devaluation
3. **New token listings**: Initial price discovery might produce extreme values
4. **Oracle misconfiguration**: Incorrect decimal settings or price feed errors
5. **Price feed manipulation**: Malicious or compromised Pyth data publishers

**Attack complexity:**
- Low - no special privileges required
- Price updates can be called by anyone interacting with the lending market
- If Pyth reports such values, they propagate automatically

**Economic constraints:**
- No direct cost to trigger (beyond transaction fees)
- Affects protocols using tokens with extreme price characteristics
- More likely in test environments or with exotic/microcap assets

**Probability:** Low-Medium - unlikely for mainstream assets but realistic for edge cases, especially microcap tokens or misconfigured feeds.

### Recommendation

**1. Add zero-price validation in `parse_price_to_decimal`:**

Add an assertion after parsing to reject zero prices:
```move
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
    
    assert!(decimal::gt(result, decimal::from(0)), EPriceUnderflow);
    result
}
```

**2. Add validation in `get_pyth_price_and_identifier`:**

Validate both spot and EMA prices are non-zero before accepting them:
```move
let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));
assert!(decimal::gt(ema_price, decimal::from(0)), EInvalidEmaPrice);

// ... existing checks ...

let spot_price = parse_price_to_decimal(price);
assert!(decimal::gt(spot_price, decimal::from(0)), EInvalidSpotPrice);
```

**3. Add minimum price threshold:**

Define a reasonable minimum price (e.g., 10^-15 USD) and reject prices below this threshold to prevent extreme edge cases.

**4. Test cases:**

Add regression tests for:
- Price with expo = -19, mag = 1 (should be rejected)
- Price with expo = -20, mag = 100 (should be rejected)
- Price with expo = -18, mag = 1 (minimum valid price)
- Mixed scenario: spot price valid, EMA price zero (should be rejected)

### Proof of Concept

**Initial state:**
- Suilend reserve exists for a microcap token
- Pyth price feed reports: price_mag = 1, expo = -19

**Exploitation steps:**

1. **Price update triggers underflow:**
   - Call `lending_market::refresh_reserve_price` or `reserve::update_price`
   - Pyth data: price_mag = 1, expo = -19
   - `parse_price_to_decimal` computes: (1 × 10^18) / 10^19 = 0
   - Zero price stored in `reserve.price` or `reserve.smoothed_price`

2. **Attempt to borrow:**
   - Call `lending_market::borrow`
   - Internally calls `obligation::max_borrow_amount`
   - Calls `reserve::usd_to_token_amount_lower_bound`
   - Divides by `price_upper_bound(reserve)` which is 0
   - **Result: Transaction aborts with arithmetic error**

3. **Attempt to withdraw:**
   - Call `lending_market::withdraw`
   - Internally calls `obligation::max_withdraw_amount`
   - Calls `reserve::usd_to_token_amount_upper_bound`
   - Divides by `price_lower_bound(reserve)` which is 0
   - **Result: Transaction aborts with arithmetic error**

4. **Volo vault operation fails:**
   - Call `suilend_adaptor::update_suilend_position_value`
   - Calls `reserve::assert_price_is_fresh` (passes)
   - Calls `reserve::ctoken_market_value` or `reserve::market_value`
   - If any subsequent operation needs USD conversions, it aborts
   - **Result: Vault cannot update Suilend position values**

**Expected vs Actual:**
- **Expected:** Price parsing should either represent the actual value correctly or reject invalid prices
- **Actual:** Zero price is accepted and causes all subsequent reserve operations to abort with division by zero

**Success condition:** Reserve becomes unusable - all borrow/withdraw operations abort, demonstrating complete DoS of the reserve's lending functionality.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L19-52)
```text
    public fun get_pyth_price_and_identifier(
        price_info_obj: &PriceInfoObject,
        clock: &Clock,
    ): (Option<Decimal>, Decimal, PriceIdentifier) {
        let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
        let price_feed = price_info::get_price_feed(&price_info);
        let price_identifier = price_feed::get_price_identifier(price_feed);

        let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));

        let price = price_feed::get_price(price_feed);
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let conf = price::get_conf(&price);

        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };

        // check current sui time against pythnet publish time. there can be some issues that arise because the
        // timestamps are from different sources and may get out of sync, but that's why we have a fallback oracle
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };

        let spot_price = parse_price_to_decimal(price);
        (option::some(spot_price), ema_price, price_identifier)
    }
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L1-9)
```text
/// fixed point decimal representation. 18 decimal places are kept.
module suilend::decimal {
    // 1e18
    const WAD: u256 = 1000000000000000000;
    const U64_MAX: u256 = 18446744073709551615;

    public struct Decimal has copy, drop, store {
        value: u256,
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L253-259)
```text
    public fun price_lower_bound<P>(reserve: &Reserve<P>): Decimal {
        min(reserve.price, reserve.smoothed_price)
    }

    public fun price_upper_bound<P>(reserve: &Reserve<P>): Decimal {
        max(reserve.price, reserve.smoothed_price)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L340-364)
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L822-850)
```text
    public(package) fun max_withdraw_amount<P>(
        obligation: &Obligation<P>,
        reserve: &Reserve<P>,
    ): u64 {
        let deposit_index = find_deposit_index(obligation, reserve);
        assert!(deposit_index < vector::length(&obligation.deposits), EDepositNotFound);

        let deposit = vector::borrow(&obligation.deposits, deposit_index);

        if (
            open_ltv(config(reserve)) == decimal::from(0) || vector::length(&obligation.borrows) == 0
        ) {
            return deposit.deposited_ctoken_amount
        };

        let max_withdraw_value = div(
            saturating_sub(
                obligation.allowed_borrow_value_usd,
                obligation.weighted_borrowed_value_upper_bound_usd,
            ),
            open_ltv(config(reserve)),
        );

        let max_withdraw_token_amount = reserve::usd_to_token_amount_upper_bound(
            reserve,
            max_withdraw_value,
        );

        floor(
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L42-89)
```text
public(package) fun parse_suilend_obligation<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &LendingMarket<ObligationType>,
    clock: &Clock,
): u256 {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());

    let mut total_deposited_value_usd = 0;
    let mut total_borrowed_value_usd = 0;
    let reserves = lending_market.reserves();

    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

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
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```
