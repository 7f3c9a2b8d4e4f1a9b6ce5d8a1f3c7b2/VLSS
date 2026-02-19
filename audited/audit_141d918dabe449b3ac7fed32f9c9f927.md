### Title
Zero Price Acceptance Due to Flawed Confidence Check Causes Division-by-Zero DoS in Lending Operations

### Summary
The confidence interval check in `get_pyth_price_and_identifier()` allows zero prices to pass validation when both `price_mag` and `conf` are zero, violating the intended protection. This zero price propagates to reserve storage and causes transaction aborts when downstream functions attempt division operations, resulting in a complete DoS of critical lending operations including borrowing and withdrawals.

### Finding Description

**Root Cause**:
The confidence check at [1](#0-0)  evaluates `conf * MIN_CONFIDENCE_RATIO > price_mag`. When both `price_mag = 0` and `conf = 0`, this becomes `0 * 10 > 0`, which evaluates to `false`, causing the check to pass rather than reject the invalid zero price.

The EMA price is parsed without any validation [2](#0-1) , so if it's also zero, both `price` and `smoothed_price` will be zero.

**Why Existing Protections Fail**:
The only downstream validation checks whether the Option contains a value, not whether that value is zero [3](#0-2)  and [4](#0-3) . A zero `Decimal` value passes the `option::is_some()` check.

**Execution Path to DoS**:
1. Zero price stored in reserve: [5](#0-4) 
2. Division-by-zero occurs in `usd_to_token_amount_lower_bound()` [6](#0-5)  and `usd_to_token_amount_upper_bound()` [7](#0-6) , which divide by `price_upper_bound()` and `price_lower_bound()` respectively
3. The `div()` function performs raw division [8](#0-7)  causing Move runtime abort on zero divisor

**Critical Call Sites**:
- `reserve::max_borrow_amount()` [9](#0-8) 
- `lending_market::max_borrow_amount()` [10](#0-9) 
- `lending_market::max_withdraw_amount()` [11](#0-10) 
- `obligation::max_borrow_amount()` [12](#0-11) 
- `obligation::max_withdraw_amount()` [13](#0-12) 

### Impact Explanation

**Operational Impact - Complete DoS of Lending Protocol**:
Once a reserve accepts a zero price, all operations that calculate maximum borrow or withdraw amounts will abort with division-by-zero errors. This affects:
- **Borrow operations**: Users cannot borrow from the affected reserve
- **Withdrawal operations**: Users cannot withdraw deposited assets
- **Liquidations**: Liquidators cannot calculate proper amounts
- **Rate limiting**: Rate limiter calculations fail

The DoS persists until the price is updated to a non-zero value via `update_price()`. All users with positions in the affected reserve are unable to perform critical operations, effectively locking their funds until price recovery.

**Severity**: High - Complete operational disruption of lending functionality for an entire reserve, affecting all users with positions in that asset.

### Likelihood Explanation

**Feasible Preconditions**:
The vulnerability requires a Pyth oracle to provide both `price_mag = 0` and `conf = 0`. While unusual, this can occur in several realistic scenarios:
1. Asset becomes economically worthless (price legitimately drops to zero)
2. Pyth feed malfunction or edge case handling
3. New asset listing with incomplete price data
4. Testing/staging environment with zero-initialized feeds

**Reachable Entry Points**:
- `create_reserve()` during reserve initialization [14](#0-13) 
- `update_price()` for periodic price updates [15](#0-14) 

**Attacker Capabilities**:
No special attacker privileges required - the vulnerability is triggered by legitimate oracle data. Any user calling borrow/withdraw operations after a zero price is accepted will experience the DoS.

**Detection/Operational Constraints**:
The issue would be immediately apparent once triggered as all affected operations would fail. However, the damage (operational disruption) occurs instantly and persists until manual intervention.

### Recommendation

**Code-Level Mitigation**:
Add explicit zero price validation in `get_pyth_price_and_identifier()`:

```move
// After line 31, before the confidence check:
if (price_mag == 0) {
    return (option::none(), ema_price, price_identifier)
};
```

**Additional Protection**:
Add zero price validation in `create_reserve()` and `update_price()`:

```move
// After extracting price_decimal:
let extracted_price = option::extract(&mut price_decimal);
assert!(!decimal::eq(extracted_price, decimal::from(0)), EInvalidPrice);
```

**Invariant Checks**:
Ensure that `reserve.price > 0` and `reserve.smoothed_price > 0` at all times after reserve creation.

**Test Cases**:
1. Test that zero price with zero confidence is rejected
2. Test that zero price with non-zero confidence is rejected  
3. Test that non-zero price with any confidence passes validation
4. Test that price update rejects zero prices
5. Integration test ensuring borrow/withdraw operations cannot be called with zero prices

### Proof of Concept

**Required Initial State**:
1. Suilend lending market deployed
2. Pyth oracle providing a price feed with `price = 0` and `conf = 0`
3. Reserve being created or updated for an asset

**Transaction Sequence**:
1. Admin calls `create_reserve()` or operator calls `update_price()` with the zero-price Pyth feed
2. Oracle check at line 36 evaluates: `0 * 10 > 0` → `false` → check passes
3. Zero price stored in `reserve.price` and `reserve.smoothed_price`
4. User attempts to call `borrow()` or `withdraw_ctokens()` 
5. Internal call to `max_borrow_amount()` or `max_withdraw_amount()`
6. Function calls `usd_to_token_amount_lower_bound()` or similar
7. Division by zero in `div()` function causes transaction abort

**Expected vs Actual Result**:
- **Expected**: Zero prices should be rejected by confidence check and never stored
- **Actual**: Zero prices pass validation when confidence is also zero, causing downstream DoS

**Success Condition**:
The vulnerability is confirmed if a reserve can be initialized or updated with zero price, and subsequent borrow/withdraw operations abort with division-by-zero errors.

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L157-165)
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
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L168-168)
```text
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L178-179)
```text
            price: option::extract(&mut price_decimal),
            smoothed_price: smoothed_price_decimal,
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-585)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L588-588)
```text
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L77-81)
```text
    public fun div(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: (a.value * WAD) / b.value,
        }
    }
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
