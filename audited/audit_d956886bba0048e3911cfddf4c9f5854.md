### Title
EMA Negative Price Causes Abort Before Spot Price Validation in Suilend Oracle

### Summary
The `get_pyth_price_and_identifier()` function parses the EMA price unconditionally at line 27 before validating the spot price. If the Pyth EMA price is negative, the function aborts via `i64::get_magnitude_if_positive()` instead of returning `option::none()`, violating the documented graceful error handling behavior and causing DoS of Volo vault's Suilend integration.

### Finding Description

The vulnerability exists in the price parsing order within `get_pyth_price_and_identifier()`: [1](#0-0) 

The EMA price is parsed unconditionally at line 27 before any validation occurs. This parsing calls `parse_price_to_decimal()`: [2](#0-1) 

The `parse_price_to_decimal()` function immediately calls `i64::get_magnitude_if_positive()` at line 56, which aborts if the price value is negative. This occurs BEFORE the spot price validation checks that handle invalid prices gracefully: [3](#0-2) [4](#0-3) 

The function documentation explicitly states it should handle invalid prices gracefully: [5](#0-4) 

However, a negative EMA price causes an abort instead of returning `option::none()`, preventing the caller from falling back to alternative oracles as intended.

### Impact Explanation

**Operational Impact - DoS of Suilend Integration:**

When the Volo vault updates Suilend position values, it requires fresh reserve prices: [6](#0-5) 

The price refresh flow calls `reserve::update_price()`: [7](#0-6) 

Which in turn calls the vulnerable `get_pyth_price_and_identifier()`: [8](#0-7) 

If the Pyth EMA price is negative, the entire chain aborts, preventing:
- Reserve price updates via `refresh_reserve_price`
- Suilend position valuation in the Volo vault
- All Suilend operations requiring fresh prices
- Normal vault operations dependent on accurate Suilend position values

The EMA price (smoothed_price) is critical for risk calculations: [9](#0-8) 

### Likelihood Explanation

**Feasibility: Low to Medium Likelihood**

Pyth price feeds use signed `i64` integers, making negative values technically possible. The code explicitly acknowledges this: [10](#0-9) 

Scenarios where negative EMA prices could occur:
- Oracle malfunction or data corruption
- Price feed misconfiguration during updates
- Certain derivative instruments with negative valuations
- Extreme market manipulation affecting the exponential moving average

While unlikely for standard cryptocurrency assets, the use of signed integers indicates this is within Pyth's threat model. The vulnerability is reachable through the public `refresh_reserve_price` function without requiring any privileged access.

### Recommendation

**Immediate Fix:**

Wrap the EMA price parsing in error handling to match the spot price behavior:

```move
public fun get_pyth_price_and_identifier(
    price_info_obj: &PriceInfoObject,
    clock: &Clock,
): (Option<Decimal>, Option<Decimal>, PriceIdentifier) {
    let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
    let price_feed = price_info::get_price_feed(&price_info);
    let price_identifier = price_feed::get_price_identifier(price_feed);

    // Check if EMA price is negative before parsing
    let ema_price_i64 = price_feed::get_ema_price(price_feed);
    let ema_price_mag = i64::get_magnitude_if_positive(&price::get_price(&ema_price_i64));
    
    // If EMA price is invalid, return none for both prices
    if (ema_price_mag == 0 && i64::get_is_negative(&price::get_price(&ema_price_i64))) {
        return (option::none(), option::none(), price_identifier)
    };
    
    let ema_price = parse_price_to_decimal(ema_price_i64);
    
    // ... rest of spot price validation
}
```

**Alternative: Validate before parsing**

Add a check for negative EMA price before calling `parse_price_to_decimal()`, returning `option::none()` for both prices to maintain consistency.

**Test Cases:**

1. Test with Pyth price feed returning negative EMA price
2. Verify graceful degradation and fallback oracle activation
3. Test reserve price update with invalid EMA price
4. Validate Volo vault operations continue with fallback prices

### Proof of Concept

**Initial State:**
- Volo vault holds Suilend positions
- Suilend reserve configured with Pyth price feed
- Pyth oracle returns valid spot price but negative EMA price

**Exploitation Steps:**

1. Pyth oracle updates price feed with:
   - Spot price: positive value (e.g., $100)
   - EMA price: negative value (e.g., -$1 due to oracle error)

2. Operator calls `lending_market::refresh_reserve_price()` to update reserve prices before vault operations

3. Execution flow:
   - `refresh_reserve_price()` → `reserve::update_price()`
   - `update_price()` → `oracles::get_pyth_price_and_identifier()`
   - Line 27: `parse_price_to_decimal(ema_price)` called
   - Line 56: `i64::get_magnitude_if_positive()` aborts due to negative EMA price

**Expected Result:**
Function should return `option::none()` for invalid prices, allowing graceful error handling and fallback to alternative oracles.

**Actual Result:**
Transaction aborts, preventing all Suilend reserve price updates and breaking Volo vault's ability to value Suilend positions. All operations requiring fresh Suilend prices fail until oracle data is corrected.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-17)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L27-27)
```text
        let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L30-38)
```text
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let conf = price::get_conf(&price);

        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L43-48)
```text
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-56)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L12-19)
```text
// @dev Need to update the price of the reserve before calling this function
//      Update function: lending_market::refresh_reserve_price
//          public fun refresh_reserve_price<P>(
//              lending_market: &mut LendingMarket<P>,
//              reserve_array_index: u64,
//              clock: &Clock,
//              price_info: &PriceInfoObject,
//           )
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-210)
```text
    public fun refresh_reserve_price<P>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
        price_info: &PriceInfoObject,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        reserve::update_price<P>(reserve, clock, price_info);
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-588)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```
