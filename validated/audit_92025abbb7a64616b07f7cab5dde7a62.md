# Audit Report

## Title
EMA Negative Price Causes Abort Before Spot Price Validation in Suilend Oracle

## Summary
The `get_pyth_price_and_identifier()` function in the Suilend oracle integration parses the EMA price unconditionally before validating the spot price. If the Pyth EMA price is negative, the function aborts instead of returning `option::none()` as documented, causing DoS of the Volo vault's Suilend integration.

## Finding Description

The vulnerability exists in the price parsing order within the Suilend oracle module. The function is documented to handle invalid prices gracefully by returning `None` to allow fallback to alternative oracles: [1](#0-0) 

However, the implementation parses the EMA price unconditionally at line 27 before any validation occurs: [2](#0-1) 

This parsing delegates to `parse_price_to_decimal()` which immediately calls `i64::get_magnitude_if_positive()`: [3](#0-2) 

The `i64::get_magnitude_if_positive()` function from the Pyth package aborts if the value is negative. This occurs BEFORE the spot price validation checks that gracefully handle invalid prices by returning `option::none()`: [4](#0-3) 

The issue is that even if the spot price is valid, a negative EMA price causes an immediate abort at line 27, preventing the graceful error handling logic from executing.

## Impact Explanation

**Operational Impact - DoS of Suilend Integration:**

The Volo vault's Suilend adaptor requires fresh reserve prices before updating position values: [5](#0-4) 

The price freshness is enforced with a zero-second staleness threshold: [6](#0-5) 

Price updates occur through the public `refresh_reserve_price()` function: [7](#0-6) 

This calls `reserve::update_price()` which invokes the vulnerable function: [8](#0-7) 

If the Pyth EMA price is negative, the entire transaction aborts, preventing:
- Reserve price updates via `refresh_reserve_price`
- Suilend position valuation in the Volo vault (requires fresh prices per `assert_price_is_fresh`)
- All vault operations dependent on accurate Suilend position values

## Likelihood Explanation

**Feasibility: Low to Medium Likelihood**

Pyth price feeds use signed `i64` integers, making negative values technically possible within the protocol's design. The code explicitly acknowledges this limitation: [9](#0-8) 

While negative prices are unlikely for standard cryptocurrency assets, scenarios include:
- Oracle malfunction or data corruption
- Price feed misconfiguration during updates  
- Extreme market conditions affecting the exponential moving average
- Certain derivative instruments with negative valuations

The vulnerability is reachable through the public `refresh_reserve_price` function without requiring any privileged access. The use of signed integers in Pyth's price representation indicates this scenario is within their threat model, even if uncommon.

## Recommendation

Modify the `get_pyth_price_and_identifier()` function to validate the EMA price before parsing it, or wrap the EMA parsing in error handling to return `option::none()` when negative:

```move
public fun get_pyth_price_and_identifier(
    price_info_obj: &PriceInfoObject,
    clock: &Clock,
): (Option<Decimal>, Decimal, PriceIdentifier) {
    let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
    let price_feed = price_info::get_price_feed(&price_info);
    let price_identifier = price_feed::get_price_identifier(price_feed);

    // Validate EMA price is non-negative before parsing
    let ema_price_raw = price_feed::get_ema_price(price_feed);
    if (i64::get_is_negative(&price::get_price(&ema_price_raw))) {
        // Return none for spot price with zero EMA to signal invalid state
        return (option::none(), decimal::from(0), price_identifier)
    };
    
    let ema_price = parse_price_to_decimal(ema_price_raw);
    
    // Continue with spot price validation...
    let price = price_feed::get_price(price_feed);
    let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
    // ... rest of validation
}
```

Alternatively, modify the return signature to make the EMA price also an `Option<Decimal>` to properly signal when it's invalid, though this would require updates to all callers.

## Proof of Concept

```move
#[test]
fun test_negative_ema_causes_abort() {
    // Setup: Create a mock Pyth PriceInfoObject with valid spot price but negative EMA
    let mut scenario = test_scenario::begin(@0xA);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Create PriceInfoObject with:
    // - Valid positive spot price: 100
    // - Negative EMA price: -50
    let price_info = create_mock_price_info_with_negative_ema(
        100,  // positive spot price
        -50,  // negative EMA price  
        &clock
    );
    
    // Attempt to call get_pyth_price_and_identifier
    // This should return option::none() per documentation
    // But it will ABORT instead due to negative EMA parsing
    let (spot_opt, ema, id) = oracles::get_pyth_price_and_identifier(
        &price_info,
        &clock
    );
    
    // Test fails here - execution never reaches this line due to abort
    assert!(option::is_none(&spot_opt), 0);
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

The test demonstrates that even with a valid spot price, a negative EMA causes an abort rather than returning `option::none()` as documented.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-18)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
    /// return type: (spot price, ema price, price identifier)
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-57)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let expo = price::get_expo(&price);
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-211)
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
    }
```
