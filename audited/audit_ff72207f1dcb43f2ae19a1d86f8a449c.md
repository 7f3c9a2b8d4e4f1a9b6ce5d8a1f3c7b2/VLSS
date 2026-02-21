# Audit Report

## Title
Design-Implementation Mismatch in Suilend Oracle Handling Causes DOS of Vault Operations with Suilend Positions

## Summary
The Suilend oracle module's `get_pyth_price_and_identifier()` function is designed to return `None` for graceful fallback when oracle quality degrades, but callers in `reserve.move` abort with `EInvalidPrice` instead of implementing fallback logic. This blocks Suilend operations (borrow, withdraw with borrows, liquidate) and prevents Volo vaults with Suilend positions from updating position values during oracle quality degradation.

## Finding Description

The vulnerability exists in a design-implementation mismatch within the Suilend integration code:

**Oracle Design Intent:**
The `get_pyth_price_and_identifier()` function explicitly documents its design to "returns None instead of aborting so the caller can handle invalid prices gracefully by eg falling back to a different oracle" [1](#0-0) . The function returns `Option<Decimal>` and returns `None` when confidence interval exceeds 10% [2](#0-1)  or staleness exceeds 60 seconds [3](#0-2) . The comment even acknowledges "that's why we have a fallback oracle" [4](#0-3) .

**Implementation Mismatch:**
Both callers abort on `None`: In `create_reserve` [5](#0-4)  and in `update_price` [6](#0-5) , which is called via `refresh_reserve_price` [7](#0-6) .

**DOS Execution Path:**
1. When oracle quality degrades, `update_price` aborts, leaving prices stale
2. The staleness threshold is 0 seconds [8](#0-7) , so prices become stale immediately
3. `obligation::refresh` detects stale oracles [9](#0-8)  and returns `Some(ExistStaleOracles)` [10](#0-9) 
4. Borrow operations abort via `assert_no_stale_oracles` [11](#0-10) 
5. Withdraw operations with borrows abort [12](#0-11) 
6. Liquidation operations abort [13](#0-12) 
7. Volo vault operations calling `parse_suilend_obligation` abort because it requires fresh prices [14](#0-13) [15](#0-14) 

## Impact Explanation

**MEDIUM-HIGH Severity - DOS of Suilend-Integrated Vault Operations**

The impact is significant for Volo vaults with Suilend positions:

**Direct Suilend Impact:**
- Users cannot borrow additional funds
- Users with borrows cannot withdraw collateral
- Liquidators cannot liquidate unhealthy positions, creating systemic risk

**Volo Vault Impact:**
- Vaults with Suilend positions cannot update position values during operations [16](#0-15) 
- This blocks vault operations requiring accurate Suilend position valuation
- The comment explicitly documents the need to update prices before operations [17](#0-16) 

**Risk Amplification:**
The DOS occurs during high volatility when confidence intervals naturally widen and risk management is most critical. The protocol becomes non-operational until external oracle conditions improve, despite the explicit design intent for fallback handling.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood**

The DOS is triggered by natural market and network conditions without attacker involvement:

1. **Confidence Check:** The `MIN_CONFIDENCE_RATIO = 10` [18](#0-17)  requires confidence < 10% of price. During volatility, Pyth naturally reports wider confidence intervals [19](#0-18) .

2. **Staleness Check:** The `MAX_STALENESS_SECONDS = 60` [20](#0-19)  threshold can be exceeded during network congestion [21](#0-20) .

These conditions occur with sufficient frequency in DeFi operations to pose material operational risk.

## Recommendation

Implement the intended fallback logic in `reserve.move`:

1. When `get_pyth_price_and_identifier()` returns `None`, use the EMA price that is always available
2. Or implement a grace period for stale prices instead of 0-second threshold
3. Or add an alternative oracle source as the code comments suggest

The fix should honor the oracle module's design intent: handle `None` gracefully instead of aborting, allowing operations to continue with fallback pricing during temporary oracle quality degradation.

## Proof of Concept

A proof of concept would require:
1. Setting up a test environment with Pyth oracle
2. Simulating conditions where Pyth confidence interval exceeds 10% or staleness exceeds 60 seconds
3. Attempting to call `refresh_reserve_price` which will abort with `EInvalidPrice`
4. Demonstrating that subsequent Suilend operations (borrow, withdraw, liquidate) abort with `EOraclesAreStale`
5. Showing Volo vault's `update_suilend_position_value` fails due to stale price assertions

The vulnerability is architectural in nature - the mismatch between the oracle module's design (returning `None` for graceful handling) and the caller's implementation (aborting on `None`) is directly observable in the codebase without requiring runtime execution.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L12-12)
```text
    const MIN_CONFIDENCE_RATIO: u64 = 10;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-17)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L36-38)
```text
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L40-41)
```text
        // check current sui time against pythnet publish time. there can be some issues that arise because the
        // timestamps are from different sources and may get out of sync, but that's why we have a fallback oracle
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L167-168)
```text
        let (mut price_decimal, smoothed_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-588)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L405-406)
```text
        let exist_stale_oracles = obligation::refresh<P>(obligation, &mut lending_market.reserves, clock);
        obligation::assert_no_stale_oracles(exist_stale_oracles);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L529-530)
```text
        let exist_stale_oracles = obligation::refresh<P>(obligation, &mut lending_market.reserves, clock);
        obligation::assert_no_stale_oracles(exist_stale_oracles);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L189-191)
```text
            if (!reserve::is_price_fresh(deposit_reserve, clock)) {
                exist_stale_oracles = true;
            };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L284-286)
```text
        if (exist_stale_oracles) {
            return option::some(ExistStaleOracles {})
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L514-518)
```text
        if (stale_oracles.is_some() && vector::is_empty(&obligation.borrows)) {
            let ExistStaleOracles {} = option::destroy_some(stale_oracles);
        } else {
            assert_no_stale_oracles(stale_oracles);
        };
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L68-68)
```text
        borrow_reserve.assert_price_is_fresh(clock);
```
