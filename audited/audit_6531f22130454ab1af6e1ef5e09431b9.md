# Audit Report

## Title
Vault Lockup via Zero Pyth Price in Suilend Position Valuation

## Summary
When Pyth oracle returns a zero price for any Suilend reserve asset, the Suilend oracle price parsing fails, preventing Suilend position value updates. This blocks vault operations from completing their mandatory value update phase, causing indefinite vault lockup in DURING_OPERATION status with no admin recovery mechanism.

## Finding Description

**Root Cause:**

The Suilend oracle parser calls `i64::get_magnitude_if_positive()` to extract price magnitudes from Pyth price feeds. [1](#0-0)  This function is called again during decimal parsing. [2](#0-1) 

When Pyth returns a zero price, the oracle parsing either panics or returns `option::none()` for the spot price. The subsequent assertion then fails. [3](#0-2)  This prevents `refresh_reserve_price` from completing successfully.

**Exploitation Path:**

1. Vault operations follow a strict three-step lifecycle where the vault status is set to DURING_OPERATION. [4](#0-3) 

2. The Suilend adaptor documentation explicitly requires calling `lending_market::refresh_reserve_price()` before updating position values. [5](#0-4) 

3. After returning borrowed assets, operators enable value updates. [6](#0-5) 

4. Before completing operations, the vault strictly enforces that ALL borrowed asset values have been updated. [7](#0-6)  This check is called during the final operation step. [8](#0-7) 

5. If the price refresh fails due to zero Pyth price, position values cannot be updated, and the vault cannot complete the operation, leaving it stuck before the status reset. [9](#0-8) 

**Why Existing Protections Fail:**

The Suilend oracle code includes confidence ratio and staleness checks, but these checks occur AFTER the calls to `get_magnitude_if_positive()` that fail on zero prices. [10](#0-9)  There is no zero-price validation before the problematic function calls.

## Impact Explanation

**Vault Lockup:**

When a vault enters DURING_OPERATION status and cannot complete value updates due to zero Pyth price, it becomes permanently locked. During this lockup:

1. All user deposit requests are blocked because deposits require NORMAL status. [11](#0-10) 

2. All user withdrawal requests are blocked because withdrawals require NORMAL status. [12](#0-11) 

3. Deposit cancellations are blocked because they require NOT during operation. [13](#0-12) 

4. Withdrawal cancellations are blocked because they require NORMAL status. [14](#0-13) 

**No Admin Recovery:**

The admin cannot manually reset vault status because `set_enabled` explicitly prevents status changes during operations. [15](#0-14)  There are no emergency override functions to bypass this restriction.

**Affected Parties:**
- All vault depositors cannot withdraw their funds
- New users cannot deposit
- Pending requests cannot be cancelled
- Vault remains frozen until the external Pyth oracle recovers
- If the Pyth feed is permanently deprecated or broken, vault funds are permanently locked

## Likelihood Explanation

**Realistic Feasibility:**

1. **No Attacker Required:** Pyth oracles can naturally return zero prices during network outages, extreme market conditions, oracle maintenance, or feed deprecation. This is a documented characteristic of oracle systems.

2. **Natural Occurrence:** The inclusion of confidence ratio and staleness checks in the Suilend oracle code demonstrates awareness that Pyth feeds can have quality issues. Zero prices fall into this category but lack specific handling.

3. **Reachable Entry Point:** Any vault using Suilend positions (a core DeFi integration) is vulnerable during routine operator-performed operations.

4. **No Economic Barrier:** The vulnerability triggers through normal operational flow, requiring no special attacker capabilities or capital investment.

5. **Permanent Lock Risk:** If a Pyth price feed becomes deprecated or permanently stuck at zero, the vault has no recovery mechanism, leading to permanent fund lockup for all users.

## Recommendation

Implement zero-price validation in the Suilend oracle parser before calling `get_magnitude_if_positive()`:

```move
public fun get_pyth_price_and_identifier(
    price_info_obj: &PriceInfoObject,
    clock: &Clock,
): (Option<Decimal>, Decimal, PriceIdentifier) {
    let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
    let price_feed = price_info::get_price_feed(&price_info);
    let price_identifier = price_feed::get_price_identifier(price_feed);
    
    let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));
    
    let price = price_feed::get_price(price_feed);
    
    // ADD: Check for zero/negative price before calling get_magnitude_if_positive
    if (!i64::is_positive(&price::get_price(&price))) {
        return (option::none(), ema_price, price_identifier)
    };
    
    let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
    // ... rest of function
}
```

Additionally, add an admin emergency function to reset vault status with appropriate safeguards:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Admin can force reset to NORMAL in emergency situations
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

## Proof of Concept

The vulnerability can be demonstrated through the following sequence:

1. Deploy a vault with Suilend obligation positions as DeFi assets
2. Start a vault operation (status becomes DURING_OPERATION)
3. Simulate Pyth oracle returning zero price for a Suilend reserve asset
4. Attempt to call `refresh_reserve_price()` → transaction aborts
5. Attempt to complete operation with `end_op_value_update_with_bag()` → fails due to incomplete value updates
6. Attempt admin `set_vault_enabled()` → blocked by line 523 assertion
7. Attempt user deposit/withdraw → blocked by NORMAL status requirements
8. Vault remains permanently locked in DURING_OPERATION status

The proof demonstrates that once the vault enters DURING_OPERATION and encounters a zero Pyth price, there is no code path to recovery without external oracle intervention.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L30-30)
```text
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L33-48)
```text
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
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L56-56)
```text
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-588)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
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

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L769-769)
```text
    self.assert_not_during_operation();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L952-952)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1215-1217)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
```
