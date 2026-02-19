# Audit Report

## Title
Vault Lockup via Invalid Pyth Price in Suilend Position Valuation

## Summary
When Pyth oracle returns zero or invalid price data for any Suilend reserve asset, the Suilend price refresh mechanism fails, preventing vault operators from completing mandatory asset value updates. This causes indefinite vault lockup in DURING_OPERATION status with no admin recovery path, blocking all user deposits, withdrawals, and request cancellations until the external Pyth feed recovers.

## Finding Description

The vulnerability stems from a critical design flaw in how Suilend oracle parsing interacts with Volo vault operation lifecycle enforcement.

**Root Cause**: The Suilend oracle parser attempts to extract positive price magnitude before performing validity checks: [1](#0-0) [2](#0-1) 

When Pyth returns zero/invalid prices, this causes transaction abort BEFORE the function's graceful error handling (returning `None`) can execute: [3](#0-2) 

**Exploitation Path**:

1. Vault operator initiates operation with Suilend positions as borrowed assets
2. Operator must refresh Suilend reserve prices via `lending_market::refresh_reserve_price`: [4](#0-3) 

3. This calls through to the flawed oracle parser: [5](#0-4) [6](#0-5) 

4. When price refresh fails, the Suilend position value cannot be updated via `finish_update_asset_value`: [15](#0-14) 

5. The vault operation lifecycle STRICTLY ENFORCES that all borrowed assets must have updated values before completion: [7](#0-6) [16](#0-15) 

6. Only after passing this mandatory check can vault status be reset to NORMAL: [10](#0-9) 

**Why Recovery is Impossible**:

Admin cannot manually reset vault status because `set_enabled` explicitly blocks changes during operations: [11](#0-10) 

**User Impact**:

All user operations require NORMAL vault status:

**Deposits blocked**: [17](#0-16) 

**Withdrawals blocked**: [18](#0-17) 

**Cancellations blocked**: [19](#0-18) [20](#0-19) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes complete vault denial-of-service with fund lockup:

1. **Complete User Lockout**: All depositors cannot withdraw funds, new users cannot deposit, and pending requests cannot be cancelled
2. **No Admin Override**: The protocol design intentionally prevents status changes during operations (to maintain integrity), but this same protection becomes a trap when operations cannot complete
3. **External Dependency Risk**: Vault availability depends entirely on external Pyth oracle health
4. **Permanent Lock Scenario**: If a Pyth price feed is permanently deprecated or stuck, the vault funds become permanently inaccessible with no protocol-level recovery mechanism

The impact is not theoretical fund loss but guaranteed operational freeze affecting all vault participants.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

1. **No Attacker Required**: Pyth oracles naturally experience downtime, price anomalies, or maintenance periods. Zero/invalid prices are documented behaviors during extreme market conditions or network partitions.

2. **Evidence of Oracle Awareness**: The Suilend code includes confidence ratio checks and staleness validation, demonstrating the developers anticipated oracle quality issues. However, the implementation has an ordering flaw where panic-inducing calls execute before protective logic.

3. **Direct Exposure**: Any vault holding Suilend positions (a core DeFi integration strategy) is vulnerable during routine operations.

4. **No Economic Barrier**: The vulnerability triggers through normal operational workflow requiring no special capabilities or capital.

5. **Real-World Precedent**: Oracle failures causing protocol disruptions are well-documented across DeFi ecosystems.

## Recommendation

**Immediate Fix**: Add zero-price validation BEFORE calling `get_magnitude_if_positive`:

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
    
    // ADD THIS CHECK FIRST
    if (i64::get_is_negative(&price::get_price(&price)) || price::get_price(&price) == i64::zero()) {
        return (option::none(), ema_price, price_identifier)
    };
    
    let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
    // ... rest of function
}
```

**Secondary Fix**: Add admin emergency recovery function for vault status reset (with appropriate governance controls and multi-sig requirements).

**Long-term Fix**: Implement fallback oracle mechanisms or circuit breakers for handling external oracle failures gracefully.

## Proof of Concept

```move
#[test]
fun test_vault_lockup_via_zero_pyth_price() {
    // Setup: Create vault with Suilend position
    let scenario = test_scenario::begin(@0x1);
    let vault = create_test_vault(&mut scenario);
    let suilend_position = create_suilend_obligation(&mut scenario);
    
    // Step 1: Start operation and borrow Suilend position
    let (assets, tx, tx_check, _, _) = operation::start_op_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[SUILEND_ASSET_ID],
        vector[type_name::get<SuilendObligationOwnerCap>()],
        0,
        0,
        &mut scenario.ctx()
    );
    
    // Step 2: Return assets
    operation::end_op_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        assets,
        tx,
        balance::zero(),
        balance::zero()
    );
    
    // Step 3: Attempt to refresh Suilend price with ZERO Pyth price
    let zero_price_info = create_pyth_price_info_with_zero_price(); // Helper creates Pyth object with price=0
    
    // This WILL ABORT, preventing value update
    lending_market::refresh_reserve_price(
        &mut lending_market,
        0, // reserve_index
        &clock,
        &zero_price_info  // ZERO PRICE
    ); // <- TRANSACTION ABORTS HERE
    
    // Step 4: Cannot complete operation because value update failed
    // This line is unreachable due to above abort
    operation::end_op_value_update_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        tx_check
    ); // Would fail with ERR_USD_VALUE_NOT_UPDATED even if reached
    
    // Result: Vault permanently stuck in DURING_OPERATION status
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, 0);
    
    // All user operations now fail
    let deposit_result = user_entry::deposit(&mut vault, ...); // FAILS: ERR_VAULT_NOT_NORMAL
    let withdraw_result = user_entry::withdraw(&mut vault, ...); // FAILS: ERR_VAULT_NOT_NORMAL
    
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L30-31)
```text
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let conf = price::get_conf(&price);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L33-38)
```text
        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L56-56)
```text
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L39-39)
```text
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L707-716)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L761-769)
```text
public(package) fun cancel_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): Coin<PrincipalCoinType> {
    self.check_version();
    self.assert_not_during_operation();
```

**File:** volo-vault/sources/volo_vault.move (L896-905)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L951-952)
```text
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1206-1218)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```
