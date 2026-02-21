# Audit Report

## Title
Vault Operations Blocked by Suilend Oracle Confidence/Staleness Check Failures

## Summary
Vault operations involving Suilend positions become permanently blocked when Pyth oracle confidence or staleness checks fail. The transaction aborts during price updates, leaving the vault locked in VAULT_DURING_OPERATION_STATUS with no admin recovery mechanism, freezing all user deposits and withdrawals until oracle conditions improve.

## Finding Description

The vulnerability arises from the interaction between Suilend's Pyth oracle validation and the Volo vault operation lifecycle.

**Oracle Failure Path**: The Suilend oracle's `get_pyth_price_and_identifier()` function returns `option::none()` for spot price when confidence ratio violations occur (`conf * MIN_CONFIDENCE_RATIO > price_mag` where MIN_CONFIDENCE_RATIO = 10) [1](#0-0)  or when staleness violations occur (timestamp difference exceeds 60 seconds) [2](#0-1) .

**Price Update Requirement**: The vault's Suilend adaptor requires fresh reserve prices before calculating position values. The `parse_suilend_obligation()` function calls `assert_price_is_fresh()` on each reserve [3](#0-2) [4](#0-3) .

**Transaction Abort**: To satisfy freshness requirements, operators must call `lending_market::refresh_reserve_price()` which invokes `reserve::update_price()` [5](#0-4) . However, `reserve::update_price()` explicitly asserts that the spot price must be Some, causing the transaction to abort when oracle checks fail [6](#0-5) .

**Vault Lock Mechanism**: The vault operation lifecycle begins by setting status to VAULT_DURING_OPERATION_STATUS [7](#0-6) . All borrowed assets are tracked in `op_value_update_record.asset_types_borrowed` during borrowing operations [8](#0-7) . 

To reset the vault status back to NORMAL, operators must call `end_op_value_update_with_bag()` [9](#0-8) , which requires ALL borrowed assets to have their values updated via `check_op_value_update_record()` [10](#0-9) . This check iterates through all borrowed asset types and asserts each has been updated [11](#0-10) .

**No Recovery Path**: The admin module provides no function to force reset the vault status. The only status-related function is `set_vault_enabled()`, which only controls the enabled flag, not the status field [12](#0-11) .

**User Impact**: All user operations like deposit requests require VAULT_NORMAL_STATUS via the `assert_normal()` check [13](#0-12) [14](#0-13) .

## Impact Explanation

**Operational DoS**: When Pyth oracle confidence or staleness checks fail during a vault operation involving Suilend positions, the price update transaction aborts with `EInvalidPrice`. The operator cannot complete the value update for the borrowed Suilend position, which prevents calling `end_op_value_update_with_bag()` to reset the vault status. The vault remains locked in VAULT_DURING_OPERATION_STATUS.

**Fund Lock**: All assets borrowed during the operation (Suilend obligations, principal coins, other DeFi positions) remain outside the vault until the Pyth oracle simultaneously satisfies both confidence and staleness checks for all reserves in the position. This could take an extended period during volatile markets or network issues.

**User Impact**: While the vault is in VAULT_DURING_OPERATION_STATUS, all user operations are blocked because they require VAULT_NORMAL_STATUS. Users cannot deposit new funds or request withdrawals.

**No Recovery Mechanism**: The protocol provides no admin override function to force reset the vault status from VAULT_DURING_OPERATION_STATUS back to VAULT_NORMAL_STATUS. The vault remains frozen until external oracle conditions improve.

## Likelihood Explanation

**Realistic Oracle Failures**: The Pyth oracle confidence and staleness checks can fail through natural market conditions:
- **Confidence failures** occur when `conf * 10 > price_mag`, which happens during periods of price uncertainty and high volatility
- **Staleness failures** occur when the timestamp difference exceeds 60 seconds [15](#0-14) , which can result from network congestion, validator delays, or Pyth oracle update lags

**No Attacker Required**: This is a natural failure mode requiring only:
1. Vault has Suilend positions with borrowed obligations
2. Operator starts an operation, borrowing those positions
3. Pyth oracle experiences confidence or staleness issues during the operation
4. Operator attempts to update Suilend position values
5. Transaction aborts, leaving vault locked

**High Probability**: The 60-second staleness threshold is aggressive for blockchain environments where block times, network partitions, or oracle update schedules can easily exceed this window. Combined with confidence ratio checks during volatile markets, the probability of encountering this failure mode is significant for active vault operations.

## Recommendation

Add an emergency admin function to force reset vault status with appropriate safeguards:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Ensure all borrowed assets have been returned
    assert!(vault.op_value_update_record.asset_types_borrowed.is_empty(), ERR_ASSETS_STILL_BORROWED);
    
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

Additionally, consider implementing:
1. Fallback oracle mechanisms for Suilend price updates
2. Configurable staleness thresholds based on market conditions
3. Grace periods before enforcing strict freshness requirements
4. Event emissions when oracle failures block operations

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Vault operator starts an operation with `start_op_with_bag()` borrowing a Suilend obligation
2. The vault status is set to VAULT_DURING_OPERATION_STATUS
3. The borrowed Suilend obligation's asset type is added to `asset_types_borrowed`
4. Operator completes DeFi operations and calls `end_op_with_bag()` to return all assets
5. Assets are returned, `enable_op_value_update()` is called
6. During this time, Pyth oracle experiences confidence or staleness issues
7. Operator attempts to call `update_suilend_position_value()` to update position values
8. This requires calling `refresh_reserve_price()` which calls `reserve::update_price()`
9. `reserve::update_price()` receives `option::none()` from oracle and aborts with `EInvalidPrice`
10. Operator cannot complete value updates for the Suilend position
11. Operator cannot call `end_op_value_update_with_bag()` because `check_op_value_update_record()` will fail
12. Vault remains locked in VAULT_DURING_OPERATION_STATUS
13. All user operations (deposits, withdrawals) revert because they require VAULT_NORMAL_STATUS
14. No admin function exists to force reset the status

The vault remains frozen until Pyth oracle conditions improve naturally, which could be hours or days during prolonged volatility or network issues.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L36-38)
```text
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L68-68)
```text
        borrow_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L209-210)
```text
        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        reserve::update_price<P>(reserve, clock, price_info);
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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}
```
