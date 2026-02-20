# Audit Report

## Title
Pyth Oracle Failure Permanently Bricks Vault Operations with Suilend Positions

## Summary
When a vault has Suilend positions, any Pyth oracle failure (stale data >60s or confidence interval >10%) during vault operations permanently locks the vault in `VAULT_DURING_OPERATION_STATUS`, blocking all deposits and withdrawals with no admin recovery mechanism.

## Finding Description

The vulnerability stems from a critical mismatch between Suilend's oracle design intention and its actual implementation integrated into Volo vaults.

The Suilend oracle wrapper `get_pyth_price_and_identifier()` is designed to return `Option::none()` for graceful degradation when validation fails. [1](#0-0)  The function returns None when confidence intervals exceed 10% of price [2](#0-1)  or when price data is more than 60 seconds stale. [3](#0-2) 

However, the caller `reserve::update_price()` aborts immediately without any fallback mechanism when receiving None. [4](#0-3) 

**Complete DoS Execution Path:**

1. Operator initiates vault operation via `start_op_with_bag`, which borrows Suilend positions from the vault and sets vault status to `VAULT_DURING_OPERATION_STATUS`. [5](#0-4) [6](#0-5) 

2. After returning assets via `end_op_with_bag`, the operator must call `end_op_value_update_with_bag` to complete the operation. [7](#0-6) 

3. This function enforces that ALL borrowed assets have their values updated via `check_op_value_update_record`. [8](#0-7) 

4. For Suilend positions, value updates require fresh prices with `PRICE_STALENESS_THRESHOLD_S = 0` (zero staleness tolerance). [9](#0-8)  The adaptor calls `assert_price_is_fresh()` which enforces this threshold. [10](#0-9) [11](#0-10) 

5. To refresh prices, the operator must call `lending_market::refresh_reserve_price`, which is the ONLY way to update the price timestamp. [12](#0-11) [13](#0-12) 

6. If Pyth oracle returns None (due to staleness or confidence issues), the transaction aborts with `EInvalidPrice`, preventing the value update from completing.

7. Without completing value updates, `check_op_value_update_record` fails because it asserts all borrowed assets must be updated. [14](#0-13) 

8. The vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS` because only `end_op_value_update_with_bag` can return it to normal status. [15](#0-14) 

9. Users cannot deposit or withdraw because both operations explicitly require `VAULT_NORMAL_STATUS`. [16](#0-15) [17](#0-16) 

10. Admin cannot recover - `set_enabled` explicitly blocks changes during operation status. [18](#0-17)  The internal `set_status` function is only `public(package)` and not exposed through any admin entry point. [19](#0-18) 

## Impact Explanation

**Critical Protocol DoS:**
- All vault deposits and withdrawals permanently blocked
- All user funds locked with no access mechanism
- Complete loss of vault operational capability
- Irreversible without contract upgrade (requires new package deployment and migration)

**Affected Assets:**
- All principal funds in vault
- All DeFi positions (Suilend, Navi, Cetus, Momentum)
- Pending deposit/withdrawal requests
- Accumulated fees and rewards

**Business Impact:**
- Total protocol shutdown for affected vault
- Reputational damage and user trust loss
- Potential legal liability for locked funds

## Likelihood Explanation

**High Likelihood - Not an Attack, but Operational Failure:**

This vulnerability triggers under realistic operational conditions without requiring any malicious actor:

1. **No Attack Required:** Normal vault operations by legitimate operators
2. **Expected Configuration:** Multi-asset vaults are designed to hold Suilend positions
3. **Realistic Trigger Conditions:** Pyth oracle returns None when:
   - Confidence interval >10% of price (common during volatile markets)
   - Price data >60 seconds stale (occurs during network congestion, oracle infrastructure issues, or Sui network delays)
4. **Regular Occurrence:** Oracle reliability issues happen in all blockchain environments:
   - Network congestion on Sui mainnet
   - Pyth price feed temporary outages
   - Cross-chain message delays
   - Market volatility causing confidence interval spikes
5. **Zero Mitigation:** No fallback oracle, no emergency recovery, no staleness grace period (0-second threshold)
6. **Permanent Impact:** Once triggered, requires contract upgrade to recover

## Recommendation

**Immediate Fix:**

1. Add an emergency admin function to force-reset vault status when stuck during operations:
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

2. Implement a reasonable staleness grace period for Suilend positions (e.g., 300 seconds instead of 0) to reduce fragility.

3. Add try-catch logic or alternative valuation methods when Pyth oracle fails, such as using the last known good price with appropriate safety margins.

**Long-term Fix:**

Implement a proper fallback oracle system as originally intended by Suilend's design, with multiple price sources and degradation strategies.

## Proof of Concept

```move
// Test scenario demonstrating the DoS:
// 1. Vault has Suilend positions
// 2. Operator starts operation (vault enters VAULT_DURING_OPERATION_STATUS)
// 3. Operator returns assets
// 4. Pyth oracle returns None due to staleness/confidence
// 5. refresh_reserve_price() aborts
// 6. Cannot complete end_op_value_update_with_bag
// 7. Vault permanently stuck
// 8. All user deposits/withdrawals blocked
// 9. Admin cannot recover

// This would be demonstrated by:
// - Setting up a vault with Suilend positions
// - Starting an operation
// - Simulating Pyth oracle failure (confidence >10% or staleness >60s)
// - Attempting to complete the operation
// - Verifying transaction aborts
// - Verifying vault is stuck in VAULT_DURING_OPERATION_STATUS
// - Verifying user operations fail
// - Verifying admin recovery attempts fail
```

## Notes

This vulnerability represents a severe design flaw where Suilend's graceful degradation pattern (returning None for fallback handling) is ignored by the actual implementation (aborting on None). The 0-second staleness threshold makes this issue extremely fragile and likely to trigger in production environments during normal market volatility or network congestion.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-18)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
    /// return type: (spot price, ema price, price identifier)
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L238-246)
```text
    public fun assert_price_is_fresh<P>(reserve: &Reserve<P>, clock: &Clock) {
        assert!(is_price_fresh(reserve, clock), EPriceStale);
    }

    public(package) fun is_price_fresh<P>(reserve: &Reserve<P>, clock: &Clock): bool {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;

        cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S
    }
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

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L94-145)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);

    let mut defi_assets = bag::new(ctx);

    let defi_assets_length = defi_asset_ids.length();
    assert!(defi_assets_length == defi_asset_types.length(), ERR_ASSETS_LENGTH_MISMATCH);

    let mut i = 0;
    while (i < defi_assets_length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = vault.borrow_defi_asset<T, CetusPosition>(cetus_asset_type);
            defi_assets.add<String, CetusPosition>(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let obligation_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = vault.borrow_defi_asset<T, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
            );
            defi_assets.add<String, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
                obligation,
            );
        };
```

**File:** volo-vault/sources/operation.move (L209-297)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();

    defi_assets.destroy_empty();
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
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

**File:** volo-vault/sources/volo_vault.move (L519-531)
```text
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

**File:** volo-vault/sources/volo_vault.move (L533-541)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;

    emit(VaultStatusChanged {
        vault_id: self.vault_id(),
        status: status,
    });
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

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
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
}
```
