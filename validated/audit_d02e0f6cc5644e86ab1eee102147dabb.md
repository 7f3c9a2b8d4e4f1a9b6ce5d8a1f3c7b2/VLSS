# Audit Report

## Title
Vault Operations with Suilend Positions Experience Permanent DoS During Pyth Oracle Downtime

## Summary
When Pyth oracle price feeds stop updating for more than 60 seconds during a vault operation involving Suilend positions, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism until Pyth resumes, blocking all deposits, withdrawals, and operations.

## Finding Description

The vulnerability arises from the interaction of five protocol components that create a permanent denial-of-service condition:

**1. Pyth Oracle Staleness Threshold**

Suilend's oracle module defines a maximum staleness of 60 seconds for Pyth prices. [1](#0-0)  When the current time exceeds the price timestamp by more than this threshold, the oracle returns `None` instead of a valid price. [2](#0-1) 

**2. No Fallback Mechanism in Reserve Price Update**

When `update_price()` receives `None` from the oracle, it aborts with `EInvalidPrice` instead of implementing any fallback mechanism. [3](#0-2)  The `refresh_reserve_price()` function in the lending market directly calls this update function. [4](#0-3) 

**3. Suilend Position Valuation Requires 0-Second Fresh Prices**

Suilend enforces a 0-second staleness threshold when valuing positions, meaning prices must be updated in the exact same second. [5](#0-4)  This freshness is verified through assertions. [6](#0-5) 

The Suilend adaptor enforces this requirement during position valuation by calling `assert_price_is_fresh()` on both deposit and borrow reserves. [7](#0-6) 

**4. Mandatory Asset Value Updates During Operations**

When DeFi assets are borrowed during vault operations, they are tracked in the operation value update record. [8](#0-7) 

Before completing an operation, all borrowed assets MUST have their values updated. The `check_op_value_update_record()` function iterates through all borrowed assets and asserts each has been updated. [9](#0-8) 

This check is enforced in the operation completion flow. [10](#0-9) 

**5. No Emergency Admin Override**

Administrators cannot disable or modify vault status during operations. The `set_enabled()` function explicitly prevents status changes when the vault is in `VAULT_DURING_OPERATION_STATUS`. [11](#0-10) 

**Attack Sequence:**

1. Operator initiates a vault operation with Suilend positions via `start_op_with_bag()`, which sets the vault status to `VAULT_DURING_OPERATION_STATUS`. [12](#0-11) 

2. Pyth oracle experiences downtime exceeding 60 seconds (realistic scenario: network congestion, validator issues, bridge delays)

3. Operator attempts to complete the operation:
   - Cannot call `refresh_reserve_price()` → aborts with `EInvalidPrice` due to stale Pyth data
   - Cannot update Suilend position values → requires freshly updated reserve prices (0-second staleness)
   - Cannot call `end_op_value_update_with_bag()` → fails `check_op_value_update_record()` due to missing asset value updates

4. Vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`. While `end_op_with_bag()` can return assets, it does not restore normal status. [13](#0-12)  Only `end_op_value_update_with_bag()` restores normal status, but it requires the value update check to pass first. [14](#0-13) 

## Impact Explanation

**Complete Operational Paralysis:**
- All vault functionality frozen: no deposits can be executed, no withdrawals can be processed, no new operations can start
- Affects 100% of vault users - funds are inaccessible but not at risk of theft
- No administrative recovery mechanism exists - even privileged admin roles cannot override or bypass the status check
- Duration is unbounded and depends entirely on external Pyth infrastructure recovery (could be hours or days based on historical oracle incidents)

**Affected Parties:**
- All vault depositors unable to access or withdraw funds
- Operators unable to perform any rebalancing or strategy adjustments
- Protocol administrators have no emergency procedures to restore operations

This represents a **HIGH severity** vulnerability because it causes complete protocol-level DoS with no internal recovery path, though funds remain secure from theft.

## Likelihood Explanation

**Realistic Trigger Conditions:**
- Pyth oracle downtime >60 seconds is a documented occurrence in production blockchain environments
- Common causes include: validator node failures, cross-chain bridge congestion, price publisher infrastructure issues, network partitions
- No attacker action required - this is a natural dependency failure scenario
- Any routine vault operation involving Suilend positions during oracle downtime triggers the condition

**Execution Complexity:**
- No special privileges needed beyond normal operator access
- Occurs during routine vault management activities
- Operators may not detect the issue until mid-operation when price updates fail
- Once triggered, requires external monitoring of Pyth oracle status for recovery timing

The likelihood is **MEDIUM** given that oracle downtimes are infrequent but have occurred historically, and the impact only affects vaults with active Suilend positions during the specific downtime window.

## Recommendation

Implement a circuit-breaker mechanism that allows admin to force-complete operations in emergency scenarios:

1. Add an emergency admin function to bypass the value update check when the vault has been stuck in operation status for an extended period (e.g., >24 hours)
2. Implement a fallback oracle system or accept the last known price with a warning flag when primary oracle fails
3. Add a grace period tolerance for Suilend price staleness during operations (e.g., allow slightly stale prices with adjusted risk parameters)
4. Consider implementing a time-based automatic reversion to normal status if an operation has been incomplete for an unreasonable duration

The minimal fix would be to add an emergency admin function in `manage.move` that can force status change from `VAULT_DURING_OPERATION_STATUS` to `VAULT_NORMAL_STATUS` after sufficient time has passed, with appropriate event logging for transparency.

## Proof of Concept

Due to the complexity of the external dependencies (Pyth oracle infrastructure, Suilend lending markets, and time-based oracle updates), a complete end-to-end PoC requires extensive test infrastructure setup beyond the scope of this report. However, the vulnerability can be validated through code inspection as demonstrated above, where each component's behavior is independently verifiable and the interaction leads to the described locked state.

The key validation steps are:
1. Confirm Pyth oracle returns `None` after 60 seconds staleness
2. Confirm `update_price()` aborts on `None`
3. Confirm Suilend position valuation requires 0-second fresh prices
4. Confirm operation completion requires all borrowed asset values updated
5. Confirm no admin override exists for operation status

All five components have been verified through direct code examination with citations provided.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L242-246)
```text
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L53-68)
```text
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

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
