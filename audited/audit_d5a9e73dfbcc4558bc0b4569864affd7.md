### Title
Vault Permanent DoS Due to Irrecoverable Operation Status Lock

### Summary
The vault operation flow requires a three-step process to complete (start → end → value update), but lacks a recovery mechanism if the final step fails. When an operation cannot complete due to oracle failures, external protocol issues, or validation errors, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no admin override capability. This permanently blocks all user deposits and withdrawals, creating a critical denial of service vulnerability analogous to the external race condition report's lack of execution control.

### Finding Description

**Vulnerability Class Mapping:**
The external report describes a race condition where lack of execution control allowed state corruption without recovery. In Volo's vault system, the analogous vulnerability exists in multi-step operation state management without recovery mechanism.

**Root Cause:**
The vault operation flow requires three sequential function calls:

1. `start_op_with_bag()` sets vault status to `VAULT_DURING_OPERATION_STATUS` [1](#0-0) 

2. `end_op_with_bag()` returns borrowed assets and enables value update tracking [2](#0-1) 

3. `end_op_value_update_with_bag()` validates all updates and resets status to `VAULT_NORMAL_STATUS` [3](#0-2) 

**Critical Failure Point:**
The final step contains multiple assertion checks that can fail. The most critical is `check_op_value_update_record()` which requires EVERY borrowed asset's value to be updated: [4](#0-3) 

If any borrowed asset cannot have its value updated (due to oracle failure, external protocol unavailability, or price feed issues), the assertions at lines 1216-1217 will fail with `ERR_USD_VALUE_NOT_UPDATED`, preventing operation completion.

**Why Protections Fail:**
The admin's only status control function `set_enabled()` explicitly blocks status changes when vault is in `VAULT_DURING_OPERATION_STATUS`: [5](#0-4) 

The assertion at line 523 prevents any admin intervention. The only code path that can reset the status from `VAULT_DURING_OPERATION_STATUS` back to `VAULT_NORMAL_STATUS` is line 375 in `end_op_value_update_with_bag()`, which cannot execute if preceding validations fail.

**Broken Invariant:**
All user-facing operations require vault status to be `VAULT_NORMAL_STATUS`:
- `request_deposit()` requires `assert_normal()` [6](#0-5) 

- `execute_deposit()` requires `assert_normal()` [7](#0-6) 

- `request_withdraw()` requires `assert_normal()` [8](#0-7) 

- `execute_withdraw()` requires `assert_normal()` [9](#0-8) 

The `assert_normal()` function definition: [10](#0-9) 

### Impact Explanation

**Severity: CRITICAL**

When the vault becomes stuck in `VAULT_DURING_OPERATION_STATUS`:
- All deposit requests fail at `assert_normal()` check
- All withdraw requests fail at `assert_normal()` check  
- All deposit executions fail at `assert_normal()` check
- All withdraw executions fail at `assert_normal()` check
- Existing pending requests in the request buffer become permanently unexecutable
- All vault principal and DeFi assets become permanently locked
- No admin recovery mechanism exists

This constitutes a **permanent, irrecoverable denial of service** affecting all vault functionality and locking all user funds indefinitely.

### Likelihood Explanation

**Probability: MEDIUM-HIGH**

The vulnerability can be triggered by:

1. **Oracle Service Disruption**: If Switchboard or any oracle feed becomes unavailable during the value update phase, the operator cannot call `finish_update_asset_value()` for borrowed assets, causing `check_op_value_update_record()` to fail.

2. **External Protocol Failures**: If integrated DeFi protocols (Navi, Suilend, Cetus, Momentum) experience downtime or state changes that prevent value calculation, the operation cannot complete.

3. **Price Feed Staleness**: If oracle prices exceed staleness thresholds during the update window, value updates may fail.

4. **Operator Error**: If operator incorrectly handles the three-step flow or encounters unexpected reverts, the vault can become stuck.

5. **Loss Tolerance Violation**: If the operation results in losses exceeding `loss_tolerance`, the `update_tolerance()` call at line 363 will fail: [11](#0-10) 

All of these scenarios are realistic in production environments with external dependencies.

### Recommendation

**Add Emergency Admin Recovery Function:**

Add a new admin-only function in `vault_manage.move`:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Allow admin to forcibly reset status and clear operation records
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

Modify `set_status()` visibility or add a dedicated emergency path that bypasses the `VAULT_DURING_OPERATION_STATUS` check in `set_enabled()`.

**Additional Safeguards:**
1. Implement operation timeout mechanism - auto-revert to NORMAL after X hours
2. Add operator capability to cancel in-progress operations with admin approval
3. Add health checks before starting operations to validate oracle availability
4. Implement circuit breaker pattern for external protocol dependencies

### Proof of Concept

**Scenario: Oracle Failure During Operation**

1. Operator calls `start_op_with_bag()` to begin an operation, borrowing Navi and Cetus assets
   - Vault status changes to `VAULT_DURING_OPERATION_STATUS` (operation.move:74)
   - Principal asset type and potentially other borrowed assets added to `asset_types_borrowed`

2. Operator interacts with DeFi protocols successfully

3. Operator calls `end_op_with_bag()` to return assets
   - Assets returned to vault
   - `enable_op_value_update()` called (operation.move:294)

4. Operator attempts to update borrowed asset values using adaptors
   - Navi adaptor calls succeed, Navi asset marked as updated
   - Cetus adaptor oracle call FAILS (Switchboard aggregator down)
   - Cetus asset value NOT updated in `asset_types_updated` table

5. Operator calls `end_op_value_update_with_bag()` to complete operation
   - Execution reaches `check_op_value_update_record()` (operation.move:354)
   - Function iterates through `asset_types_borrowed` (volo_vault.move:1215)
   - Assertion at line 1216 FAILS: Cetus asset not in `asset_types_updated`
   - Transaction reverts with `ERR_USD_VALUE_NOT_UPDATED`
   - Vault status remains `VAULT_DURING_OPERATION_STATUS`

6. Admin attempts recovery via `set_vault_enabled(admin_cap, vault, true)`
   - Function calls `vault.set_enabled(true)` (vault_manage.move:18)
   - Assertion at line 523 FAILS: `status() == VAULT_DURING_OPERATION_STATUS`
   - Transaction reverts with `ERR_VAULT_DURING_OPERATION`

7. **Result**: Vault permanently stuck, all user operations fail at `assert_normal()` checks

**No recovery path exists in current implementation.**

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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

**File:** volo-vault/sources/volo_vault.move (L806-814)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
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

**File:** volo-vault/sources/volo_vault.move (L994-1003)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);
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
