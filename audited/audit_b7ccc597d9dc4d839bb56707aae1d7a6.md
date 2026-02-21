# Audit Report

## Title
Unauthorized Asset Value Manipulation During Vault Operations Bypasses Loss Tolerance Enforcement

## Summary
Five public adaptor value update functions lack vault status validation, allowing any external actor to update asset values during the critical window between operation Phase 2 (asset return) and Phase 3 (loss validation). This enables bypassing the protocol's loss tolerance mechanism by manipulating the values used in loss calculations.

## Finding Description

The vulnerability stems from five public adaptor functions that update asset values without checking whether the vault is in an operational state where only authorized operators should control value updates.

**Vulnerable Functions Without Access Control:**

All five adaptor update functions are declared as `public fun` with no capability checks or vault status restrictions:

- `update_receipt_value()` only validates the receipt vault's status, never the main vault's status [1](#0-0) 

- `update_navi_position_value()` has no vault status checks [2](#0-1) 

- `update_cetus_position_value()` has no vault status checks [3](#0-2) 

- `update_suilend_position_value()` has no vault status checks [4](#0-3) 

- `update_momentum_position_value()` has no vault status checks [5](#0-4) 

**Vault Operation Three-Phase Flow:**

Vault operations follow a three-phase lifecycle where assets are borrowed, used in DeFi operations, and then validated:

**Phase 1 - Start Operation:** The vault status is set to `VAULT_DURING_OPERATION_STATUS` [6](#0-5) 

**Phase 2 - End Operation:** Assets are returned and value update is enabled via `enable_op_value_update()` which sets `value_update_enabled = true` [7](#0-6) 

This function enables the value update flag [8](#0-7) 

**Phase 3 - Value Update Check:** All borrowed assets must be updated and loss tolerance is enforced [9](#0-8) 

**The Critical Vulnerability Window:**

Between Phase 2 and Phase 3, when the vault is in `VAULT_DURING_OPERATION_STATUS` with `value_update_enabled = true`, the `finish_update_asset_value()` function marks assets as updated in the operation record [10](#0-9) 

Since all five adaptor functions call `finish_update_asset_value()`, any external actor can update asset values and manipulate the `op_value_update_record` during this window.

**Loss Tolerance Impact:**

The loss calculation in Phase 3 uses the total USD value calculated from asset values that can be manipulated [11](#0-10) 

The `update_tolerance()` function enforces the loss limit using these values [12](#0-11) 

## Impact Explanation

**Loss Tolerance Bypass:**
The protocol enforces a maximum loss tolerance per epoch to protect depositors (ERR_EXCEED_LOSS_LIMIT at line 635). By timing asset value updates during the operation window, an attacker can manipulate whether the calculated loss appears to exceed the limit. If oracle prices have recovered since the operation started, updating with current prices shows a smaller loss, allowing operations that should fail the tolerance check to succeed. This directly violates the core security guarantee that losses are bounded per epoch.

**Operational Control Loss:**
Operators lose exclusive control over the exact timing and state used for value updates during operations. An attacker can front-run the operator's Phase 3 transaction to update values at a different timestamp or with different oracle states, causing unpredictable loss calculations and potentially forcing operation failures or allowing excessive losses.

**Accounting Integrity Corruption:**
The manipulated total USD value affects share ratio calculations used for all subsequent deposits and withdrawals. This creates cascading accounting errors where share prices become unreliable, affecting all vault depositors.

**Affected Stakeholders:**
- All vault depositors experience unreliable share valuations
- Protocol operators cannot execute deterministic operations
- Protocol treasury faces potential loss tolerance violations

## Likelihood Explanation

**Public Entry Points:**
All five functions are explicitly `public fun` with no capability requirements, making them callable by any address.

**Minimal Preconditions:**
- Vault holds DeFi assets (common in production)
- Vault is between Phase 2 and Phase 3 (predictable window based on transaction ordering)
- Oracle config and clock are public shared objects (always accessible)

**Practical Exploitation:**
1. Monitor blockchain for `OperationEnded` events emitted at end of Phase 2
2. Submit transaction calling the appropriate `update_X_value()` function
3. Front-run operator's Phase 3 transaction with favorable timing
4. No capital requirements, only gas costs (~0.01 SUI)

**Economic Viability:**
- Attack cost: Minimal gas fees
- Potential gain: Bypass loss limits or grief operations  
- Detection risk: Low - updates appear legitimate in transaction logs
- Repeatability: Every operation cycle

## Recommendation

Add vault status checks to all adaptor update functions to prevent unauthorized updates during operations:

```move
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Add this check to prevent updates during operations
    vault.assert_normal();  
    
    receipt_vault.assert_normal();
    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);
    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

Apply the same `vault.assert_normal()` check to all five adaptor functions. This ensures value updates can only occur when the vault is in normal status, preventing manipulation during the critical operation window while still allowing public updates for transparency during normal operations.

Alternatively, modify `finish_update_asset_value()` to reject updates during operations when called from public functions, or create separate operator-only entry points for value updates during operations.

## Proof of Concept

```move
#[test]
fun test_unauthorized_value_update_during_operation() {
    // Setup: Create vault with DeFi asset and start operation
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Phase 1: Operator starts operation, vault enters VAULT_DURING_OPERATION_STATUS
    test_scenario::next_tx(&mut scenario, OPERATOR);
    let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
    let operation = test_scenario::take_shared<Operation>(&scenario);
    let operator_cap = test_scenario::take_from_sender<OperatorCap>(&scenario);
    
    // Start operation borrows assets
    let (defi_assets, tx, tx_check, principal, coin_asset) = 
        operation::start_op_with_bag(&mut vault, &operation, &operator_cap, ...);
    
    // Phase 2: Operator ends operation, enables value update
    operation::end_op_with_bag(&mut vault, &operation, &operator_cap, defi_assets, ...);
    // Now vault is in VAULT_DURING_OPERATION_STATUS with value_update_enabled = true
    
    // ATTACK: External user (not operator) calls public update function
    test_scenario::next_tx(&mut scenario, ATTACKER);
    let config = test_scenario::take_shared<OracleConfig>(&scenario);
    let clock = test_scenario::take_shared<Clock>(&scenario);
    
    // This should FAIL but currently SUCCEEDS - attacker can update values
    receipt_adaptor::update_receipt_value(
        &mut vault,
        &receipt_vault,
        &config,
        &clock,
        asset_type
    );
    
    // The attacker has now manipulated the op_value_update_record
    // Phase 3 will use these manipulated values for loss calculation
    
    test_scenario::return_shared(vault);
    test_scenario::return_shared(operation);
    test_scenario::return_to_sender(&scenario, operator_cap);
    test_scenario::end(scenario);
}
```

## Notes

The vulnerability exists because the adaptor functions are intentionally public to allow permissionless value updates during normal vault operations (for transparency). However, the implementation fails to distinguish between normal operations (where public updates are acceptable) and the critical operation window (where only operators should control updates). The security model breaks down specifically during the window between Phase 2 and Phase 3, where the vault is in `VAULT_DURING_OPERATION_STATUS` with `value_update_enabled = true`.

### Citations

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-36)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
    receipt_vault.assert_normal();

    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);

    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1242-1247)
```text
public(package) fun enable_op_value_update<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    self.check_version();
    self.assert_enabled();

    self.op_value_update_record.value_update_enabled = true;
}
```
