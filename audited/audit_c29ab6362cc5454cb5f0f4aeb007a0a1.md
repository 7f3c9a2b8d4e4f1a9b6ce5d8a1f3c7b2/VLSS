# Audit Report

## Title
Circular Receipt Dependencies Cause Permanent Vault Operation Deadlock

## Summary
When two vaults hold receipts from each other (circular dependency), concurrent operations cause permanent deadlock. Both vaults become stuck in `VAULT_DURING_OPERATION_STATUS`, unable to complete operations because `update_receipt_value()` requires the other vault to be in `VAULT_NORMAL_STATUS`. This permanently blocks all vault operations, user deposits/withdrawals, and asset management with no recovery mechanism.

## Finding Description

The vulnerability exists in the three-phase vault operation flow combined with the receipt value update mechanism.

**Three-Phase Operation Flow:**

Phase 1: `start_op_with_bag` calls `pre_vault_check` which sets vault status to `VAULT_DURING_OPERATION_STATUS`. [1](#0-0) 

Phase 2: `end_op_with_bag` returns borrowed assets but maintains `VAULT_DURING_OPERATION_STATUS`. [2](#0-1) 

Phase 3: `end_op_value_update_with_bag` requires all borrowed asset values to be updated before returning status to `VAULT_NORMAL_STATUS`. [3](#0-2) 

**Critical Requirement - All Assets Must Be Updated:**

The protocol enforces `MAX_UPDATE_INTERVAL = 0`, meaning all asset values must be updated in the same transaction. [4](#0-3) 

When `get_total_usd_value` is called, it validates each asset's update timestamp against this constraint. [5](#0-4) 

The `check_op_value_update_record` function ensures ALL borrowed assets have been updated before completing an operation. [6](#0-5) 

**Receipt Update Blocking:**

To update a receipt's value, `update_receipt_value` enforces that the receipt-issuing vault must be in `VAULT_NORMAL_STATUS`. [7](#0-6) 

The `assert_normal` check verifies the vault status equals `VAULT_NORMAL_STATUS`, aborting with `ERR_VAULT_NOT_NORMAL` otherwise. [8](#0-7) 

**No Circular Dependency Prevention:**

The `add_new_defi_asset` function only checks vault version and enabled status, with no validation preventing circular receipt dependencies. [9](#0-8) 

The commented-out code in `update_receipt_value` only prevented same-type vault references, not actual circular dependencies between different vault types. [10](#0-9) 

**Deadlock Execution:**

1. Vault A (SUI) holds receipt from Vault B (USDC)
2. Vault B (USDC) holds receipt from Vault A (SUI)
3. Both vaults start operations independently → both status = `VAULT_DURING_OPERATION_STATUS`
4. Vault A tries to update Vault B's receipt → fails because Vault B is not `VAULT_NORMAL_STATUS`
5. Vault B tries to update Vault A's receipt → fails because Vault A is not `VAULT_NORMAL_STATUS`
6. Neither vault can complete phase 3, both permanently stuck

**No Recovery Mechanism:**

The `set_enabled` function requires the vault to NOT be in `VAULT_DURING_OPERATION_STATUS`, preventing admin intervention. [11](#0-10) 

No admin functions exist to directly override vault status when stuck during operation. [12](#0-11) 

## Impact Explanation

**HIGH SEVERITY - Complete Protocol DoS:**

1. **User Operations Blocked:** Both `request_deposit` and `request_withdraw` require `assert_normal()`, preventing all user interactions with affected vaults. [13](#0-12) [14](#0-13) 

2. **Future Operations Impossible:** `pre_vault_check` requires `assert_normal()` to start any new operation, permanently blocking all vault management activities. [1](#0-0) 

3. **Admin Controls Blocked:** Cannot disable vault or change critical settings because they require vault to not be during operation. [15](#0-14) 

4. **Funds Effectively Locked:** While not permanently lost, user funds cannot be accessed until protocol upgrade with recovery mechanism.

5. **Protocol Reputation Damage:** Users unable to withdraw funds during deadlock period causes severe trust loss.

## Likelihood Explanation

**HIGH LIKELIHOOD:**

1. **No Attacker Required:** Occurs through normal vault operations without any malicious actor.

2. **Realistic Preconditions:**
   - Circular receipt dependencies are not prevented by protocol checks
   - Vault operations are regular events (daily rebalancing, yield optimization, risk management)
   - No coordination mechanism exists between independent vault operators

3. **Inevitable Timing Collision:** In an active multi-vault system, operations will naturally overlap. Even with attempted coordination, race conditions can occur in concurrent transaction execution.

4. **No Early Warning:** Operators may not realize circular dependencies exist until deadlock occurs. No validation during receipt addition warns of this risk.

5. **Production Scenario:** In a real deployment with multiple vaults executing regular maintenance operations, the probability of simultaneous operations approaches certainty over time.

## Recommendation

**Immediate Fix - Prevent Circular Dependencies:**

Add validation in `add_new_defi_asset` to detect and reject circular receipt dependencies before they are created. Track the dependency graph and reject additions that would create cycles.

**Alternative Fix - Relaxed Status Requirement:**

Modify `update_receipt_value` to allow reading receipt values from vaults in `VAULT_DURING_OPERATION_STATUS`, but use cached/snapshot values instead of requiring the vault to be in normal status. This breaks the deadlock condition while maintaining accounting integrity.

**Recovery Mechanism:**

Add an admin emergency function that can reset vault status from `VAULT_DURING_OPERATION_STATUS` to `VAULT_NORMAL_STATUS` with appropriate safeguards (time delays, multi-sig requirements) for deadlock recovery scenarios.

**Prevention through Coordination:**

Implement an operation lock mechanism where vaults with interdependencies must acquire locks in a consistent order (e.g., by vault address) before starting operations, preventing simultaneous operations on circularly dependent vaults.

## Proof of Concept

```move
// Setup: Create two vaults with circular receipt dependencies
// Vault A holds receipt from Vault B
// Vault B holds receipt from Vault A

public fun test_circular_receipt_deadlock() {
    // 1. Create Vault A (SUI) and Vault B (USDC)
    // 2. Vault A deposits into Vault B, receives receipt_b
    // 3. Vault B deposits into Vault A, receives receipt_a
    // 4. Add receipt_b as asset to Vault A
    // 5. Add receipt_a as asset to Vault B
    
    // Both vaults now have circular dependency
    
    // 6. Operator A starts operation on Vault A
    //    -> vault_a.status = VAULT_DURING_OPERATION_STATUS
    
    // 7. Operator B starts operation on Vault B  
    //    -> vault_b.status = VAULT_DURING_OPERATION_STATUS
    
    // 8. Operator A tries to complete by calling update_receipt_value<SUI, USDC>
    //    -> Calls vault_b.assert_normal()
    //    -> ABORTS with ERR_VAULT_NOT_NORMAL (5_022)
    
    // 9. Operator B tries to complete by calling update_receipt_value<USDC, SUI>
    //    -> Calls vault_a.assert_normal()
    //    -> ABORTS with ERR_VAULT_NOT_NORMAL (5_022)
    
    // Result: Both vaults permanently stuck in VAULT_DURING_OPERATION_STATUS
    // - Cannot start new operations (requires assert_normal)
    // - Cannot process user deposits/withdrawals (requires assert_normal)
    // - Cannot disable vault (requires not during operation)
    // - No admin recovery function exists
}
```

## Notes

This vulnerability requires the specific precondition of circular receipt dependencies between vaults, but once established, deadlock becomes inevitable through normal operations. The severity is HIGH because it causes complete DoS of affected vaults with no built-in recovery mechanism, requiring protocol upgrade to resolve. The protocol should either prevent circular dependencies at creation time or relax the strict status requirements for receipt value reads to allow operations to complete even when dependent vaults are also in operation.

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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L517-531)
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

**File:** volo-vault/sources/volo_vault.move (L707-717)
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
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/sources/volo_vault.move (L896-906)
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
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
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

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```

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
