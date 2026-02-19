### Title
Vault Permanent Corruption via Missing Asset Return Validation

### Summary
The `end_op_with_bag` function directly calls `bag.remove()` on borrowed DeFi assets without verifying their existence in the bag. If an operator fails to return an asset correctly (through error or malicious action), the transaction aborts, permanently locking the vault in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism, rendering all deposited funds inaccessible.

### Finding Description

**Root Cause:**
In `end_op_with_bag`, the function receives a mutable `Bag` containing borrowed assets by value and attempts to remove each asset without prior existence verification: [1](#0-0) 

The function then directly calls `bag.remove()` for each asset type without checking if the key exists: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

In Move's Sui framework, `bag::remove()` aborts if the specified key doesn't exist. Since operators receive the mutable bag and have complete control over it between `start_op_with_bag` and `end_op_with_bag`, they can remove assets from the bag, transfer them elsewhere, or fail to maintain the bag structure correctly.

**Why Existing Protections Fail:**

1. The vault status is set to `VAULT_DURING_OPERATION_STATUS` at operation start: [7](#0-6) 

2. Admin cannot disable the vault to recover because `set_enabled` explicitly prevents status changes during operations: [8](#0-7) 

3. Users cannot deposit or withdraw because these operations require `VAULT_NORMAL_STATUS`: [9](#0-8) 

4. The asset return verification in `end_op_value_update_with_bag` only executes AFTER `end_op_with_bag` succeeds: [10](#0-9) 

This creates an unrecoverable state where the vault cannot transition back to normal status.

### Impact Explanation

**Direct Fund Impact:**
- All user deposits (principal balances) permanently locked in the vault
- All DeFi positions (Navi, Cetus, Suilend, Momentum, Receipt assets) become inaccessible
- Complete loss of vault functionality

**Operational Impact:**
- Vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`
- Users cannot deposit, withdraw, or cancel requests (requires NORMAL status)
- Admin cannot disable or recover the vault (blocked during operations)
- No recovery mechanism exists in the codebase
- Vault is effectively bricked with all funds trapped

**Severity: HIGH** - Results in permanent loss of access to all deposited funds with no recovery path, affecting all vault users and protocol operations.

### Likelihood Explanation

**Attacker Capabilities:**
- Any holder of `OperatorCap` can trigger this condition
- Operators are not fully trusted roles (separate from AdminCap)
- Multiple operators may exist for operational redundancy

**Attack Complexity:**
The attack is straightforward:
1. Call `start_op_with_bag` to receive mutable bag with assets
2. Manipulate the bag by removing assets via `bag.remove()` and transferring them elsewhere, or simply not returning them properly
3. Call `end_op_with_bag` with the corrupted bag
4. Transaction aborts, vault status remains DURING_OPERATION

**Feasibility Conditions:**
- Requires OperatorCap (designed for operational use, not just admin)
- Can occur accidentally through programming errors in operation logic
- Can occur maliciously by compromised or rogue operator
- No safeguards prevent bag manipulation between borrow and return

**Probability: MEDIUM-HIGH** - Given the complexity of multi-protocol operations and multiple operator scenarios, the risk of accidental or intentional asset mishandling is substantial.

### Recommendation

**1. Add existence checks before all `bag.remove()` calls:**

In `end_op_with_bag`, verify each asset exists before attempting removal. Replace direct `remove()` calls with checked removals that provide clear error messages if assets are missing.

**2. Add admin emergency recovery function:**

Create a new admin-only function that can force vault status reset to NORMAL even during operations, with appropriate safety checks and event logging for audit trails.

**3. Implement comprehensive test coverage:**

Add test cases specifically for:
- Asset return failure scenarios
- Bag manipulation detection
- Recovery mechanism validation
- Status transition edge cases

**4. Consider implementing a custody wrapper:**

Wrap the bag in a type that tracks which assets were borrowed and enforces their return, preventing manipulation between borrow and return operations.

### Proof of Concept

**Initial State:**
- Vault deployed with NaviAccountCap asset at index 0
- Vault status = VAULT_NORMAL_STATUS
- Users have deposited funds

**Attack Steps:**

1. Operator calls `start_op_with_bag()`:
   - Vault status transitions to VAULT_DURING_OPERATION_STATUS
   - Operator receives mutable Bag containing borrowed NaviAccountCap [11](#0-10) 

2. Operator manipulates the bag:
   - Removes NaviAccountCap from bag: `let cap = defi_assets.remove<String, NaviAccountCap>(key)`
   - Transfers it elsewhere or keeps it: `transfer::transfer(cap, operator_address)`
   - Bag no longer contains the borrowed asset

3. Operator attempts to call `end_op_with_bag()`:
   - Function tries to remove NaviAccountCap at line 237
   - `bag.remove()` aborts because key doesn't exist
   - Transaction fails [12](#0-11) 

4. Vault corruption confirmed:
   - Vault status remains VAULT_DURING_OPERATION_STATUS
   - Users cannot deposit/withdraw (line 650 check fails)
   - Admin cannot disable vault (line 523 check fails)
   - No recovery function exists in manage.move [13](#0-12) 

**Expected Result:** Operation completes successfully, assets returned, vault returns to NORMAL status

**Actual Result:** Transaction aborts, vault permanently stuck in DURING_OPERATION status, all funds locked

**Success Condition:** Vault status never returns to NORMAL, all user operations permanently blocked, admin recovery attempts fail due to status check

### Citations

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L104-207)
```text
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

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = vault.borrow_defi_asset<T, Receipt>(receipt_asset_type);
            defi_assets.add<String, Receipt>(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    let principal_balance = if (principal_amount > 0) {
        vault.borrow_free_principal(principal_amount)
    } else {
        balance::zero<T>()
    };

    let coin_type_asset_balance = if (coin_type_asset_amount > 0) {
        vault.borrow_coin_type_asset<T, CoinType>(
            coin_type_asset_amount,
        )
    } else {
        balance::zero<CoinType>()
    };

    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };

    emit(OperationStarted {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount,
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount,
        total_usd_value,
    });

    (defi_assets, tx, tx_for_check_value_update, principal_balance, coin_type_asset_balance)
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

**File:** volo-vault/sources/operation.move (L319-351)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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
