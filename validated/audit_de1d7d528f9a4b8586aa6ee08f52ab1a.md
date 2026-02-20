# Audit Report

## Title
Operator Can Permanently Brick Vault by Manipulating DeFi Asset Bag Between Operation Phases

## Summary
The `end_op_with_bag()` function fails to validate operator-controlled Bag contents before attempting asset removal, allowing malicious operators to permanently brick the vault in VAULT_DURING_OPERATION_STATUS while stealing DeFi assets, with no admin recovery mechanism available.

## Finding Description

The vault's operation lifecycle creates a critical custody vulnerability through unchecked trust in operator-controlled asset containers. 

When `start_op_with_bag()` executes, it changes the vault status to VAULT_DURING_OPERATION_STATUS and borrows DeFi assets (NaviAccountCap, CetusPosition, SuilendObligationOwnerCap, MomentumPosition, Receipt) from the vault. [1](#0-0)  These assets are placed in a temporary Bag that is returned to the operator along with an immutable TxBag recording what was borrowed. [2](#0-1) 

The assets are permanently removed from vault custody via `borrow_defi_asset()` which calls `self.assets.remove()`. [3](#0-2) 

Between receiving the Bag and calling `end_op_with_bag()`, the operator has full ownership of the Bag object and can manipulate it arbitrarily in separate transactions, including calling `bag::remove()` to extract valuable assets.

When the operator subsequently calls `end_op_with_bag()` with a manipulated Bag, the function unpacks the TxBag and iterates through all recorded asset IDs, attempting to remove each from the operator-provided Bag without any pre-validation. [4](#0-3) 

Since Sui Move's `bag::remove()` aborts when a key doesn't exist, any missing asset causes immediate transaction reversion. The critical issue is that the vault status change to VAULT_DURING_OPERATION_STATUS occurred in the successful `start_op_with_bag()` transaction, while the abort happens in the separate `end_op_with_bag()` transaction, leaving the vault permanently stuck.

**No Recovery Mechanism Exists:** The admin's `set_vault_enabled()` function explicitly prevents status changes when the vault is in VAULT_DURING_OPERATION_STATUS. [5](#0-4)  The only other status change mechanism is `set_status()` which is `public(package)` with no public admin wrapper that bypasses the check. [6](#0-5) 

The alternative recovery path through `end_op_value_update_with_bag()` also fails because it requires all assets to be present in the vault. [7](#0-6)  Since the assets were removed but never returned due to the abort, this path is blocked.

This represents a privilege escalation vulnerability where operators, who should only USE assets for DeFi operations, can instead STEAL them while permanently bricking the vault. The existence of the operator freeze mechanism proves operators are not fully trusted. [8](#0-7) 

## Impact Explanation

**Complete Protocol Failure:**
- Vault permanently stuck in VAULT_DURING_OPERATION_STATUS with no admin override capability
- All borrowed DeFi assets lost from vault custody and stolen by operator
- No new operations can start (would require VAULT_NORMAL_STATUS)
- Users cannot deposit or withdraw (functions require VAULT_NORMAL_STATUS)
- User funds trapped in vault with no access path

**Asset Theft:** Assets removed during `borrow_defi_asset()` cannot be recovered because the operation never completes, effectively transferring ownership to the malicious operator.

This is **HIGH severity** due to permanent protocol DoS combined with theft of potentially high-value DeFi position assets that may contain substantial deposited collateral.

## Likelihood Explanation

**Highly Feasible Attack Path:**
1. Operator calls `start_op_with_bag()` with legitimate asset IDs → receives Bag with borrowed assets
2. In separate transaction, operator calls `bag::remove()` to extract valuable assets
3. Operator calls `end_op_with_bag()` with manipulated Bag
4. Transaction aborts on missing asset → vault permanently stuck

**Prerequisites:** Only requires OperatorCap, which operators legitimately possess. The operator freeze mechanism demonstrates operators can be malicious/compromised, validating this threat model.

**Economic Rationality:** Zero-cost attack (only gas fees) enabling theft of DeFi position assets while causing maximum protocol damage. Frozen operators could execute as revenge attack.

## Recommendation

Add validation in `end_op_with_bag()` to verify all expected assets exist in the Bag before attempting removal:

```move
// After unpacking TxBag, before the removal loop:
let mut i = 0;
while (i < length) {
    let defi_asset_id = defi_asset_ids[i];
    let defi_asset_type = defi_asset_types[i];
    
    if (defi_asset_type == type_name::get<NaviAccountCap>()) {
        let asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
        assert!(defi_assets.contains<String>(asset_type), ERR_ASSETS_NOT_IN_BAG);
    };
    // Repeat for other asset types...
    i = i + 1;
};
```

Additionally, provide an emergency admin function to force vault status reset as a recovery mechanism:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    new_status: u8,
) {
    vault.set_status(new_status);
}
```

## Proof of Concept

```move
#[test]
fun test_operator_brick_vault_via_bag_manipulation() {
    let mut scenario = test_scenario::begin(@0xADMIN);
    
    // Setup: Create vault with DeFi assets
    test_scenario::next_tx(&mut scenario, @0xADMIN);
    {
        let admin_cap = vault::create_admin_cap(test_scenario::ctx(&mut scenario));
        let mut vault = vault::create_vault<SUI>(&admin_cap, test_scenario::ctx(&mut scenario));
        
        // Add a NaviAccountCap to vault
        let navi_cap = /* create NaviAccountCap */;
        vault::add_new_defi_asset(&op, &op_cap, &mut vault, 0, navi_cap);
        
        transfer::public_share_object(vault);
    };
    
    // Attack Phase 1: Operator starts operation and receives Bag
    test_scenario::next_tx(&mut scenario, @0xOPERATOR);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let op = test_scenario::take_shared<Operation>(&scenario);
        let op_cap = test_scenario::take_from_sender<OperatorCap>(&scenario);
        
        let asset_ids = vector[0u8];
        let asset_types = vector[type_name::get<NaviAccountCap>()];
        
        let (bag, tx_bag, tx_check, principal, coin_asset) = operation::start_op_with_bag(
            &mut vault, &op, &op_cap, &clock, asset_ids, asset_types, 0, 0, 
            test_scenario::ctx(&mut scenario)
        );
        
        // Vault is now in VAULT_DURING_OPERATION_STATUS
        assert!(vault.status() == 1, 0);
        
        // Operator extracts asset from Bag
        let navi_key = vault_utils::parse_key<NaviAccountCap>(0u8);
        let stolen_cap = bag::remove<String, NaviAccountCap>(&mut bag, navi_key);
        transfer::public_transfer(stolen_cap, @0xOPERATOR); // Steal it
        
        // Store manipulated bag for next transaction
        transfer::public_transfer(bag, @0xOPERATOR);
        transfer::public_transfer(tx_bag, @0xOPERATOR);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(op);
        test_scenario::return_to_sender(&scenario, op_cap);
    };
    
    // Attack Phase 2: Operator tries to end operation with manipulated Bag
    test_scenario::next_tx(&mut scenario, @0xOPERATOR);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let op = test_scenario::take_shared<Operation>(&scenario);
        let op_cap = test_scenario::take_from_sender<OperatorCap>(&scenario);
        let bag = test_scenario::take_from_sender<Bag>(&scenario);
        let tx_bag = test_scenario::take_from_sender<TxBag>(&scenario);
        
        // This ABORTS because Bag is missing the NaviAccountCap
        operation::end_op_with_bag(
            &mut vault, &op, &op_cap, bag, tx_bag,
            balance::zero(), balance::zero()
        ); // Transaction reverts here
        
        // Vault status remains VAULT_DURING_OPERATION_STATUS from Phase 1
        // Assets are permanently gone, vault is bricked
    };
    
    // Verify: Admin cannot recover
    test_scenario::next_tx(&mut scenario, @0xADMIN);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
        
        // This ABORTS due to assertion at line 523
        vault_manage::set_vault_enabled(&admin_cap, &mut vault, true); // FAILS
        
        test_scenario::return_shared(vault);
        test_scenario::return_to_sender(&scenario, admin_cap);
    };
    
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability exploits the multi-transaction nature of Sui Move operations where the operator receives custody of a mutable Bag object between operation phases. The lack of validation in `end_op_with_bag()` combined with the absence of admin recovery mechanisms creates an irreversible attack vector.

The operator freeze mechanism's existence confirms that operators are explicitly untrusted actors in the protocol's threat model, making this a valid privilege escalation vulnerability rather than a trusted-role assumption violation.

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

**File:** volo-vault/sources/operation.move (L94-206)
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

**File:** volo-vault/sources/volo_vault.move (L380-393)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}

public fun operator_freezed(operation: &Operation, op_cap_id: address): bool {
    if (operation.freezed_operators.contains(op_cap_id)) {
        *operation.freezed_operators.borrow(op_cap_id)
    } else {
        false
    }
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

**File:** volo-vault/sources/volo_vault.move (L1415-1434)
```text
public(package) fun borrow_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
): AssetType {
    self.check_version();
    self.assert_enabled();

    assert!(contains_asset_type(self, asset_type), ERR_ASSET_TYPE_NOT_FOUND);

    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };

    emit(DefiAssetBorrowed {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
}
```
