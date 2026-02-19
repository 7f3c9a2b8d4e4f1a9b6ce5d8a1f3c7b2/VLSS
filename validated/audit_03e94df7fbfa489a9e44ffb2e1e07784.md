# Audit Report

## Title
Operator Can Permanently Brick Vault by Manipulating DeFi Asset Bag Between Operation Phases

## Summary
A malicious or compromised operator can permanently disable a vault by manipulating the DeFi asset Bag between `start_op_with_bag()` and `end_op_with_bag()` calls. When the operator removes assets from the Bag before calling `end_op_with_bag()`, the function's unchecked `bag::remove()` calls abort, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no admin recovery mechanism.

## Finding Description

The vulnerability exists in the three-phase operation flow where operators borrow DeFi assets from the vault. In `start_op_with_bag()`, the vault's status is changed to `VAULT_DURING_OPERATION_STATUS` [1](#0-0) , and assets are borrowed from the vault into a new temporary Bag that is returned to the operator [2](#0-1) . A TxBag struct immutably records which assets were borrowed [3](#0-2) .

The critical flaw occurs in `end_op_with_bag()`. This function unpacks the TxBag and loops through all recorded asset IDs, attempting to remove each asset from the operator-provided Bag without first validating the assets exist [4](#0-3) . In Sui Move, `bag::remove()` aborts if the key doesn't exist—this behavior is confirmed by the test case that expects abort code 0x1 when an asset is missing [5](#0-4) .

**Attack Vector**: Between `start_op_with_bag()` and `end_op_with_bag()` transactions, the operator owns the Bag and can manipulate it by calling standard Sui Move functions to remove assets. When `end_op_with_bag()` subsequently tries to remove those same assets, the transaction aborts before reaching `destroy_empty()` [6](#0-5)  or the status reset in `end_op_value_update_with_bag()` [7](#0-6) .

**No Recovery Mechanism**: The admin cannot recover the vault because `set_vault_enabled()` explicitly rejects vaults in `VAULT_DURING_OPERATION_STATUS` [8](#0-7) . This is confirmed by a test case that expects this function to fail with `ERR_VAULT_DURING_OPERATION` [9](#0-8) . The only `set_status()` function that could bypass this check is marked `public(package)` and not exposed through any admin interface [10](#0-9) .

## Impact Explanation

**Severity: HIGH - Complete Protocol Failure**

The impact is catastrophic and permanent:

1. **Permanent Vault DoS**: The vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all critical operations including user deposits, withdrawals, and new operator operations.

2. **Asset Loss**: DeFi assets (NaviAccountCap, CetusPosition, SuilendObligationOwnerCap, MomentumPosition, Receipt) borrowed from the vault cannot be returned. These assets are effectively stolen by the operator who removed them from the Bag.

3. **Zero Recovery Path**: Unlike temporary issues, there is absolutely no mechanism for the admin to recover the vault. The explicit check in `set_vault_enabled()` prevents any status change while in `VAULT_DURING_OPERATION_STATUS`.

4. **User Fund Lock**: All users with deposited funds lose access to their assets as the vault cannot process withdrawals in this state.

## Likelihood Explanation

**Likelihood: HIGH - Easily Executable**

The attack is highly feasible:

1. **Public Entry Points**: Both `start_op_with_bag()` and `end_op_with_bag()` are public functions callable by any operator with OperatorCap [11](#0-10) .

2. **Standard Role Required**: The attacker only needs OperatorCap, which is a legitimate operational role. The existence of an operator freeze mechanism [12](#0-11)  indicates that malicious operators are within the threat model.

3. **Zero Technical Barriers**: In Sui Move's ownership model, the operator receives the Bag as an owned object and can freely manipulate it between transactions by calling standard library functions like `bag::remove()`.

4. **Economic Rationality**: The attack costs only gas fees but enables the operator to steal DeFi assets while permanently disabling the entire vault, making it attractive for revenge attacks by frozen operators or opportunistic theft.

5. **Confirmed Behavior**: The test suite explicitly validates that removing assets from the Bag causes `end_op_with_bag()` to abort [13](#0-12) , proving the technical feasibility.

## Recommendation

Implement pre-validation checks in `end_op_with_bag()` before attempting to remove assets from the Bag:

```move
public fun end_op_with_bag<T, CoinType, ObligationType>(
    // ... parameters ...
) {
    // ... existing checks ...
    
    // ADDED: Validate all assets exist before attempting removal
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];
        
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let key = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(defi_assets.contains<String, NaviAccountCap>(key), ERR_ASSETS_NOT_RETURNED);
        };
        // ... repeat for other asset types ...
        
        i = i + 1;
    };
    
    // Now proceed with actual removal
    // ... existing removal logic ...
}
```

Additionally, add an emergency admin function to force-reset vault status when stuck in `VAULT_DURING_OPERATION_STATUS` for more than a specified timeout period.

## Proof of Concept

The existing test at lines 1417-1527 of `volo-vault/tests/operation/operation.test.move` demonstrates the core vulnerability: when an asset is removed from the Bag (line 1513-1516), the subsequent call to `end_op_with_bag()` (line 1519) aborts with error code 0x1. While this test validates the abort behavior, it doesn't test the permanent vault lock that results from this abort, which is the critical security impact.

A complete PoC would extend this test to show:
1. Vault status remains `VAULT_DURING_OPERATION_STATUS` after abort
2. Admin `set_vault_enabled()` call fails with `ERR_VAULT_DURING_OPERATION`
3. No subsequent operations can be performed on the vault
4. Assets remain unrecoverable

## Notes

This vulnerability exploits a fundamental mismatch between the immutable TxBag record and the mutable operator-owned Bag. The protocol assumes operators will act honestly with owned assets between transactions, but Sui Move's ownership model provides no enforcement of this assumption. The operator freeze mechanism suggests the protocol designers anticipated malicious operators, but this specific attack vector was not adequately protected against.

### Citations

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L80-84)
```text
public struct TxBag {
    vault_id: address,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
}
```

**File:** volo-vault/sources/operation.move (L94-94)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
```

**File:** volo-vault/sources/operation.move (L108-162)
```text
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
```

**File:** volo-vault/sources/operation.move (L229-274)
```text
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
```

**File:** volo-vault/sources/operation.move (L296-296)
```text
    defi_assets.destroy_empty();
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/tests/operation/operation.test.move (L1417-1420)
```text
#[test]
#[expected_failure(abort_code = 0x1)]
// [TEST-CASE: Should do op fail if assets bag lose asset.] @test-case OPERATION-011
public fun test_start_op_fail_assets_bag_lose_asset() {
```

**File:** volo-vault/tests/operation/operation.test.move (L1513-1527)
```text
        let navi_account_cap = asset_bag.remove<String, NaviAccountCap>(
            vault_utils::parse_key<NaviAccountCap>(0),
        );
        transfer::public_transfer(navi_account_cap, OWNER);

        // Step 2
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            asset_bag,
            tx_bag,
            principal_balance,
            coin_type_asset_balance,
        );
```

**File:** volo-vault/tests/operation/operation.test.move (L3797-3800)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION, location = vault)]
// [TEST-CASE: Should set vault disabled fail if vault is during operation.] @test-case OPERATION-022
public fun test_start_op_and_set_vault_enabled_fail_vault_during_operation() {
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
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

**File:** volo-vault/sources/manage.move (L88-95)
```text
public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
}
```
