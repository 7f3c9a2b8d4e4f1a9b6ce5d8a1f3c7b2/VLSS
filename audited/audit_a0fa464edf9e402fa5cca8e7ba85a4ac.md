### Title
Operator Can Permanently Brick Vault by Manipulating DeFi Asset Bag Between Operation Phases

### Summary
The `end_op_with_bag()` function iterates through `defi_asset_ids` from TxBag and attempts to remove each asset from the operator-controlled `defi_assets` Bag without validating the assets exist first. Since `bag::remove()` aborts on missing keys in Sui Move, an operator can cause permanent vault DoS by removing assets from the Bag before calling `end_op_with_bag()`, leaving the vault stuck in VAULT_DURING_OPERATION_STATUS with no admin recovery mechanism.

### Finding Description

**Root Cause**: Unchecked Bag removal operation with mismatch between immutable TxBag record and mutable operator-controlled Bag.

In `start_op_with_bag()`, assets are borrowed from the vault and placed in a temporary Bag that is returned to the operator alongside an immutable TxBag recording which assets were borrowed: [1](#0-0) 

The TxBag struct immutably records the asset IDs and types: [2](#0-1) 

In `end_op_with_bag()`, the function unpacks TxBag and loops through all recorded assets, attempting to remove each from the mutable `defi_assets` Bag: [3](#0-2) 

**Critical Flaw**: The loop iterates `length` times based on `defi_asset_ids.length()` (line 229), but there is NO validation that the Bag actually contains these assets before calling `defi_assets.remove()`. In Sui Move, `bag::remove()` aborts if the key doesn't exist, causing transaction reversion.

**Why Protections Fail**:
1. The operator receives the mutable `defi_assets` Bag and can manipulate it between transactions
2. No pre-validation checks that Bag contains expected assets exist before the removal loop
3. Each if-statement (lines 235-271) calls `remove()` which will abort on missing keys
4. The `destroy_empty()` call at line 296 never executes if abort occurs earlier [4](#0-3) 

**No Recovery Mechanism**: When the vault gets stuck in VAULT_DURING_OPERATION_STATUS, the admin cannot use `set_vault_enabled()` to recover because it explicitly rejects this state: [5](#0-4) 

### Impact Explanation

**Operational Impact - Permanent Vault DoS**:
- Vault becomes permanently stuck in VAULT_DURING_OPERATION_STATUS with no recovery path
- Borrowed DeFi assets (NaviAccountCap, CetusPosition, SuilendObligationOwnerCap, MomentumPosition, Receipt) are lost from vault custody
- No new operations can be started since vault is already "during operation"
- Users cannot deposit or withdraw funds (vault operations require VAULT_NORMAL_STATUS)
- Admin has zero recovery options due to the ERR_VAULT_DURING_OPERATION check

**Custody/Receipt Integrity Impact**:
- Assets removed from vault's Bag during `borrow_defi_asset()` are now unrecoverable: [6](#0-5) 

- These assets cannot be returned via `return_defi_asset()` because the operation never completes
- Operator effectively steals the removed assets while vault records them as "borrowed"

**Severity**: HIGH - Complete protocol failure with asset loss and no recovery mechanism.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is triggered through standard operation flow callable by any operator with OperatorCap:
- `start_op_with_bag()` is a public function
- Operator receives mutable Bag between transactions
- `end_op_with_bag()` is a public function accepting operator-controlled parameters

**Feasible Preconditions**:
- Attacker needs OperatorCap (but operators can be malicious, as evidenced by operator freeze mechanism)
- No technical barriers - operator simply calls `bag::remove()` on the returned Bag before calling `end_op_with_bag()`

**Execution Practicality**: 
1. Call `start_op_with_bag()` requesting 5 assets → receives Bag with 5 assets
2. In separate transaction, call `bag::remove()` to extract 2 assets from the Bag
3. Call `end_op_with_bag()` with manipulated Bag containing only 3 assets
4. Loop attempts to remove asset #4 → `bag::remove()` aborts → vault permanently stuck

**Economic Rationality**: 
- Zero cost attack (just gas fees)
- Operator can steal extracted assets while causing permanent vault DoS
- Frozen operator could execute this as revenge attack
- Accidental triggering possible if operator makes programming error in custom operation logic

### Recommendation

**Immediate Fix**: Add pre-validation before removal loop in `end_op_with_bag()`:

```move
// After line 229, before line 230:
let mut i = 0;
while (i < length) {
    let defi_asset_id = defi_asset_ids[i];
    let defi_asset_type = defi_asset_types[i];
    
    // Validate asset exists in Bag before attempting removal
    if (defi_asset_type == type_name::get<NaviAccountCap>()) {
        let key = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
        assert!(defi_assets.contains<String>(key), ERR_ASSETS_NOT_RETURNED);
    };
    // ... repeat for all asset types ...
    
    i = i + 1;
};

// Then proceed with existing removal loop
```

**Additional Safeguards**:
1. Add admin emergency function to forcibly reset vault status from VAULT_DURING_OPERATION_STATUS:
```move
public fun emergency_reset_vault_status<T>(
    _: &AdminCap,
    vault: &mut Vault<T>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

2. Add operator bond/collateral requirement that gets slashed if operation doesn't complete properly

3. Add `bag::length()` check to ensure Bag size matches expected asset count

**Test Cases**:
- Test operator removing 1 asset from Bag before `end_op_with_bag()` → should abort with ERR_ASSETS_NOT_RETURNED
- Test operator removing all assets → should abort  
- Test operator adding extra assets → should be caught by existing `destroy_empty()` check
- Test admin emergency recovery after stuck vault

### Proof of Concept

**Initial State**:
- Vault in VAULT_NORMAL_STATUS
- Vault contains 5 DeFi assets (3 NaviAccountCap, 1 CetusPosition, 1 Receipt)
- Operator has valid OperatorCap (not frozen)

**Attack Steps**:

**Transaction 1 - Start Operation**:
```move
let (defi_assets_bag, tx_bag, tx_check, principal, coin_asset) = 
    operation::start_op_with_bag<SUI, USDC, SUI>(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[0u8, 1u8, 2u8, 3u8, 4u8], // 5 asset IDs
        vector[type_name::get<NaviAccountCap>(), ...], // 5 types
        1_000_000,
        0,
        ctx
    );
// Vault status → VAULT_DURING_OPERATION_STATUS
// defi_assets_bag contains 5 assets
```

**Transaction 2 - Manipulate Bag**:
```move
// Operator removes 2 assets from the Bag
let stolen_asset_1 = defi_assets_bag.remove<String, NaviAccountCap>("navi_0");
let stolen_asset_2 = defi_assets_bag.remove<String, CetusPosition>("cetus_3");
// Transfer or keep stolen assets
// defi_assets_bag now contains only 3 assets
```

**Transaction 3 - Attempt to End Operation**:
```move
operation::end_op_with_bag<SUI, USDC, SUI>(
    &mut vault,
    &operation,
    &operator_cap,
    defi_assets_bag,  // Contains only 3 assets
    tx_bag,           // Records 5 assets
    principal,
    coin_asset
);
// Loop iteration 4 tries: defi_assets.remove<String, NaviAccountCap>("navi_0")
// ABORTS - key "navi_0" doesn't exist in Bag
// Transaction reverts
```

**Expected vs Actual Result**:
- **Expected**: Operation completes, assets returned, vault status reset to VAULT_NORMAL_STATUS
- **Actual**: Transaction aborts at line 237, vault permanently stuck in VAULT_DURING_OPERATION_STATUS, 2 assets stolen, 3 assets unrecoverable, vault completely non-functional

**Success Condition**: 
- Vault status remains VAULT_DURING_OPERATION_STATUS after failed `end_op_with_bag()`
- Admin cannot call `set_vault_enabled()` (aborts with ERR_VAULT_DURING_OPERATION)
- No recovery mechanism exists
- Operator successfully extracted 2 assets

### Citations

**File:** volo-vault/sources/operation.move (L80-84)
```text
public struct TxBag {
    vault_id: address,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
}
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

**File:** volo-vault/sources/operation.move (L221-274)
```text
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
```

**File:** volo-vault/sources/operation.move (L296-296)
```text
    defi_assets.destroy_empty();
```

**File:** volo-vault/sources/volo_vault.move (L520-531)
```text
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
