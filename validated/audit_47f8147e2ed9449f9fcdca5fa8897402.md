### Title
Incomplete Cleanup in `remove_defi_asset_support` Causes Permanent Asset Type DoS

### Summary
The `remove_defi_asset_support` function fails to remove entries from the `assets_value` and `assets_value_updated` tables while removing the asset type from other storage locations. This incomplete cleanup prevents the same asset type from ever being re-added to the vault, causing permanent denial of service for specific DeFi protocol integrations.

### Finding Description

This vulnerability is directly analogous to the external report's "Vault Closure" issue where incomplete cleanup wastes storage and creates operational problems.

**Root Cause in Volo:** [1](#0-0) 

The `remove_defi_asset_support` function removes the asset type from:
- `asset_types` vector (line 1401)
- `assets` bag (line 1412)

But FAILS to remove from:
- `assets_value` table (missing cleanup)
- `assets_value_updated` table (missing cleanup)

**Comparison with correct implementation:** [2](#0-1) 

The `remove_coin_type_asset` function properly cleans up ALL four storage locations (lines 1492, 1495, 1498, 1499), including both tables.

**Why Protections Fail:**

When attempting to re-add the same asset type via `add_new_defi_asset`: [3](#0-2) 

The function calls `set_new_asset_type`: [4](#0-3) 

Line 1362 checks only `asset_types` vector (which was cleaned up), so it passes. However, lines 1365-1366 attempt to call `table::add()` with keys that already exist from the previous incomplete removal. In Move, `table::add()` aborts if the key exists, causing the transaction to fail.

**Public Entry Point:** [5](#0-4) 

Operators can call this function to remove mistakenly added DeFi assets.

### Impact Explanation

**High-Confidence Protocol DoS:**

Once a DeFi asset type (e.g., Navi lending position, Suilend position, Cetus LP position, Momentum position) is removed via `remove_defi_asset_support`, that specific asset type becomes permanently blocked from being added back to the vault. 

This severely restricts the vault's investment strategies:
- Cannot re-integrate with important DeFi protocols like Navi, Suilend, Cetus, or Momentum after removal
- No recovery mechanism exists without deploying an entirely new vault
- All existing user deposits in the affected vault are locked into degraded investment strategies
- Protocol cannot adapt to changing market conditions or fix integration mistakes

The storage waste aspect is secondary but compounds over repeated add/remove cycles.

### Likelihood Explanation

**High Likelihood - Realistic Operator Workflow:**

1. **Intended Use Case**: The function comment states "The asset must be added by mistake" (line 1389), indicating this is designed for error correction scenarios.

2. **Realistic Scenario**: 
   - Operator integrates new DeFi protocol (e.g., Navi lending)
   - Discovers integration issue or better alternative
   - Removes the asset using `remove_defi_asset_support`
   - Later attempts to re-add (either same protocol fixed, or different idx for same type)
   - Permanent failure occurs

3. **Preconditions**: Only requires OperatorCap, which is deliberately delegated for operational flexibility

4. **Not Blocked**: No validation prevents this sequence; the check at line 1362 only verifies `asset_types` vector, not the orphaned table entries

### Recommendation

Modify `remove_defi_asset_support` to match the complete cleanup pattern of `remove_coin_type_asset`:

```move
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();

    let asset_type = vault_utils::parse_key<AssetType>(idx);

    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    self.asset_types.remove(index);

    let asset_value = self.assets_value[asset_type];
    let asset_value_updated = self.assets_value_updated[asset_type];
    assert!(asset_value == 0 || asset_value_updated == 0, ERR_ASSET_TYPE_NOT_FOUND);

    // ADD THESE TWO LINES:
    self.assets_value.remove(asset_type);
    self.assets_value_updated.remove(asset_type);

    emit(DefiAssetRemoved {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
}
```

### Proof of Concept

**Step-by-step exploit:**

1. **Initial State**: Vault exists with principal coin type SUI

2. **Operator adds Navi integration**:
   - Calls `operation::add_new_defi_asset<SUI, NaviAccountCap>(operation, cap, vault, 0, navi_cap)`
   - Asset type `"NaviAccountCap_0"` added to: `asset_types`, `assets`, `assets_value`, `assets_value_updated`

3. **Operator removes asset (mistake correction)**:
   - Calls `operation::remove_defi_asset_support<SUI, NaviAccountCap>(operation, cap, vault, 0)`
   - Asset type `"NaviAccountCap_0"` removed from: `asset_types`, `assets`
   - **BUT** entries remain in: `assets_value`, `assets_value_updated`

4. **Operator attempts to re-add Navi**:
   - Calls `operation::add_new_defi_asset<SUI, NaviAccountCap>(operation, cap, vault, 0, new_navi_cap)`
   - Reaches `set_new_asset_type` at line 1384
   - Check at line 1362 passes (asset not in `asset_types` vector)
   - Line 1365: `self.assets_value.add(asset_type, 0)` **ABORTS** - key already exists
   - Transaction fails permanently

5. **Result**: Asset type `"NaviAccountCap_0"` is permanently blocked. The vault can never integrate with Navi protocol again.

**Verification**: Test case at lines 100-130 of assets.test.move only verifies `!vault.contains_asset_type(navi_asset_type)` but does not attempt re-adding, missing this DoS condition. [6](#0-5)

### Citations

**File:** volo-vault/sources/volo_vault.move (L1353-1372)
```text
public(package) fun set_new_asset_type<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    // assert!(!self.assets.contains(asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);
    assert!(!self.asset_types.contains(&asset_type), ERR_ASSET_TYPE_ALREADY_EXISTS);

    self.asset_types.push_back(asset_type);
    self.assets_value.add(asset_type, 0);
    self.assets_value_updated.add(asset_type, 0);

    emit(NewAssetTypeAdded {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });
}
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

**File:** volo-vault/sources/volo_vault.move (L1390-1413)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();

    let asset_type = vault_utils::parse_key<AssetType>(idx);

    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    self.asset_types.remove(index);

    let asset_value = self.assets_value[asset_type];
    let asset_value_updated = self.assets_value_updated[asset_type];
    assert!(asset_value == 0 || asset_value_updated == 0, ERR_ASSET_TYPE_NOT_FOUND);

    emit(DefiAssetRemoved {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
}
```

**File:** volo-vault/sources/volo_vault.move (L1478-1505)
```text
public(package) fun remove_coin_type_asset<PrincipalCoinType, AssetType>(
    self: &mut Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_normal();
    assert!(
        type_name::get<AssetType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<AssetType>().into_string();

    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    self.asset_types.remove(index);

    // The coin type asset must have 0 balance
    let removed_balance = self.assets.remove<String, Balance<AssetType>>(asset_type);
    removed_balance.destroy_zero();

    self.assets_value.remove(asset_type);
    self.assets_value_updated.remove(asset_type);

    emit(CoinTypeAssetRemoved {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });
}
```

**File:** volo-vault/sources/operation.move (L576-584)
```text
public fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    vault::assert_operator_not_freezed(operation, cap);
    vault.remove_defi_asset_support(idx)
}
```

**File:** volo-vault/tests/update/assets.test.move (L100-130)
```text
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();

        let navi_account_cap = operation::remove_defi_asset_support<SUI_TEST_COIN, NaviAccountCap>(
            &operation,
            &cap,
            &mut vault,
            0,
        );
        transfer::public_transfer(navi_account_cap, OWNER);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
    };

    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        assert!(!vault.contains_asset_type(navi_asset_type));

        test_scenario::return_shared(vault);
    };

    clock.destroy_for_testing();
    s.end();
}
```
