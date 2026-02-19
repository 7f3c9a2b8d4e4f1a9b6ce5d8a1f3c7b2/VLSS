### Title
Unbounded Asset Type Growth Causes Vault Object Size Limit DoS

### Summary
The Volo vault's `asset_types` vector can grow without limit as operators add new coin-type or DeFi assets, directly analogous to the external `StorageNodeInfo` unbounded field issue. Once the Vault object approaches Sui's `max_move_object_size` limit (~250KB), all vault operations fail permanently, including deposits, withdrawals, and even asset removal operations, effectively locking all user funds with no recovery path.

### Finding Description

The vulnerability exists in the vault's asset management system where operators can add unlimited asset types to the `asset_types` vector without any maximum size enforcement.

**Root Cause:**

The Vault struct stores all registered asset types in an unbounded vector [1](#0-0) .

When operators add new assets via `add_new_coin_type_asset` or `add_new_defi_asset`, the internal `set_new_asset_type` function unconditionally pushes to this vector [2](#0-1) . The only check is for duplicate asset types (`ERR_ASSET_TYPE_ALREADY_EXISTS`), but no maximum count limit exists.

**Exploit Path:**

1. Operator with `OperatorCap` calls `operation::add_new_coin_type_asset` repeatedly with different type parameters [3](#0-2)  or `operation::add_new_defi_asset` [4](#0-3) 

2. Each call invokes the vault's `add_new_coin_type_asset` [5](#0-4)  or `add_new_defi_asset` [6](#0-5) , which adds an entry to the `asset_types` vector plus corresponding Table entries

3. Each asset type string (~50-100 bytes) plus associated Table entries (~200-300 bytes total per asset) accumulates in the Vault object

4. After adding ~1000-2000 unique asset types (achievable by deploying modules with many dummy struct types), the Vault object approaches the `max_move_object_size` limit

5. At this threshold, ANY transaction attempting to modify the Vault object fails, including:
   - User deposit/withdraw executions
   - Operator operations (start_op/end_op)
   - Asset removal attempts via `remove_coin_type_asset` [7](#0-6) 
   - Admin configuration changes

**Why Existing Protections Fail:**

- No `MAX_ASSET_TYPES` constant or enforcement exists (unlike `MAX_VALIDATORS = 50` in liquid_staking validator_pool)
- Duplicate check only prevents re-adding the same type, not limiting total count
- Removal functions exist but become unusable once object is too large, as they also require modifying the Vault object
- Operator freeze mechanism cannot prevent quick execution before freezing
- The asset type is derived from Type parameters, making it trivial to create unique types by deploying modules with many dummy structs

### Impact Explanation

**Severity: HIGH - Complete Vault Denial of Service**

Once the Vault object exceeds the modifiable size threshold:

1. **User Fund Lock**: All user deposits already in `deposit_coin_buffer` and pending withdrawals cannot be processed. Users cannot execute new deposits or withdrawals.

2. **DeFi Position Lock**: All DeFi positions held by the vault (Navi, Suilend, Cetus, Momentum) become unmanageable, as operators cannot call `start_op_with_bag` or `end_op_with_bag`.

3. **Permanent State**: No recovery mechanism exists:
   - Cannot remove assets (removal also modifies vault)
   - Cannot migrate/upgrade (requires modifying vault)
   - Cannot process any user requests
   - Admin operations blocked

4. **Multi-Vault Impact**: If attacker is an operator across multiple vaults, can DOS all of them simultaneously.

### Likelihood Explanation

**Likelihood: MEDIUM-HIGH - Realistic Operator Attack**

**Feasibility:**
- Requires `OperatorCap`, which is a semi-trusted but realistic threat (compromised operator, malicious insider, or operator key theft)
- Attack cost: ~2 SUI (1 SUI to deploy module with 1000 dummy types + ~0.001 SUI × 1000 for gas)
- Execution time: Minutes to execute all transactions
- No admin intervention can stop it once started (operator freeze would require detecting the attack pattern)

**Preconditions:**
- Operator must have unfrozen `OperatorCap` (normal operating condition)
- Vault must be in `VAULT_NORMAL_STATUS` for coin-type assets or any enabled status for DeFi assets
- Attacker deploys a module with many dummy struct definitions or references existing types across the ecosystem

**Realistic Scenario:**
A disgruntled or compromised operator executes the attack in a short timeframe before detection. The operator freeze mechanism is reactive, not preventative, making this attack realistic before admin intervention.

### Recommendation

Implement a maximum asset type limit with strict enforcement:

```move
// In vault.move constants section
const MAX_ASSET_TYPES: u64 = 50; // Conservative limit

// Add error constant
const ERR_EXCEED_MAX_ASSET_TYPES: u64 = 5_XXX;

// In set_new_asset_type function, add check after line 1362:
assert!(self.asset_types.length() < MAX_ASSET_TYPES, ERR_EXCEED_MAX_ASSET_TYPES);
```

Additional recommendations:
1. Enforce the limit in `set_new_asset_type` before pushing to the vector
2. Document the maximum asset types in protocol documentation
3. Monitor asset type count via off-chain monitoring
4. Consider implementing emergency asset removal that bypasses normal checks if count exceeds safe threshold (requires careful design to prevent abuse)

### Proof of Concept

**Setup:**
1. Deploy a module `DummyAssets` containing many struct definitions:
   ```
   module attacker::dummy_assets {
       public struct Asset1 has drop {}
       public struct Asset2 has drop {}
       // ... repeat for Asset3 to Asset1500
   }
   ```

**Execution Steps:**

1. Operator calls `operation::add_new_coin_type_asset<USDC, attacker::dummy_assets::Asset1>(operation, op_cap, vault)`
2. Repeat for Asset2, Asset3, ..., Asset1500
3. Each call succeeds, adding to `asset_types` vector
4. After ~1000-1500 additions, Vault object size approaches 200-250KB

**Result Verification:**

5. Attempt user deposit execution: `operation::execute_deposit(...)` → **FAILS** (object too large to modify)
6. Attempt operator operation: `operation::start_op_with_bag(...)` → **FAILS** (object too large to modify)  
7. Attempt asset removal: `operation::remove_coin_type_asset<USDC, attacker::dummy_assets::Asset1>(...)` → **FAILS** (object too large to modify)
8. All vault operations permanently blocked, user funds locked

**Cost Analysis:**
- Deploy DummyAssets module: ~1 SUI
- 1500 × add_new_coin_type_asset calls: ~1.5 SUI gas
- Total attack cost: ~2.5 SUI for complete vault DoS

### Citations

**File:** volo-vault/sources/volo_vault.move (L113-113)
```text
    asset_types: vector<String>, // All assets types, used for looping
```

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

**File:** volo-vault/sources/volo_vault.move (L1461-1476)
```text
public(package) fun add_new_coin_type_asset<PrincipalCoinType, AssetType>(
    self: &mut Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_normal();
    assert!(
        type_name::get<AssetType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<AssetType>().into_string();
    set_new_asset_type(self, asset_type);

    // Add the asset to the assets table (initial as 0 balance)
    self.assets.add(asset_type, balance::zero<AssetType>());
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

**File:** volo-vault/sources/operation.move (L547-554)
```text
public fun add_new_coin_type_asset<PrincipalCoinType, AssetType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_coin_type_asset<PrincipalCoinType, AssetType>();
}
```

**File:** volo-vault/sources/operation.move (L565-574)
```text
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```
