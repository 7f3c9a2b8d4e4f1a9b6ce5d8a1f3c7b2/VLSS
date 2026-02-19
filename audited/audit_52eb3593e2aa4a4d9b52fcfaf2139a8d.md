### Title
AccountCap Type Incompatibility After Module Upgrade Causes Vault Operation Failure

### Summary
When the `lending_core` module is upgraded in Sui Move, the package ID changes, making all existing `AccountCap` objects incompatible with the new module's type signatures. Since the Volo Vault stores `AccountCap` objects in dynamic storage bags and retrieves them using type parameters, any module upgrade will cause type mismatches that prevent the vault from accessing stored Navi lending positions, breaking position valuation and blocking vault operations including user withdrawals.

### Finding Description

**Root Cause: Sui Move Type System and Package IDs**

In Sui Move, types are fully qualified with their package ID (e.g., `0xOLD::lending_core::account::AccountCap`). When a module is upgraded, a new package is published with a different package ID, creating incompatible types even if the struct definition remains unchanged. [1](#0-0) 

**Critical Usage Pattern in Vault**

The Volo Vault stores `AccountCap` objects as DeFi assets in dynamic storage bags. During operations, it borrows these capabilities using explicit type parameters: [2](#0-1) 

The vault later returns these assets using the same type-based lookup: [3](#0-2) 

**Position Valuation Dependency**

The Navi adaptor requires access to the `AccountCap` to calculate position values. It retrieves the capability and extracts the owner address: [4](#0-3) 

**Failure Mechanism After Upgrade**

1. Before upgrade: Vault stores `OLD_PACKAGE::lending_core::account::AccountCap` in bag
2. After upgrade: Code references `NEW_PACKAGE::lending_core::account::AccountCap`
3. Type mismatch: Bag lookups fail because stored type ≠ requested type
4. Operations fail: Cannot retrieve AccountCap → Cannot get owner address → Cannot calculate position value
5. Vault blocked: Position valuation is required for operation value checks: [5](#0-4) 

**No Migration Mechanism**

The codebase lacks any migration mechanism to handle AccountCap type transitions. The account module only provides basic creation and deletion functions: [6](#0-5) 

### Impact Explanation

**Direct Operational Impact - Vault Operations Blocked**

After a `lending_core` module upgrade, any vault holding Navi `AccountCap` objects will experience complete operational failure:

1. **Position Valuation Failure**: The vault cannot retrieve stored AccountCaps due to type mismatch, preventing calculation of Navi lending position values
2. **Operation Blocking**: Value updates are mandatory for completing operations. The vault checks operation value changes and enforces loss tolerance: [7](#0-6) 

3. **Withdrawal Denial**: Users cannot withdraw funds because vault operations cannot complete without valid position valuation
4. **Permanent Lockup**: Without a migration path, user funds remain locked indefinitely

**Affected Parties**
- All users with deposits in vaults using Navi integration
- Protocol operators unable to manage vault operations
- All deposited principal funds become inaccessible

**Severity Justification: HIGH**

This meets HIGH severity criteria because:
- Direct fund custody impact: User deposits become inaccessible
- Complete operational disruption: Vault cannot perform any operations requiring Navi position data
- Permanent without intervention: No automatic recovery mechanism exists
- Wide scope: Affects all vaults integrated with Navi protocol

### Likelihood Explanation

**Certainty: Guaranteed on Module Upgrade**

This is not an "attack" but a guaranteed failure condition triggered by legitimate module upgrades:

**Preconditions (Minimal)**
1. Vault has stored AccountCap objects from Navi integration
2. `lending_core` module undergoes package upgrade

**Execution Path (Automatic)**
- No attacker action required
- Sui Move type system automatically enforces package ID matching
- First operation after upgrade attempting to access AccountCap will fail

**Feasibility: Standard Operations**
- Module upgrades are standard protocol maintenance
- The Volo codebase shows upgrade patterns for other modules: [8](#0-7) 

- No indication that `lending_core` would be exempted from future upgrades

**Probability Assessment: HIGH**

Over the protocol's lifetime, module upgrades are expected for:
- Bug fixes and security patches
- Feature additions
- Performance optimizations
- Dependency updates

Each upgrade event will trigger this failure for all affected vaults.

### Recommendation

**Immediate Mitigation: Implement Type-Agnostic Storage Pattern**

1. **Add Version-Based AccountCap Wrapper**
```
Create a wrapper struct owned by the vault package that stores AccountCap 
with version metadata, allowing gradual migration
```

2. **Implement Migration Entry Function**
```
Add admin-gated function to:
    - Extract old AccountCaps from vault storage
    - Wrap or re-create with new package type
    - Re-insert into vault storage with new type key
```

3. **Add Pre-Upgrade Checklist**
Before any `lending_core` upgrade:
    - Identify all vaults holding AccountCaps
    - Execute migration for each vault
    - Verify new AccountCaps accessible post-upgrade
    - Test position valuation with new types

**Long-term Solution: Decouple AccountCap Storage**

Store only the derived owner address (not the capability itself) in vault storage, and maintain AccountCaps separately with explicit migration support. This requires architectural changes to the Navi integration pattern.

**Test Cases to Add**
1. Simulate module upgrade by creating AccountCap with test package, upgrading to new package, and verifying retrieval fails
2. Test migration function successfully transfers AccountCaps between old and new type storage
3. Verify position valuation works correctly after migration

### Proof of Concept

**Initial State:**
1. Deploy `lending_core` package with ID `0xOLD`
2. Vault creates and stores AccountCap: `bag.add<String, 0xOLD::account::AccountCap>(key, cap)`
3. Position valuation succeeds: `vault.get_defi_asset<T, 0xOLD::account::AccountCap>(key)`

**Upgrade Sequence:**
1. Upgrade `lending_core` module → New package ID `0xNEW` assigned
2. Vault code now references: `0xNEW::lending_core::account::AccountCap`
3. Stored object remains: `0xOLD::lending_core::account::AccountCap`

**Expected Result:**
Vault retrieves AccountCap successfully and calculates Navi position value

**Actual Result:**
1. Vault attempts: `vault.get_defi_asset<T, 0xNEW::account::AccountCap>(key)`
2. Bag lookup searches for: `0xNEW::account::AccountCap` type
3. Stored object has type: `0xOLD::account::AccountCap`
4. Type mismatch → Bag lookup returns none or aborts
5. `update_navi_position_value` fails → Cannot calculate total_usd_value
6. `end_op_value_update_with_bag` cannot complete → Vault stuck in operation status
7. All subsequent operations blocked → User withdrawals denied

**Success Condition for Vulnerability:**
Demonstrate that after module upgrade, the type-parameterized bag retrieval fails due to package ID mismatch, blocking vault operations that depend on AccountCap access.

### Notes

This vulnerability is distinct from application-level version control (version fields in structs) demonstrated elsewhere in the codebase. The issue stems from Sui Move's type system treating objects from different package IDs as fundamentally incompatible types, even with identical struct definitions. While the codebase shows sophisticated version management for shared objects, it lacks awareness that owned objects stored in dynamic collections face type compatibility issues across package upgrades.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L8-11)
```text
    struct AccountCap has key, store {
        id: UID,
        owner: address
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L13-32)
```text
    public(friend) fun create_account_cap(ctx: &mut TxContext): AccountCap {
        let id = object::new(ctx);
        let owner = object::uid_to_address(&id);
        AccountCap { id, owner}
    }

    public(friend) fun create_child_account_cap(parent_account_cap: &AccountCap, ctx: &mut TxContext): AccountCap {
        let owner = parent_account_cap.owner;
        assert!(object::uid_to_address(&parent_account_cap.id) == owner, error::required_parent_account_cap());

        AccountCap {
            id: object::new(ctx),
            owner: owner
        }
    }

    public(friend) fun delete_account_cap(cap: AccountCap) {
        let AccountCap { id, owner: _} = cap;
        object::delete(id)
    }
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

**File:** volo-vault/sources/operation.move (L353-377)
```text
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

**File:** volo-vault/sources/volo_vault.move (L464-469)
```text
public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
```
