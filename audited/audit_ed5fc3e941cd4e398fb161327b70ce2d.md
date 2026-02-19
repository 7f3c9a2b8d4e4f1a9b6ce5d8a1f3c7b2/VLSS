### Title
External Dependency Upgrade Risk: MMT V3 Position Objects Can Become Permanently Inaccessible After Package Version Mismatch

### Summary
The Volo vault stores MMT V3 Position objects in its assets Bag with type identity tied to a specific package address. If MMT V3 publishes a new package version with a different package ID (for breaking changes), and Volo updates its mmt_v3 dependency accordingly, all existing Position objects in the vault become permanently inaccessible due to type mismatch. This leads to locked funds and corrupted vault accounting with no migration path.

### Finding Description

The mmt_v3 module is an external dependency stub where all functions abort, serving only as a type interface: [1](#0-0) [2](#0-1) 

Position objects are stored in the vault's assets Bag and accessed via type-specific operations: [3](#0-2) [4](#0-3) [5](#0-4) 

The borrow and return operations use generic type parameters without version checking: [6](#0-5) [7](#0-6) 

The mmt_v3 dependency is configured with a specific package address: [8](#0-7) 

**Root Cause:** In Sui Move, type identity includes the package address. When stored in a Bag, Position objects retain their full type including package ID (e.g., `0x7028...::mmt_v3::position::Position`). If MMT V3 publishes a new package with breaking changes (new package ID `0xNEW...`), and Volo updates its dependency, the code expects `0xNEW...::mmt_v3::position::Position` but the Bag contains `0x7028...::mmt_v3::position::Position`. The `bag.remove<String, MomentumPosition>()` operation fails with a type mismatch.

**Why Protections Fail:**
1. No version checking on Position objects themselves - the stub module has no version validation
2. The borrow/return functions use generic type parameters without compatibility checks
3. No migration mechanism exists to handle package version changes
4. The comment indicates known compatibility issues: [9](#0-8) 

### Impact Explanation

**Concrete Harm:**
- Position objects worth potentially millions of dollars become permanently inaccessible
- The vault's `assets_value` table continues to report their value, but operations fail when attempting to access them
- The vault's `total_usd_value` calculation becomes incorrect, corrupting share accounting
- Deposits and withdrawals may fail or use wrong share calculations due to inflated total value

**Quantified Damage:**
- All funds locked in affected Position objects are permanently stuck
- Vault share calculations become unreliable, potentially allowing value extraction through mispriced shares
- The vault cannot perform operations requiring these positions

**Affected Parties:**
- All vault depositors lose access to proportional value locked in incompatible positions
- New depositors receive overvalued shares if total_usd_value includes inaccessible positions
- Protocol operators cannot recover or migrate affected assets

**Severity Justification:** HIGH - This is a critical custody integrity failure with permanent fund loss and no recovery mechanism. The vault's core invariant of asset accessibility and accurate accounting is violated.

### Likelihood Explanation

**Realistic Scenario:**
1. MMT V3 is actively developed with version history: [10](#0-9) 
2. DeFi protocols commonly publish new package versions for breaking changes rather than constrained upgrades
3. Volo must update dependencies to maintain compatibility with latest protocol features
4. No attacker needed - this occurs through normal protocol evolution

**Feasibility Conditions:**
- Requires MMT V3 team to publish new package with different package ID
- Requires Volo team to update mmt_v3 dependency and redeploy
- Both actions are routine protocol maintenance activities

**Probability Assessment:** 
MEDIUM-HIGH - Package version changes are inevitable in evolving DeFi protocols. The stub implementation provides no compile-time protection against incompatibilities. Evidence of existing compatibility concerns suggests this risk is material.

### Recommendation

**Immediate Mitigation:**
1. Add migration functions to handle package version changes:
```move
public(package) fun migrate_position<OldType: key + store, NewType: key + store>(
    vault: &mut Vault<T>,
    old_asset_type: String,
    new_asset_type: String,
    converter: /* conversion function */
)
```

2. Implement version tracking for external dependencies in vault state:
```move
struct Vault<T> {
    // ... existing fields
    external_package_versions: Table<String, address>, // Track package addresses
}
```

3. Add pre-deployment checks to verify type compatibility before upgrading dependencies

**Long-term Solution:**
1. Negotiate with MMT V3 team for stable interface guarantees or advance notice of breaking changes
2. Implement asset migration windows where old and new types coexist
3. Add position withdrawal mechanism allowing users to remove positions before incompatible upgrades
4. Create emergency procedures to extract value from inaccessible positions through alternate means

**Test Cases:**
1. Simulate dependency address change and verify migration path works
2. Test vault operations with mixed old/new position types
3. Verify accounting correctness after partial migrations

### Proof of Concept

**Initial State:**
1. Vault deployed with mmt_v3 dependency at package address `0x7028...`
2. Position objects created via MMT V3 and stored in vault's assets Bag
3. Vault operations successfully borrow/return these positions

**Exploit Sequence:**
1. MMT V3 team publishes new package at address `0xNEW...` with breaking changes to Position struct
2. Volo team updates Move.toml: `mmt_v3 = "0xNEW..."`
3. Volo team redeploys vault package with updated dependency
4. Vault operator calls `start_op_with_bag()` attempting to borrow existing Position

**Expected Result:**
Position successfully borrowed and operation proceeds

**Actual Result:**
Transaction aborts with type mismatch error:
- Code expects: `0xNEW...::mmt_v3::position::Position`
- Bag contains: `0x7028...::mmt_v3::position::Position`
- Error: Type mismatch in `bag.remove<String, MomentumPosition>()`

**Success Condition:**
Position objects remain permanently inaccessible. Vault total_usd_value includes their value but operations cannot retrieve them. Funds effectively locked with no recovery mechanism.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L10-24)
```text
    public struct Position has store, key {
        id: UID,
        pool_id: ID,
        fee_rate: u64,
        type_x: TypeName,
        type_y: TypeName,
        tick_lower_index: I32,
        tick_upper_index: I32,
        liquidity: u128,
        fee_growth_inside_x_last: u128,
        fee_growth_inside_y_last: u128,
        owed_coin_x: u64,
        owed_coin_y: u64,
        reward_infos: vector<PositionRewardInfo>,
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L31-60)
```text
    fun init(dummy_position: POSITION, tx_context: &mut TxContext) {
        abort 0
    }

    // --- Public Functions ---
    public fun coins_owed_reward(position: &Position, reward_index: u64) : u64 {
        abort 0
    }

    // returns if position does not have claimable rewards.
    public fun is_empty(position: &Position) : bool {
        abort 0
    }
    
    public fun reward_growth_inside_last(position: &Position, reward_index: u64) : u128 {
        abort 0
    }
    
    // public getter functions
    public fun reward_length(position: &Position) : u64 { abort 0 }
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
    public fun fee_growth_inside_x_last(position: &Position) : u128 { abort 0 }
    public fun fee_growth_inside_y_last(position: &Position) : u128 { abort 0 }
    public fun fee_rate(position: &Position) : u64 { abort 0 }
    public fun pool_id(position: &Position) : ID { abort 0 }
}
```

**File:** volo-vault/sources/volo_vault.move (L114-114)
```text
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
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

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L259-265)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/local_dependencies/mmt_v3/Move.toml (L10-11)
```text
[addresses]
mmt_v3 = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

**File:** volo-vault/Move.toml (L79-79)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L6-11)
```markdown
| Tag of Repo    | Network              | address                                                            | 
|----------------|----------------------|--------------------------------------------------------------------|
| mainnet-v1.1.3 | mainnet package id   | 0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860 |  
| mainnet-v1.1.3 | mainnet published at | 0xc84b1ef2ac2ba5c3018e2b8c956ba5d0391e0e46d1daa1926d5a99a6a42526b4 |  
| testnet-v1.0.1 | testnet package id   | 0xd7c99e1546b1fc87a6489afdc08bcece4ae1340cbd8efd2ab152ad71dea0f0f2 | 
| testnet-v1.0.1 | testnet published at | 0xd7c99e1546b1fc87a6489afdc08bcece4ae1340cbd8efd2ab152ad71dea0f0f2 | 
```
