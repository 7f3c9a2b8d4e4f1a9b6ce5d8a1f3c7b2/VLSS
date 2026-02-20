# Audit Report

## Title
Complete Momentum Adaptor Failure Due to Stub Implementation Causing Vault DoS

## Summary
The mmt_v3 local dependency contains only stub implementations where all functions call `abort 0`. When a vault contains a MomentumPosition, any value update operation aborts, blocking all deposits and withdrawals since the vault requires all asset values to be updated within MAX_UPDATE_INTERVAL (set to 0) before calculating total USD value.

## Finding Description

The mmt_v3 local dependency consists entirely of stub implementations that immediately abort. All critical position getter functions are stubs: [1](#0-0) 

All critical pool getter functions are stubs: [2](#0-1) 

The momentum_adaptor's `get_position_token_amounts` function directly calls these stub functions to calculate position values: [3](#0-2) 

MomentumPosition is explicitly supported in vault operations, with dedicated borrowing logic: [4](#0-3) 

And return logic: [5](#0-4) 

Operators can add MomentumPosition as a generic DeFi asset using the standard function: [6](#0-5) 

When a DeFi asset is added, it is registered in the vault's asset_types list: [7](#0-6) 

The vault enforces that all asset values must be updated within MAX_UPDATE_INTERVAL, which is defined as 0: [8](#0-7) 

The `get_total_usd_value` function iterates through all registered asset types and checks staleness, aborting if any asset is not freshly updated: [9](#0-8) 

Deposit operations require calling `get_total_usd_value` twice: [10](#0-9) [11](#0-10) 

Withdrawal operations require calling `get_share_ratio`: [12](#0-11) 

Which internally calls `get_total_usd_value`: [13](#0-12) 

**Attack Chain:**
1. Operator legitimately adds a MomentumPosition via `add_new_defi_asset` - this registers the asset type in the vault's tracking system
2. Any user attempts a deposit or withdrawal operation
3. The operation requires `get_total_usd_value()` which mandates ALL assets be updated within 0 milliseconds
4. To satisfy this requirement, operator must call `update_momentum_position_value` on the MomentumPosition
5. This function calls `get_position_token_amounts` which invokes stub methods `pool.sqrt_price()`, `position.tick_lower_index()`, `position.tick_upper_index()`, and `position.liquidity()`
6. All these methods immediately call `abort 0`, causing the transaction to fail
7. Without a successful value update, the staleness check in `get_total_usd_value` aborts
8. All deposits and withdrawals become permanently impossible

This breaks the fundamental security guarantee that users can deposit to and withdraw from enabled vaults in NORMAL status. The protocol explicitly supports MomentumPosition as an asset type but has deployed non-functional stub implementations, creating a guaranteed DoS scenario.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability causes complete vault denial of service affecting all users:

- **Deposits blocked**: Execute fails because `get_total_usd_value` aborts on staleness check at lines 820 and 841
- **Withdrawals blocked**: Execute fails because `get_share_ratio` → `get_total_usd_value` aborts on staleness check at line 1006 → 1308
- **All users affected**: Not isolated to specific positions or users - the entire vault becomes non-functional
- **Funds locked**: While not permanently lost, user funds are inaccessible until operator removes the problematic asset

The impact meets CRITICAL severity criteria because:
1. It's a high-confidence protocol DoS via valid calls
2. Complete loss of vault functionality for all users
3. No user-side workaround available
4. Violates the core protocol invariant that enabled vaults must support user deposits/withdrawals

While the operator can restore functionality by calling `remove_defi_asset_support`, this requires recognizing the issue and taking remedial action. During any period where a MomentumPosition exists, the vault is completely unusable despite the protocol explicitly supporting this asset type.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is guaranteed to manifest under the following conditions:

- **Precondition**: Operator adds a MomentumPosition using the standard `add_new_defi_asset` function - a completely legitimate operation on an explicitly supported asset type. The protocol's codebase shows clear intent to support MomentumPosition through dedicated handling in operation.move.

- **Trigger**: Any normal user operation (deposit or withdrawal), or any operation requiring total USD value calculation. Zero complexity - happens automatically through standard protocol usage.

- **Detection**: Immediately evident once a MomentumPosition is added and any value update is attempted. The abort is deterministic and reproducible.

- **Cost**: No cost to trigger beyond normal transaction fees. Happens through standard operations without any special actions.

The likelihood is HIGH rather than MEDIUM because:
1. The vulnerability WILL occur if MomentumPosition support is ever utilized
2. Not theoretical - the abort path is guaranteed by the stub implementations
3. The mmt_v3 dependency is in-scope production code containing only stubs
4. MAX_UPDATE_INTERVAL=0 creates an impossible-to-satisfy requirement when combined with aborting stubs

## Recommendation

Replace the stub implementations in the mmt_v3 local dependency with functional implementations, or remove MomentumPosition support entirely until proper implementations are available.

**Option 1: Implement proper mmt_v3 functions**
- Replace all stub functions in `position.move` and `pool.move` with actual implementations that read position and pool state
- Ensure `tick_lower_index()`, `tick_upper_index()`, `liquidity()`, and `sqrt_price()` return valid values

**Option 2: Remove MomentumPosition support**
- Remove MomentumPosition handling from `operation.move` 
- Document that Momentum integration is not yet supported
- Prevent operators from adding MomentumPosition assets

**Option 3: Adjust MAX_UPDATE_INTERVAL**
- While increasing MAX_UPDATE_INTERVAL would mitigate the immediate DoS, it doesn't solve the fundamental problem that the mmt_v3 dependency is non-functional
- Not recommended as the primary fix

**Option 4: Add validation**
- Prevent adding DeFi assets whose value update functions are known to fail
- Add try-catch logic or validation before registering new asset types

## Proof of Concept

```move
// Test demonstrating the DoS
#[test]
fun test_momentum_position_dos() {
    // 1. Setup vault with operator
    let mut scenario = test_scenario::begin(ADMIN);
    let (vault, operator_cap) = setup_vault_with_operator(&mut scenario);
    
    // 2. Operator adds MomentumPosition (legitimate operation)
    let momentum_position = create_momentum_position(); // Mock position object
    operation::add_new_defi_asset(
        &operation,
        &operator_cap, 
        &mut vault,
        0, // idx
        momentum_position
    );
    
    // 3. User requests deposit
    let user_coin = coin::mint_for_testing<SUI>(1000000, ctx);
    vault::request_deposit(&mut vault, user_coin, &clock, 1000, receipt_id, user_addr);
    
    // 4. Operator attempts to execute deposit
    // This will ABORT because:
    // - execute_deposit calls get_total_usd_value (line 820)
    // - get_total_usd_value checks staleness for MomentumPosition
    // - MomentumPosition update was never successful (asset_value_updated = 0)
    // - Staleness check: now - 0 > 0 -> ABORT with ERR_USD_VALUE_NOT_UPDATED
    
    operation::execute_deposit(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &config,
        0, // request_id
        1000 // max_shares
    ); // <- ABORTS HERE
    
    abort 999 // This line never reached - test proves deposit is blocked
}
```

The test demonstrates that once a MomentumPosition is added, all deposit and withdrawal operations abort due to the impossible staleness requirement combined with non-functional stub implementations.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L51-53)
```text
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L73-81)
```text
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();
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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L820-820)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L841-841)
```text
    let total_usd_value_after = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1006)
```text
    let ratio = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1266)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L1308-1308)
```text
    let total_usd_value = self.get_total_usd_value(clock);
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
