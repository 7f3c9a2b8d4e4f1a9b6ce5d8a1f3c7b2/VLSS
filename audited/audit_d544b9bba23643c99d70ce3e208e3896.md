# Audit Report

## Title
Complete Vault DoS via Non-Functional MMT v3 Stub Implementation in Momentum Adaptor

## Summary
The mmt_v3 local dependency contains only stub implementations where all functions unconditionally abort. When an operator adds a MomentumPosition to a vault during an active operation (DURING_OPERATION status), the vault becomes permanently stuck because: (1) completing the operation requires updating all asset values via `get_total_usd_value`, (2) updating MomentumPosition values fails due to stub functions aborting, (3) removing the MomentumPosition requires NORMAL status which is unattainable, and (4) no admin recovery mechanism exists to reset vault status from DURING_OPERATION.

## Finding Description

The vulnerability stems from three critical design flaws working in combination:

**Flaw 1: Non-Functional MMT v3 Stubs**

All mmt_v3 modules contain only stub implementations that unconditionally abort: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Flaw 2: Momentum Adaptor Depends on Stubs**

The momentum adaptor's value calculation directly calls these stub functions, causing immediate abort: [5](#0-4) [6](#0-5) 

**Flaw 3: Asymmetric Status Requirements**

Assets can be added during operations (only requires `assert_enabled()`): [7](#0-6) 

But removing assets requires NORMAL status: [8](#0-7) 

**The DoS Attack Path:**

1. Vault enters DURING_OPERATION status via `start_op_with_bag`
2. Operator calls `add_new_defi_asset<T, MomentumPosition>()` which succeeds (only checks enabled, not normal)
3. Asset is initialized with `assets_value_updated = 0`: [9](#0-8) 

4. Operator attempts to complete operation via `end_op_value_update_with_bag`, which requires `get_total_usd_value`: [10](#0-9) 

5. `get_total_usd_value` aborts because MomentumPosition hasn't been updated (MAX_UPDATE_INTERVAL = 0): [11](#0-10) [12](#0-11) 

6. Attempting to update MomentumPosition value fails (all stub functions abort)
7. Cannot remove MomentumPosition (requires normal status, vault is DURING_OPERATION)
8. Cannot reset vault status via admin (explicitly blocked during operations): [13](#0-12) 

9. All vault operations now permanently blocked as they require NORMAL status: [14](#0-13) [15](#0-14) 

## Impact Explanation

**Critical Denial of Service - Permanent Vault Lock:**

Once a MomentumPosition is added during an active operation, the vault enters an unrecoverable state where:

- **Operation cannot complete**: `end_op_value_update_with_bag` requires `get_total_usd_value` which aborts for unupdated assets
- **Asset cannot be updated**: All mmt_v3 stub functions abort immediately  
- **Asset cannot be removed**: `remove_defi_asset_support` requires `assert_normal()` but vault is stuck in DURING_OPERATION
- **Status cannot be reset**: Admin's `set_vault_enabled` explicitly prevents changes during operations
- **All user operations blocked**: Deposits and withdrawals require NORMAL status

**Affected Parties:**
- All vault depositors permanently lose access to funds
- Protocol reputation severely damaged
- No recovery mechanism exists without contract upgrade

**Severity: CRITICAL** - This breaks the fundamental protocol invariant that operations must be completable. While funds are not stolen, they are permanently locked with zero recoverability.

## Likelihood Explanation

**Reachable Entry Point:**
The standard operator function `add_new_defi_asset` is the entry point, accessible via OperatorCap: [16](#0-15) 

**Feasible Preconditions:**
- Operator has valid OperatorCap (normal operational role, not compromised)
- Vault is in DURING_OPERATION status (normal during rebalancing)
- Operator attempts Momentum integration (reasonable given complete adaptor exists)
- No code validation prevents this scenario

**Execution Practicality:**
Requires only calling `add_new_defi_asset<T, MomentumPosition>()` during an active operation. The DoS is immediate and automatic upon attempting to complete the operation.

**Probability: MEDIUM**
- Lower than HIGH because requires operator to add asset during operation (unusual but not prevented)
- Higher than LOW because momentum adaptor's existence suggests integration is intended
- Could easily occur during initial deployment, testing, or strategic rebalancing

**Important Distinction:** If MomentumPosition is added in NORMAL status (not during operation), it can be immediately removed since `asset_value_updated == 0` satisfies the removal condition. The permanent DoS only occurs when added during DURING_OPERATION status.

## Recommendation

**Immediate Fixes:**

1. **Add status check to asset addition**:
```move
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    self.assert_normal();  // ADD THIS CHECK
    self.assert_enabled();
    // ... rest of function
}
```

2. **Remove non-functional mmt_v3 stubs** or clearly mark as unavailable:
```move
// Either remove entirely or add explicit error
const ERR_MOMENTUM_NOT_SUPPORTED: u64 = 9999;
public fun add_new_defi_asset<T, MomentumPosition>(...) {
    abort ERR_MOMENTUM_NOT_SUPPORTED
}
```

3. **Add admin emergency status override**:
```move
public fun emergency_reset_vault_status<T>(
    _: &AdminCap,
    vault: &mut Vault<T>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
}
```

## Proof of Concept

```move
#[test]
fun test_momentum_position_dos() {
    let mut scenario = test_scenario::begin(@0xA);
    
    // Setup vault and operation
    let mut vault = create_test_vault(scenario.ctx());
    let op = create_test_operation(scenario.ctx());
    let cap = create_test_operator_cap(scenario.ctx());
    
    // Start operation - vault becomes DURING_OPERATION
    operation::pre_vault_check(&mut vault, scenario.ctx());
    
    // Add MomentumPosition during operation (this succeeds)
    let momentum_pos = create_test_momentum_position();
    operation::add_new_defi_asset<SUI, MomentumPosition>(
        &op, &cap, &mut vault, 0, momentum_pos
    );
    
    // Try to complete operation - this will ABORT
    let clock = clock::create_for_testing(scenario.ctx());
    
    // This call will abort with ERR_USD_VALUE_NOT_UPDATED
    // because get_total_usd_value requires all assets updated
    // but MomentumPosition update aborts due to stub implementations
    operation::end_op_value_update_with_bag<SUI, NoObligation>(
        &mut vault, &op, &cap, &clock, tx_bag
    ); // ABORTS HERE - VAULT PERMANENTLY STUCK
    
    abort 0 // Will never reach here
}
```

**Note:** This vulnerability represents a genuine protocol invariant break where the vault becomes permanently non-operational due to the interaction between stub implementations, asymmetric status requirements, and mandatory value update enforcement.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L51-53)
```text
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-5)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L26-26)
```text
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L75-81)
```text
    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L83-89)
```text
    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L814-814)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1002-1002)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1264-1266)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L1365-1366)
```text
    self.assets_value.add(asset_type, 0);
    self.assets_value_updated.add(asset_type, 0);
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

**File:** volo-vault/sources/volo_vault.move (L1390-1395)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
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
