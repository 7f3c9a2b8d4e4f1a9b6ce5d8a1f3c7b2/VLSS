# Audit Report

## Title
Stubbed MMT v3 Implementation Causes Permanent Vault Bricking When Momentum Positions Are Used

## Summary
The mmt_v3 library consists entirely of stub implementations where all functions unconditionally abort with `abort 0`. When a MomentumPosition is borrowed during vault operations, the mandatory value update via momentum_adaptor triggers these stubbed functions, causing transaction abortion. This prevents operation completion, permanently locking the vault in VAULT_DURING_OPERATION_STATUS with no admin recovery mechanism, freezing all user funds.

## Finding Description

The mmt_v3 library modules (i32, i64, i128, tick_math, liquidity_math) contain only stub implementations. Every public function unconditionally executes `abort 0`: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The momentum_adaptor's value update function directly calls these stubbed implementations: [6](#0-5) 

The critical vulnerability flow:

**1. MomentumPosition is explicitly supported** as a borrowable DeFi asset type in the operation workflow: [7](#0-6) 

**2. When borrowed, it's tracked** in `op_value_update_record.asset_types_borrowed`: [8](#0-7) 

**3. Before completing any operation**, `check_op_value_update_record()` verifies all borrowed assets have had their values updated by iterating through `asset_types_borrowed` and asserting each exists in `asset_types_updated`: [9](#0-8) 

**4. This check is mandatory** in `end_op_value_update_with_bag` before the vault status can be reset: [10](#0-9) 

**5. Admin cannot reset vault status** when stuck in VAULT_DURING_OPERATION_STATUS: [11](#0-10) 

The internal `set_status()` function is package-only with no admin wrapper: [12](#0-11) [13](#0-12) 

## Impact Explanation

**Severity: CRITICAL - Complete Vault Bricking**

If any MomentumPosition is added to the vault and borrowed during an operation:
- The momentum_adaptor's value update function will always abort due to stubbed mmt_v3 implementations
- The operation cannot be completed because `check_op_value_update_record()` will fail (MomentumPosition won't be in `asset_types_updated`)
- The vault remains permanently stuck in VAULT_DURING_OPERATION_STATUS (status = 1)
- All vault functionality is frozen: no deposits, withdrawals, or further operations can execute
- The admin's only status-changing function (`set_enabled`) explicitly prevents operation when vault is during operation
- The internal `set_status()` function is package-only with no admin wrapper
- All user funds become permanently locked in the vault with zero recovery path

This represents a complete loss of protocol functionality for that vault instance, affecting all depositors.

## Likelihood Explanation

**Likelihood: HIGH (Certain if MomentumPosition is used)**

The vulnerability has deterministic exploitability:
- No malicious actor required - occurs during normal operator workflow
- MomentumPosition is explicitly implemented as a fully supported DeFi asset type alongside Cetus, Navi, and Suilend
- The adaptor code exists and is integrated into the operation flow
- Any operator who adds a MomentumPosition via `add_new_defi_asset` and attempts to use it in an operation will trigger the issue
- The stubbed implementation is deterministic - it will always abort with no conditional logic
- No special privileges or complex attack vectors needed

The only mitigating factor is that MomentumPosition must be actively added and used. However, given it's implemented as a production-ready feature with full integration, operators would reasonably attempt to use it, making this a critical production-blocking bug.

## Recommendation

Replace the stubbed mmt_v3 implementations with proper functional implementations that can calculate position values without aborting. Alternatively, if Momentum integration is not intended for production:
1. Remove MomentumPosition support from `start_op_with_bag` and `end_op_with_bag`
2. Remove the momentum_adaptor module
3. Add validation to prevent MomentumPosition from being added via `add_new_defi_asset`

## Proof of Concept

A test demonstrating the vulnerability would:
1. Create a vault with principal coin
2. Add a MomentumPosition as a DeFi asset
3. Call `start_op_with_bag` borrowing the MomentumPosition
4. Call `end_op_with_bag` returning the MomentumPosition
5. Attempt to call momentum_adaptor's update function - this will abort
6. Attempt to call `end_op_value_update_with_bag` - this will fail the check
7. Verify vault is stuck in VAULT_DURING_OPERATION_STATUS
8. Verify admin cannot call `set_vault_enabled` - it will abort with ERR_VAULT_DURING_OPERATION

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L15-16)
```text
    public fun zero(): I32 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i64.move (L15-16)
```text
    public fun zero(): I64 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i128.move (L18-19)
```text
    public fun zero(): I128 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-5)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L4-5)
```text
    public fun add_delta(current_liquidity: u128, delta_liquidity: I128) : u128 {
        abort 0
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L69-91)
```text
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();

    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
    (amount_a, amount_b, sqrt_price)
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

**File:** volo-vault/sources/operation.move (L354-375)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L518-530)
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
```

**File:** volo-vault/sources/volo_vault.move (L533-540)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;

    emit(VaultStatusChanged {
        vault_id: self.vault_id(),
        status: status,
    });
```

**File:** volo-vault/sources/volo_vault.move (L1206-1218)
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
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}
```
