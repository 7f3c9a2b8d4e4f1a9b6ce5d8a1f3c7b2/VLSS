# Audit Report

## Title
Stubbed MMT v3 Implementation Causes Permanent Vault Bricking When Momentum Positions Are Used

## Summary
The entire mmt_v3 library consists of stub implementations where all functions unconditionally abort with `abort 0`. When a MomentumPosition is borrowed during vault operations, updating its value via the momentum_adaptor triggers these stubbed functions, causing the transaction to abort. This prevents operation completion, permanently locking the vault in VAULT_DURING_OPERATION_STATUS with no admin recovery mechanism, freezing all user funds.

## Finding Description

The mmt_v3 library modules (i32, i64, i128, tick_math, liquidity_math) are stub implementations where every function unconditionally executes `abort 0`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The momentum_adaptor's `update_momentum_position_value` function calls these stubbed implementations to calculate position values. [6](#0-5)  The calculation flow calls `get_position_token_amounts` which invokes the stubbed functions. [7](#0-6) 

The critical vulnerability flow:

1. **MomentumPosition is explicitly supported** as a borrowable defi asset type in the operation workflow. [8](#0-7) 

2. **When borrowed, it's tracked** in `op_value_update_record.asset_types_borrowed` during operations. [9](#0-8) 

3. **Before completing any operation**, `check_op_value_update_record()` verifies all borrowed assets have had their values updated. [10](#0-9)  This function iterates through `asset_types_borrowed` and asserts each one exists in `asset_types_updated` with value `true`.

4. **This check is mandatory** in `end_op_value_update_with_bag` before the vault status can be reset. [11](#0-10) 

5. **Admin cannot reset vault status** when stuck in VAULT_DURING_OPERATION_STATUS. The `set_enabled()` function explicitly checks and aborts if the vault is during operation. [12](#0-11)  There is no other admin function that can force-reset the status. [13](#0-12) 

## Impact Explanation

**Severity: CRITICAL - Complete Vault Bricking**

If any MomentumPosition is added to the vault and borrowed during an operation:
- The momentum_adaptor's value update function will always abort due to stubbed mmt_v3 implementations
- The operation cannot be completed because `check_op_value_update_record()` will fail (the MomentumPosition won't be in `asset_types_updated`)
- The vault remains permanently stuck in VAULT_DURING_OPERATION_STATUS (status = 1)
- All vault functionality is frozen: no deposits, withdrawals, or further operations can be executed
- The admin's only status-changing function (`set_enabled`) explicitly prevents operation when vault is during operation
- The internal `set_status()` function is package-only with no admin wrapper
- All user funds become permanently locked in the vault with zero recovery path

This represents a complete loss of protocol functionality for that vault instance, affecting all depositors.

## Likelihood Explanation

**Likelihood: HIGH (Certain if MomentumPosition is used)**

The vulnerability has deterministic exploitability:
- No malicious actor required - occurs during normal operator workflow
- MomentumPosition is explicitly implemented as a fully supported defi asset type alongside Cetus, Navi, and Suilend
- The adaptor code exists and is integrated into the operation flow
- Any operator who adds a MomentumPosition via `add_new_defi_asset` and attempts to use it in an operation will trigger the issue
- The stubbed implementation is deterministic - it will always abort with no conditional logic
- No special privileges or complex attack vectors needed

The only mitigating factor is that MomentumPosition must be actively added and used. However, given it's implemented as a production-ready feature with full integration, operators would reasonably attempt to use it, making this a critical production-blocking bug.

## Recommendation

**Immediate Fix Options:**

1. **Remove MomentumPosition support** from the operation flow until mmt_v3 library is properly implemented:
   - Remove MomentumPosition handling from `start_op_with_bag` and `end_op_with_bag` in operation.move
   - Add validation to prevent adding MomentumPosition as a defi asset

2. **Add emergency admin recovery function**:
   - Create an admin entry point in `vault_manage` that directly calls `set_status()` to force-reset vault status
   - This provides recovery for any vault stuck in VAULT_DURING_OPERATION_STATUS

3. **Implement mmt_v3 library properly**:
   - Replace stub implementations with actual liquidity math logic
   - This is the proper long-term fix

**Recommended code addition to manage.move:**
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    status: u8,
) {
    vault.set_status(status);
}
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Admin creates vault and operator creates OperatorCap
2. Operator adds a MomentumPosition to the vault using `add_new_defi_asset`
3. Operator calls `start_op_with_bag` including MomentumPosition in `defi_asset_types`
   - Vault status changes to VAULT_DURING_OPERATION_STATUS (1)
   - MomentumPosition is added to `asset_types_borrowed`
4. Operator calls `end_op_with_bag` to return the MomentumPosition
   - `value_update_enabled` is set to true
5. Operator attempts to call `momentum_adaptor::update_momentum_position_value`
   - Transaction aborts due to `tick_math::get_sqrt_price_at_tick()` or `liquidity_math::get_amounts_for_liquidity()` executing `abort 0`
6. Operator cannot call `end_op_value_update_with_bag` because:
   - `check_op_value_update_record()` requires MomentumPosition to be in `asset_types_updated`
   - Since update aborted, it's not in the table
   - Transaction aborts with ERR_USD_VALUE_NOT_UPDATED
7. Vault is permanently stuck with:
   - Status = VAULT_DURING_OPERATION_STATUS
   - Cannot accept deposits/withdrawals (blocked by status check)
   - Admin cannot call `set_vault_enabled` (aborts due to status check at line 523)
   - No recovery mechanism exists

The test would show that once step 3 completes, the vault becomes unrecoverable, proving the critical impact.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/i64.move (L15-17)
```text
    public fun zero(): I64 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L15-17)
```text
    public fun zero(): I32 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i128.move (L18-20)
```text
    public fun zero(): I128 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-6)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L19-27)
```text
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
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
