### Title
Stubbed MMT v3 Implementation Causes Permanent Vault Bricking When Momentum Positions Are Used

### Summary
The entire mmt_v3 library consists of stub implementations where all functions unconditionally abort. When a MomentumPosition is borrowed during vault operations, the vault requires updating its value via the momentum_adaptor, which calls these stubbed functions and always aborts. This prevents operation completion, permanently locking the vault in VAULT_DURING_OPERATION_STATUS with no recovery mechanism.

### Finding Description

The mmt_v3::i64 module and all related liquidity math modules are stub implementations where every function unconditionally executes `abort 0`: [1](#0-0) [2](#0-1) [3](#0-2) 

The momentum_adaptor module's `update_momentum_position_value` function calls these stubbed implementations to calculate position values: [4](#0-3) 

The critical flow path is:

1. When a defi asset is borrowed during an operation, it's tracked in `op_value_update_record.asset_types_borrowed`: [5](#0-4) 

2. MomentumPosition is explicitly supported as a borrowable defi asset type: [6](#0-5) 

3. Before completing any operation, `check_op_value_update_record()` verifies all borrowed assets have been updated: [7](#0-6) 

4. This check is mandatory in `end_op_value_update_with_bag`: [8](#0-7) 

5. The admin cannot reset the vault status when it's stuck in VAULT_DURING_OPERATION_STATUS: [9](#0-8) 

### Impact Explanation

**Severity: CRITICAL - Complete Vault Bricking**

If any MomentumPosition is added to the vault and borrowed during an operation:
- The update function will always abort due to stubbed mmt_v3 implementations
- The operation cannot be completed because `check_op_value_update_record()` will fail
- The vault remains permanently stuck in VAULT_DURING_OPERATION_STATUS
- All vault functionality is frozen: no deposits, withdrawals, or further operations
- No recovery mechanism exists - even admin functions cannot reset the vault status during operations
- All user funds become permanently locked in the vault

This affects all users with deposits in the vault and represents a complete loss of protocol functionality for that vault instance.

### Likelihood Explanation

**Likelihood: HIGH (Certain if MomentumPosition is used)**

The vulnerability has certain exploitability:
- No malicious actor required - this occurs during normal operations
- MomentumPosition is explicitly implemented as a supported defi asset type in the operation flow
- The adaptor code exists and is integrated alongside other active adaptors (Cetus, Navi, Suilend)
- Any operator who adds a MomentumPosition and attempts to use it will trigger the issue
- The stubbed implementation is deterministic - it will always abort
- No special privileges or attack vectors needed

The only mitigating factor is that MomentumPosition must be actively added and used. However, given it's implemented as a fully integrated feature alongside other active adaptors, this represents a critical production-blocking bug.

### Recommendation

**Immediate Actions:**
1. Remove or disable MomentumPosition support until mmt_v3 library has proper implementations
2. Add pre-deployment validation tests that verify all adaptor dependencies are functional
3. Document that mmt_v3 integration is incomplete and must not be used in production

**Code-Level Fixes:**
1. Replace the stubbed mmt_v3 library with a proper implementation, or
2. Remove MomentumPosition from the supported asset types in `operation.move`
3. Add integration tests that exercise the full operation flow with each supported asset type

**Additional Safeguards:**
1. Implement an emergency admin function to force-reset vault status (with appropriate multi-sig controls)
2. Add circuit breakers that detect when borrowed assets cannot be updated within reasonable time
3. Add validation that prevents adding defi asset types whose adaptors call unimplemented dependencies

### Proof of Concept

**Initial State:**
- Vault is deployed and operational
- Admin adds a MomentumPosition as a defi asset to the vault

**Exploitation Steps:**
1. Operator calls `start_op_with_bag` including MomentumPosition in the borrowed assets
   - Vault status changes to VAULT_DURING_OPERATION_STATUS
   - MomentumPosition asset_type is added to `op_value_update_record.asset_types_borrowed`

2. Operator attempts to call `update_momentum_position_value` to update the position value
   - Function calls `get_position_token_amounts` 
   - This calls `tick_math::get_sqrt_price_at_tick(lower_tick)` which executes `abort 0`
   - Transaction fails with abort

3. Operator attempts to complete operation via `end_op_value_update_with_bag`
   - Function calls `vault.check_op_value_update_record()`
   - This asserts that MomentumPosition was updated, but it wasn't
   - Transaction fails with ERR_USD_VALUE_NOT_UPDATED

4. Operator cannot complete the operation without updating the position
5. Operator cannot update the position because all update paths abort
6. Admin cannot reset vault status because it checks `status() != VAULT_DURING_OPERATION_STATUS`

**Result:**
- Vault is permanently bricked in VAULT_DURING_OPERATION_STATUS
- All deposits, withdrawals, and operations are permanently frozen
- No recovery mechanism exists

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/i64.move (L15-77)
```text
    public fun zero(): I64 {
        abort 0
    }

    public fun from_u64(v: u64): I64 {
        abort 0
    }

    public fun from(v: u64): I64 {
        abort 0
    }

    public fun neg_from(v: u64): I64 {
        abort 0
    }

    public fun wrapping_add(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun add(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun wrapping_sub(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun sub(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun mul(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun div(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun abs(v: I64): I64 {
        abort 0
    }

    public fun abs_u64(v: I64): u64 {
        abort 0
    }

    public fun shl(v: I64, shift: u8): I64 {
        abort 0
    }

    public fun shr(v: I64, shift: u8): I64 {
        abort 0
    }

    public fun mod(v: I64, n: I64): I64 {
        abort 0
    }

    public fun as_u64(v: I64): u64 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-10)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
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

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```
