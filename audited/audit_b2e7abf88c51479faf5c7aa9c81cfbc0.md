### Title
Momentum Adaptor DoS: Unimplemented mmt_v3 Math Functions Cause Vault Operation Failure

### Summary
The local `mmt_v3` dependency contains only stub implementations that abort with error code 0. The momentum adaptor relies on these functions (`tick_math`, `liquidity_math`) to calculate position values during vault operations. If any MomentumPosition is added to a vault and borrowed during an operation, the mandatory value update will fail, permanently locking the vault in "during operation" status and preventing all user deposits/withdrawals.

### Finding Description

The `mmt_v3` module at `volo-vault/local_dependencies/mmt_v3/` contains stub implementations. While the `bit_math` module itself is unused, other critical math modules are called by the momentum adaptor but also abort: [1](#0-0) [2](#0-1) [3](#0-2) 

The momentum adaptor depends on these functions to calculate position token amounts: [4](#0-3) 

The `update_momentum_position_value` function is called during vault operations to update asset values: [5](#0-4) 

When a MomentumPosition is borrowed during an operation, it's tracked in `asset_types_borrowed`: [6](#0-5) 

Before completing an operation, all borrowed assets must have their values updated, verified by: [7](#0-6) 

This check is called during operation finalization: [8](#0-7) 

**Root Cause**: The Move.toml intentionally uses local stub implementations instead of the real mmt_v3 package: [9](#0-8) 

### Impact Explanation

**Operational Impact - Critical DoS**:

1. **Vault Lock**: If a MomentumPosition is borrowed during any operation, calling `update_momentum_position_value` will abort at the first mmt_v3 function call (e.g., `pool.sqrt_price()` at line 73 of momentum.adaptor.move)

2. **Permanent State**: The vault remains in `VAULT_DURING_OPERATION_STATUS` (status = 1) because `check_op_value_update_record` will fail - the momentum position is in `asset_types_borrowed` but not in `asset_types_updated`

3. **User Funds Frozen**: With the vault stuck in "during operation" status:
   - No new deposits can be requested (requires `assert_normal()`)
   - No withdrawals can be requested (requires normal status)
   - Existing deposit/withdrawal requests cannot be executed
   - The vault becomes permanently non-functional

4. **Complete Protocol Failure**: Any vault that adds a MomentumPosition becomes unusable the moment an operation involving that position is initiated.

**Affected Users**: All vault depositors lose access to their funds until admin intervention (if possible through status override, which may not exist).

### Likelihood Explanation

**Execution Practicality**: 
- The vulnerability triggers automatically if the momentum adaptor is used
- No attacker action required - normal protocol operation causes the failure
- 100% reproducible with any MomentumPosition operation

**Current Status**:
- No tests exist for momentum positions
- No MomentumPosition assets appear to be deployed in current vaults
- The feature appears to be scaffolding for future integration

**Feasibility**: 
- Requires admin/operator to add a MomentumPosition to a vault
- Once added, any operation borrowing it will fail
- No special preconditions beyond feature deployment

**Economic Rationality**: 
- Not an attack - this is a fundamental implementation gap
- Will manifest as operational failure during legitimate use
- Medium-to-high probability if momentum integration is deployed without replacing stub implementations

### Recommendation

**Immediate Fix**:
1. Replace the local stub mmt_v3 dependency with the real implementation before deploying any MomentumPositions:

```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
```

2. Or remove the momentum adaptor entirely if the feature is not ready for production.

**Testing Requirements**:
1. Add end-to-end tests for momentum position operations that verify:
   - Position value calculation succeeds
   - Operations complete successfully with momentum positions
   - All mmt_v3 math functions return correct values

2. Add integration tests that borrow and return MomentumPositions during vault operations

**Validation**:
- Test with real Momentum pools on testnet/mainnet
- Verify `get_sqrt_price_at_tick`, `get_amounts_for_liquidity`, and all pool getter functions work correctly
- Confirm operation completion with momentum positions before mainnet deployment

### Proof of Concept

**Scenario**: Vault with MomentumPosition enters DoS state

**Initial State**:
- Vault deployed with normal status (status = 0)
- MomentumPosition added via `add_new_defi_asset`
- Position registered in vault's `assets` bag

**Transaction Sequence**:

1. Operator calls `start_op_with_bag` with MomentumPosition in `defi_asset_ids`
   - Position borrowed from vault
   - Added to `asset_types_borrowed` vector
   - Vault status set to 1 (during operation)

2. Operator performs investment strategy operations

3. Operator calls `end_op_with_bag`
   - Position returned to vault
   - `value_update_enabled` set to true

4. Operator calls `update_momentum_position_value`
   - **Transaction aborts** at `pool.sqrt_price()` call (line 73 of pool.move: `abort 0`)
   - MomentumPosition value NOT updated
   - Asset NOT added to `asset_types_updated`

5. Operator attempts `end_op_value_update_with_bag`
   - Calls `check_op_value_update_record` (line 354)
   - **Transaction aborts** at assertion (line 1216-1217): MomentumPosition is in `asset_types_borrowed` but not in `asset_types_updated`

**Result**: 
- Vault permanently stuck with status = 1
- All user operations blocked (deposits require normal status)
- Protocol effectively DoS'd for that vault

**Expected**: Operations should complete successfully with proper mmt_v3 implementations

---

## Notes

The `bit_math` module specifically is **not** directly used by any vault code. However, the broader mmt_v3 dependency has the same stub implementation pattern across `tick_math`, `liquidity_math`, and `pool` modules, which **are** used by the momentum adaptor.

The Move.toml comment indicates this was intentional: "MMT V3 uses local dependencies because we need to remove some test functions with errors." This suggests the stubs were created to avoid compilation issues with the upstream package, but the implementations were never completed.

The Cetus adaptor works correctly because it uses the real `CetusClmm` package from GitHub, not a local stub.

This issue only affects momentum position functionality. If momentum positions are never deployed, the vulnerability remains dormant. However, the presence of the adaptor code and the operation flow support for MomentumPosition types indicates this feature was intended for production use.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/bit_math.move (L1-9)
```text
module mmt_v3::bit_math {
    public fun least_significant_bit(mut value: u256) : u8 {
        abort 0
    }
    
    public fun most_significant_bit(mut value: u256) : u8 {
        abort 0
    }
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L1-35)
```text
module mmt_v3::tick_math {
    use mmt_v3::i32::{I32};
    
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
        abort 0
    }
    
    public fun is_valid_index(arg0: I32, arg1: u32) : bool {
        abort 0
    }
    
    public fun max_sqrt_price() : u128 {
        abort 0
    }
    
    public fun max_tick() : I32 {
        abort 0
    }
    
    public fun min_sqrt_price() : u128 {
        abort 0
    }
    
    public fun min_tick() : I32 {
        abort 0
    }
    
    public fun tick_bound() : u32 {
        abort 0
    }
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L1-53)
```text
module mmt_v3::liquidity_math {
    use mmt_v3::i128::{I128};

    public fun add_delta(current_liquidity: u128, delta_liquidity: I128) : u128 {
        abort 0
    }
    
    // get amount x for delta liquidity
    public fun get_amount_x_for_liquidity(sqrt_price_current: u128, sqrt_price_target: u128, liquidity: u128, round_up: bool) : u64 {
        abort 0
    }
    
    // get amount y for delta liquidity.
    public fun get_amount_y_for_liquidity(sqrt_price_current: u128, sqrt_price_target: u128, liquidity: u128, round_up: bool) : u64 {
        abort 0
    }
    
    // returns amounts of both assets as per delta liquidity.
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
    
    // get delta liquidity by amount x.
    public fun get_liquidity_for_amount_x(sqrt_price_current: u128, sqrt_price_target: u128, amount_x: u64) : u128 {
        abort 0
    }
    
    // get delta liquidity by amount y.
    public fun get_liquidity_for_amount_y(sqrt_price_current: u128, sqrt_price_target: u128, amount_y: u64) : u128 {
        abort 0
    }
    
    // returns liquidity from amounts x & y.
    public fun get_liquidity_for_amounts(sqrt_price_current: u128, sqrt_price_lower: u128, sqrt_price_upper: u128, amount_x: u64, amount_y: u64) : u128 {
        abort 0
    }

    public fun check_is_fix_coin_a(
        lower_sqrt_price: u128,
        upper_sqrt_price: u128,
        current_sqrt_price: u128,
        amount_a: u64,
        amount_b: u64
    ): (bool, u64, u64) {
        abort 0
    }
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

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

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

**File:** volo-vault/Move.toml (L79-86)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/mmt_v3"
rev = "main"
```
