# Audit Report

## Title
Momentum Adaptor DoS: Unimplemented mmt_v3 Math Functions Cause Permanent Vault Lock

## Summary
The local `mmt_v3` dependency contains only stub implementations that abort with error code 0. When a vault operation borrows a MomentumPosition, the mandatory value update process will abort, permanently locking the vault in "during operation" status and freezing all user funds.

## Finding Description

The `mmt_v3` math modules contain only stub implementations that unconditionally abort. [1](#0-0) [2](#0-1) [3](#0-2) 

The momentum adaptor depends on these functions to calculate position values. [4](#0-3) 

When a MomentumPosition is borrowed during an operation, it's added to the `asset_types_borrowed` tracking vector. [5](#0-4) 

Before completing an operation, the protocol enforces that all borrowed assets have their values updated. [6](#0-5)  This check is mandatory during operation finalization. [7](#0-6) 

**Attack Path:**
1. Admin/operator adds a MomentumPosition to vault
2. Operator starts an operation that borrows the MomentumPosition [8](#0-7) 
3. Operator attempts to update the position value via `update_momentum_position_value`
4. The call aborts at the first mmt_v3 function (e.g., `pool.sqrt_price()` at line 73)
5. The position cannot be marked as updated in `asset_types_updated`
6. Operation completion fails at `check_op_value_update_record` with `ERR_USD_VALUE_NOT_UPDATED` (error 5_007)
7. Vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`
8. Admin cannot recover because `enable_vault` aborts when status is "during operation" [9](#0-8) 

The root cause is the intentional use of local stub implementations. [10](#0-9) 

## Impact Explanation

**Critical Protocol DoS - Complete Vault Freeze:**

Once triggered, the vault enters an unrecoverable state:
- Status permanently locked at `VAULT_DURING_OPERATION_STATUS` (value 1)
- All user deposit requests blocked (require normal status via `assert_normal()`)
- All user withdrawal requests blocked (require normal status)
- Existing pending requests cannot be executed
- All deposited user funds become inaccessible

The only function that can restore normal status is `end_op_value_update_with_bag`, which sets status back to `VAULT_NORMAL_STATUS` at line 375. However, this function requires `check_op_value_update_record()` to pass first (line 354), which is impossible when the momentum position value update aborts.

No emergency recovery mechanism exists - even the admin's `enable_vault` function explicitly rejects status changes during operations.

**Scope of Impact:**
- Affects any vault with MomentumPosition assets
- All vault depositors lose access to their principal and yields
- Permanent capital lockup until contract upgrade/migration

## Likelihood Explanation

**Current Status - Latent Vulnerability:**
- No tests exist for momentum positions (verified via grep search)
- The feature infrastructure is complete but mmt_v3 functions are stubs
- No MomentumPosition assets appear to be currently deployed

**Trigger Conditions:**
- Requires trusted operator to add MomentumPosition to vault (within threat model)
- Once added, ANY operation borrowing it triggers the DoS
- 100% reproducible - not probabilistic

**Deployment Risk:**
- **Currently**: LOW likelihood (feature not enabled)
- **If momentum integration deployed without fixing stubs**: CERTAIN (100% occurrence rate)
- The Move.toml comment indicates awareness of the stub implementation but not the DoS risk

**Economic Rationality:**
This is not an "attack" but an implementation gap. If the momentum feature is enabled in production with stub dependencies, normal vault operations will cause self-inflicted DoS.

## Recommendation

**Immediate Actions:**
1. Replace local stub dependencies with real mmt_v3 package:
```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
```

2. Add comprehensive tests for momentum position operations before enabling the feature

3. Implement emergency recovery mechanism:
   - Add admin function to force-reset vault status in emergency situations
   - Or add admin function to remove stuck assets from `asset_types_borrowed`

**Long-term:**
4. Add deployment validation that verifies all adaptor dependencies are properly implemented (not stubs)
5. Implement feature flags to disable untested adaptors at runtime

## Proof of Concept

```move
// Test demonstrating the DoS
#[test]
fun test_momentum_position_dos() {
    // Setup: Create vault, add MomentumPosition
    let vault = create_test_vault();
    let momentum_position = create_momentum_position();
    add_new_defi_asset(&mut vault, 1, momentum_position);
    
    // Start operation borrowing the momentum position
    let defi_asset_types = vector[type_name::get<MomentumPosition>()];
    let (bag, tx, tx_check, _, _) = start_op_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[1],
        defi_asset_types,
        0,
        0,
        &mut tx_context
    );
    
    // Attempt to update position value - THIS ABORTS WITH ERROR 0
    update_momentum_position_value(
        &mut vault,
        &oracle_config,
        &clock,
        asset_type,
        &mut momentum_pool, // Pool with stub sqrt_price() function
    ); // <- Aborts here
    
    // Operation cannot complete because check_op_value_update_record fails
    // Vault permanently stuck in VAULT_DURING_OPERATION_STATUS
    // All user operations now blocked
}
```

The test would abort at `update_momentum_position_value` when it calls `pool.sqrt_price()`, demonstrating the DoS condition.

### Citations

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
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

**File:** volo-vault/sources/volo_vault.move (L516-531)
```text
}

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
