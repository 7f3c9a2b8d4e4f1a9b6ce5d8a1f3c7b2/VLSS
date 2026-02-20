# Audit Report

## Title
MMT V3 Stub Implementation Causes Permanent Vault Lockup When Momentum Positions Are Used

## Summary
The vault's momentum adaptor calls MMT v3 math functions that only contain `abort 0` stub implementations in the local dependencies. When a MomentumPosition is used in vault operations, the mandatory value update step fails due to these stubs aborting, permanently locking the vault in `VAULT_DURING_OPERATION_STATUS` and creating a complete denial of service.

## Finding Description

The vulnerability stems from a critical mismatch between the vault's operation requirements and the MMT v3 dependency implementation.

**Root Cause: Stub Implementations**

All MMT v3 math functions contain only stub implementations that immediately abort. The `liquidity_math::get_amounts_for_liquidity` function that the momentum adaptor depends on is just a stub: [1](#0-0) 

Similarly, the `tick_math::get_sqrt_price_at_tick` function: [2](#0-1) 

**Momentum Adaptor Calls Stub Functions**

The momentum adaptor's `get_position_token_amounts` function directly calls these stub implementations: [3](#0-2) 

This function is invoked by `update_momentum_position_value`, which operators must call to mark positions as updated: [4](#0-3) 

**Configuration Uses Local Stubs**

The Move.toml explicitly configures the local stub implementation instead of the actual on-chain MMT v3 package: [5](#0-4) 

**The Vault Operation Flow Breaks**

When vault operations borrow DeFi assets, they are tracked in the operation record: [6](#0-5) 

After the operation completes, the protocol MANDATES that all borrowed assets must have their USD values updated. The `check_op_value_update_record` function enforces this requirement: [7](#0-6) 

This check is called before the vault status can return to normal: [8](#0-7) 

**The Lockup Mechanism**

The vault status must be NORMAL to start new operations: [9](#0-8) 

The `assert_normal` function prevents operations when the vault is in DURING_OPERATION status: [10](#0-9) 

MomentumPosition assets can be borrowed during operations: [11](#0-10) 

## Impact Explanation

**Critical Denial of Service**

When a MomentumPosition is added to the vault and used in operations, the following sequence causes permanent lockup:

1. **Operation starts**: Vault status changes to `VAULT_DURING_OPERATION_STATUS`, MomentumPosition is borrowed and tracked in `asset_types_borrowed`

2. **Operation completes**: Assets are returned via `end_op_with_bag`, operator must call `update_momentum_position_value` to mark the position as updated

3. **Value update fails**: The function calls `tick_math::get_sqrt_price_at_tick` and `liquidity_math::get_amounts_for_liquidity` which immediately abort with code 0

4. **Cannot mark as updated**: Without successful value update, the `finish_update_asset_value` function never marks the asset in `asset_types_updated`

5. **Check fails**: `check_op_value_update_record` aborts with `ERR_USD_VALUE_NOT_UPDATED` (error code 5_007) because the MomentumPosition is in `asset_types_borrowed` but not marked as updated

6. **Permanent lockup**: The vault remains stuck in `VAULT_DURING_OPERATION_STATUS` because line 375 in `operation.move` that sets status back to NORMAL is never reached

7. **All operations blocked**: `assert_normal` prevents starting any new operations while in DURING_OPERATION status

**Affects All Users**

- No user deposits can be processed (requires NORMAL status)
- No user withdrawals can be executed (requires NORMAL status)
- Share price calculations fail (requires vault value updates)
- All vault functionality is completely frozen
- Funds remain locked until contract upgrade that either removes the MomentumPosition or fixes the stub implementations

## Likelihood Explanation

**Current Likelihood: Low**

The vulnerability is currently not exploitable because:
- No MomentumPosition assets appear to be actively deployed in production vaults
- Test suite contains zero test cases for momentum positions, indicating the feature is not yet in use

**Future Likelihood: High (upon activation)**

Once a MomentumPosition is added to any vault, the likelihood becomes HIGH because:

1. **Supported Feature**: Dedicated adaptor code exists specifically for momentum positions, indicating planned or intended usage
2. **Normal Operations**: Adding DeFi positions to diversify yield is standard vault management
3. **Legitimate Admin Action**: Requires only normal operator privileges, not any compromise or malicious intent
4. **Automatic Trigger**: Any routine vault operation that borrows the position will trigger the vulnerability
5. **Inevitable**: The stub implementations will ALWAYS abort with code 0 - there is no probabilistic element

The vulnerability activates through completely normal protocol usage once momentum integration begins.

## Recommendation

Replace the local MMT v3 stub implementations with the actual on-chain MMT v3 package. Update the Move.toml configuration:

```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
addr = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

Alternatively, if local dependencies are required (as the comment suggests "we need to remove some test functions with errors"), ensure that only test-specific functions are removed, and all production math functions (`get_amounts_for_liquidity`, `get_sqrt_price_at_tick`, etc.) contain proper implementations rather than `abort 0` stubs.

Before deploying momentum positions to production, thoroughly test the integration with realistic position values to ensure the math functions execute correctly.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Deploy a vault with a MomentumPosition added as a DeFi asset
2. Start an operation that borrows the MomentumPosition using `start_op_with_bag`
3. Complete the operation and return the position using `end_op_with_bag`
4. Attempt to call `update_momentum_position_value` to update the position's USD value
5. Observe that the transaction aborts with code 0 when `get_position_token_amounts` calls the stub implementations
6. Attempt to call `end_op_value_update_with_bag` to complete the operation
7. Observe that it aborts with `ERR_USD_VALUE_NOT_UPDATED` because the position was never marked as updated
8. Verify the vault is permanently stuck in `VAULT_DURING_OPERATION_STATUS`
9. Confirm all subsequent operations fail at `assert_normal` check

### Citations

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-6)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L1205-1219)
```text
// * @dev Check if the value of each borrowed asset during operation is updated correctly
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

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
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
