# Audit Report

## Title
Missing Asset Type Validation in finish_update_asset_value() Allows Updating Non-Borrowed Assets During Operations

## Summary
The `finish_update_asset_value()` function unconditionally updates asset values before checking if the asset was borrowed during an operation. This allows operators to update non-borrowed asset values during operations, corrupting the vault's total USD value calculation and bypassing loss tolerance enforcement.

## Finding Description

The vulnerability exists in the vault's asset value update mechanism where updates occur unconditionally for any asset, but tracking only happens for borrowed assets.

The `finish_update_asset_value()` function updates `assets_value` and `assets_value_updated` tables unconditionally for any `asset_type` parameter provided. [1](#0-0) 

The function then conditionally checks if the asset was borrowed, only adding it to `asset_types_updated` if it exists in `asset_types_borrowed`. [2](#0-1) 

The validation function `check_op_value_update_record()` only performs a one-directional check - it verifies all borrowed assets were updated, but does not prevent non-borrowed assets from being updated. [3](#0-2) 

All protocol adaptors expose public update functions that accept an `asset_type` parameter without validation against borrowed assets. [4](#0-3) [5](#0-4) 

**Attack Scenario:**
1. Vault has two Cetus positions: `CetusPosition_0` (worth $1000) and `CetusPosition_1` (worth $900)
2. Operator borrows only `CetusPosition_0` via `start_op_with_bag()`
3. Operation causes $100 loss on `CetusPosition_0` (now $900)
4. Meanwhile, `CetusPosition_1` gained $100 through market movements (now $1000)
5. Operator returns `CetusPosition_0` and calls `enable_op_value_update()` [6](#0-5) 
6. Operator updates `CetusPosition_0` value to $900 (tracked correctly)
7. Operator also calls `update_cetus_position_value()` with `CetusPosition_1`, updating its value to $1000 (NOT tracked)
8. `check_op_value_update_record()` passes because borrowed asset was updated [7](#0-6) 
9. Total USD before: $1900, Total USD after: $1900, Loss: $0 (should be $100)

## Impact Explanation

This vulnerability breaks the critical accounting invariant: "only borrowed DeFi assets should have their values updated during operations."

**1. Loss Tolerance Bypass:** Operations calculate losses as `total_usd_value_before - total_usd_value_after`. [8](#0-7)  The loss limit is enforced via `update_tolerance()` which asserts the cumulative loss is within limits. [9](#0-8) 

By updating non-borrowed assets that gained value, operators can artificially inflate `total_usd_value_after`, hiding real losses from operations and bypassing the loss tolerance limit.

**2. Total USD Value Corruption:** The `get_total_usd_value()` function sums all asset values from the `assets_value` table without distinguishing between borrowed and non-borrowed assets. [10](#0-9) 

**3. Share Price Manipulation:** Since share prices depend on `total_usd_value / total_shares`, incorrect asset valuations directly impact deposit/withdrawal amounts, potentially causing value extraction or losses for users.

**4. Staleness Bypass:** Non-borrowed assets receive fresh timestamps in `assets_value_updated` without actual price discovery during the operation, defeating staleness checks.

All vault users are affected as the corrupted total USD value impacts every share-based calculation.

## Likelihood Explanation

**Attack Complexity:** Low - Operators simply call update functions with different `asset_type` parameters in a single transaction.

**Attacker Capabilities:** While operators are trusted roles, this represents a **mis-scoping of operator privileges**. Operators should only be able to update borrowed assets during operations, but the code allows them to update any asset. This is a privilege escalation where operators can manipulate accounting beyond their intended scope.

**Preconditions:** 
- Vault with multiple protocol positions of the same type (common via `idx` parameter)
- Operator capability (standard role)
- Single atomic transaction

**Detection:** Difficult - The operation completes successfully because `check_op_value_update_record()` only validates borrowed assets. Event logs show value updates but don't flag non-borrowed asset modifications.

**Accidental Triggering:** This could occur accidentally through wrong asset IDs in operator scripts, copy-paste errors, or configuration mistakes in automated flows.

The combination of low complexity, mis-scoped privileges, and potential for accidental triggering makes this highly likely.

## Recommendation

Add validation in `finish_update_asset_value()` to prevent updating non-borrowed assets during operations:

```move
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    // Add validation: during operations, only allow updating borrowed assets
    if (self.status() == VAULT_DURING_OPERATION_STATUS && self.op_value_update_record.value_update_enabled) {
        assert!(
            self.op_value_update_record.asset_types_borrowed.contains(&asset_type),
            ERR_ASSET_NOT_BORROWED
        );
    };

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Create a vault with two Cetus positions (idx=0 and idx=1)
2. Start operation borrowing only position 0
3. Simulate loss on position 0 and gain on position 1
4. Return position 0 and enable value updates
5. Update both positions' values
6. Verify that loss calculation is incorrect (shows $0 loss instead of actual loss)
7. Verify that loss tolerance check passes when it should fail

The test would demonstrate that `check_op_value_update_record()` passes validation while the total USD value includes non-borrowed asset updates, allowing loss tolerance bypass.

### Citations

**File:** volo-vault/sources/volo_vault.move (L631-635)
```text
    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L1183-1187)
```text
    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1189-1195)
```text
    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L361-363)
```text
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
```
