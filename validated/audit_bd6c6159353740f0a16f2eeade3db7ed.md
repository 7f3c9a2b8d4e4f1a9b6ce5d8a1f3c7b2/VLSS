# Audit Report

## Title
Front-Running Vulnerability in Position Value Updates Allows Operator DoS and Limited Value Manipulation

## Summary
All adaptor position value update functions (`update_momentum_position_value`, `update_navi_position_value`, `update_suilend_position_value`, `update_cetus_position_value`) are publicly callable without access control. This allows any user to front-run the operator's value update during vault operations, causing operator transaction failures due to Move's `table::add()` duplicate key abort semantics, and enabling attackers to control position value sampling timing within oracle slippage bounds.

## Finding Description

The vulnerability stems from missing access control on all position value update functions combined with Move's `table::add()` abort behavior. [1](#0-0) 

The same pattern exists across all adaptors: [2](#0-1) [3](#0-2) [4](#0-3) 

During vault operations, after assets are returned, the system enables value update tracking and emits an observable event: [5](#0-4) 

The tracking mechanism is enabled here: [6](#0-5) 

When value updates occur, `finish_update_asset_value()` attempts to add the asset_type to a tracking table using `table::add()`, which aborts if the key already exists: [7](#0-6) 

The validation only checks that all borrowed assets were updated, not who performed the update: [8](#0-7) 

Assets are tracked when borrowed during operations: [9](#0-8) 

## Impact Explanation

**Operator DoS (HIGH):** When an attacker front-runs the operator's value update call, the attacker's transaction succeeds in adding the asset to `asset_types_updated` (line 1194 of volo_vault.move). The operator's subsequent transaction attempts the same `table::add()` and aborts with a duplicate key error, requiring transaction reconstruction.

**Value Manipulation (LIMITED):** The attacker controls the exact moment when pool state is sampled for position valuation. Pool prices must be within the `dex_slippage` tolerance of oracle prices (default 1%): [10](#0-9)  Within this window, attackers can choose favorable or unfavorable moments, affecting loss calculations: [11](#0-10) 

**Loss Tolerance Impact:** The manipulated values feed into loss calculations that gate whether operations can complete, potentially allowing small losses to be hidden or triggering false alerts within the slippage bounds.

## Likelihood Explanation

**Attacker Capabilities:** Any user can execute this attack with standard transaction permissions. They only need access to publicly shared objects (Vault, OracleConfig, Clock, Pool/Storage).

**Attack Complexity:** Low. The attacker monitors the blockchain for `OperationEnded` events which reveal borrowed asset types, then submits a front-running transaction with higher gas priority.

**Observable Attack Window:** The window opens when `end_op_with_bag()` completes and `enable_op_value_update()` is called, making `value_update_enabled = true`. It closes when `end_op_value_update_with_bag()` validates all updates. This is fully observable through on-chain events and vault status.

**Economic Rationality:** Attack cost is minimal (standard gas fees). Enables operator griefing for competitive purposes, or marginal influence on vault valuations within slippage tolerance.

## Recommendation

Add operator capability checks to all position value update functions:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    _: &OperatorCap,  // Add operator capability requirement
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) { ... }
```

Apply the same pattern to all adaptor update functions. Alternatively, modify `finish_update_asset_value()` to use `table::borrow_mut()` instead of `table::add()` to allow idempotent updates without aborting on duplicates.

## Proof of Concept

```move
#[test]
fun test_frontrun_value_update() {
    // 1. Setup: Operator starts operation with borrowed Navi position
    // 2. Operator calls end_op_with_bag() - enables value updates
    // 3. Attacker observes OperationEnded event
    // 4. Attacker calls update_navi_position_value() before operator
    // 5. Attacker's tx succeeds, adds to asset_types_updated
    // 6. Operator's update_navi_position_value() call aborts with duplicate key
    // 7. Operation proceeds with attacker's chosen timestamp
}
```

## Notes

The vulnerability is confirmed through code analysis. The primary concrete impact is operator transaction DoS/griefing. Value manipulation is constrained by the oracle's `dex_slippage` parameter (default 1%), limiting the attacker to choosing favorable moments within that tolerance window rather than arbitrary price manipulation. The fix should prioritize adding access control to prevent unauthorized value updates during the critical operation phase.

### Citations

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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
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

**File:** volo-vault/sources/operation.move (L209-297)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();

    defi_assets.destroy_empty();
}
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

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

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

**File:** volo-vault/sources/volo_vault.move (L1242-1247)
```text
public(package) fun enable_op_value_update<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    self.check_version();
    self.assert_enabled();

    self.op_value_update_record.value_update_enabled = true;
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

**File:** volo-vault/sources/oracle.move (L10-90)
```text
// ---------------------  Constants  ---------------------//
const VERSION: u64 = 2;
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute

const DEFAULT_DEX_SLIPPAGE: u256 = 100; // 1%

// ---------------------  Errors  ---------------------//
const ERR_AGGREGATOR_NOT_FOUND: u64 = 2_001;
const ERR_PRICE_NOT_UPDATED: u64 = 2_002;
const ERR_AGGREGATOR_ALREADY_EXISTS: u64 = 2_003;
const ERR_AGGREGATOR_ASSET_MISMATCH: u64 = 2_004;
const ERR_INVALID_VERSION: u64 = 2_005;

// ---------------------  Structs  ---------------------//
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
}

public struct OracleConfig has key, store {
    id: UID,
    version: u64,
    aggregators: Table<String, PriceInfo>,
    update_interval: u64,
    dex_slippage: u256, // Pool price and oracle price slippage parameter (used in adaptors related to DEX)
}

// ---------------------  Events  ---------------------//

public struct UpdateIntervalSet has copy, drop {
    update_interval: u64,
}

public struct DexSlippageSet has copy, drop {
    dex_slippage: u256,
}

// deprecated
#[allow(unused_field)]
public struct PriceUpdated has copy, drop {
    price: u256,
    timestamp: u64,
}

public struct SwitchboardAggregatorAdded has copy, drop {
    asset_type: String,
    aggregator: address,
}

public struct SwitchboardAggregatorRemoved has copy, drop {
    asset_type: String,
    aggregator: address,
}

public struct SwitchboardAggregatorChanged has copy, drop {
    asset_type: String,
    old_aggregator: address,
    new_aggregator: address,
}

public struct OracleConfigUpgraded has copy, drop {
    oracle_config_id: address,
    version: u64,
}

public struct AssetPriceUpdated has copy, drop {
    asset_type: String,
    price: u256,
    timestamp: u64,
}

// ---------------------  Initialization  ---------------------//
fun init(ctx: &mut TxContext) {
    let config = OracleConfig {
        id: object::new(ctx),
        version: VERSION,
        aggregators: table::new(ctx),
        update_interval: MAX_UPDATE_INTERVAL,
        dex_slippage: DEFAULT_DEX_SLIPPAGE,
```
