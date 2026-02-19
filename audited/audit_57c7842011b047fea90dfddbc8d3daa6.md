# Audit Report

## Title
Zero Slippage Configuration Causes Vault Operational DoS via Momentum Position Value Update Failure

## Summary
The `get_position_value()` function in the Momentum adaptor contains a flawed assertion that always fails when `dex_slippage` is set to 0, even when pool prices perfectly match oracle prices. This prevents vault operations from completing their value update phase, causing the vault to remain stuck in `VAULT_DURING_OPERATION_STATUS` and blocking all future operations until admin intervention.

## Finding Description

The root cause lies in the price validation assertion logic within the Momentum adaptor's position valuation: [1](#0-0) 

When `slippage = 0`, the mathematical evaluation becomes:
- Right side: `DECIMAL * 0 / SLIPPAGE_BASE = 0`
- Left side (with perfect price match): `pool_price.diff(relative_price_from_oracle) * DECIMAL / relative_price_from_oracle = 0 * DECIMAL / relative_price_from_oracle = 0`
- Final assertion: `0 < 0` → **always false**

The strict less-than operator `<` means that zero price deviation cannot satisfy zero tolerance, causing the assertion to fail even in the ideal case of perfectly matching prices.

The `set_dex_slippage` function lacks any validation to prevent setting slippage to zero: [2](#0-1) 

The public entry point similarly has no validation: [3](#0-2) 

During the three-phase operation lifecycle, after `start_op_with_bag` borrows assets and sets the vault to operation status: [4](#0-3) 

Assets are returned via `end_op_with_bag`, which enables value update mode: [5](#0-4) 

The operator must then call `update_momentum_position_value` for all Momentum positions, which internally calls `get_position_value`: [6](#0-5) 

When the assertion fails, `finish_update_asset_value` is never reached, so the asset is not marked as updated. The final `end_op_value_update_with_bag` function then fails its validation check: [7](#0-6) 

This check verifies all borrowed assets were updated by iterating through borrowed assets and asserting each exists in the updated list: [8](#0-7) 

Since the Momentum position was never marked as updated (due to the assertion failure), this check fails. The vault remains stuck in `VAULT_DURING_OPERATION_STATUS`. All future operations are blocked because `pre_vault_check` requires normal status: [9](#0-8) 

## Impact Explanation

**Operational DoS**: Once `dex_slippage` is set to 0 and any operation involving Momentum positions is initiated, the vault becomes stuck in operation mode. All subsequent operations are blocked because they require normal vault status. This affects:

- **Operators**: Cannot complete the current operation or start new ones
- **Users**: Cannot execute deposits, withdrawals, or any vault operations
- **Protocol**: Operational continuity is compromised until admin intervention

The severity is **Medium** because:
1. Requires admin misconfiguration (setting slippage to 0)
2. Does not result in direct fund loss
3. Is reversible by admin action (changing slippage to non-zero value, then operator retrying the operation)
4. Could occur accidentally through configuration error rather than malicious intent

However, the impact is still significant as it causes complete operational disruption until resolved.

## Likelihood Explanation

**Configuration Error Likelihood**: The vulnerability can be triggered through legitimate admin operations:

- Admin might misunderstand slippage semantics (thinking 0 means "exact match required")
- Admin might accidentally input 0 when intending a different value
- Admin might deliberately set to 0 believing it represents "no tolerance needed"

**Attack Complexity**: Low. The sequence is straightforward:
1. Admin calls `set_dex_slippage(0)` via the manage entry point
2. Next operation involving Momentum positions fails at value update step
3. Vault becomes stuck until slippage is changed and operation retried

**Feasibility**: High. No special preconditions needed beyond normal admin access. The lack of input validation makes this misconfiguration trivially possible.

**Detection**: The issue becomes immediately apparent when operations fail, but by then the vault is already stuck and requires emergency admin intervention to restore operations.

## Recommendation

Add validation in the `set_dex_slippage` function to prevent setting slippage to zero:

```move
public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();
    
    // Prevent zero slippage to avoid assertion failures
    assert!(dex_slippage > 0, ERR_INVALID_SLIPPAGE);
    
    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
```

Alternatively, if zero slippage is intended to be supported, change the assertion in `get_position_value` to use `<=` instead of `<`:

```move
assert!(
    (pool_price.diff(relative_price_from_oracle) * DECIMAL / relative_price_from_oracle) <= (DECIMAL * slippage / SLIPPAGE_BASE),
    ERR_INVALID_POOL_PRICE,
);
```

## Proof of Concept

```move
#[test]
fun test_zero_slippage_dos() {
    let mut scenario = test_scenario::begin(@admin);
    
    // Setup: Create vault with Momentum position
    scenario.next_tx(@admin);
    {
        let ctx = scenario.ctx();
        vault::init_for_testing(ctx);
        vault_oracle::init_for_testing(ctx);
    };
    
    scenario.next_tx(@admin);
    {
        let admin_cap = scenario.take_from_sender<AdminCap>();
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        
        // Admin sets slippage to 0 (misconfiguration)
        manage::set_dex_slippage(&admin_cap, &mut oracle_config, 0);
        
        scenario.return_to_sender(admin_cap);
        test_scenario::return_shared(oracle_config);
    };
    
    scenario.next_tx(@operator);
    {
        let operator_cap = scenario.take_from_sender<OperatorCap>();
        let operation = scenario.take_shared<Operation>();
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let clock = scenario.take_shared<Clock>();
        
        // Start operation and borrow Momentum position
        let (defi_assets, tx, tx_check, principal, coin_type) = 
            operation::start_op_with_bag(
                &mut vault,
                &operation,
                &operator_cap,
                &clock,
                vector[0u8],
                vector[type_name::get<MomentumPosition>()],
                0,
                0,
                scenario.ctx()
            );
        
        // Return assets
        operation::end_op_with_bag(
            &mut vault,
            &operation,
            &operator_cap,
            defi_assets,
            tx,
            principal,
            coin_type
        );
        
        // Try to update Momentum position value - WILL FAIL
        let oracle_config = scenario.take_shared<OracleConfig>();
        let mut pool = scenario.take_shared<MomentumPool<USDC, USDT>>();
        
        // This call will abort with ERR_INVALID_POOL_PRICE
        // even when prices match perfectly
        momentum_adaptor::update_momentum_position_value(
            &mut vault,
            &oracle_config,
            &clock,
            string::utf8(b"momentum_usdc_usdt"),
            &mut pool
        );
        
        // This line will never be reached, proving the DoS
        // The vault remains stuck in DURING_OPERATION_STATUS
    };
    
    scenario.end();
}
```

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/oracle.move (L117-122)
```text
public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();

    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
```

**File:** volo-vault/sources/manage.move (L136-138)
```text
public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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
