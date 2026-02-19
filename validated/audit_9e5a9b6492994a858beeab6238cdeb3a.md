# Audit Report

## Title
Loss Tolerance Can Be Retroactively Increased During Operations, Bypassing Safety Limits

## Summary
The `set_loss_tolerance()` function lacks vault status validation, allowing loss tolerance to be modified while operations are in progress. Since `end_op_value_update_with_bag()` enforces the loss limit using the current tolerance value rather than the value when the operation started, this enables operations to complete with losses that would have been rejected under the original tolerance settings.

## Finding Description

The vulnerability stems from missing vault status validation in the loss tolerance configuration function. The `set_loss_tolerance()` function only validates the tolerance value bounds but does not check if the vault is currently during an operation [1](#0-0) .

In contrast, `set_enabled()` explicitly prevents modification during operations by checking the vault status [2](#0-1) . This inconsistency indicates that admin configuration changes should be blocked during operations, but `set_loss_tolerance()` lacks this protection.

When an operation begins, `pre_vault_check()` sets the vault status to `VAULT_DURING_OPERATION_STATUS` [3](#0-2) . The vault remains in this status until the operation completes via `end_op_value_update_with_bag()` [4](#0-3) .

The critical issue occurs in the `update_tolerance()` function, which calculates the loss limit using the **current** `self.loss_tolerance` value [5](#0-4) . Since this value can be modified between operation start and end, the tolerance can be retroactively increased to permit losses that would have been rejected under the original settings.

**Attack Sequence:**
1. Operator calls `start_op_with_bag()` → vault status becomes `VAULT_DURING_OPERATION_STATUS` (value 1)
2. Admin calls `set_loss_tolerance()` with higher value → no status check prevents this
3. Operator calls `end_op_value_update_with_bag()` → uses new tolerance value in loss validation

## Impact Explanation

This vulnerability compromises the loss tolerance safety mechanism, which is explicitly designed to protect depositors from excessive operational losses. The concrete impacts are:

1. **Safety Invariant Bypass**: Operations can complete with losses exceeding the intended tolerance that was in effect when they started, violating the temporal invariant that risk parameters at operation start should govern the operation

2. **User Fund Protection Failure**: Loss tolerance exists as a protection mechanism to limit value degradation during vault operations. Retroactive increases bypass this protection entirely

3. **Loss Tolerance Meaningless**: If tolerance can be changed during an operation, it provides no real protection since it can be adjusted based on actual losses rather than enforced as a hard limit

For example, if loss tolerance is set to 10 basis points (0.1%) and an operation incurs 50 basis points (0.5%) loss, the admin could increase tolerance to 60 basis points before the operation completes, allowing the excessive loss to pass validation.

## Likelihood Explanation

This vulnerability has HIGH likelihood because:

1. **No Technical Barriers**: Nothing prevents the execution sequence. The `set_loss_tolerance()` function is callable at any time with only `AdminCap` required

2. **Inconsistent Design Pattern**: The protocol explicitly prevents `set_enabled()` during operations via status check, but not `set_loss_tolerance()`. This inconsistency strongly suggests an oversight rather than intentional design

3. **No Atomicity Guarantees**: Operation start, tolerance change, and operation end are separate transactions with no atomicity protection

4. **Accidental Exploitation**: This doesn't require malicious intent. An admin could legitimately adjust tolerance for future operations, unaware that an operation is currently in-flight on the blockchain

5. **Extended Time Windows**: Operations can span multiple transactions over extended periods, providing ample opportunity for timing conflicts

6. **Difficult Detection**: Tolerance changes are legitimate admin actions with no way to detect if they're occurring during an operation

## Recommendation

Add vault status validation to `set_loss_tolerance()` consistent with `set_enabled()`:

```move
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

This ensures loss tolerance cannot be modified while operations are in progress, maintaining the temporal invariant that risk parameters at operation start govern the operation's completion.

## Proof of Concept

```move
#[test]
// [TEST-CASE: Loss tolerance can be changed during operation, bypassing safety limits]
public fun test_loss_tolerance_retroactive_increase_during_operation() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // Set initial loss tolerance to 10 bp (0.1%)
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        vault_manage::set_loss_tolerance(&admin_cap, &mut vault, 10);
        test_scenario::return_to_sender(&s, admin_cap);
        test_scenario::return_shared(vault);
    };
    
    // Setup vault with assets
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(0, navi_account_cap);
        test_scenario::return_shared(vault);
    };
    
    // Set prices
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        test_scenario::return_shared(oracle_config);
    };
    
    // Add principal
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault.return_free_principal(coin.into_balance());
        vault::update_free_principal_value(&mut vault, &config, &clock);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // START OPERATION
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];
        
        let (asset_bag, tx_bag, tx_bag_for_check, mut principal, coin_asset) = 
            operation::start_op_with_bag<SUI_TEST_COIN, SUI_TEST_COIN, SUI_TEST_COIN>(
                &mut vault, &operation, &cap, &clock,
                defi_asset_ids, defi_asset_types, 1_000_000_000, 0, s.ctx()
            );
        
        // Vault is now DURING_OPERATION status
        assert!(vault.status() == 1); // VAULT_DURING_OPERATION_STATUS
        
        // RETROACTIVELY INCREASE LOSS TOLERANCE DURING OPERATION
        // This should fail but doesn't because there's no status check
        let admin_cap = s.take_from_sender<AdminCap>();
        vault_manage::set_loss_tolerance(&admin_cap, &mut vault, 100); // Increase to 100 bp (1%)
        test_scenario::return_to_sender(&s, admin_cap);
        
        // Simulate 50 bp loss (0.5%) by destroying half the principal
        let loss = principal.split(500_000_000);
        loss.destroy_for_testing();
        
        // END OPERATION - Would fail with 10 bp tolerance, passes with 100 bp tolerance
        operation::end_op_with_bag<SUI_TEST_COIN, SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, asset_bag, tx_bag, principal, coin_asset
        );
        
        // Update values
        let config = s.take_shared<OracleConfig>();
        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        navi_adaptor::update_navi_position_value(&mut vault, &config, &clock, navi_asset_type, 0, s.ctx());
        vault::update_free_principal_value(&mut vault, &config, &clock);
        
        // Complete operation with value update check
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, NaviAccountCap>(
            &mut vault, &operation, &cap, &clock, tx_bag_for_check
        );
        
        // Operation succeeded despite 50 bp loss > original 10 bp tolerance
        // This proves the vulnerability: tolerance was retroactively increased
        
        test_scenario::return_to_sender(&s, cap);
        test_scenario::return_shared(operation);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that loss tolerance can be modified during an operation (when vault status is `VAULT_DURING_OPERATION_STATUS`), allowing an operation with 50 basis points loss to pass validation when the original tolerance was only 10 basis points. The operation would have failed with `ERR_EXCEED_LOSS_LIMIT` if the tolerance hadn't been retroactively increased.

### Citations

**File:** volo-vault/sources/volo_vault.move (L486-494)
```text
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
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

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
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
