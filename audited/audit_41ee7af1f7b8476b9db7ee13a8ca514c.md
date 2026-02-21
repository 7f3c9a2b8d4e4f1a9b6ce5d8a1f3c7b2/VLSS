# Audit Report

## Title
Loss Tolerance Bypass via Mid-Operation Parameter Change

## Summary
The `set_loss_tolerance()` function lacks vault status validation, allowing admins to modify the loss tolerance parameter while an operation is in progress. This enables retroactive approval of operations exceeding the original loss tolerance limit, completely defeating the per-epoch loss protection mechanism designed to safeguard vault depositors.

## Finding Description

The vulnerability stems from a missing vault status check in the `set_loss_tolerance()` function. Unlike other administrative functions that explicitly prevent changes during operations, `set_loss_tolerance()` only validates the tolerance value itself without checking the vault's operational state. [1](#0-0) 

In contrast, the `set_enabled()` function demonstrates the correct pattern by explicitly blocking changes during operations: [2](#0-1) 

The three-phase operation lifecycle creates an exploitable window:

**Phase 1** - `start_op_with_bag()` sets the vault to `VAULT_DURING_OPERATION_STATUS` via `pre_vault_check()`: [3](#0-2) 

The `TxBagForCheckValueUpdate` structure captures `total_usd_value` and `total_shares` but critically **does not capture the `loss_tolerance`** value: [4](#0-3) 

**Phase 2** - `end_op_with_bag()` returns borrowed assets but maintains `VAULT_DURING_OPERATION_STATUS` (no status change occurs in this function): [5](#0-4) 

**Phase 3** - `end_op_value_update_with_bag()` validates losses by calling `update_tolerance()`: [6](#0-5) 

The critical flaw: `update_tolerance()` reads the **current** `loss_tolerance` value from vault state, not from a snapshot: [7](#0-6) 

Because `set_loss_tolerance()` requires `AdminCap` but lacks timing restrictions: [8](#0-7) 

An admin can change the tolerance between Phase 2 and Phase 3, causing the validation to use the modified value instead of the tolerance in effect when the operation began.

## Impact Explanation

**Security Guarantee Violated**: The loss tolerance mechanism is a fundamental safety control that enforces maximum acceptable losses per epoch to protect depositor funds from excessive operational risk.

**Concrete Harm Scenario**:
- Vault has $10M total value with 0.1% (10 bps) loss tolerance = $10,000 maximum loss per operation
- Operator executes a strategy that loses $15,000 (0.15%)
- Under normal conditions, the operation would abort with `ERR_EXCEED_LOSS_LIMIT`
- Admin increases tolerance to 0.2% (20 bps) between Phase 2 and Phase 3
- The operation now validates against the NEW $20,000 limit and succeeds
- The $15,000 loss is accepted despite violating the original safety threshold

**Systemic Impact**: This defeats the epoch-based loss tracking system entirely. Multiple operations within an epoch can have their limits retroactively increased, allowing accumulated losses far beyond intended safeguards. All vault depositors are affected, as they rely on these limits to constrain operational risk exposure.

**Severity Justification**: HIGH - This is a critical design flaw that allows a fundamental security control to be retroactively disabled. While it requires legitimate admin privileges, it represents mis-scoped authority that undermines protocol invariants.

## Likelihood Explanation

**Required Capabilities**: Requires `AdminCap` to invoke the admin-only `set_loss_tolerance()` function. However, this is about the admin having authority at the wrong time, not requiring compromised credentials (mis-scoped privilege issue per validation framework).

**Attack Window**: The window exists during every operation lifecycle - specifically between `end_op_with_bag()` (when assets are returned) and `end_op_value_update_with_bag()` (when loss validation occurs). During this period, the vault remains in `VAULT_DURING_OPERATION_STATUS`, yet `set_loss_tolerance()` can still be called.

**Realistic Scenarios**:
1. **Operational Rescue Attempt**: An admin notices an operation is about to fail due to market volatility and increases tolerance to "save" it
2. **Admin/Operator Collusion**: Coordinated action to execute high-risk strategies with retroactive approval
3. **Governance Compromise**: If admin keys are compromised, attacker can systematically approve excessive losses

**Attack Complexity**: LOW - Single function call with no complex setup. The admin simply calls `vault_manage::set_loss_tolerance()` with a higher value while an operation is in progress.

**Probability Assessment**: MEDIUM-HIGH - While requiring admin privileges, this represents a design flaw that can be exploited intentionally or accidentally. The conditions naturally arise during normal operations (operators experiencing losses), making this a realistic threat vector.

## Recommendation

Add vault status validation to `set_loss_tolerance()` to prevent modifications during operations, mirroring the pattern used in `set_enabled()`:

```move
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    // ADD THIS LINE:
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

This ensures loss tolerance remains immutable during the operation lifecycle, preserving the integrity of the loss validation mechanism.

## Proof of Concept

```move
#[test]
// [TEST-CASE: Demonstrates loss tolerance can be changed mid-operation to bypass validation]
public fun test_loss_tolerance_bypass_during_operation() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with 0.1% loss tolerance (10 bps)
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Add initial vault value
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault.return_free_principal(coin.into_balance());
        vault.update_free_principal_value(&config, &clock);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // Phase 1: Start operation
    s.next_tx(OWNER);
    let (asset_bag, tx_bag, tx_bag_for_check) = {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let (bag, tx, tx_check, principal, coin_asset) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
                &mut vault, &operation, &cap, &clock,
                vector[], vector[], 1_000_000_000, 0, s.ctx()
            );
        
        // Simulate loss of 0.15% (exceeds 0.1% tolerance)
        principal.split(150_000_000).destroy_for_testing();
        
        test_scenario::return_shared(operation);
        test_scenario::return_shared(vault);
        s.return_to_sender(cap);
        (bag, tx, tx_check, principal, coin_asset)
    };
    
    // Phase 2: Return assets - vault still in DURING_OPERATION status
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, asset_bag, tx_bag, principal, coin_asset
        );
        
        test_scenario::return_shared(operation);
        test_scenario::return_shared(vault);
        s.return_to_sender(cap);
    };
    
    // VULNERABILITY: Admin changes loss tolerance to 0.2% DURING operation
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let admin_cap = s.take_from_sender<AdminCap>();
        
        // This should FAIL but succeeds - no status check!
        vault_manage::set_loss_tolerance(&admin_cap, &mut vault, 20); // 0.2%
        
        test_scenario::return_shared(vault);
        s.return_to_sender(admin_cap);
    };
    
    // Phase 3: Complete operation - validation uses NEW 0.2% limit
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        let config = s.take_shared<OracleConfig>();
        
        vault.update_free_principal_value(&config, &clock);
        
        // Operation succeeds with 0.15% loss against NEW 0.2% limit
        // Should have failed against original 0.1% limit
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, &clock, tx_bag_for_check
        );
        
        test_scenario::return_shared(operation);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        s.return_to_sender(cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

The vulnerability represents a mis-scoped privilege issue where the admin has authority to modify a critical safety parameter at the wrong time. The fix is straightforward: add the same vault status check that exists in `set_enabled()` to `set_loss_tolerance()`. This ensures the loss tolerance value used for validation is the same value in effect when the operation began, preserving the integrity of the per-epoch loss protection mechanism.

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

**File:** volo-vault/sources/operation.move (L86-92)
```text
public struct TxBagForCheckValueUpdate {
    vault_id: address,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    total_usd_value: u256,
    total_shares: u256,
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

**File:** volo-vault/sources/operation.move (L359-377)
```text
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

**File:** volo-vault/sources/manage.move (L58-64)
```text
public fun set_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    loss_tolerance: u256,
) {
    vault.set_loss_tolerance(loss_tolerance);
}
```
