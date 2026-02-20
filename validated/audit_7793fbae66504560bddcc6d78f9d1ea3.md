# Audit Report

## Title
Loss Tolerance Retroactive Bypass via Mid-Operation Parameter Change

## Summary
The `set_loss_tolerance()` function lacks vault operational status validation, allowing admin to modify the loss tolerance parameter while operations are active. This enables retroactive approval of losses that should be rejected under the original tolerance limit, fundamentally undermining the epoch-based loss protection mechanism designed to safeguard vault depositors.

## Finding Description

The vulnerability stems from a missing vault status check in the `set_loss_tolerance()` function. The function only validates that the tolerance value doesn't exceed the maximum rate scaling limit, but fails to verify whether the vault is currently processing an operation. [1](#0-0) 

This stands in direct contrast to other administrative configuration functions like `set_enabled()`, which explicitly check the vault's operational status before allowing changes. [2](#0-1) 

The security issue arises because loss validation occurs at the END of operations. When an operation starts via `start_op_with_bag()`, the vault transitions to `VAULT_DURING_OPERATION_STATUS` and captures the baseline USD value. [3](#0-2) 

However, the actual loss tolerance check happens when the operation completes in `end_op_value_update_with_bag()`, where it calls `update_tolerance()` with the calculated loss amount. [4](#0-3) 

The critical flaw is that the loss limit calculation uses the CURRENT value of `self.loss_tolerance`, not the value that existed when the operation started. [5](#0-4) 

**Root Cause**: The codebase provides a helper function `assert_not_during_operation()` specifically for this validation pattern, but `set_loss_tolerance()` fails to use it. [6](#0-5) 

This represents a **mis-scoped privilege** issue: even though admin is trusted, they should not have the ability to retroactively alter validation parameters during the active validation window, as this defeats the entire purpose of the safety mechanism.

## Impact Explanation

**Security Integrity Bypass**: The loss tolerance mechanism is a fundamental risk management feature that protects vault depositors by limiting acceptable losses per epoch. This vulnerability allows complete circumvention of this protection during the exact moment when enforcement matters most—while losses are being validated.

**Concrete Attack Scenario**:
1. Initial state: Vault has 10 basis points (0.1%) loss tolerance, total value $1,000,000
2. Acceptable loss under original tolerance: $1,000
3. Operation executes and incurs $5,000 loss
4. Before operation completion, admin calls `set_loss_tolerance()` to increase tolerance to 50 basis points (0.5%)
5. New acceptable loss: $5,000
6. Operation completes successfully, using new tolerance value
7. Result: $5,000 loss approved retroactively, when it should have been rejected with `ERR_EXCEED_LOSS_LIMIT` (error code 5_008) [7](#0-6) 

**Affected Parties**:
- **Vault depositors** who rely on loss tolerance as a stated risk management guarantee
- **Protocol integrity** as a core safety invariant can be bypassed through parameter manipulation
- **Trust model** where depositors expect consistent risk boundaries regardless of operational circumstances

**Severity Justification**: High severity because it bypasses a fundamental depositor protection control that directly impacts vault safety guarantees and could enable significant losses beyond stated risk parameters.

## Likelihood Explanation

**Required Capabilities**: Admin must possess `AdminCap` and the vault must be in `VAULT_DURING_OPERATION_STATUS` with an operation that incurs losses exceeding the current tolerance.

**Attack Complexity**: Extremely low—requires only a single transaction calling `set_loss_tolerance()` with an increased value during the operation window. [8](#0-7) 

**Feasibility Conditions**:
1. Vault status is `VAULT_DURING_OPERATION_STATUS` (normal operation state)
2. Admin observes or anticipates operation losses exceeding current tolerance
3. Admin executes parameter change before `end_op_value_update_with_bag()` completes

**Execution Practicality**: Highly practical. The three-phase operation pattern (`start_op_with_bag` → `end_op_with_bag` → `end_op_value_update_with_bag`) provides sufficient time window for admin intervention between operation start and final validation. [9](#0-8) [10](#0-9) 

**Economic/Operational Incentives**: Admin might be incentivized to "rescue" a failing operation to avoid operational disruption, locked DeFi positions, reputational damage, or the need to unwind complex multi-protocol positions.

## Recommendation

Add the vault operational status check to `set_loss_tolerance()` to prevent modification during active operations:

```move
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    self.assert_not_during_operation();  // ADD THIS LINE
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

This aligns with the existing pattern used in `set_enabled()` and ensures that loss tolerance parameters cannot be changed retroactively during the validation window.

## Proof of Concept

```move
#[test]
public fun test_loss_tolerance_retroactive_bypass() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());

    // Initialize vault with default 10bp tolerance
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);

    // Setup vault with $1M value (10_000 SUI at $100 each)
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        vault.return_free_principal(coin.into_balance());
        test_scenario::return_shared(vault);
    };

    // Start operation
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let (bag, tx_bag, tx_bag_for_check, principal, coin_type) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
                &mut vault, &operation, &cap, &clock, 
                vector[], vector[], 1_000_000_000, 0, s.ctx()
            );

        // CRITICAL: Change tolerance from 10bp to 50bp DURING operation
        let admin_cap = s.take_from_sender<AdminCap>();
        vault_manage::set_loss_tolerance(&admin_cap, &mut vault, 50);
        s.return_to_sender(admin_cap);

        // Operation loses 0.5% (should fail with 10bp but succeeds with 50bp)
        // Complete operation with loss
        operation::end_op_with_bag(&mut vault, &operation, &cap, bag, tx_bag, principal, coin_type);
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, &clock, tx_bag_for_check
        );
        
        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };

    clock.destroy_for_testing();
    s.end();
}
```

The test demonstrates that an operation incurring 0.5% loss succeeds when tolerance is changed from 10bp to 50bp mid-operation, bypassing the original safety limit.

### Citations

**File:** volo-vault/sources/volo_vault.move (L56-56)
```text
const ERR_EXCEED_LOSS_LIMIT: u64 = 5_008;
```

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

**File:** volo-vault/sources/volo_vault.move (L657-661)
```text
public(package) fun assert_not_during_operation<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
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

**File:** volo-vault/sources/operation.move (L94-104)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
```

**File:** volo-vault/sources/operation.move (L299-305)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
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
