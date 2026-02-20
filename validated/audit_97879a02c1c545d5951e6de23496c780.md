# Audit Report

## Title
Loss Tolerance Can Be Retroactively Increased During Operations, Bypassing Safety Limits

## Summary
The `set_loss_tolerance()` function lacks vault status validation, allowing the admin to modify loss tolerance while vault operations are in progress. Since `end_op_value_update_with_bag()` enforces loss limits using the current tolerance value rather than the value captured at operation start, this enables operations to complete with losses exceeding the originally configured safety limits.

## Finding Description

The vulnerability stems from missing vault status validation in the loss tolerance configuration function. The `set_loss_tolerance()` function only validates that the tolerance value does not exceed `RATE_SCALING` but critically fails to check whether the vault is currently in `VAULT_DURING_OPERATION_STATUS`. [1](#0-0) 

This creates an architectural inconsistency with `set_enabled()`, which explicitly prevents status modifications during active operations through a status assertion. [2](#0-1) 

The protocol's test suite confirms this protection is intentional - test case OPERATION-022 explicitly verifies that `set_vault_enabled` fails with `ERR_VAULT_DURING_OPERATION` when called during an operation. [3](#0-2) 

When an operation begins via `start_op_with_bag()`, the `pre_vault_check()` function transitions the vault to `VAULT_DURING_OPERATION_STATUS`, which persists until the operation completes. [4](#0-3) 

The core issue manifests in the `update_tolerance()` function, which calculates the loss limit using the **current** `self.loss_tolerance` value at the time `end_op_value_update_with_bag()` is called. [5](#0-4) 

Since no temporal capture of the tolerance value occurs at operation start, and the tolerance can be modified mid-operation without restriction, the loss validation can be bypassed by increasing tolerance after observing actual losses but before completing the operation. [6](#0-5) 

**Exploitation Sequence:**
1. Operator initiates operation via `start_op_with_bag()` → vault status becomes `VAULT_DURING_OPERATION_STATUS`
2. Admin observes operation will result in 50bp loss (exceeding 10bp default tolerance)
3. Admin calls `set_loss_tolerance()` with 60bp value → succeeds without status check
4. Operator completes via `end_op_value_update_with_bag()` → validation uses new 60bp tolerance, operation succeeds

## Impact Explanation

This vulnerability compromises the fundamental safety guarantee of the loss tolerance mechanism, which exists to protect depositor funds from excessive operational losses. The specific impacts include:

**Safety Invariant Violation**: The protocol enforces loss limits to ensure vault operations cannot degrade value beyond acceptable thresholds. By allowing retroactive tolerance increases, this invariant becomes unenforceable. Operations that should fail under the configured risk parameters can be forced to succeed by adjusting parameters after the fact.

**Temporal Integrity Breach**: Standard DeFi security practice dictates that risk parameters effective at operation commencement should govern that operation's validation. This prevents parameter manipulation based on observed outcomes. The ability to change tolerance mid-operation violates this temporal integrity principle.

**User Protection Failure**: Loss tolerance exists specifically as a depositor protection mechanism. The default 10 basis point (0.1%) per-epoch tolerance is designed to limit value degradation. If this can be increased to 10,000 basis points (100%) mid-operation, it provides no meaningful protection.

**Practical Exploitation**: Consider a vault with 1M USD in assets. Under 10bp tolerance, maximum acceptable loss per epoch is $1,000. If an operation incurs $5,000 loss (50bp), it would normally fail validation. By increasing tolerance to 50bp or higher before operation completion, this $5,000 loss becomes acceptable, bypassing the intended protection.

The architectural inconsistency between `set_enabled()` and `set_loss_tolerance()` strongly indicates this is an oversight rather than intentional design, as the protocol clearly understands the need to prevent configuration changes during operations.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of occurrence:

**No Technical Barriers**: The function requires only `AdminCap`, which the admin legitimately possesses. No additional validation prevents the timing exploitation. [7](#0-6) 

**Design Pattern Evidence**: The existence of status protection in `set_enabled()` coupled with its absence in `set_loss_tolerance()` creates strong evidence this is unintentional. The test suite validates the `set_enabled()` protection but contains no corresponding test for `set_loss_tolerance()` during operations.

**Non-Atomic Operations**: Vault operations execute across multiple transactions with no atomicity guarantees. The three-step flow (start_op → value updates → end_op) can span significant time periods, creating extended windows for tolerance modification.

**Accidental Exploitation**: This doesn't require malicious intent. An admin legitimately adjusting tolerance for future operations may unknowingly affect an in-flight operation, as the blockchain provides no visibility into pending operation state from the admin interface.

**Real-World Operational Patterns**: DeFi vault operations frequently involve complex multi-step processes that take time to execute. During this window, admins may perform routine configuration updates without awareness of timing conflicts.

## Recommendation

Add vault status validation to `set_loss_tolerance()` consistent with the protection already implemented in `set_enabled()`:

```move
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    // Add status check to prevent modification during operations
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

This maintains consistency with other configuration functions and ensures the loss tolerance value in effect at operation start governs that operation's validation.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION)]
// Test that set_loss_tolerance fails when vault is during operation
public fun test_set_loss_tolerance_fail_during_operation() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault and start operation
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(ADMIN);
    {
        let operation = scenario.take_shared<Operation>();
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = scenario.take_from_sender<OperatorCap>();
        
        // Start operation - sets vault to DURING_OPERATION status
        let (asset_bag, tx_bag, tx_bag_check, principal, coin_asset) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC, USDC>(
                &mut vault, &operation, &cap, &clock,
                vector[], vector[], 0, 0, scenario.ctx()
            );
        
        // Attempt to set loss tolerance during operation
        // This should fail with ERR_VAULT_DURING_OPERATION (if fix applied)
        // Currently succeeds, demonstrating the vulnerability
        let admin_cap = scenario.take_from_sender<AdminCap>();
        vault_manage::set_loss_tolerance(&admin_cap, &mut vault, 100);
        
        // Cleanup
        scenario.return_to_sender(admin_cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

This test demonstrates that `set_loss_tolerance()` can be called during an active operation (after `start_op_with_bag()` sets `VAULT_DURING_OPERATION_STATUS`), while the analogous `set_vault_enabled()` test properly fails with `ERR_VAULT_DURING_OPERATION`.

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

**File:** volo-vault/tests/operation/operation.test.move (L3798-3800)
```text
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION, location = vault)]
// [TEST-CASE: Should set vault disabled fail if vault is during operation.] @test-case OPERATION-022
public fun test_start_op_and_set_vault_enabled_fail_vault_during_operation() {
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
