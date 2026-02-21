# Audit Report

## Title
Loss Tolerance Base Can Be Manipulated During Active Operations Leading to Incorrect Loss Limit Validation

## Summary
The `reset_loss_tolerance()` admin function lacks vault status validation, allowing it to be called while operations are active. This modifies the `cur_epoch_loss_base_usd_value` mid-operation, breaking the protocol invariant that operation parameters remain immutable during the operation lifecycle. This can enable loss tolerance bypass when vault value is inflated or cause DoS of legitimate operations when vault value is deflated.

## Finding Description

The vulnerability stems from a missing operation status guard in the admin function `reset_loss_tolerance()`. [1](#0-0) 

This function directly calls `try_reset_tolerance` with `by_admin = true`, which unconditionally resets the loss tolerance state regardless of vault status. [2](#0-1) 

When `by_admin = true`, line 618 resets `cur_epoch_loss_base_usd_value` to the current vault's total USD value without verifying if an operation is in progress.

During the operation lifecycle, the vault status changes to `VAULT_DURING_OPERATION_STATUS` at the start of operations. [3](#0-2) 

At operation completion, loss is validated against `cur_epoch_loss_base_usd_value` to ensure operations don't exceed acceptable loss limits. [4](#0-3) 

The loss limit calculation occurs in `update_tolerance`, which uses `cur_epoch_loss_base_usd_value` as the base for calculating the maximum allowed loss. [5](#0-4) 

**Root Cause:** The `reset_loss_tolerance` function does not include an `assert_not_during_operation()` check. In contrast, other admin configuration functions such as `set_enabled` explicitly prevent execution during operations through a status assertion at line 523. [6](#0-5) 

The `assert_not_during_operation` function exists in the codebase specifically for this purpose. [7](#0-6) 

This inconsistency indicates that the missing check in `reset_loss_tolerance` is a design oversight rather than intentional behavior, allowing admins to inadvertently modify critical operation parameters mid-execution and violate the protocol invariant that operation parameters remain stable throughout the operation lifecycle.

## Impact Explanation

**Loss Tolerance Bypass:**
When an admin resets tolerance during an operation while vault value is temporarily inflated (e.g., from unrealized profitable positions), the `cur_epoch_loss_base_usd_value` increases. The loss limit calculation becomes: `inflated_value * loss_tolerance / RATE_SCALING`. Operations can now sustain larger absolute losses while still passing validation. For example, with 0.1% tolerance on a $1M vault (max loss $1,000), if reset at $1.1M mid-operation, it allows $1,100 loss—a 10% increase in absolute loss tolerance beyond the intended limit established at operation start.

**Denial of Service of Valid Operations:**
Conversely, if an admin resets tolerance when vault value is temporarily deflated, the `cur_epoch_loss_base_usd_value` decreases. Legitimate operations that would have passed with the original base now fail with `ERR_EXCEED_LOSS_LIMIT`. For example, an operation starting at $1M (max loss $1,000) where admin resets at $900K (max loss $900) will cause an actual loss of $950 to unexpectedly revert.

**Protocol Invariant Violation:**
The operation flow captures `total_usd_value` at start to ensure consistent validation throughout the operation. However, the loss limit calculation uses `cur_epoch_loss_base_usd_value` which can be modified mid-operation, breaking the fundamental assumption that loss tolerance parameters are immutable during operations—similar to how vault status itself is protected from changes during operations.

## Likelihood Explanation

**Entry Point:** The function is directly callable by anyone holding `AdminCap` through the standard administrative interface.

**Feasibility:** While this requires `AdminCap` (a trusted role), this represents unintended behavior based on the protocol's own established pattern. Other admin configuration functions like `set_enabled` explicitly prevent execution during operations, with this constraint validated by test cases. The missing check in `reset_loss_tolerance` is a design oversight—admins could legitimately attempt to reset tolerance without realizing an operation is active, triggering the issue accidentally.

**Execution Practicality:** The operation flow spans multiple transactions (start → execute DeFi strategies → return assets → validate). During this window, vault value naturally fluctuates from DeFi interactions (Navi lending positions, Cetus liquidity positions, etc.). Admins could attempt to reset tolerance for legitimate reasons (e.g., after recovering from temporary losses) without checking vault status first. No technical barriers prevent the call.

**Detection Constraints:** While vault status is publicly visible on-chain, admins may not check it before every configuration change. Effects are not immediately visible until operation completes. The modification of the loss limit calculation occurs silently without obvious indicators.

This represents a **protocol design flaw** rather than malicious admin behavior—analogous to how missing input validation is still a vulnerability even in admin-only functions. The function should have proper guards regardless of caller privileges. The inconsistency with `set_enabled` strongly indicates this violates the protocol's own established security pattern for admin functions.

## Recommendation

Add the `assert_not_during_operation()` check to the `reset_loss_tolerance()` function in `manage.move`:

```move
public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.assert_not_during_operation();  // Add this line
    vault.try_reset_tolerance(true, ctx);
}
```

This aligns the function with the established pattern used by `set_enabled()` and other admin configuration functions, preventing accidental modification of operation parameters during active operations.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION)]
fun test_reset_loss_tolerance_fail_during_operation() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and operation
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Setup and start operation to set vault status to DURING_OPERATION
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let (asset_bag, tx_bag, tx_bag_check, principal_bal, coin_bal) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, ObligationType>(
                &mut vault, &operation, &cap, &clock,
                vector[], vector[], 0, 0, s.ctx()
            );
        
        // Vault is now in DURING_OPERATION status
        // Attempt to reset loss tolerance - should fail
        let admin_cap = s.take_from_sender<AdminCap>();
        vault_manage::reset_loss_tolerance(&admin_cap, &mut vault, s.ctx());
        
        // Cleanup (unreachable due to expected failure)
        abort 0
    };
}
```

## Notes

This vulnerability is classified as a **design flaw** rather than a malicious admin attack. The admin role is trusted, but the function lacks defensive programming to prevent accidental protocol invariant violations. The strong evidence for this being unintended behavior includes:

1. The existence of `assert_not_during_operation()` function specifically for this purpose
2. Consistent use of this guard in `set_enabled()` and validation via test case `test_start_op_and_set_vault_enabled_fail_vault_during_operation`
3. No test coverage for `reset_loss_tolerance()` during operations, unlike other admin functions
4. The error code `ERR_VAULT_DURING_OPERATION` exists but is not utilized by this function

The vulnerability allows modification of `cur_epoch_loss_base_usd_value` mid-operation, which directly affects loss validation at operation completion, potentially allowing excessive losses or incorrectly rejecting valid operations based on timing of the admin action relative to vault value fluctuations.

### Citations

**File:** volo-vault/sources/manage.move (L170-176)
```text
public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.try_reset_tolerance(true, ctx);
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

**File:** volo-vault/sources/volo_vault.move (L608-624)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
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

**File:** volo-vault/sources/volo_vault.move (L657-660)
```text
public(package) fun assert_not_during_operation<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
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
