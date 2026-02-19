### Title
Loss Tolerance Bypass via Admin Reset During Active Operation

### Summary
The `reset_loss_tolerance()` admin function lacks vault status validation, allowing it to be called while the vault is in `VAULT_DURING_OPERATION_STATUS`. This creates a race condition where the admin can reset the epoch loss counter after an operation starts but before it completes, bypassing the `ERR_EXCEED_LOSS_LIMIT` check and allowing operations that would otherwise fail the loss tolerance invariant.

### Finding Description

The vulnerability exists in the `reset_loss_tolerance()` function which lacks any vault status check: [1](#0-0) 

This function directly calls `try_reset_tolerance(true, ctx)` which only performs a version check: [2](#0-1) 

When `by_admin=true`, the function unconditionally resets `cur_epoch_loss` to 0 (line 616), bypassing the epoch check.

**The Critical Race Window:**

During the three-step operation flow, the vault status transitions as follows:

1. `start_op_with_bag` sets status to `VAULT_DURING_OPERATION_STATUS`: [3](#0-2) 

2. Between start and end, assets are borrowed and DeFi operations execute

3. `end_op_value_update_with_bag` checks loss tolerance: [4](#0-3) 

**Root Cause:**

The loss is checked at line 363 by calling `vault.update_tolerance(loss)`: [5](#0-4) 

The check at line 635 compares `loss_limit >= cur_epoch_loss`. If admin calls `reset_loss_tolerance()` during the operation window, `cur_epoch_loss` is reset to 0, causing previously accumulated losses to be ignored.

**Why Existing Protections Fail:**

Other admin configuration functions properly check vault status during operations. For example, `set_enabled()` explicitly prevents changes during operations: [6](#0-5) 

Similarly, user-facing functions like `cancel_deposit` check status: [7](#0-6) 

The absence of this check in `reset_loss_tolerance()` is a design inconsistency that violates the protocol's status-based synchronization pattern.

### Impact Explanation

**Security Integrity Bypass:**
- The loss tolerance mechanism is a critical safety invariant designed to prevent unlimited value degradation per epoch
- By resetting the counter mid-operation, accumulated losses are erased from tracking
- Multiple operations can exceed tolerance within a single epoch if reset between each operation

**Concrete Harm:**
- Vault with $20,000 base value and 0.1% tolerance (default) should reject operations causing >$20 loss per epoch
- If vault has already lost $15 and current operation will lose $10, it should fail (total $25 > $20)
- Admin reset before `end_op_value_update_with_bag` makes counter show only $10, check passes
- Actual loss of $25 exceeds limit but is not enforced

**Who Is Affected:**
- All vault depositors who rely on loss tolerance as downside protection
- Protocol reputation if tolerance limits are advertised but not enforced

**Severity Justification:**
- Bypasses explicitly configured safety limit (Critical invariant #3: loss_tolerance per epoch)
- No technical limit to accumulated losses if reset is timed repeatedly
- Defeats documented purpose of loss tolerance system

### Likelihood Explanation

**Reachable Entry Point:**
`reset_loss_tolerance()` is a public entry function requiring `AdminCap`: [1](#0-0) 

**Feasible Preconditions:**
- Admin and operator can be different parties or roles
- Admin may use automated scripts/bots to reset tolerance at epoch boundaries
- Network latency creates natural race windows between transaction submission and execution
- Admin may legitimately attempt to reset tolerance without knowing operation is in progress

**Execution Sequence:**
1. Operator submits `start_op_with_bag` transaction (vault enters DURING_OPERATION status)
2. DeFi operations execute, losses accumulate
3. Admin submits `reset_loss_tolerance()` transaction (possibly automated/scheduled)
4. Due to transaction ordering (gas prices, network timing), admin tx executes first
5. Operator's `end_op_value_update_with_bag` transaction then succeeds with reset counter

**Attack Complexity:**
- Low - requires only transaction timing, no exploit contract needed
- Can occur accidentally through concurrent legitimate usage
- Higher probability in automated operation environments

**Detection Constraints:**
- No on-chain detection mechanism for this race condition
- Events emit both reset and operation completion, but correlation requires off-chain monitoring

### Recommendation

Add vault status validation to `reset_loss_tolerance()` to prevent resets during active operations:

```move
public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.assert_not_during_operation(); // Add this check
    vault.try_reset_tolerance(true, ctx);
}
```

Alternatively, add the check within `try_reset_tolerance()` when called with `by_admin=true`:

```move
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();
    
    if (by_admin) {
        self.assert_not_during_operation(); // Add this for admin resets
    }
    
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

**Test Case:**
Add test verifying `reset_loss_tolerance()` reverts with `ERR_VAULT_DURING_OPERATION` when called between `start_op_with_bag` and `end_op_value_update_with_bag`.

### Proof of Concept

**Initial State:**
- Vault with $20,000 base value
- Loss tolerance: 10 (0.1%) = $20 max loss per epoch
- Current epoch loss: $15 (accumulated from previous operations)
- Loss limit remaining: $5

**Transaction Sequence:**

1. **T1**: Operator calls `start_op_with_bag`
   - Vault status → `VAULT_DURING_OPERATION_STATUS`
   - `cur_epoch_loss` = $15 (unchanged)

2. **T2**: DeFi operations execute
   - Operation will cause $10 loss (total would be $25)

3. **T3**: Admin calls `reset_loss_tolerance()` (races with T4)
   - No status check performed
   - `cur_epoch_loss` → $0
   - `cur_epoch_loss_base_usd_value` updated

4. **T4**: Operator calls `end_op_value_update_with_bag`
   - Calculates loss = $10
   - Calls `update_tolerance($10)`
   - Check: `loss_limit ($20) >= cur_epoch_loss ($0 + $10)` ✓ **PASSES**
   - Vault status → `VAULT_NORMAL_STATUS`

**Expected Result:**
Transaction T4 should fail with `ERR_EXCEED_LOSS_LIMIT` because total epoch loss ($15 + $10 = $25) exceeds limit ($20).

**Actual Result:**
Transaction T4 succeeds because admin reset erased the $15 accumulated loss, making the check see only $10.

**Success Condition:**
Operation completes successfully with total epoch losses ($25) exceeding configured tolerance ($20), violating the loss tolerance invariant.

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

**File:** volo-vault/sources/volo_vault.move (L761-770)
```text
public(package) fun cancel_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): Coin<PrincipalCoinType> {
    self.check_version();
    self.assert_not_during_operation();

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
