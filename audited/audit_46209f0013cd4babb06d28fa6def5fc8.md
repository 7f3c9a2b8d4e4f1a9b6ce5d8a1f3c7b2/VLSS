### Title
Immediate Operation Failure via Loss Tolerance Decrease During Active Operations

### Summary
The `vault_manage::set_loss_tolerance()` function allows the AdminCap holder to update the loss tolerance parameter for a vault, with immediate effect on in-progress operations. If the loss tolerance is decreased while an operation is active, the operation will fail to complete when attempting value update validation, causing the vault to become stuck in VAULT_DURING_OPERATION_STATUS and blocking all user deposits and withdrawals until admin intervention.

### Finding Description
This vulnerability is analogous to the external MMR update issue, where a risk parameter change immediately invalidates existing positions. In Volo's vault system:

The `set_loss_tolerance()` function in `vault_manage` [1](#0-0)  calls the internal `vault::set_loss_tolerance()` [2](#0-1)  which updates the tolerance immediately without any grace period or checks for active operations.

During vault operations, the three-phase process includes a value update check in `operation::end_op_value_update_with_bag()` [3](#0-2)  which calls `vault::update_tolerance()` to validate that accumulated losses do not exceed the tolerance limit [4](#0-3) . The critical assertion at line 635 fails if `loss_limit < cur_epoch_loss`.

**Root Cause:** The loss_tolerance parameter change takes effect immediately on the shared vault object, affecting in-progress operations that were initiated under different tolerance expectations.

**Why Protections Fail:**
- No check exists to prevent tolerance updates during VAULT_DURING_OPERATION_STATUS [2](#0-1) 
- The `cur_epoch_loss` value accumulates and cannot decrease (only resets at epoch boundaries or admin reset) [4](#0-3) 
- Operations cannot complete once tolerance is decreased below accumulated loss

**Exploit Path:**
1. Operator initiates operation via `start_op_with_bag()` which sets vault status to DURING_OPERATION [5](#0-4) 
2. Operation executes and incurs 0.8% loss (80 basis points), within initial 1% tolerance
3. Admin calls `set_loss_tolerance(50)` to decrease tolerance to 0.5% [1](#0-0) 
4. Operator attempts to complete via `end_op_value_update_with_bag()`
5. The tolerance check calculates: `loss_limit = base_value * 0.5% / 10000` but `cur_epoch_loss = base_value * 0.8% / 10000`
6. Assertion fails: `assert!(loss_limit >= cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT)` [6](#0-5) 
7. Vault remains stuck in VAULT_DURING_OPERATION_STATUS
8. All user operations blocked: deposits/withdrawals require VAULT_NORMAL_STATUS [7](#0-6) 

### Impact Explanation
**Concrete Protocol Impact:**
- **Denial of Service:** Vault becomes stuck in VAULT_DURING_OPERATION_STATUS until admin intervention
- **Fund Lock:** All user deposits and withdrawals are blocked, as they require vault status to be NORMAL [7](#0-6) 
- **Loss of Protection:** The loss_tolerance mechanism designed to protect users from excessive operational losses is undermined when it can be arbitrarily changed mid-operation

**Severity:** Medium-High. While admin can recover by either increasing tolerance back or calling `reset_loss_tolerance()` [8](#0-7) , users experience temporary fund inaccessibility and loss of expected risk guarantees. The admin cannot use `set_enabled()` as recovery since it explicitly blocks DURING_OPERATION status [9](#0-8) .

### Likelihood Explanation
**Realistic Exploit Feasibility:**
- **Trigger:** Requires only AdminCap holder calling `set_loss_tolerance()` with lower value during active operation
- **Preconditions:** Minimal - vault must have an active operation with accumulated loss
- **Complexity:** Low - single function call with no complex setup
- **Realistic Scenarios:**
  - Accidental: Admin adjusts risk parameters not realizing operation is in progress
  - Intentional: Malicious or compromised admin deliberately blocks operations
  - Governance: Multi-sig/DAO governance changes tolerance during maintenance window that overlaps with operation

The vulnerability is highly likely in normal protocol operation as operations can span multiple transactions and admin parameter updates are expected to occur independently.

### Recommendation
Implement one or more of the following mitigations:

1. **Add Operation Status Check:** Prevent loss_tolerance updates during active operations
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

2. **Implement Timelock/Grace Period:** Store a `pending_loss_tolerance` and `tolerance_change_timestamp`, applying changes only after a delay (e.g., 24 hours) to allow in-progress operations to complete.

3. **Tolerance Decrease Restrictions:** Only allow tolerance increases immediately; require special admin procedures (with epoch delay) for decreases that could affect active operations.

4. **Grandfathering:** Store the tolerance value at operation start and use that value for the specific operation's validation, isolating parameter changes from in-flight operations.

### Proof of Concept
**Scenario Setup:**
- Vault with 10,000 USD total value
- Initial loss_tolerance: 100 (1.0% = 100 basis points)
- Operator starts operation borrowing assets

**Exploit Steps:**

1. **T0 - Operation Start:** Operator calls `start_op_with_bag()` 
   - Vault status → VAULT_DURING_OPERATION_STATUS
   - Records `cur_epoch_loss_base_usd_value = 10,000 USD`
   - Current `loss_tolerance = 100`

2. **T1 - Operation Executes:** DeFi positions incur 0.8% loss (80 USD)
   - Expected loss_limit: 10,000 * 100 / 10,000 = 100 USD
   - Actual loss: 80 USD
   - Status: Within tolerance ✓

3. **T2 - Admin Updates (Exploit):** Admin calls `vault_manage::set_loss_tolerance(admin_cap, vault, 50)`
   - New `loss_tolerance = 50` (0.5%)
   - Takes effect immediately on shared vault
   - No check for DURING_OPERATION status

4. **T3 - Operation Completion Fails:** Operator calls `end_op_value_update_with_bag()`
   - Calculates: `loss_limit = 10,000 * 50 / 10,000 = 50 USD`
   - But: `cur_epoch_loss = 80 USD`
   - Assertion fails: `assert!(50 >= 80)` → ERR_EXCEED_LOSS_LIMIT (5_008)
   - Transaction aborts, vault remains DURING_OPERATION

5. **T4 - User Impact:** Users attempt deposits/withdrawals
   - All operations check `assert_normal()` 
   - Fail with ERR_VAULT_NOT_NORMAL (5_022)
   - Funds locked until admin intervention

**Recovery:** Admin must either:
- Call `set_loss_tolerance(100+)` to restore tolerance, OR
- Call `reset_loss_tolerance()` to reset accumulated loss to 0

### Citations

**File:** volo-vault/sources/manage.move (L58-63)
```text
public fun set_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    loss_tolerance: u256,
) {
    vault.set_loss_tolerance(loss_tolerance);
```

**File:** volo-vault/sources/manage.move (L170-175)
```text
public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.try_reset_tolerance(true, ctx);
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

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
