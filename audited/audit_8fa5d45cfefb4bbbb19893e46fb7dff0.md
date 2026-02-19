### Title
Critical Parameter Modification During Vault Operations Bypasses Loss Tolerance Protection

### Summary
The setter functions in `manage.move` (`set_deposit_fee`, `set_withdraw_fee`, `set_loss_tolerance`, `set_locking_time_for_withdraw`, `set_locking_time_for_cancel_request`) do not verify that the vault is not in `VAULT_DURING_OPERATION_STATUS` before modifying critical parameters. This allows the admin to change loss tolerance mid-operation, bypassing the loss limit protection that is essential for protecting vault funds from excessive losses during DeFi operations.

### Finding Description

The vault implements three status states: `VAULT_NORMAL_STATUS` (0), `VAULT_DURING_OPERATION_STATUS` (1), and `VAULT_DISABLED_STATUS` (2). [1](#0-0) 

The `set_enabled` function correctly checks that the vault is not during operation before changing the status: [2](#0-1) 

However, all other setter functions exposed through `manage.move` fail to implement this check:

1. **set_loss_tolerance** - Only calls `check_version()`, missing vault status check: [3](#0-2) 

2. **set_deposit_fee** - Only calls `check_version()`, missing vault status check: [4](#0-3) 

3. **set_withdraw_fee** - Only calls `check_version()`, missing vault status check: [5](#0-4) 

4. **set_locking_time_for_withdraw** - Only calls `check_version()`, missing vault status check: [6](#0-5) 

5. **set_locking_time_for_cancel_request** - Only calls `check_version()`, missing vault status check: [7](#0-6) 

The root cause is the absence of `assert_not_during_operation()` or equivalent check in these functions.

**Critical Execution Path for Loss Tolerance Bypass:**

During an operation flow, the vault status changes and loss tolerance is enforced:

1. Operation starts and captures initial total_usd_value: [8](#0-7) 

2. At operation end, the loss is calculated and checked against loss_tolerance: [9](#0-8) 

3. The `update_tolerance` function enforces the loss limit using the current `loss_tolerance` value: [10](#0-9) 

If the admin calls `set_loss_tolerance` during the operation (between steps 1 and 2), the check at step 3 uses the modified tolerance value instead of the original value in effect when the operation started, allowing the bypass.

### Impact Explanation

**Security Integrity Impact - Loss Tolerance Bypass:**
The loss tolerance mechanism is a critical safety feature that limits the maximum loss per epoch to protect vault depositors. By default, it's set to 0.1% (10 basis points). [11](#0-10) 

An admin can:
1. Observe an ongoing operation that is losing money
2. Increase the loss tolerance from 0.1% to the maximum (10000 basis points = 100%)
3. Allow the operation to complete with losses that should have been rejected

This completely bypasses the loss protection mechanism, allowing operations that lose significantly more than the intended tolerance. For a vault with $1M USD value, this could mean allowing a $100K+ loss instead of the intended $1K limit.

**Direct Fund Impact - Unexpected Fee Collection:**
By changing `deposit_fee_rate` or `withdraw_fee_rate` during operations, fees can be increased from the default 10 basis points up to the maximum 500 basis points (5%). [12](#0-11) 

Users who submitted deposit/withdraw requests expecting 0.1% fees could be charged 5% fees when their requests are executed after the operation completes, resulting in a 50x fee increase.

**Operational Impact - Modified Locking Times:**
Changing locking times during operations affects users' ability to cancel pending requests. Users who submitted requests with a 5-minute cancellation window could suddenly face a 24-hour window, locking their funds unexpectedly.

### Likelihood Explanation

**Reachable Entry Point:**
All setter functions are callable by the admin through public functions in `manage.move`: [13](#0-12) 

**Feasible Preconditions:**
- Requires admin role (AdminCap), which is a trusted role
- However, this is a **design flaw** that removes critical safeguards, not a malicious compromise scenario
- Admin may legitimately need to adjust parameters, but the protocol should prevent modifications during sensitive operation periods
- The existence of the check in `set_enabled` proves the protocol intended to prevent mid-operation modifications

**Execution Practicality:**
The vulnerability is trivially exploitable:
1. Wait for operator to call `start_op_with_bag` (vault enters DURING_OPERATION status)
2. Call any setter function (e.g., `set_loss_tolerance`)
3. Parameter change takes effect immediately, affecting the ongoing operation

**Detection/Operational Constraints:**
Even well-intentioned admins could accidentally trigger this vulnerability:
- Admin may not be aware operations are in progress
- No atomic operation tracking visible to admin at the time of parameter changes
- Protocol design assumes parameters remain stable during operations for loss calculations

The likelihood is HIGH because:
1. The inconsistent implementation (set_enabled has the check, others don't) suggests this was an oversight
2. Admin actions during operations are operationally feasible
3. The impact on loss tolerance directly undermines a critical security invariant

### Recommendation

**Immediate Fix:**
Add `assert_not_during_operation()` check to all critical parameter setter functions in `volo_vault.move`:

```move
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    self.assert_not_during_operation();  // ADD THIS CHECK
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

Apply the same check to:
- `set_deposit_fee` (line 497)
- `set_withdraw_fee` (line 508)
- `set_locking_time_for_withdraw` (line 543)
- `set_locking_time_for_cancel_request` (line 556)

The `assert_not_during_operation()` function already exists and is used by `set_enabled`: [14](#0-13) 

**Invariant Checks:**
Add assertions to verify:
1. Loss tolerance cannot be modified between `pre_vault_check` and `end_op_value_update_with_bag`
2. Fee rates used in deposit/withdraw execution match the rates when requests were submitted
3. Locking times remain consistent from request submission to cancellation eligibility

**Test Cases:**
1. Attempt to call each setter function while vault status is `VAULT_DURING_OPERATION_STATUS` - should revert with `ERR_VAULT_DURING_OPERATION`
2. Verify loss tolerance enforcement uses the value set before operation started, not mid-operation changes
3. Test that parameter changes revert during the entire operation lifecycle (from `start_op_with_bag` through `end_op_value_update_with_bag`)

### Proof of Concept

**Initial State:**
- Vault has $1,000,000 USD total value
- Loss tolerance set to 10 (0.1% = $1,000 max loss per epoch)
- Admin has AdminCap
- Operator has OperatorCap

**Exploit Sequence:**

1. **Operator starts operation:**
   - Calls `start_op_with_bag` to begin DeFi strategy
   - Vault status changes to `VAULT_DURING_OPERATION_STATUS` (1)
   - Initial total_usd_value captured: $1,000,000

2. **Admin observes operation losing money:**
   - Current operation is down to $990,000 (loss of $10,000 = 1%)
   - This exceeds the 0.1% tolerance and would fail the check

3. **Admin modifies loss tolerance mid-operation:**
   - Calls `set_loss_tolerance(vault, 1000)` (setting to 10%)
   - Transaction succeeds because function lacks `assert_not_during_operation()` check
   - New loss_tolerance: 1000 (10%)

4. **Operator completes operation:**
   - Calls `end_op_value_update_with_bag`
   - Loss calculated: $1,000,000 - $990,000 = $10,000
   - Loss limit check: `loss_limit = $1,000,000 * 1000 / 10000 = $100,000`
   - Check passes: $10,000 < $100,000 ✓
   - Operation completes successfully

**Expected Result:** 
Operation should fail at step 4 with `ERR_EXCEED_LOSS_LIMIT` because the loss ($10,000) exceeds the original tolerance ($1,000).

**Actual Result:** 
Operation succeeds because the modified tolerance ($100,000 limit) is checked instead, bypassing the loss protection mechanism.

**Success Condition:**
An operation that should be rejected for exceeding loss limits is allowed to complete, demonstrating the bypass of the critical loss tolerance invariant.

### Citations

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
```

**File:** volo-vault/sources/volo_vault.move (L30-33)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/sources/volo_vault.move (L497-505)
```text
public(package) fun set_deposit_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_DEPOSIT_FEE_RATE, ERR_EXCEED_LIMIT);
    self.deposit_fee_rate = fee;
    emit(DepositFeeChanged { vault_id: self.vault_id(), fee: fee })
}
```

**File:** volo-vault/sources/volo_vault.move (L508-516)
```text
public(package) fun set_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_WITHDRAW_FEE_RATE, ERR_EXCEED_LIMIT);
    self.withdraw_fee_rate = fee;
    emit(WithdrawFeeChanged { vault_id: self.vault_id(), fee: fee })
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

**File:** volo-vault/sources/volo_vault.move (L543-554)
```text
public(package) fun set_locking_time_for_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    self.locking_time_for_withdraw = locking_time;

    emit(LockingTimeForWithdrawChanged {
        vault_id: self.vault_id(),
        locking_time: locking_time,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L556-567)
```text
public(package) fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    self.locking_time_for_cancel_request = locking_time;

    emit(LockingTimeForCancelRequestChanged {
        vault_id: self.vault_id(),
        locking_time: locking_time,
    });
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/manage.move (L42-80)
```text
public fun set_deposit_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    deposit_fee: u64,
) {
    vault.set_deposit_fee(deposit_fee);
}

public fun set_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    withdraw_fee: u64,
) {
    vault.set_withdraw_fee(withdraw_fee);
}

public fun set_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    loss_tolerance: u256,
) {
    vault.set_loss_tolerance(loss_tolerance);
}

public fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_cancel_request(locking_time);
}

public fun set_locking_time_for_withdraw<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_withdraw(locking_time);
}
```
