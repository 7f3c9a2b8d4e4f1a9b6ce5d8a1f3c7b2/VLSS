### Title
Asymmetric Request Cancellation Creates DoS for Pending Withdrawals When Vault is Disabled

### Summary
The `set_vault_enabled(false)` function creates an asymmetric denial-of-service condition for users with pending withdrawal requests. While deposit requests can be cancelled when the vault is disabled, withdrawal requests cannot be cancelled or executed, leaving users' shares locked in the `pending_withdraw_shares` state until the vault is re-enabled.

### Finding Description

The vulnerability stems from inconsistent vault status checks between deposit and withdrawal cancellation functions.

The `set_vault_enabled()` function in `manage.move` sets the vault status to `VAULT_DISABLED_STATUS` (2) when `enabled` is false: [1](#0-0) [2](#0-1) 

The vault status constants are defined as: [3](#0-2) 

**Root Cause - Asymmetric Status Checks:**

The `cancel_deposit()` function uses `assert_not_during_operation()`, which only blocks cancellation when status equals 1 (during operation): [4](#0-3) [5](#0-4) 

This allows deposit cancellation when the vault is disabled (status=2).

However, the `cancel_withdraw()` function uses `assert_normal()`, which requires status to exactly equal 0 (normal): [6](#0-5) [7](#0-6) 

This blocks withdrawal cancellation when the vault is disabled (status=2).

Additionally, `execute_withdraw()` also requires normal status, preventing execution: [8](#0-7) 

When a user requests a withdrawal, their shares are moved to `pending_withdraw_shares` and the receipt status changes: [9](#0-8) 

If the vault is disabled before cancellation or execution, users cannot recover their shares because `cancel_withdraw` requires normal status: [10](#0-9) 

### Impact Explanation

**Direct Operational Impact:**
- Users with pending withdrawal requests experience a denial-of-service on their funds when the vault is disabled
- Their shares remain locked in `pending_withdraw_shares` state and cannot be accessed
- Unlike deposit requests (which can be cancelled even when disabled), withdrawal requests are completely stuck

**Custody Integrity Impact:**
- The `VaultReceiptInfo` status remains in `PENDING_WITHDRAW_STATUS` (2) or `PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS` (3)
- Users cannot perform any operations with their pending shares until vault is re-enabled
- If the vault remains disabled for an extended period (maintenance, emergency pause, regulatory issues), users' funds are effectively frozen

**Security Integrity Impact:**
- Asymmetric behavior creates an inconsistent security model that violates user expectations
- The design allows deposit cancellation during disabled state but not withdrawal cancellation, with no documented rationale for this asymmetry

**Severity Justification:**
This is a HIGH severity issue because it directly impacts users' ability to access their funds through a legitimate operational flow (vault maintenance/emergency disable), creates an inconsistent security model, and can result in extended fund lockup if the vault remains disabled.

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is triggered through normal protocol operations:
1. Users call `request_withdraw()` when vault is normal (status=0)
2. Admin calls `set_vault_enabled(false)` for legitimate reasons (maintenance, emergency pause, etc.)
3. Users attempt to call `cancel_withdraw()` to recover their shares

**Feasible Preconditions:**
- Users have completed deposits and hold shares in their receipts
- Users submit withdrawal requests during normal vault operation
- Admin disables the vault before the withdrawal requests are executed (common during maintenance windows or emergency situations)

**Execution Practicality:**
The scenario requires no malicious behavior - it occurs during normal protocol maintenance:
- Vault operators may need to disable the vault for upgrades, parameter changes, or emergency pauses
- Users may have pending withdrawal requests that have passed the locking period but not yet been executed
- The timing window for this to occur is substantial given the default 5-minute cancellation locking period

**Economic Rationality:**
This is not an attack scenario but a protocol design flaw that manifests during legitimate operations. The issue affects users regardless of economic incentives and depends purely on the timing of admin actions relative to pending user requests.

**Probability Reasoning:**
The likelihood is MODERATE to HIGH because:
- Vault maintenance/disabling is a normal operational procedure
- Withdrawal requests can remain pending for extended periods awaiting operator execution
- The asymmetry is not documented, so operators may not realize users with pending withdrawals will be locked out
- The impact increases with the number of pending withdrawal requests at the time of disabling

### Recommendation

**Fix the Asymmetry:**

Modify `cancel_withdraw()` to use `assert_not_during_operation()` instead of `assert_normal()`, making it consistent with `cancel_deposit()`:

```move
public(package) fun cancel_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): u256 {
    self.check_version();
    self.assert_not_during_operation();  // Changed from assert_normal()
    // ... rest of function
}
```

**Rationale:**
- Users should be able to cancel their pending withdrawal requests even when the vault is disabled, just as they can cancel deposit requests
- Cancellation is a protective user action that doesn't require vault operations or oracle updates
- The only time cancellation should be blocked is during active operations (status=1) to prevent race conditions

**Alternative Consideration:**
If there is a specific reason why withdrawals should not be cancellable when disabled, then `cancel_deposit()` should also be changed to use `assert_normal()` for consistency, and this behavior should be clearly documented. However, this would be more restrictive and user-unfriendly.

**Add Test Cases:**
Create test case `test_cancel_withdraw_success_vault_disabled` (similar to the existing `test_cancel_deposit_success_vault_disabled` for deposits) to verify withdrawal requests can be cancelled when vault is disabled:
1. Request withdraw when vault is normal
2. Disable vault using `set_vault_enabled(false)`
3. Wait for locking period to pass
4. Successfully cancel withdraw request
5. Verify shares are returned to active state in receipt

**Invariant Checks:**
Document the expected behavior: "Request cancellation operations should be available whenever the vault is not during active operation (status != 1), including when disabled (status = 2), to allow users to recover their pending requests during vault maintenance periods."

### Proof of Concept

**Initial State:**
1. Vault is created and in NORMAL status (0)
2. User Alice deposits 1000 USDC and receives vault shares
3. Alice's receipt has `shares: 1000`, `pending_withdraw_shares: 0`, `status: NORMAL_STATUS`

**Transaction Sequence:**

**T1: Alice Requests Withdrawal**
```
user_entry::withdraw(vault, shares: 1000, expected_amount: 950, receipt, clock)
```
- Creates withdraw_request_id = 0
- Receipt updated: `pending_withdraw_shares: 1000`, `status: PENDING_WITHDRAW_STATUS (2)`
- Request stored in `vault.request_buffer.withdraw_requests[0]`

**T2: Admin Disables Vault**
```
vault_manage::set_vault_enabled(admin_cap, vault, enabled: false)
```
- Vault status changes: `VAULT_NORMAL_STATUS (0)` → `VAULT_DISABLED_STATUS (2)`

**T3: Time Passes - Locking Period Expires**
```
clock advances 5+ minutes past request_time
```

**T4: Alice Attempts to Cancel Withdrawal** ❌
```
user_entry::cancel_withdraw(vault, receipt, request_id: 0, clock)
  → calls vault.cancel_withdraw()
    → calls self.assert_normal()
      → Aborts with ERR_VAULT_NOT_NORMAL (5_022)
```

**T5: Operator Attempts to Cancel on Behalf of Alice** ❌
```
operation::cancel_user_withdraw(operation, operator_cap, vault, request_id: 0, receipt_id, recipient, clock)
  → calls vault.cancel_withdraw()
    → calls self.assert_normal()
      → Aborts with ERR_VAULT_NOT_NORMAL (5_022)
```

**T6: Operator Attempts to Execute Withdrawal** ❌
```
operation::execute_withdraw(operation, operator_cap, vault, clock, config, request_id: 0, max_amount: 1000)
  → calls vault.execute_withdraw()
    → calls self.assert_normal()
      → Aborts with ERR_VAULT_NOT_NORMAL (5_022)
```

**Expected vs Actual Result:**

**Expected:** Alice should be able to cancel her withdrawal request after the locking period, even when the vault is disabled, to recover her shares and regain control of her funds (consistent with how deposit cancellation works).

**Actual:** Alice's 1000 shares remain locked in `pending_withdraw_shares` state. She cannot cancel the request, operators cannot execute it, and the request remains stuck until the admin re-enables the vault. If the vault remains disabled for days or weeks, Alice's funds are effectively frozen despite having done nothing wrong.

**Success Condition for Fix:**
After applying the recommended fix, transaction T4 should succeed, with:
- `cancel_withdraw()` completes successfully even when vault status = 2 (disabled)
- Receipt updated: `pending_withdraw_shares: 0`, `status: NORMAL_STATUS (0)`, `shares: 1000`
- Withdraw request deleted from buffer
- Alice regains full control of her 1000 shares

### Citations

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}
```

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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

**File:** volo-vault/sources/volo_vault.move (L944-953)
```text
public(package) fun cancel_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): u256 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/sources/volo_vault.move (L994-1003)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);
```

**File:** volo-vault/sources/vault_receipt_info.move (L78-90)
```text
// Request withdraw: shares =, pending_withdraw_shares ↑
public(package) fun update_after_request_withdraw(
    self: &mut VaultReceiptInfo,
    pending_withdraw_shares: u256,
    recipient: address,
) {
    self.status = if (recipient == address::from_u256(0)) {
        PENDING_WITHDRAW_STATUS
    } else {
        PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS
    };
    self.pending_withdraw_shares = self.pending_withdraw_shares + pending_withdraw_shares;
}
```

**File:** volo-vault/sources/vault_receipt_info.move (L93-99)
```text
public(package) fun update_after_cancel_withdraw(
    self: &mut VaultReceiptInfo,
    cancelled_withdraw_shares: u256,
) {
    self.status = NORMAL_STATUS;
    self.pending_withdraw_shares = self.pending_withdraw_shares - cancelled_withdraw_shares;
}
```
