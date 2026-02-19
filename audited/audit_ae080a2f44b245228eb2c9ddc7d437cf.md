### Title
Retroactive Application of Locking Time Changes Affects Existing Requests and Receipts

### Summary
The admin functions `set_locking_time_for_cancel_request` and `set_locking_time_for_withdraw` modify global vault parameters that are retroactively applied to all existing pending requests and deposited receipts. This violates user expectations as locking conditions change after users have committed their funds, potentially extending lock periods indefinitely or allowing premature access, creating operational DoS or bypassing intended safety mechanisms.

### Finding Description

**Location 1: Cancel Request Locking Time**

The admin can modify `locking_time_for_cancel_request` via: [1](#0-0) 

This updates the vault's global locking time parameter: [2](#0-1) 

However, when checking if a request can be cancelled, the code uses the **current** vault locking time, not the time when the request was created: [3](#0-2) [4](#0-3) 

The request only stores `request_time` (timestamp when created): [5](#0-4) 

**Location 2: Withdraw Locking Time**

The admin can modify `locking_time_for_withdraw` via: [6](#0-5) 

This updates the vault's global locking time parameter: [7](#0-6) 

When checking if withdrawal is allowed, the code uses the **current** vault locking time: [8](#0-7) 

This check is enforced in user-facing withdrawal functions: [9](#0-8) 

The receipt only stores `last_deposit_time` (timestamp when deposited): [10](#0-9) 

**Root Cause:**
Neither requests nor receipts store the locking time parameter value at the moment of creation. Instead, all time-based checks read from the vault's current global state, making any admin parameter changes immediately affect all historical positions.

### Impact Explanation

**Concrete Harm:**
1. **Extended Lock Period (DoS)**: Admin increases locking times from default 12 hours to 7 days. All existing users who deposited expecting 12-hour withdrawal lock suddenly face 7-day lock. Users with pending requests expecting 5-minute cancellation window now must wait significantly longer. Funds are effectively frozen beyond agreed terms.

2. **Premature Access**: Admin decreases locking times to zero. Users can immediately cancel requests or withdraw after deposits, bypassing the safety mechanism designed to prevent flash-loan style attacks or give operators time to process requests properly.

**Who is Affected:**
- All users with pending deposit/withdraw requests
- All users with deposited funds (receipts) in the vault
- Any user planning cancellations or withdrawals based on original locking parameters

**Severity Justification:**
HIGH severity because it creates operational DoS (funds locked beyond expectations) and undermines the security model's time-based protections. While requiring admin action, this is a design flaw where legitimate parameter updates have unintended retroactive consequences, not requiring malicious intent or compromise.

### Likelihood Explanation

**Attacker Capabilities:**
Admin with `AdminCap` can call setter functions. However, this is a design vulnerability, not an attack requiring malicious admin. Well-intentioned admins updating parameters for improved future operations will inadvertently affect existing users.

**Attack Complexity:**
Simple single-transaction parameter update. No complex sequencing required.

**Feasibility Conditions:**
- Admin legitimately adjusting parameters (e.g., increasing from 12h to 24h for better operational margins)
- Existing users with pending requests or deposited funds
- Users attempt to cancel requests or initiate withdrawals under changed conditions

**Probability Reasoning:**
HIGH probability as this will occur naturally during normal protocol governance when adjusting locking parameters for operational reasons. The retroactive effect is an unintended consequence, not requiring deliberate exploitation.

### Recommendation

**Code-Level Mitigation:**

1. Store locking time values within each request and receipt at creation time:

For requests - modify `DepositRequest` and `WithdrawRequest` to include:
```move
locking_time_for_cancel: u64  // Snapshot at request creation
```

For receipts - modify `VaultReceiptInfo` to include:
```move
locking_time_for_withdraw: u64  // Snapshot at last deposit
```

2. Update request creation functions to capture current locking time:
    - In `request_deposit`: store `vault.locking_time_for_cancel_request` in request
    - In `request_withdraw`: store `vault.locking_time_for_cancel_request` in request
    - In `execute_deposit`: store `vault.locking_time_for_withdraw` in receipt

3. Update checking functions to use stored values:
    - `cancel_deposit`: use `request.locking_time_for_cancel` instead of `self.locking_time_for_cancel_request`
    - `cancel_withdraw`: use `request.locking_time_for_cancel` instead of `self.locking_time_for_cancel_request`
    - `check_locking_time_for_withdraw`: use `receipt.locking_time_for_withdraw` instead of `self.locking_time_for_withdraw`

**Invariant Checks:**
Add documentation stating: "Locking time changes apply only to new requests/deposits created after the change. Existing positions retain their original locking terms."

**Test Cases:**
1. Create request with 5-minute lock → admin changes to 10 minutes → verify original request still cancellable after 5 minutes
2. Deposit with 12-hour lock → admin changes to 24 hours → verify withdrawal still possible after 12 hours from original deposit
3. Create request → admin changes to 0 → verify original request still requires original locking period

### Proof of Concept

**Initial State:**
- Vault created with default `locking_time_for_withdraw = 12 hours` (43,200,000 ms)
- User deposits 1000 principal tokens at timestamp T0, receives receipt

**Transaction Steps:**

1. **T0 + 6 hours**: User attempts withdrawal
   - Calls `user_entry::withdraw` 
   - Check: `T0 + 43,200,000 <= T0 + 21,600,000` → FAILS
   - Result: Transaction reverts with `ERR_WITHDRAW_LOCKED`

2. **T0 + 8 hours**: Admin increases locking time to 24 hours
   - Calls `manage::set_locking_time_for_withdraw(vault, 86,400,000)`
   - Vault's `locking_time_for_withdraw` updated to 86,400,000 ms

3. **T0 + 13 hours**: User attempts withdrawal again (past original 12-hour lock)
   - Calls `user_entry::withdraw`
   - Check: `T0 + 86,400,000 <= T0 + 46,800,000` → FAILS  
   - Result: Transaction reverts with `ERR_WITHDRAW_LOCKED`

**Expected vs Actual:**
- **Expected**: User can withdraw after 12 hours from deposit (original locking term at T0)
- **Actual**: User must now wait 24 hours from deposit (retroactively applied new locking term)

**Success Condition for Exploit:**
Admin parameter change successfully extends lock period for existing receipt beyond originally agreed terms, demonstrating retroactive application vulnerability.

### Citations

**File:** volo-vault/sources/manage.move (L66-72)
```text
public fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_cancel_request(locking_time);
}
```

**File:** volo-vault/sources/manage.move (L74-80)
```text
public fun set_locking_time_for_withdraw<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_withdraw(locking_time);
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

**File:** volo-vault/sources/volo_vault.move (L694-703)
```text
public fun check_locking_time_for_withdraw<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    receipt_id: address,
    clock: &Clock,
): bool {
    self.check_version();

    let receipt = self.receipts.borrow(receipt_id);
    self.locking_time_for_withdraw + receipt.last_deposit_time() <= clock.timestamp_ms()
}
```

**File:** volo-vault/sources/volo_vault.move (L776-782)
```text

    let deposit_request = &mut self.request_buffer.deposit_requests[request_id];
    assert!(receipt_id == deposit_request.receipt_id(), ERR_RECEIPT_ID_MISMATCH);
    assert!(
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/sources/volo_vault.move (L962-967)
```text
    let withdraw_request = &mut self.request_buffer.withdraw_requests[request_id];
    assert!(receipt_id == withdraw_request.receipt_id(), ERR_RECEIPT_ID_MISMATCH);
    assert!(
        withdraw_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/sources/requests/deposit_request.move (L5-17)
```text
public struct DepositRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Deposit Info ---- //
    amount: u64, // Amount (of principal) to deposit
    expected_shares: u256, // Expected shares to get after deposit
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** volo-vault/sources/user_entry.move (L133-136)
```text
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
```

**File:** volo-vault/sources/vault_receipt_info.move (L19-29)
```text
public struct VaultReceiptInfo has store {
    status: u8, // 0: normal, 1: pending_deposit, 2: pending_withdraw
    shares: u256,
    pending_deposit_balance: u64,
    pending_withdraw_shares: u256,
    last_deposit_time: u64,
    claimable_principal: u64,
    // ---- Reward Info ---- //
    reward_indices: Table<TypeName, u256>,
    unclaimed_rewards: Table<TypeName, u256>, // store unclaimed rewards, decimal: reward coin
}
```
