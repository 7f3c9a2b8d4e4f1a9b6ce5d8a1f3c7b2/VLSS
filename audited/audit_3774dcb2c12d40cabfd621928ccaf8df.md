### Title
Insufficient Validation Allows Multiple Withdrawal Requests to Exceed Available Shares, Creating Impossible-to-Fulfill Requests

### Summary
The `request_withdraw` function validates that requested shares don't exceed the receipt's total shares, but fails to account for already pending withdrawal shares. This allows users to create multiple withdrawal requests that collectively exceed their available shares, resulting in impossible-to-fulfill requests that lock buffer space until the cancellation timeout period expires.

### Finding Description

**Root Cause Location:** [1](#0-0) 

The validation only checks `vault_receipt.shares() >= shares`, which compares against the receipt's total shares without considering `pending_withdraw_shares`. 

**Why Protection Fails:**
When `update_after_request_withdraw` is called, it increases `pending_withdraw_shares` but does NOT decrease the actual `shares` field: [2](#0-1) 

The actual shares are only decremented during withdrawal execution: [3](#0-2) 

**Execution Path:**
When executing a withdrawal, the code performs unsigned integer subtraction on both `vault.total_shares` and `receipt.shares`: [4](#0-3) 

If `shares_to_withdraw > vault.total_shares` or `shares_to_withdraw > receipt.shares`, the Move VM aborts due to underflow, making the request impossible to fulfill.

### Impact Explanation

**Operational DoS Impact:**
- Users can create withdrawal requests that appear valid at creation time but become impossible to execute
- These requests occupy buffer space and cannot be executed (transaction aborts on underflow)
- Requests remain locked until the `locking_time_for_cancel_request` timeout expires: [5](#0-4) 

**Affected Parties:**
- Users who accidentally or maliciously create overlapping withdrawal requests experience failed executions
- Operators must wait for timeout periods before requests can be cancelled
- The request buffer accumulates unfulfillable requests, causing operational overhead

**Severity Justification (Medium):**
- No direct fund loss or theft
- No permanent lock (requests can be cancelled after timeout)
- Creates operational inefficiency and temporary DoS of buffer space
- Could be exploited at scale to degrade vault operations

### Likelihood Explanation

**Reachable Entry Point:**
Users can call public withdrawal functions multiple times: [6](#0-5) 

**Attack Complexity: Low**
- Requires only that a user has shares in a receipt
- No special privileges needed
- Can be triggered with two simple transactions
- Could happen accidentally (user submits withdrawal twice)

**Execution Practicality:**
1. User deposits and receives 100 shares
2. User calls `withdraw(shares=100)` → passes validation (100 >= 100)
3. User calls `withdraw(shares=100)` again → passes validation (shares still 100, pending_withdraw_shares not checked)
4. Operator executes first request: vault.total_shares and receipt.shares both decrease to 0
5. Operator attempts second request: underflows on subtraction, transaction aborts
6. Request remains stuck until cancellation timeout expires

**Economic Rationality:**
- Attack cost is minimal (just gas fees)
- Could be used for griefing or happen accidentally
- High likelihood of occurrence

### Recommendation

**Code-Level Mitigation:**
Modify the validation in `request_withdraw` to account for pending withdrawal shares:

```move
// Current (vulnerable):
assert!(vault_receipt.shares() >= shares, ERR_EXCEED_RECEIPT_SHARES);

// Fixed:
assert!(
    vault_receipt.shares() >= vault_receipt.pending_withdraw_shares() + shares, 
    ERR_EXCEED_AVAILABLE_SHARES
);
```

**Additional Checks:**
Add getter function in `vault_receipt_info.move` if not already present:
```move
public fun available_shares(self: &VaultReceiptInfo): u256 {
    self.shares - self.pending_withdraw_shares
}
```

**Test Cases:**
1. Verify user cannot create withdrawal request exceeding available shares (total - pending)
2. Verify multiple concurrent withdrawal requests respect the combined limit
3. Verify edge case where pending_withdraw_shares equals total shares blocks new requests
4. Test cancellation properly restores available shares

### Proof of Concept

**Initial State:**
- User Alice has receipt with 100 shares
- Vault has total_shares = 100
- No pending withdrawals

**Attack Sequence:**
1. **Transaction 1:** Alice calls `withdraw(shares=100)`
   - Check: `vault_receipt.shares() (100) >= 100` ✓ PASSES
   - Result: `pending_withdraw_shares = 100`, `shares = 100` (unchanged)
   - WithdrawRequest #1 created

2. **Transaction 2:** Alice calls `withdraw(shares=100)` again
   - Check: `vault_receipt.shares() (100) >= 100` ✓ PASSES (vulnerability!)
   - Result: `pending_withdraw_shares = 200`, `shares = 100` (still unchanged)
   - WithdrawRequest #2 created

3. **Transaction 3:** Operator executes WithdrawRequest #1
   - `vault.total_shares = 100 - 100 = 0` ✓
   - `receipt.shares = 100 - 100 = 0` ✓
   - `receipt.pending_withdraw_shares = 200 - 100 = 100` ✓
   - Execution succeeds

4. **Transaction 4:** Operator attempts to execute WithdrawRequest #2
   - Attempts: `vault.total_shares = 0 - 100` → **UNDERFLOW ABORT**
   - Attempts: `receipt.shares = 0 - 100` → **UNDERFLOW ABORT**
   - Execution fails permanently

5. **Transaction 5:** After timeout, Alice cancels WithdrawRequest #2
   - `receipt.pending_withdraw_shares = 100 - 100 = 0` ✓
   - Request removed from buffer

**Expected vs Actual:**
- Expected: Second withdrawal request should be rejected at creation
- Actual: Second request is accepted but becomes impossible to fulfill, occupying buffer space until cancellation timeout

**Success Condition:**
The vulnerability is confirmed when WithdrawRequest #2 is created successfully but execution consistently aborts with underflow, requiring cancellation after timeout period.

### Citations

**File:** volo-vault/sources/volo_vault.move (L910-910)
```text
    assert!(vault_receipt.shares() >= shares, ERR_EXCEED_RECEIPT_SHARES);
```

**File:** volo-vault/sources/volo_vault.move (L964-967)
```text
    assert!(
        withdraw_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1033-1033)
```text
    self.total_shares = self.total_shares - shares_to_withdraw;
```

**File:** volo-vault/sources/vault_receipt_info.move (L79-90)
```text
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

**File:** volo-vault/sources/vault_receipt_info.move (L102-110)
```text
public(package) fun update_after_execute_withdraw(
    self: &mut VaultReceiptInfo,
    executed_withdraw_shares: u256,
    claimable_principal: u64,
) {
    self.status = NORMAL_STATUS;
    self.shares = self.shares - executed_withdraw_shares;
    self.pending_withdraw_shares = self.pending_withdraw_shares - executed_withdraw_shares;
    self.claimable_principal = self.claimable_principal + claimable_principal;
```

**File:** volo-vault/sources/user_entry.move (L124-148)
```text
public fun withdraw<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    shares: u256,
    expected_amount: u64,
    receipt: &mut Receipt,
    clock: &Clock,
    _ctx: &mut TxContext,
): u64 {
    vault.assert_vault_receipt_matched(receipt);
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
    assert!(shares > 0, ERR_INVALID_AMOUNT);

    let request_id = vault.request_withdraw(
        clock,
        receipt.receipt_id(),
        shares,
        expected_amount,
        address::from_u256(0),
    );

    request_id
}
```
