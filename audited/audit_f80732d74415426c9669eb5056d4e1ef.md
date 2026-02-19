### Title
Locking Time Changes Applied Retroactively to Existing Requests and Receipts

### Summary
The vault's locking time parameters (`locking_time_for_cancel_request` and `locking_time_for_withdraw`) are not captured at the time of request/receipt creation. Instead, the current vault configuration values are used when checking if the locking period has elapsed. This allows admin parameter changes to retroactively affect all existing users' pending requests and deposited receipts, potentially locking funds indefinitely or allowing premature access contrary to the original terms.

### Finding Description

**Root Cause:**
The locking times are stored only in the Vault struct [1](#0-0) , not in individual requests or receipts. When users create deposit/withdraw requests, only the `request_time` timestamp is stored [2](#0-1) [3](#0-2) . Similarly, receipts only store `last_deposit_time` [4](#0-3) .

**Retroactive Application in Cancel Request Checks:**
When canceling a deposit, the check uses the CURRENT vault locking time: [5](#0-4) 

When canceling a withdraw, the same pattern applies: [6](#0-5) 

**Retroactive Application in Withdraw Checks:**
When checking if a receipt holder can withdraw, it uses the CURRENT vault locking time: [7](#0-6) 

**Admin Can Change Locking Times:**
The admin has unrestricted ability to modify locking times at any time [8](#0-7) [9](#0-8) .

### Impact Explanation

**Immediate Operational Impact:**
1. **Withdrawal Lock Extension**: Users who deposited funds expecting to withdraw after 12 hours (default) could have this extended indefinitely if admin increases `locking_time_for_withdraw`. Their deposited principal becomes inaccessible beyond agreed terms.

2. **Request Cancellation Lock Extension**: Users with pending deposit/withdraw requests expecting to cancel after 5 minutes (default) could be forced to wait arbitrarily longer if admin increases `locking_time_for_cancel_request`, locking their funds in pending state.

3. **Premature Access**: Conversely, decreasing locking times allows users to cancel/withdraw earlier than the security model intended, potentially enabling arbitrage or front-running opportunities.

**Affected Users:**
All users with existing pending requests or deposited receipts at the time of any locking time parameter change are affected. Given the default 12-hour withdrawal lock, this impacts a significant portion of active users.

**Severity Justification:**
This violates the fundamental user expectation that locking periods are determined at the time of action (deposit/request), not subject to retroactive modification. While it requires admin action, this is a design flaw affecting protocol integrity rather than requiring malicious compromise.

### Likelihood Explanation

**Triggering Conditions:**
- Admin modifies locking time parameters via `set_locking_time_for_withdraw` or `set_locking_time_for_cancel_request`
- Change immediately affects ALL existing requests/receipts retroactively
- No malicious intent required - legitimate parameter updates for new users will unintentionally impact existing users

**Execution Feasibility:**
This is not an "attack" requiring compromise, but an unintended consequence of normal admin operations. Any parameter adjustment for protocol improvement will cause this retroactive effect.

**Detection Difficulty:**
Users cannot predict or detect when locking times will change. The change is silent from user perspective until they attempt to cancel/withdraw.

**Probability:**
HIGH - Any governance-driven parameter optimization will trigger this. As the protocol matures and optimizes locking periods based on observed behavior, these changes become inevitable.

### Recommendation

**Fix 1: Capture Locking Times at Creation**
Modify request and receipt structures to capture the applicable locking time at creation:

For `DepositRequest` and `WithdrawRequest`, add field:
```
locking_time_for_cancel: u64
```

For `VaultReceiptInfo`, add field:
```
locking_time_for_withdraw: u64
```

Populate these fields at creation time by reading current vault values, then use these captured values in all locking checks instead of current vault values.

**Fix 2: Add Transition Logic**
If Fix 1 is impractical due to migration concerns, implement a transition mechanism:
- New requests/receipts use captured times
- Existing requests/receipts can opt-in to new times or remain on old times
- Emit events when locking times change to inform users

**Test Cases:**
1. Test that changing `locking_time_for_cancel_request` after request creation does not affect when the request can be cancelled
2. Test that changing `locking_time_for_withdraw` after deposit does not affect when withdrawal requests can be made
3. Test edge cases where locking time is changed multiple times before expiration

### Proof of Concept

**Initial State:**
- Vault exists with default locking times: `locking_time_for_cancel_request = 5 * 60 * 1000` (5 minutes), `locking_time_for_withdraw = 12 * 3600 * 1000` (12 hours)
- User Alice deposits 1000 tokens at time T, receives Receipt with `last_deposit_time = T`
- User Bob creates withdraw request at time T', stored with `request_time = T'`

**Attack/Issue Sequence:**

Step 1: At time T + 6 minutes (after 5-minute lock), Bob attempts to cancel withdraw request
- Expected: Cancellation succeeds (5 minutes elapsed)
- Actual: Cancellation succeeds

Step 2: Admin calls `set_locking_time_for_cancel_request(vault, 30 * 60 * 1000)` (30 minutes)

Step 3: User Charlie creates new withdraw request at time T + 10 minutes, stored with `request_time = T + 10 minutes`

Step 4: At time T + 11 minutes, Charlie attempts to cancel (1 minute after creation)
- Expected: Cancellation fails (30-minute lock not elapsed)
- Actual: Cancellation fails ✓ (correct for new request)

Step 5: At time T + 11 minutes, Bob attempts to cancel his ORIGINAL request from T'
- Expected: Cancellation succeeds (original 5-minute lock long passed)
- **Actual: Cancellation FAILS** - Bob's old request now requires 30 minutes due to retroactive application

Step 6: At time T + 13 hours (after 12-hour lock), Alice attempts to create withdraw request
- Expected: Withdraw request creation succeeds
- Actual: Withdraw request creation succeeds

Step 7: Admin calls `set_locking_time_for_withdraw(vault, 72 * 3600 * 1000)` (72 hours)

Step 8: User Dave deposits at time T + 14 hours, receives Receipt with `last_deposit_time = T + 14 hours`

Step 9: At time T + 15 hours, Alice attempts to create another withdraw request
- Expected: Withdraw request creation succeeds (12-hour lock passed at T + 12 hours)
- **Actual: Withdraw request creation FAILS** - Alice's original deposit now requires 72 hours due to retroactive application

**Success Condition:**
The vulnerability is confirmed if existing requests/receipts are subject to the NEW locking times rather than the times that were active when they were created. The PoC demonstrates both cancellation and withdrawal locks being retroactively extended, preventing users from accessing funds according to original terms.

### Citations

**File:** volo-vault/sources/volo_vault.move (L102-103)
```text
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
```

**File:** volo-vault/sources/volo_vault.move (L543-567)
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

**File:** volo-vault/sources/volo_vault.move (L779-782)
```text
    assert!(
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/sources/volo_vault.move (L964-967)
```text
    assert!(
        withdraw_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/sources/requests/deposit_request.move (L16-16)
```text
    request_time: u64, // Time when the request is created
```

**File:** volo-vault/sources/requests/withdraw_request.move (L16-16)
```text
    request_time: u64, // Time when the request is created
```

**File:** volo-vault/sources/vault_receipt_info.move (L24-24)
```text
    last_deposit_time: u64,
```

**File:** volo-vault/sources/manage.move (L66-80)
```text
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
