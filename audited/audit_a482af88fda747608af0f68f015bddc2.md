### Title
Withdraw Fee Changes Applied Retroactively to Pending Requests Cause User Fund Loss

### Summary
The `WithdrawRequest` struct stores immutable fields including `expected_amount` for slippage protection, but does NOT store the `withdraw_fee_rate` at request creation time. When requests are executed, the CURRENT vault fee rate is applied, meaning admin fee increases from 10bp to 500bp (max allowed) result in users receiving up to 4.9% less than expected, as the `expected_amount` check only validates the gross amount before fee deduction.

### Finding Description

The vulnerability exists in the withdraw request execution flow where fee rates are applied:

**Request Creation:** [1](#0-0) 

The `WithdrawRequest` struct stores `expected_amount` but no fee rate information. When users create withdraw requests, they provide an `expected_amount` based on current conditions: [2](#0-1) 

**Fee Rate Configuration:**
Admins can change the withdraw fee rate at any time within the cap: [3](#0-2) [4](#0-3) 

**Request Execution with Current Fee:**
When executing withdrawals, the code uses the CURRENT vault fee rate, not the rate at request time: [5](#0-4) 

The critical issue is at lines 1029 and 1040:
- Line 1029: Validates `amount_to_withdraw >= expected_amount` (BEFORE fee deduction)
- Line 1040: Calculates fee using CURRENT `self.withdraw_fee_rate`

This means the slippage protection (`expected_amount`) only guards the gross withdrawal amount, not the net amount after fees. If fees increase between request and execution, users receive less than expected with no protection.

### Impact Explanation

**Direct Fund Loss:**
- Users with pending withdraw requests lose the difference between old and new fee rates
- Maximum impact: 490bp (5% - 0.1%) = 4.9% of withdrawal amount
- Example: User expects 999 tokens (with 0.1% fee), receives 950 tokens (with 5% fee) - a 4.9% loss

**Affected Parties:**
- All users with pending withdraw requests when admin increases fees
- No distinction between small and large withdrawals - percentage impact is uniform
- No warning mechanism or grace period for pending requests

**Protocol Benefit:**
- Vault collects additional fees (490bp extra) from pending requests
- Creates misalignment between user expectations and actual outcomes
- Potentially exploitable if admin coordination with pending request timing

### Likelihood Explanation

**Realistic Scenario:**
- Admin legitimately increases fees for protocol needs (not necessarily malicious)
- Withdraw requests can remain pending for extended periods during busy operator queues
- No special attacker capabilities required - occurs through normal operations

**Execution Path:**
1. User calls `user_entry::withdraw()` with expected_amount calculated at 10bp fee
2. Admin calls `vault_manage::set_withdraw_fee()` increasing to 500bp
3. Operator calls `operation::execute_withdraw()` applying new 500bp fee
4. User receives net amount 4.9% less than expected_amount implied

**No Mitigation Present:**
- No time-lock on fee changes
- No grandfathering of pending requests at old rates
- No notification mechanism for affected users
- `expected_amount` check insufficient to protect net amount

**Probability:**
- High likelihood in active vaults with frequent parameter adjustments
- Increases with longer operator execution delays
- Economic rationality: Admin benefits protocol at user expense

### Recommendation

**Code-Level Mitigation:**

1. **Store fee rate in WithdrawRequest:**
```
public struct WithdrawRequest has copy, drop, store {
    request_id: u64,
    receipt_id: address,
    recipient: address,
    vault_id: address,
    shares: u256,
    expected_amount: u64,
    request_time: u64,
    withdraw_fee_rate: u64,  // ADD: Store fee at request time
}
```

2. **Use stored fee rate at execution:**
Modify `execute_withdraw()` to use `withdraw_request.withdraw_fee_rate` instead of `self.withdraw_fee_rate` when calculating fee_amount.

3. **Alternative: Add net amount validation:**
Add post-fee validation:
```
let net_amount = amount_to_withdraw - fee_amount;
assert!(net_amount >= expected_net_amount, ERR_UNEXPECTED_NET_AMOUNT);
```

**Invariant to Enforce:**
- Pending withdraw requests must execute with parameters (fees) from request creation time, OR
- Users must provide expected_net_amount (after fees) for validation post-deduction

**Test Cases:**
1. Create withdraw request at 10bp fee
2. Increase fee to 500bp via `set_withdraw_fee()`
3. Execute old request
4. Verify: Fee deducted = 10bp (from request), not 500bp (current)
5. Edge case: Multiple fee changes between request and execution

### Proof of Concept

**Initial State:**
- Vault created with default 10bp (0.1%) withdraw fee
- User deposits 1000 tokens, receives 2000 shares (ratio 0.5)
- User calculates: withdrawal of 1000 shares = ~500 tokens - 0.5 fee = 499.5 expected

**Transaction Sequence:**

1. **User creates withdraw request (T=0):**
   - Calls `user_entry::withdraw(vault, 1000 shares, 499, receipt, clock, ctx)`
   - WithdrawRequest stored with expected_amount = 499
   - Current withdraw_fee_rate = 10bp

2. **Admin increases fees (T=1):**
   - Calls `vault_manage::set_withdraw_fee(admin_cap, vault, 500)` 
   - Vault withdraw_fee_rate updated to 500bp (5%)

3. **Operator executes withdrawal (T=2):**
   - Calls `operation::execute_withdraw(..., request_id=0, max_amount_received=510, ...)`
   - Calculates amount_to_withdraw = 500 (current ratio/price)
   - Check passes: 500 >= 499 ✓
   - Applies NEW fee: fee_amount = 500 * 500 / 10000 = 25
   - User receives: 500 - 25 = 475 tokens

**Expected vs Actual:**
- **Expected (by user):** 499.5 tokens (accounting for 0.1% fee)
- **Actual received:** 475 tokens (with 5% fee applied)
- **Loss:** 24.5 tokens (4.9% of withdrawal amount)
- **Success condition:** User received significantly less than expected due to fee change, with no protection from expected_amount check

### Citations

**File:** volo-vault/sources/requests/withdraw_request.move (L5-17)
```text
public struct WithdrawRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Withdraw Info ---- //
    shares: u256, // Shares to withdraw
    expected_amount: u64, // Expected amount to get after withdraw
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** volo-vault/sources/volo_vault.move (L30-33)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
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

**File:** volo-vault/sources/volo_vault.move (L896-925)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);
    assert!(vault_receipt.shares() >= shares, ERR_EXCEED_RECEIPT_SHARES);

    // Generate request id
    let current_request_id = self.request_buffer.withdraw_id_count;
    self.request_buffer.withdraw_id_count = current_request_id + 1;

    // Record this new request in Vault
    let new_request = withdraw_request::new(
        current_request_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        shares,
        expected_amount,
        clock.timestamp_ms(),
    );
```

**File:** volo-vault/sources/volo_vault.move (L1024-1042)
```text
    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

    // Decrease the share in vault and receipt
    self.total_shares = self.total_shares - shares_to_withdraw;

    // Split balances from the vault
    assert!(amount_to_withdraw <= self.free_principal.value(), ERR_NO_FREE_PRINCIPAL);
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);

    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
```
