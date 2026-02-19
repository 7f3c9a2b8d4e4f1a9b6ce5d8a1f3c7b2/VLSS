### Title
Withdraw Fee Rate Changes Between Request and Execution Allow Unexpected Fee Deduction Beyond User's Expected Amount

### Summary
The `withdraw_fee_rate` can be changed by admin between `request_withdraw()` and `execute_withdraw()`, causing users to pay significantly more fees than anticipated. The `expected_amount` slippage check validates the pre-fee withdrawal amount, not the post-fee amount users actually receive, allowing fee increases up to 5% to bypass user protections entirely.

### Finding Description

**Code Locations:**

The vulnerability exists in the interaction between withdraw request creation and execution: [1](#0-0) [2](#0-1) [3](#0-2) 

**Root Cause:**

When users create a withdrawal request, they specify an `expected_amount` parameter intended as slippage protection. However, during execution, this check occurs **before** fee deduction: [4](#0-3) 

The fee is then calculated using the **current** `withdraw_fee_rate` and deducted after the slippage check passes: [5](#0-4) 

The admin can change the `withdraw_fee_rate` at any time with no restrictions on pending requests: [6](#0-5) 

**Why Protections Fail:**

The fee rate can range from 0 to the maximum: [7](#0-6) 

Users calculate `expected_amount` based on the fee rate at request time, but there is no mechanism to lock this rate or validate the post-fee amount. The `expected_amount` check only ensures the gross withdrawal amount is sufficient, not the net amount after fees.

### Impact Explanation

**Direct Financial Loss:**

Users suffer unexpected loss of funds between their anticipated net withdrawal and actual receipt. In the worst case:

- User creates request when `withdraw_fee_rate = 10` (0.1%)
- User sets `expected_amount` based on receiving 99.9% of their withdrawal
- Admin increases `withdraw_fee_rate` to `500` (5% - the maximum)
- User receives 95% instead of expected 99.9%
- **Unexpected loss: 4.9% of withdrawal amount**

**Quantified Example:**

For a 10,000 USDC withdrawal:
- Expected to receive: 9,990 USDC (with 0.1% fee = 10 USDC)
- Actually receives: 9,500 USDC (with 5% fee = 500 USDC)
- Unexpected loss: **490 USDC**

**Who Is Affected:**

All users with pending withdrawal requests are vulnerable whenever admin fee adjustments occur. This breaks the fundamental user expectation that slippage protection (`expected_amount`) guards their net receipt.

**Severity Justification:**

Medium severity due to:
- Direct fund loss (up to 4.9% of withdrawal)
- Normal operational occurrence (fee adjustments are expected admin actions)
- Affects all pending withdrawals system-wide
- No user recourse once execution occurs

### Likelihood Explanation

**Feasible Preconditions:**

- No malicious intent required - occurs during normal fee adjustments
- Admin capability to change fees is expected functionality
- Withdrawal requests commonly pending between creation and execution
- No time restrictions prevent fee changes affecting pending requests

**Execution Practicality:**

The scenario unfolds through normal protocol operations:

1. Users create withdrawal requests (public entry point via `user_entry::withdraw`)
2. Requests queue in the vault's request buffer
3. Admin adjusts fees for legitimate protocol management reasons
4. Operator executes pending requests using updated fee rate

**Attack Complexity:**

Not an attack - this is a design flaw in the slippage protection mechanism. The issue manifests during routine protocol operations without any exploitation required.

**Probability Reasoning:**

High probability of occurrence because:
- Fee adjustments are normal governance actions
- Requests commonly pending during market volatility or operational delays
- No warning or protection mechanism exists
- Users have no visibility into fee rate changes before execution

### Recommendation

**Code-Level Mitigation:**

Store the `withdraw_fee_rate` snapshot in the `WithdrawRequest` at creation time and use this locked rate during execution:

1. Modify `WithdrawRequest` struct to include:
```
fee_rate_at_request: u64
```

2. Update `withdraw_request::new()` to capture current rate: [8](#0-7) 

3. Modify `execute_withdraw()` to use the stored rate instead of current vault rate: [9](#0-8) 

**Alternative Solution:**

Validate the post-fee amount instead of pre-fee amount by adjusting the slippage check to occur after fee calculation, or require users to specify both pre-fee and post-fee expectations.

**Invariant Checks:**

Add assertion: `final_amount_to_user >= expected_amount_after_fee` where the fee is calculated using a locked rate or clearly documented pre-fee semantics.

**Test Cases:**

Add test case: `test_withdraw_fee_change_between_request_and_execution()` that:
1. Creates withdraw request with fee = 10 bps
2. Changes fee to 500 bps
3. Executes request
4. Verifies user receives amount consistent with fee rate at request time

### Proof of Concept

**Initial State:**
- Vault has 10,000 USDC in free principal
- User has receipt with shares worth 10,000 USDC
- Current `withdraw_fee_rate = 10` (0.1%)

**Transaction Steps:**

1. **User creates withdrawal request:**
   - Calls `user_entry::withdraw()` with shares representing 10,000 USDC
   - Sets `expected_amount = 9,990` (expecting 10 USDC fee)
   - Request stored in vault's request buffer

2. **Admin increases fee:**
   - Calls `vault_manage::set_withdraw_fee()` with `fee = 500` (5%)
   - Vault's `withdraw_fee_rate` now = 500

3. **Operator executes withdrawal:**
   - Calls `execute_withdraw()` for the request
   - Calculates `amount_to_withdraw = 10,000 USDC`
   - Slippage check: `10,000 >= 9,990` ✓ **PASSES**
   - Fee calculation: `10,000 * 500 / 10,000 = 500 USDC`
   - User receives: `10,000 - 500 = 9,500 USDC`

**Expected vs Actual Result:**
- **Expected by user:** 9,990 USDC (based on 0.1% fee)
- **Actually received:** 9,500 USDC (charged 5% fee)
- **Unexpected loss:** 490 USDC (4.9% of withdrawal)

**Success Condition:**

Transaction executes successfully despite user receiving 490 USDC less than anticipated, demonstrating that `expected_amount` does not protect against fee rate changes.

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

**File:** volo-vault/sources/requests/withdraw_request.move (L21-39)
```text
public(package) fun new(
    request_id: u64,
    receipt_id: address,
    recipient: address,
    vault_id: address,
    shares: u256,
    expected_amount: u64,
    timestamp: u64,
): WithdrawRequest {
    WithdrawRequest {
        request_id,
        receipt_id,
        recipient,
        vault_id,
        shares,
        expected_amount,
        request_time: timestamp,
    }
}
```

**File:** volo-vault/sources/volo_vault.move (L31-33)
```text
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

**File:** volo-vault/sources/volo_vault.move (L896-940)
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
    self.request_buffer.withdraw_requests.add(current_request_id, new_request);

    emit(WithdrawRequested {
        request_id: current_request_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        shares: shares,
        expected_amount: expected_amount,
    });

    vault_receipt.update_after_request_withdraw(shares, recipient);

    current_request_id
}
```

**File:** volo-vault/sources/volo_vault.move (L994-1077)
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

    // Get the current share ratio
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

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

    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
    });

    // Update total usd value after withdraw executed
    // This update should not generate any performance fee
    // (actually the total usd value will decrease, so there is no performance fee)
    self.update_free_principal_value(config, clock);

    // Update the vault receipt info
    let vault_receipt = &mut self.receipts[withdraw_request.receipt_id()];

    let recipient = withdraw_request.recipient();
    if (recipient != address::from_u256(0)) {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            0,
        )
    } else {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            withdraw_balance.value(),
        )
    };

    self.delete_withdraw_request(request_id);

    (withdraw_balance, recipient)
}
```
