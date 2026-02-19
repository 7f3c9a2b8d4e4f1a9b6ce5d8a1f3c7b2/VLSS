### Title
Receipt Transfer Before Deposit Execution Allows Share Misdirection to Unintended Recipient

### Summary
The `DepositRequest.recipient` field is validated only in `cancel_deposit` but not in `execute_deposit`, while the `Receipt` object has `store` ability allowing transfers. If a user transfers their Receipt after creating a deposit request but before operator execution, the shares will be credited to the VaultReceiptInfo accessible by the new Receipt holder, not the original depositor who provided the funds. This breaks the fundamental invariant that depositors receive shares for their deposits.

### Finding Description

The vulnerability exists in the asymmetric validation of the `recipient` field across deposit operations:

**DepositRequest Structure**: The struct stores a `recipient` address with a comment indicating it's "only used for check when 'with_lock' is true", but this is misleading as it's actually checked in cancel operations. [1](#0-0) 

**Receipt Transferability**: The `Receipt` object has `key, store` abilities, making it fully transferable between accounts. [2](#0-1) 

**Deposit Request Creation**: When a user deposits, the `recipient` is set to `ctx.sender()` (the depositor's address), and the Receipt is returned to them. [3](#0-2) 

**Cancel Validation**: The `cancel_deposit` function enforces that only the original `recipient` can cancel, AND requires possession of the Receipt object. [4](#0-3) [5](#0-4) 

**Execute Without Validation**: The `execute_deposit` function retrieves the request and directly updates the VaultReceiptInfo at the stored `receipt_id` WITHOUT verifying the current Receipt owner matches the original `recipient`. The operator only needs the `request_id`. [6](#0-5) [7](#0-6) 

**Root Cause**: The system treats Receipt as a bearer token for shares distribution (whoever holds it gets the shares), but simultaneously tries to protect the original depositor through the `recipient` field in cancellation. This creates an inconsistent security model where shares can be redirected through Receipt transfer while cancellation rights remain with the original depositor.

### Impact Explanation

**Direct Fund Misrouting**: User A deposits funds (e.g., 10,000 USDC), then transfers the Receipt to User B (maliciously, accidentally, or through sale). When the operator executes the deposit, all shares are credited to the VaultReceiptInfo at `receipt_id`, which User B can now access. User A loses their entire deposit amount, and User B receives shares they didn't pay for.

**Custody Integrity Violation**: Neither party can cancel the deposit once the Receipt is transferred:
- User A (original recipient) cannot cancel because they no longer possess the Receipt object required as a parameter
- User B (new Receipt holder) cannot cancel because `ctx.sender()` would not match the stored `recipient` address [8](#0-7) 

This creates a forced execution scenario where the original depositor has no recourse to recover their funds before execution redirects shares to the wrong party.

**Affected Parties**: 
- All depositors are at risk if they unknowingly transfer their Receipt while having pending deposits
- Marketplace scenarios where Receipts are traded could result in systematic misdirection
- Social engineering attacks where malicious actors trick users into transferring Receipts

**Severity Justification**: HIGH - This is a direct funds loss vulnerability where User A's deposit becomes User B's shares, with no recovery mechanism available to either party once the transfer occurs.

### Likelihood Explanation

**Attacker Capabilities**: Any untrusted user can execute this attack:
1. Create a deposit request (public function)
2. Transfer the Receipt using standard Sui transfer functions
3. Wait for operator to execute the deposit

**Execution Practicality**: The attack requires no special permissions or complex state manipulation:
- Deposit creation: `user_entry::deposit()` is publicly callable
- Receipt transfer: `transfer::public_transfer()` works on any object with `store` ability
- Execution happens automatically when operator processes the queue

**Feasibility Conditions**:
- **Intentional Attack**: User A deposits, transfers Receipt to accomplice/victim User B, shares go to B
- **Accidental Loss**: User A lists Receipt on marketplace/sends wrong object, loses deposit when executed
- **Market Exploitation**: Buyers/sellers of Receipts uncertain who owns pending deposit value

**Detection Constraints**: No on-chain mechanism prevents or detects this scenario. The protocol emits a `DepositExecuted` event with the original `recipient` address, but shares are already credited to the new Receipt holder. [9](#0-8) 

**Economic Rationality**: Attack cost is minimal (just deposit amount + gas), and benefit is the full deposit amount converted to shares. For victims, accidental transfers result in total loss.

### Recommendation

**Code-Level Mitigation**: Add recipient validation in `execute_deposit` to ensure the current Receipt owner matches the original depositor, OR implement a Receipt locking mechanism during pending operations.

**Option 1 - Add Recipient Check** (Recommended):
```move
// In execute_deposit, before line 864:
let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
// Add: Verify receipt hasn't been transferred
// Note: This requires the operator to pass in the receipt owner proof
// Alternative: Lock receipts during pending deposits
```

**Option 2 - Lock Receipt During Pending Deposit**:
Prevent Receipt transfers when `VaultReceiptInfo.status == PENDING_DEPOSIT_STATUS` by removing the `store` ability from Receipt or adding transfer guards that check vault receipt status.

**Invariant Checks to Add**:
1. Assert that shares from a deposit request are credited only when the Receipt owner can be verified
2. Add integration test: "test_deposit_with_receipt_transfer_before_execution_should_fail"
3. Document Receipt transfer restrictions clearly for users

**Test Cases**:
- Test depositing, transferring Receipt to another address, then executing → should fail or revert shares to original depositor
- Test canceling after Receipt transfer → should fail appropriately (current behavior may be acceptable)
- Test normal flow without transfer → should succeed (regression test)

### Proof of Concept

**Initial State**:
- User A (address: 0xAAAA) has 10,000 USDC
- User B (address: 0xBBBB) has no vault position
- Vault has normal status

**Transaction Steps**:

1. **User A creates deposit request**:
   - Calls `user_entry::deposit()` with 10,000 USDC
   - Receives Receipt (id: 0xRECEIPT)
   - DepositRequest created with `recipient = 0xAAAA`, `receipt_id = 0xRECEIPT`, `amount = 10,000 USDC`
   - VaultReceiptInfo at 0xRECEIPT has status = PENDING_DEPOSIT_STATUS

2. **User A transfers Receipt to User B**:
   - User A calls `transfer::public_transfer(receipt, 0xBBBB)`
   - User B now owns Receipt at 0xRECEIPT
   - DepositRequest still has `recipient = 0xAAAA`

3. **Neither can cancel**:
   - User A cannot call `cancel_deposit()` because they don't have the Receipt parameter
   - User B cannot call `cancel_deposit()` because `ctx.sender()` (0xBBBB) ≠ `recipient` (0xAAAA)

4. **Operator executes deposit**:
   - Operator calls `operation::execute_deposit(request_id)`
   - Shares calculated and credited to VaultReceiptInfo at 0xRECEIPT
   - User B (who owns Receipt 0xRECEIPT) can now withdraw/claim those shares

**Expected Result**: User A (depositor, recipient) should receive the shares for their 10,000 USDC deposit

**Actual Result**: User B (who received the transferred Receipt) receives all shares, while User A lost their 10,000 USDC deposit with no recovery mechanism

**Success Condition for Attack**: After step 4, User B can call withdrawal functions with the Receipt and receive funds, while User A has no shares despite depositing 10,000 USDC.

### Citations

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

**File:** volo-vault/sources/receipt.move (L12-15)
```text
public struct Receipt has key, store {
    id: UID,
    vault_id: address, // This receipt belongs to which vault
}
```

**File:** volo-vault/sources/user_entry.move (L52-58)
```text
    let request_id = vault.request_deposit(
        split_coin,
        clock,
        expected_shares,
        receipt_id,
        ctx.sender(),
    );
```

**File:** volo-vault/sources/user_entry.move (L91-100)
```text
public fun cancel_deposit<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt: &mut Receipt,
    request_id: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<PrincipalCoinType> {
    vault.assert_vault_receipt_matched(receipt);

    let coin = vault.cancel_deposit(clock, request_id, receipt.receipt_id(), ctx.sender());
```

**File:** volo-vault/sources/volo_vault.move (L777-783)
```text
    let deposit_request = &mut self.request_buffer.deposit_requests[request_id];
    assert!(receipt_id == deposit_request.receipt_id(), ERR_RECEIPT_ID_MISMATCH);
    assert!(
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
```

**File:** volo-vault/sources/volo_vault.move (L823-824)
```text
    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);
```

**File:** volo-vault/sources/volo_vault.move (L855-862)
```text
    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });
```

**File:** volo-vault/sources/volo_vault.move (L864-869)
```text
    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );
```
