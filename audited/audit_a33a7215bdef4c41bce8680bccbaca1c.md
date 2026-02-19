### Title
Receipt Transfer Enables Deposit Fund Theft Through Operator Cancellation Path

### Summary
The deposit cancellation mechanism only validates that the provided `recipient` matches the stored recipient in the `DepositRequest`, but does not verify that the Receipt is currently owned by that address. An attacker can create a deposit request, transfer the Receipt to another party, then have the operator cancel the deposit to reclaim the buffered coins while the new Receipt holder is left with a worthless receipt.

### Finding Description

The vulnerability exists in the interaction between transferable Receipts and the operator-initiated cancellation flow:

**Receipt Transferability**: The `Receipt` struct has both `key` and `store` abilities, making it fully transferable between addresses. [1](#0-0) 

**Deposit Request Creation**: When a user creates a deposit request through `user_entry::deposit`, the function stores `ctx.sender()` as the recipient in the `DepositRequest` struct and returns the Receipt to the user. [2](#0-1) 

**Operator Cancellation Path**: The `operation::cancel_user_deposit` function allows operators to cancel deposits by providing the `recipient` address as a parameter, which is then passed directly to `vault.cancel_deposit`. [3](#0-2) 

**Insufficient Validation**: The `vault::cancel_deposit` function only checks that the provided `recipient` parameter matches the recipient stored in the `DepositRequest`, but does not verify current Receipt ownership. [4](#0-3) 

**Root Cause**: The recipient field is captured at request creation time but becomes stale after Receipt transfers. The cancellation logic treats this stale recipient as authoritative without verifying current Receipt ownership, creating a time-of-check-time-of-use (TOCTOU) vulnerability.

### Impact Explanation

**Direct Fund Theft**: An attacker (Alice) can:
1. Deposit funds worth amount X, receiving a Receipt with pending deposit status
2. Transfer or sell the Receipt to victim (Bob) for value Y
3. Request the operator to cancel her deposit using her original address as recipient
4. Receive her X coins back while Bob holds a Receipt with no value

**Quantified Impact**: 
- Alice gains: X (recovered coins) + Y (payment for Receipt) - transaction fees
- Bob loses: Y (payment for Receipt) as his Receipt now has zero pending deposit value
- The VaultReceiptInfo is correctly updated (status reset, pending_deposit_balance decremented) but Bob bears the loss [5](#0-4) 

**Affected Parties**: Any user who acquires a Receipt with pending deposits through transfer or trade becomes vulnerable to the original depositor reclaiming the buffered funds.

### Likelihood Explanation

**Reachable Entry Point**: The exploit uses the standard `operation::cancel_user_deposit` function, which is a legitimate operator function accessible to any operator with `OperatorCap`.

**Feasible Preconditions**:
- Attacker creates a deposit request (normal user action)
- Attacker transfers Receipt to victim (enabled by `key, store` abilities)
- Operator processes cancellation request (normal operational procedure)

**Execution Practicality**: The attack is straightforward:
1. Call `user_entry::deposit` to create request and receive Receipt
2. Transfer Receipt to another address via `transfer::public_transfer`
3. Submit off-chain cancellation request to operator after locking period expires
4. Operator calls `cancel_user_deposit` with original recipient address
5. Funds return to attacker while victim holds worthless Receipt

**Operator Involvement Without Compromise**: The operator doesn't need to be malicious. They may follow standard procedures: verify the cancellation request is signed by the original depositor (matching the stored recipient), check that the locking time has elapsed, and execute the cancellation. The protocol itself doesn't enforce verification that the Receipt is still owned by the requester.

**Economic Rationality**: Profitable if the Receipt can be transferred for value (e.g., sold to another user or used as collateral), as the attacker recovers the original deposit while retaining the transfer proceeds.

### Recommendation

**Add Receipt Ownership Verification**: Modify `vault::cancel_deposit` to require proof of current Receipt ownership, or restrict the operator cancellation path to prevent cancellation after Receipt transfers.

**Option 1 - Require Receipt Object**: Change `operation::cancel_user_deposit` to require passing the Receipt object:
```move
public fun cancel_user_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    receipt: &mut Receipt,  // Add this parameter
    request_id: u64,
    clock: &Clock,
)
```

**Option 2 - Track Transfers**: Add a transfer counter or ownership validation in VaultReceiptInfo that gets updated on Receipt transfers, and check this in cancellation.

**Option 3 - Disable Operator Path After Transfer**: Add a flag in VaultReceiptInfo indicating if the Receipt has been transferred, and prevent operator cancellation if true while still allowing the current owner to cancel through the user entry path.

**Test Cases**: Add regression tests that:
1. Create deposit request as Alice
2. Transfer Receipt to Bob
3. Attempt operator cancellation with Alice as recipient
4. Verify cancellation fails with appropriate error

### Proof of Concept

**Initial State**:
- Alice (0xA11ce) has 1000 SUI
- Bob (0xB0b) has 500 SUI
- Vault is operational

**Attack Sequence**:

1. **Alice creates deposit request** (Epoch 1):
   - Calls `user_entry::deposit_with_auto_transfer(vault, reward_manager, coin<1000 SUI>, 1000, expected_shares, none, clock, ctx)`
   - Receipt (0xReceipt1) created and transferred to Alice
   - DepositRequest created with recipient = 0xA11ce
   - 1000 SUI buffered in `deposit_coin_buffer[request_id_0]`
   - VaultReceiptInfo: status = PENDING_DEPOSIT_STATUS, pending_deposit_balance = 1000

2. **Alice transfers Receipt to Bob**:
   - `transfer::public_transfer(receipt<0xReceipt1>, 0xB0b)`
   - Bob now owns Receipt (0xReceipt1)
   - DepositRequest still has recipient = 0xA11ce

3. **Wait for locking period** (configurable, e.g., 1 day)

4. **Alice requests operator to cancel** (off-chain):
   - Provides signed message: "Cancel deposit request_id_0 for receipt 0xReceipt1"
   - Operator verifies signature matches 0xA11ce (the stored recipient)

5. **Operator executes cancellation**:
   - Calls `operation::cancel_user_deposit(operation, cap, vault, request_id_0, 0xReceipt1, 0xA11ce, clock)`
   - Checks pass: recipient (0xA11ce) == deposit_request.recipient() (0xA11ce)
   - 1000 SUI transferred to 0xA11ce
   - VaultReceiptInfo: status = NORMAL_STATUS, pending_deposit_balance = 0

**Expected Result**: Cancellation should fail because Alice no longer owns the Receipt.

**Actual Result**: 
- Cancellation succeeds
- Alice receives 1000 SUI back
- Bob holds Receipt (0xReceipt1) with no pending deposit value
- Bob lost whatever value he paid/traded for the Receipt

### Citations

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

**File:** volo-vault/sources/operation.move (L435-447)
```text
public fun cancel_user_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    request_id: u64,
    receipt_id: address,
    recipient: address,
    clock: &Clock,
) {
    vault::assert_operator_not_freezed(operation, cap);
    let buffered_coin = vault.cancel_deposit(clock, request_id, receipt_id, recipient);
    transfer::public_transfer(buffered_coin, recipient);
}
```

**File:** volo-vault/sources/volo_vault.move (L783-783)
```text
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
```

**File:** volo-vault/sources/vault_receipt_info.move (L57-63)
```text
public(package) fun update_after_cancel_deposit(
    self: &mut VaultReceiptInfo,
    cancelled_deposit_balance: u64,
) {
    self.status = NORMAL_STATUS;
    self.pending_deposit_balance = self.pending_deposit_balance - cancelled_deposit_balance;
}
```
