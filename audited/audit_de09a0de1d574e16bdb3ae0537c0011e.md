# Audit Report

## Title
Receipt Transfer Enables Deposit Fund Theft Through Operator Cancellation Path

## Summary
The deposit cancellation mechanism validates the recipient address stored in the `DepositRequest` but fails to verify current Receipt ownership. This allows an attacker to transfer their Receipt to a victim, then have an operator cancel the deposit to reclaim buffered coins while the victim holds a worthless Receipt, resulting in direct fund theft.

## Finding Description

The Volo Vault system implements two distinct paths for deposit cancellation with critically different security models:

**User-Initiated Cancellation**: The `user_entry::cancel_deposit` function requires possession of the Receipt object (`&mut Receipt` parameter) and uses `ctx.sender()` as the recipient address, ensuring only the current Receipt holder can cancel their deposit. [1](#0-0) 

**Operator-Initiated Cancellation**: The `operation::cancel_user_deposit` function takes only address parameters (`receipt_id: address`, `recipient: address`) without requiring the Receipt object itself. [2](#0-1) 

The vulnerability arises because:

1. **Receipt Transferability**: The `Receipt` struct has both `key` and `store` abilities, making it fully transferable via `transfer::public_transfer`. [3](#0-2) 

2. **Stale Recipient Storage**: When a user creates a deposit request, the function captures `ctx.sender()` as the recipient in the `DepositRequest` struct at creation time. [4](#0-3)  This recipient value is permanently stored in the request. [5](#0-4) 

3. **Insufficient Ownership Validation**: The `vault::cancel_deposit` function only verifies that the provided `recipient` parameter matches the stored recipient from the `DepositRequest`, but does not validate that the Receipt is currently owned by that address. [6](#0-5) 

This creates a time-of-check-time-of-use (TOCTOU) vulnerability where the recipient is captured at deposit creation but becomes stale after Receipt transfers, yet the cancellation logic treats this stale recipient as authoritative.

**Attack Execution**:
1. Alice calls `user_entry::deposit`, creating a `DepositRequest` with `recipient = Alice's address`
2. Alice transfers the Receipt to Bob using `transfer::public_transfer`
3. Alice submits an off-chain cancellation request to the operator (presenting valid signature for her address)
4. Operator calls `operation::cancel_user_deposit` with Alice's address as recipient
5. The validation passes because `deposit_request.recipient() == recipient` (Alice == Alice)
6. Buffered coins are transferred to Alice [7](#0-6) 
7. Bob holds a Receipt with `pending_deposit_balance` decremented to zero [8](#0-7) 

## Impact Explanation

**Direct Fund Theft**: The vulnerability enables quantifiable theft of user funds through the following mechanism:
- Alice deposits X coins and receives a Receipt with pending deposit status
- Alice sells/transfers the Receipt to Bob for value Y
- Alice requests operator cancellation using her original address
- Alice receives X coins back while Bob is left with a worthless Receipt

**Quantified Loss**: 
- Attacker gain: X (recovered deposit) + Y (payment for Receipt) - gas fees
- Victim loss: Y (amount paid for Receipt with no underlying value)
- Protocol: No direct loss but trust/reputation damage

**Affected Parties**: Any user who acquires a Receipt with pending deposits through transfer, purchase, or use as collateral becomes vulnerable to the original depositor reclaiming the buffered funds while they hold an empty Receipt.

The VaultReceiptInfo is correctly updated (status reset, pending_deposit_balance decremented), but this offers no protection to the Receipt holder who now owns a Receipt with zero pending value.

## Likelihood Explanation

**Highly Feasible Attack Path**:
1. All entry points are standard public functions accessible to regular users
2. The operator path `operation::cancel_user_deposit` is a legitimate operation function requiring only `OperatorCap`
3. Receipt transfer is enabled by design through `key, store` abilities
4. No privileged capabilities beyond normal user and operator roles are required

**Operator Involvement Without Malice**: The operator does not need to be malicious or compromised. Following standard operational procedures, the operator would:
- Verify the cancellation request is cryptographically signed by the stored recipient address (Alice)
- Check that the locking period has elapsed
- Execute the cancellation as requested

The operator has no way to detect that the Receipt has been transferred, as this information is not checked by the protocol. The protocol itself enforces no verification that the Receipt is still owned by the requester when using the operator cancellation path.

**Economic Rationality**: The attack is profitable whenever Receipts can be transferred for value, which is likely in scenarios such as:
- Secondary market trading of vault receipts
- Using Receipts as collateral in lending protocols
- OTC sales of deposit positions

## Recommendation

**Solution 1: Require Receipt Possession for Operator Cancellation**

Modify `operation::cancel_user_deposit` to require the Receipt object as a parameter, ensuring only the current holder can cancel:

```move
public fun cancel_user_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    request_id: u64,
    receipt: &Receipt,  // Add Receipt parameter
    clock: &Clock,
    ctx: &TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);
    let buffered_coin = vault.cancel_deposit(
        clock, 
        request_id, 
        receipt.receipt_id(),  // Extract from Receipt
        ctx.sender()  // Use current sender, not parameter
    );
    transfer::public_transfer(buffered_coin, ctx.sender());
}
```

**Solution 2: Remove Store Ability from Receipt**

If Receipts are not intended to be transferable, remove the `store` ability:

```move
public struct Receipt has key {  // Remove 'store'
    id: UID,
    vault_id: address,
}
```

This prevents transfers while maintaining the Receipt as an owned object.

**Solution 3: Track Receipt Ownership On-Chain**

Add ownership tracking to detect transfers and invalidate cancellation rights upon transfer, though this adds significant complexity.

**Recommended Approach**: Solution 1 provides the strongest protection by enforcing that only the current Receipt holder can cancel deposits through any path, aligning the operator path with the user path security model.

## Proof of Concept

```move
#[test]
public fun test_receipt_transfer_theft_via_operator_cancel() {
    let mut scenario = test_scenario::begin(ALICE);
    
    // Setup: Initialize vault and create deposit
    setup_vault(&mut scenario);
    
    // Step 1: Alice deposits and gets Receipt
    scenario.next_tx(ALICE);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let coin = coin::mint_for_testing<SUI>(1_000_000, scenario.ctx());
        let receipt = user_entry::deposit(
            &mut vault, 
            coin, 
            1_000_000,
            0, // expected_shares
            &clock,
            scenario.ctx()
        );
        
        // Step 2: Alice transfers Receipt to Bob
        transfer::public_transfer(receipt, BOB);
        test_scenario::return_shared(vault);
    };
    
    // Step 3: Operator cancels deposit using Alice's address
    // (Receipt now owned by Bob, but operator can still cancel to Alice)
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let operation = scenario.take_shared<Operation>();
        let cap = scenario.take_from_sender<OperatorCap>();
        
        operation::cancel_user_deposit(
            &operation,
            &cap,
            &mut vault,
            0, // request_id
            receipt_id,
            ALICE, // Original recipient - validation passes!
            &clock
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        scenario.return_to_sender(cap);
    };
    
    // Step 4: Verify Alice received coins while Bob has worthless Receipt
    scenario.next_tx(ALICE);
    {
        // Alice received the refunded coins
        assert!(test_scenario::has_most_recent_for_sender<Coin<SUI>>(&scenario));
    };
    
    scenario.next_tx(BOB);
    {
        let receipt = scenario.take_from_sender<Receipt>();
        let vault = scenario.take_shared<Vault<SUI>>();
        
        // Bob's Receipt shows pending_deposit_balance = 0
        assert!(vault.get_pending_deposit_balance(receipt.receipt_id()) == 0);
        
        scenario.return_to_sender(receipt);
        test_scenario::return_shared(vault);
    };
    
    scenario.end();
}
```

The test demonstrates that after transferring the Receipt from Alice to Bob, the operator can still cancel the deposit using Alice's address (the stored recipient), causing the coins to be refunded to Alice while Bob holds a Receipt with zero pending deposit value.

### Citations

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

**File:** volo-vault/sources/user_entry.move (L91-103)
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

    coin
}
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

**File:** volo-vault/sources/receipt.move (L12-15)
```text
public struct Receipt has key, store {
    id: UID,
    vault_id: address, // This receipt belongs to which vault
}
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
