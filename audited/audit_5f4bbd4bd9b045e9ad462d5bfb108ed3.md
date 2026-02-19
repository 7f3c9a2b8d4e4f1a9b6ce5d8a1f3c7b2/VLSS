### Title
Deposit Shares Can Be Stolen via Receipt Transfer Between Request and Execution

### Summary
The `execute_deposit` function does not validate that the current owner of the Receipt object matches the original depositor stored in `DepositRequest.recipient`. An attacker can receive a transferred Receipt after a deposit request is made, then when the operator executes the deposit, the attacker receives the shares while the original depositor loses their funds.

### Finding Description

The `DepositRequest` struct stores both `receipt_id` and `recipient` fields: [1](#0-0) 

When a user calls `deposit`, the system captures `ctx.sender()` as the recipient: [2](#0-1) 

The `Receipt` object has `key, store` abilities, making it transferable: [3](#0-2) 

The critical issue is that `cancel_deposit` validates the recipient field: [4](#0-3) 

But `execute_deposit` does NOT perform this check. It only validates the vault_id and updates the VaultReceiptInfo directly by receipt_id: [5](#0-4) [6](#0-5) 

The function updates shares for whoever currently holds the Receipt object at `deposit_request.receipt_id()`, without verifying they are the original depositor who paid the funds.

### Impact Explanation

**Direct Fund Theft**: An attacker can steal deposited funds through the following mechanism:
1. Victim (Alice) owns Receipt R and deposits 1000 SUI, creating DepositRequest with `recipient = Alice`
2. Alice transfers Receipt R to Attacker (Bob) - this is a normal Sui object transfer
3. Operator executes the deposit via `operation::execute_deposit`
4. Bob now owns the shares minted from Alice's 1000 SUI deposit
5. Alice lost 1000 SUI, Bob gained the equivalent shares for free

The vulnerability allows complete theft of deposited principal. For any deposit amount X, the attacker gains X worth of vault shares while the original depositor loses X. This violates the critical invariant that deposited funds must be credited to the depositor.

**Affected Parties**: All vault depositors are at risk. Any user who makes a deposit request and subsequently transfers or loses control of their Receipt object will have their funds stolen.

### Likelihood Explanation

**Attack Complexity**: Low - requires only normal user operations:
1. Wait for any user to make a deposit request
2. Acquire their Receipt object (purchase, social engineering, or receive as gift)
3. Wait for operator to execute the deposit
4. Automatically receive the shares

**Attacker Capabilities**: No special privileges required. The Receipt object has `store` ability as shown in the code, making transfer a standard Sui operation. Any address can receive and own a transferred Receipt.

**Feasibility**: High - the attack is completely practical:
- Receipt transfers are demonstrated throughout the test suite using `transfer::public_transfer`
- No time constraints prevent the attack (requests can be pending indefinitely)
- The operator execution is a normal protocol operation that will occur
- No economic cost to the attacker beyond gas fees

**Detection**: Difficult to detect before execution since Receipt transfers are legitimate operations. After execution, the mismatch between depositor and share recipient would only be visible by comparing on-chain events.

### Recommendation

Add recipient validation in `execute_deposit` to match the check in `cancel_deposit`:

```move
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
    recipient: address,  // Add parameter
) {
    // ... existing code ...
    
    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);
    
    // ADD THIS CHECK:
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
    
    // ... rest of function ...
}
```

Update `operation::execute_deposit` to require the Receipt object as a reference parameter and extract its owner or pass the expected recipient address explicitly. The key invariant to enforce is: **shares must only be credited to VaultReceiptInfo if the Receipt object is currently owned by the original depositor (deposit_request.recipient())**.

Add test cases:
1. Test that execute_deposit fails if Receipt ownership changed
2. Test that legitimate transfers after execution succeed
3. Test cancellation works correctly with transferred Receipts (already checked via recipient field)

### Proof of Concept

**Initial State**:
- Alice owns Receipt R (address 0xR)
- Vault is operational with oracle configured

**Attack Steps**:

1. **Alice deposits 1000 SUI** (Transaction 1):
   ```
   Call: user_entry::deposit(vault, reward_manager, 1000_SUI, expected_shares, Some(Receipt_R))
   Result: DepositRequest created with receipt_id=0xR, recipient=Alice, amount=1000
   Receipt R returned to Alice
   ```

2. **Alice transfers Receipt to Bob** (Transaction 2):
   ```
   Call: transfer::public_transfer(Receipt_R, Bob_address)
   Result: Receipt R now owned by Bob
   ```

3. **Operator executes deposit** (Transaction 3):
   ```
   Call: operation::execute_deposit(operation, cap, vault, reward_manager, clock, config, request_id=0, max_shares)
   Result: 
   - Vault processes Alice's 1000 SUI deposit
   - Shares minted and credited to VaultReceiptInfo[0xR]
   - Bob (owner of Receipt R) can now withdraw using these shares
   ```

**Expected Result**: Shares should be credited to Alice's receipt or execution should fail.

**Actual Result**: Shares are credited to Receipt R which Bob now owns. Alice lost 1000 SUI, Bob gained the shares.

**Success Condition**: Bob can withdraw funds using Receipt R that he did not deposit.

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

**File:** volo-vault/sources/receipt.move (L12-15)
```text
public struct Receipt has key, store {
    id: UID,
    vault_id: address, // This receipt belongs to which vault
}
```

**File:** volo-vault/sources/volo_vault.move (L783-783)
```text
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
```

**File:** volo-vault/sources/volo_vault.move (L823-824)
```text
    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);
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
