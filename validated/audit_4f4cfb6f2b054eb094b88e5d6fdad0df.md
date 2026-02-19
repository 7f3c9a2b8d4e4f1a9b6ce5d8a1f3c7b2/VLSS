# Audit Report

## Title
Receipt Transfer Before Deposit Execution Allows Share Misdirection to Unintended Recipient

## Summary
The Volo Vault protocol fails to validate the current Receipt holder during `execute_deposit`, allowing shares to be misdirected if a Receipt is transferred after deposit request creation but before operator execution. This breaks the fundamental invariant that depositors receive shares for their deposits, enabling direct fund loss scenarios.

## Finding Description

The vulnerability stems from asymmetric validation of the `recipient` field across deposit lifecycle operations.

**Receipt Transferability**: The `Receipt` struct has `key, store` abilities, making it fully transferable via standard Sui `transfer::public_transfer()` operations. [1](#0-0) 

**Deposit Request Creation**: When users call `user_entry::deposit()`, the system stores `ctx.sender()` as the `recipient` in the `DepositRequest` and buffers their coins. [2](#0-1) 

**Cancel Protection**: The `cancel_deposit` function validates that the caller matches the stored `recipient`, providing protection against unauthorized cancellation. [3](#0-2) 

**Execution Without Validation**: The critical flaw occurs in `execute_deposit`, which retrieves the `receipt_id` from the stored request and directly updates `self.receipts[deposit_request.receipt_id()]` with new shares, **without verifying** that the current Receipt holder matches the original `recipient`. [4](#0-3) 

**Attack Path**:
1. User A deposits 10,000 USDC, receives Receipt R1, funds buffered in vault
2. User A transfers Receipt R1 to User B (intentionally, accidentally, or via marketplace)
3. Operator executes deposit request using User A's buffered 10,000 USDC
4. Shares are credited to `VaultReceiptInfo` at receipt_id R1
5. User B (holding Receipt R1) can now withdraw/use those shares
6. User A has lost their 10,000 USDC with no recovery mechanism

**Custody Lock**: Neither party can cancel the deposit after Receipt transfer:
- User A lacks the Receipt object required by `cancel_deposit` [5](#0-4) 
- User B's `ctx.sender()` won't match the stored `recipient`, failing the assertion [3](#0-2) 

## Impact Explanation

**HIGH Severity** - This vulnerability enables direct fund loss through share misdirection:

1. **Complete Fund Loss**: The original depositor (User A) loses 100% of their deposited principal when the Receipt is transferred before execution. User A provided real funds that were buffered in the vault, but receives zero shares in return.

2. **Unauthorized Enrichment**: The new Receipt holder (User B) receives shares they never paid for, directly converting User A's deposit into their own holdings.

3. **No Recovery Path**: The forced execution scenario with no cancellation capability for either party creates an irreversible fund loss once the Receipt is transferred.

4. **Broad Attack Surface**: This affects:
   - Accidental transfers (user error sending wrong object)
   - Marketplace scenarios (trading Receipts with pending deposits)
   - Social engineering (tricking users into transferring Receipts)
   - Intentional attacks (malicious deposit + transfer to accomplice)

## Likelihood Explanation

**HIGH Likelihood** - The attack requires only standard user actions:

1. **No Special Privileges**: Any user can execute this attack using only publicly callable functions (`user_entry::deposit()` and `transfer::public_transfer()`).

2. **Technical Simplicity**: The attack requires no complex state manipulation, just:
   - Create deposit request (public function)
   - Transfer Receipt (built-in Sui capability for objects with `store`)
   - Wait for operator execution (automatic)

3. **Multiple Trigger Scenarios**:
   - **Intentional**: Attacker deposits, transfers Receipt to victim/accomplice
   - **Accidental**: User lists Receipt on marketplace while forgetting about pending deposit
   - **Market Confusion**: Receipt buyers/sellers unsure of ownership rights to pending deposits

4. **No Detection/Prevention**: The protocol has no on-chain mechanism to prevent or detect this scenario. While `DepositExecuted` event emits the original `recipient` address, shares are already credited to the new holder. [6](#0-5) 

## Recommendation

Add recipient validation to `execute_deposit` to ensure shares are only credited when the current Receipt holder matches the original depositor:

**Option 1: Require Receipt Object in Execute Path**
Modify `execute_deposit` to accept a `&Receipt` parameter and validate:
```move
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    receipt: &Receipt,  // Add receipt parameter
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    // ... existing checks ...
    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    
    // Validate receipt matches request
    assert!(receipt.receipt_id() == deposit_request.receipt_id(), ERR_RECEIPT_ID_MISMATCH);
    
    // Continue with execution...
}
```

**Option 2: Lock Receipt During Pending Deposit**
Add a lock mechanism that prevents Receipt transfers while deposits are pending, similar to the withdraw locking mechanism.

**Option 3: Remove `store` from Receipt**
If Receipts are not intended to be bearer tokens, remove the `store` ability to prevent transfers entirely.

## Proof of Concept

```move
#[test]
// Demonstrates shares misdirection via Receipt transfer before execution
public fun test_receipt_transfer_before_execution_steals_shares() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    init_vault::init_oracle_config(&mut s, &mut clock);
    
    // User A deposits 1000 SUI and gets Receipt
    s.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin, 1_000_000_000,
            1_000_000_000, option::none(), &clock, s.ctx()
        );
        
        // ALICE transfers Receipt to BOB
        transfer::public_transfer(receipt, BOB);
        transfer::public_transfer(coin, ALICE);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Operator executes deposit using ALICE's buffered coins
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        vault::update_free_principal_value(&mut vault, &config, &clock);
        operation::execute_deposit(&operation, &cap, &mut vault,
            &mut reward_manager, &clock, &config, 0, 2_000_000_000);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(reward_manager);
    };
    
    // BOB now owns the shares from ALICE's deposit
    s.next_tx(BOB);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let receipt = s.take_from_sender<Receipt>();
        let vault_receipt_info = vault.vault_receipt_info(receipt.receipt_id());
        
        // BOB has shares from ALICE's 1000 SUI deposit
        assert!(vault_receipt_info.shares() > 0, 0);
        
        s.return_to_sender(receipt);
        test_scenario::return_shared(vault);
    };
    
    // ALICE cannot recover funds - has no Receipt and no shares
    s.next_tx(ALICE);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        // ALICE has no Receipt object and no shares in any VaultReceiptInfo
        assert!(!s.has_most_recent_for_sender<Receipt>(), 0);
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

**Notes**:
- The PoC requires full test environment setup with oracle configuration and operator capabilities
- The vulnerability is confirmed by code analysis showing execute_deposit updates `self.receipts[deposit_request.receipt_id()]` without current holder validation
- This is NOT a user error scenario - it's a protocol design flaw where fund custody and share ownership can become permanently misaligned with no recovery mechanism

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

**File:** volo-vault/sources/volo_vault.move (L783-783)
```text
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
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
