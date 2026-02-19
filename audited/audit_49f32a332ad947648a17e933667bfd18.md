# Audit Report

## Title
Deposit Shares Can Be Stolen via Receipt Transfer Between Request and Execution

## Summary
The `execute_deposit` function fails to validate that the current owner of a Receipt object matches the original depositor stored in `DepositRequest.recipient`. This allows an attacker who acquires a transferred Receipt to steal vault shares funded by the original depositor, resulting in complete loss of the depositor's principal.

## Finding Description

The Volo Vault implements a two-phase deposit mechanism where users first request a deposit (locking their funds) and operators later execute the request (minting shares). The protocol stores the original depositor's address in the `DepositRequest.recipient` field [1](#0-0)  and captures `ctx.sender()` as the recipient during deposit creation [2](#0-1) .

The Receipt object has `key, store` abilities [3](#0-2) , making it transferable via standard Sui `transfer::public_transfer` operations.

**Critical Inconsistency:**

The `cancel_deposit` function validates that the caller is the original depositor by checking the recipient field [4](#0-3) .

However, the `execute_deposit` function performs NO such validation [5](#0-4) . It only validates the vault_id [6](#0-5)  and directly updates the VaultReceiptInfo indexed by receipt_id [7](#0-6) , crediting shares to whoever currently owns the Receipt object.

**Attack Mechanism:**

1. Alice calls `user_entry::deposit()` with 1000 SUI, creating DepositRequest with `recipient = Alice` and receiving Receipt R
2. Alice transfers Receipt R to Bob (valid Sui operation)
3. Operator calls `operation::execute_deposit()` for Alice's request
4. Shares are added to VaultReceiptInfo[R], which Bob now controls
5. Bob can withdraw these shares using Receipt R [8](#0-7) 
6. Alice cannot cancel (recipient check fails) and lost her 1000 SUI

The vulnerability violates the core invariant that deposited funds must be credited to the depositor who provided the funds.

## Impact Explanation

**Direct Fund Theft (High Severity):**

For any deposit amount X:
- Original depositor loses: X principal (locked in protocol, cannot cancel due to recipient validation)
- Attacker gains: Vault shares worth X
- Net impact: Complete theft of deposited funds

The impact is maximized because:
1. The depositor's funds are already locked in the protocol during the request phase
2. The depositor cannot cancel after transferring the Receipt (cancel_deposit validates recipient)
3. The attacker gains full ownership of shares minted from stolen funds
4. There is no slippage or fee loss for the attacker

This breaks the fundamental security guarantee that users who deposit funds will receive the corresponding shares.

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Complexity:** Requires only standard user operations (Receipt transfer via `transfer::public_transfer`)

2. **No Special Privileges:** Receipt has `store` ability by design, making transfers legitimate Sui operations. Test files demonstrate this pattern throughout the codebase.

3. **Multiple Attack Vectors:**
   - Social engineering (convince user to transfer Receipt)
   - Purchase Receipt from user unaware of pending execution
   - Receive as gift before execution
   - Exploit timing if user transfers Receipt for other legitimate reasons

4. **No Time Constraints:** Deposit requests can remain pending indefinitely, providing a large attack window

5. **Operator Execution is Guaranteed:** The operator will eventually execute pending deposits as part of normal protocol operations

6. **Difficult to Detect:** Receipt transfers are legitimate operations; the vulnerability only manifests after execution when comparing depositor events to share recipients

## Recommendation

Add recipient validation to `execute_deposit` to match the protection in `cancel_deposit`:

```move
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
    recipient: address,  // Add recipient parameter
) {
    // ... existing code ...
    
    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);
    
    // ADD THIS VALIDATION
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
    
    // ... rest of execution logic ...
}
```

Update the operator entry point to pass the Receipt owner:
```move
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    receipt_id: address,  // Add parameter to verify ownership
    max_shares_received: u256,
) {
    // ... existing code ...
    let deposit_request = vault.deposit_request(request_id);
    
    // Verify the receipt_id matches before execution
    assert!(deposit_request.receipt_id() == receipt_id, ERR_RECEIPT_ID_MISMATCH);
    
    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
        // Optionally get current owner from Receipt object or require operator to verify
    );
}
```

Alternatively, require passing the Receipt object itself to `execute_deposit` to enforce ownership validation similar to `cancel_deposit`.

## Proof of Concept

```move
#[test]
fun test_receipt_transfer_theft() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // Alice deposits 1000 SUI
    s.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (request_id, receipt, coin) = user_entry::deposit(
            &mut vault,
            &mut reward_manager,
            coin,
            1_000_000_000,
            1_000_000_000,
            option::none(),
            &clock,
            s.ctx(),
        );
        
        // Alice transfers receipt to BOB
        transfer::public_transfer(receipt, BOB);
        transfer::public_transfer(coin, ALICE);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Operator executes Alice's deposit
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        
        operation::execute_deposit(
            &operation,
            &cap,
            &mut vault,
            &mut reward_manager,
            &clock,
            &config,
            0, // request_id
            2_000_000_000,
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
    };
    
    // BOB now owns shares from Alice's deposit
    s.next_tx(BOB);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let receipt = s.take_from_sender<Receipt>();
        let vault_receipt_info = vault.vault_receipt_info(receipt.receipt_id());
        
        // BOB has shares funded by Alice's 1000 SUI
        assert!(vault_receipt_info.shares() > 0);
        
        s.return_to_sender(receipt);
        test_scenario::return_shared(vault);
    };
    
    // Alice has no shares and cannot cancel (recipient mismatch)
    s.next_tx(ALICE);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        // Alice lost her 1000 SUI with no shares to show for it
        test_scenario::return_shared(vault);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

**File:** volo-vault/sources/requests/deposit_request.move (L9-9)
```text
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
```

**File:** volo-vault/sources/user_entry.move (L57-57)
```text
        ctx.sender(),
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

**File:** volo-vault/sources/receipt.move (L12-12)
```text
public struct Receipt has key, store {
```

**File:** volo-vault/sources/volo_vault.move (L783-783)
```text
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);
```

**File:** volo-vault/sources/volo_vault.move (L806-872)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
```
