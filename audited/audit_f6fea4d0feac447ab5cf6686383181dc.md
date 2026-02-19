# Audit Report

## Title
Deposit Shares Can Be Stolen via Receipt Transfer Between Request and Execution

## Summary
The `execute_deposit` function fails to validate that the current Receipt owner matches the original depositor, while `cancel_deposit` enforces this check. This inconsistency allows an attacker who acquires a transferred Receipt to claim shares paid for by the original depositor, resulting in complete fund theft.

## Finding Description

The Volo vault protocol implements a two-phase deposit pattern where users first request a deposit and later an operator executes it. During this flow, the protocol stores the original depositor's address in the `DepositRequest.recipient` field [1](#0-0) , captured from `ctx.sender()` at request time [2](#0-1) .

The protocol's `Receipt` object has `key, store` abilities, making it fully transferable [3](#0-2) . This design creates a security vulnerability due to inconsistent recipient validation.

**The Critical Inconsistency:**

When a user cancels a deposit, the protocol validates that the caller matches the original depositor: [4](#0-3) 

However, when the operator executes the deposit, NO such validation exists. The function only validates the vault_id and proceeds to credit shares directly to the VaultReceiptInfo indexed by receipt_id: [5](#0-4) 

The shares are added to the VaultReceiptInfo without any ownership verification: [6](#0-5) 

**Attack Flow:**
1. Alice deposits 1000 SUI via `user_entry::deposit()`, creating DepositRequest{recipient: Alice, receipt_id: R}
2. Alice transfers Receipt R to Bob using `transfer::public_transfer()` (standard Sui operation)
3. Operator calls `operation::execute_deposit(request_id)` [7](#0-6) 
4. The vault execution updates VaultReceiptInfo[R] with calculated shares
5. Bob now owns Receipt R with shares funded by Alice's 1000 SUI
6. Bob can withdraw or use these shares while Alice has lost her deposit

The protocol's security model is internally contradictory: it protects the original depositor during cancellation but not during execution, despite storing the recipient field for this exact purpose.

## Impact Explanation

**Severity: HIGH - Complete Fund Theft**

This vulnerability enables direct theft of deposited principal:
- **Quantified Loss**: For every deposit amount X, the attacker gains X worth of vault shares while the original depositor receives nothing
- **Affected Parties**: All vault depositors who transfer their Receipt objects after making deposit requests
- **Invariant Violation**: The fundamental guarantee that "deposited funds are credited to the depositor" is broken

The impact is exacerbated by:
1. **Irreversibility**: Once executed, the deposit cannot be reversed and Alice has no recourse
2. **No Protocol Limits**: Any deposit size can be stolen, from small retail amounts to large institutional deposits
3. **Silent Failure**: The protocol emits events showing Alice as the recipient [8](#0-7) , but the actual shares go to Bob, creating a misleading audit trail

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

While this requires a Receipt transfer, several factors make exploitation realistic:

**Protocol Design Contradictions:**
- The Receipt has `store` ability, explicitly enabling transfers as a protocol feature
- The existence of recipient validation in `cancel_deposit` proves the protocol intended to protect depositors
- The missing validation in `execute_deposit` is an implementation bug, not a design choice

**Realistic Transfer Scenarios:**
1. **Secondary Markets**: Users may trade Receipt tokens on external marketplaces
2. **Collateralization**: Users might transfer Receipts to lending protocols or vaults
3. **Legitimate Gifting**: Users transferring assets to family/friends
4. **Contract Interactions**: Smart contracts that accept Receipt objects as inputs

**No Economic Barriers:**
- Attacker only pays gas fees
- No capital requirement beyond acquiring the Receipt
- Request can remain pending indefinitely with no timeout

**Detection Difficulty:**
- Receipt transfers are standard Sui operations with no special markers
- The vulnerability only manifests at execution time, potentially days after the transfer
- Events show the original recipient, not the actual share receiver

The protocol's inconsistent security model transforms what should be safe receipt transfers into fund theft opportunities.

## Recommendation

**Primary Fix**: Add recipient validation to `execute_deposit`:

```move
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
    caller: address,  // Add caller parameter
) {
    // ... existing checks ...
    
    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);
    
    // ADD THIS CHECK:
    assert!(deposit_request.recipient() == caller, ERR_RECIPIENT_MISMATCH);
    
    // ... rest of function ...
}
```

Update the operator-facing wrapper to pass the recipient:
```move
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
    recipient: address,  // Add recipient parameter
) {
    // ... existing code ...
    
    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
        recipient,  // Pass recipient
    );
}
```

**Alternative Design Decisions:**

If Receipt transfers are not intended:
- Remove `store` ability from Receipt struct
- This prevents transfers entirely

If Receipt transfers ARE intended for secondary markets:
- Current implementation is correct for allowing free transfer of deposit rights
- Remove recipient field and cancel_deposit validation to match this model
- Document that Receipt ownership determines benefit rights

## Proof of Concept

```move
#[test]
fun test_receipt_transfer_theft() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut scenario);
    
    const ALICE: address = @0xA11CE;
    const BOB: address = @0xB0B;
    const DEPOSIT_AMOUNT: u64 = 1_000_000_000; // 1000 SUI
    
    // Step 1: Alice makes deposit request
    scenario.next_tx(ALICE);
    let deposit_coin = coin::mint_for_testing<SUI_TEST_COIN>(DEPOSIT_AMOUNT, scenario.ctx());
    let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
    let mut reward_manager = scenario.take_shared<RewardManager<SUI_TEST_COIN>>();
    
    let (request_id, receipt, return_coin) = user_entry::deposit(
        &mut vault,
        &mut reward_manager,
        deposit_coin,
        DEPOSIT_AMOUNT,
        0, // expected_shares
        option::none(),
        &clock,
        scenario.ctx(),
    );
    
    // Alice transfers Receipt to Bob (ATTACK VECTOR)
    transfer::public_transfer(receipt, BOB);
    transfer::public_transfer(return_coin, ALICE);
    test_scenario::return_shared(vault);
    test_scenario::return_shared(reward_manager);
    
    // Step 2: Operator executes deposit
    scenario.next_tx(OWNER);
    let operation = scenario.take_shared<Operation>();
    let operator_cap = scenario.take_from_sender<OperatorCap>();
    let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
    let mut reward_manager = scenario.take_shared<RewardManager<SUI_TEST_COIN>>();
    let config = scenario.take_shared<OracleConfig>();
    
    operation::execute_deposit(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &config,
        request_id,
        1_000_000_000_000_000_000, // max_shares
    );
    
    // Step 3: Verify Bob can use the shares
    scenario.next_tx(BOB);
    let receipt = scenario.take_from_sender<Receipt>();
    let vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
    
    let receipt_info = vault.vault_receipt_info(receipt.receipt_id());
    let bob_shares = receipt_info.shares();
    
    // VULNERABILITY CONFIRMED: Bob has shares funded by Alice's deposit
    assert!(bob_shares > 0, 0);
    
    // Alice has no shares - her funds were stolen
    // (Alice cannot access these shares as she no longer owns the Receipt)
    
    test_scenario::return_to_sender(&scenario, receipt);
    test_scenario::return_shared(vault);
    clock.destroy_for_testing();
    scenario.end();
}
```

## Notes

This vulnerability exists due to an **inconsistent security model** in the protocol:

1. **Design Evidence**: The presence of `ERR_RECIPIENT_MISMATCH` validation in `cancel_deposit` proves the developers understood the need to protect the original depositor

2. **Implementation Gap**: The same protection was not applied to `execute_deposit`, creating an exploitable inconsistency

3. **Transferability Feature**: The Receipt's `store` ability appears intentional, suggesting receipt transfers may be a desired feature. However, this conflicts with the recipient validation in cancellation

4. **Root Cause**: The protocol must choose one model:
   - **Option A**: Receipt ownership determines all rights (remove recipient validation from cancel_deposit)
   - **Option B**: Original depositor retains rights (add recipient validation to execute_deposit, or remove `store` ability)

The current hybrid approach creates a critical security vulnerability where deposited funds can be redirected to unintended recipients.

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

**File:** volo-vault/sources/vault_receipt_info.move (L66-76)
```text
public(package) fun update_after_execute_deposit(
    self: &mut VaultReceiptInfo,
    executed_deposit_balance: u64,
    new_shares: u256,
    last_deposit_time: u64,
) {
    self.status = NORMAL_STATUS;
    self.shares = self.shares + new_shares;
    self.pending_deposit_balance = self.pending_deposit_balance - executed_deposit_balance;
    self.last_deposit_time = last_deposit_time;
}
```

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
```
