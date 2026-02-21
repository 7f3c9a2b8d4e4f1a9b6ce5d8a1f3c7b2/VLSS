# Audit Report

## Title
Receipt Status Reset During Deposit Execution Enables Multiple Withdraw Requests Leading to Execution Failures

## Summary
The `update_after_execute_deposit` function unconditionally resets a receipt's status to `NORMAL_STATUS` without checking for existing pending withdrawals. This allows users to create multiple withdraw requests through normal deposit/withdrawal interleaving, causing the `pending_withdraw_shares` to exceed available `shares`, which results in arithmetic underflow during withdrawal execution.

## Finding Description

The vulnerability arises from improper state synchronization between the `status` flag and `pending_withdraw_shares` field during deposit execution, breaking the critical protocol invariant that `pending_withdraw_shares <= shares`.

**Root Cause - Unconditional Status Reset:**

When a deposit is executed, `update_after_execute_deposit` unconditionally resets the receipt status to `NORMAL_STATUS` regardless of whether pending withdrawals exist. [1](#0-0) 

The function modifies `shares` and `pending_deposit_balance` but never touches `pending_withdraw_shares`, creating a desynchronization where the status indicates "normal" but pending withdrawals still exist in the accounting.

**Insufficient Protection in Withdraw Request Creation:**

The `request_withdraw` function enforces a status check intended to prevent multiple pending withdrawals, but this protection is bypassed after deposit execution resets the status. [2](#0-1) 

The shares validation at line 910 only checks `vault_receipt.shares() >= shares` without accounting for shares already committed in `pending_withdraw_shares`, allowing over-commitment of shares across multiple requests.

**Unbounded Accumulation:**

The `update_after_request_withdraw` function accumulates `pending_withdraw_shares` without bounds checking against available shares. [3](#0-2) 

This accumulation can exceed the actual `shares` field when the status check is bypassed through deposit execution.

**Execution Failure - Arithmetic Underflow:**

During withdrawal execution, the function attempts to subtract the requested shares directly from the receipt's `shares` field. [4](#0-3) 

In Sui Move, the arithmetic operation at line 108 will abort with underflow when `executed_withdraw_shares > shares`, causing the entire transaction to fail.

**Concrete Attack Scenario:**

1. User has receipt with 100 shares, status=0, pending_withdraw_shares=0
2. User requests withdraw of 80 shares → pending_withdraw_shares=80, status=2
3. User deposits additional funds, operator executes deposit → shares=110, status=0 (reset), pending_withdraw_shares=80 (unchanged)
4. User requests withdraw of 110 shares → Status check passes (0==0), shares check passes (110>=110) → pending_withdraw_shares=190
5. Operator executes first withdraw (80 shares) → shares=30, pending_withdraw_shares=110
6. Operator executes second withdraw (110 shares) → Arithmetic underflow: 30 - 110 causes transaction abort

## Impact Explanation

**Concrete Harm:**
- **Transaction failures**: Valid withdraw requests become unexecutable due to arithmetic underflow, requiring cancellation
- **Temporary fund lock**: User funds remain locked in pending state for the cancellation timeout period (default 5 minutes) [5](#0-4) 
- **Protocol operational disruption**: Batch withdrawal execution operations fail when encountering invalid requests [6](#0-5) 
- **State integrity violation**: Receipt maintains mathematically impossible state where `pending_withdraw_shares > shares`

**Severity: HIGH**

This is a HIGH severity issue because:
1. It causes definite execution failures with 100% reproducibility (not theoretical)
2. It temporarily locks user funds in an invalid protocol state
3. It can be triggered by normal, legitimate user behavior without malicious intent
4. It affects the core withdrawal functionality of the vault system
5. It creates operational overhead for both users (canceling requests) and operators (handling failed batches)

While funds are not permanently lost (users can cancel after timeout), the guaranteed execution failure and temporary lock constitute a significant protocol malfunction affecting core functionality.

## Likelihood Explanation

**Trigger Conditions:**

This occurs through completely normal user operations without malicious intent:
1. User creates a withdraw request (common vault operation)
2. User deposits more funds to the same receipt (legitimate behavior - users often add capital while having pending withdrawals)
3. Deposit is executed by operator (standard protocol operation)
4. User creates another withdraw request (now allowed due to bypassed status check)
5. Operator attempts to execute both requests (standard batch operation)

**Feasibility: HIGH**

- No special permissions required beyond normal user access
- No precise timing constraints beyond normal operational flow
- Reproducible with any deposit amount that increases shares
- No economic barriers or prerequisites
- Natural user behavior pattern in vault systems where users manage positions dynamically

**Attack Complexity: VERY LOW**

The entire flow uses standard public entry functions (`user_entry::deposit`, `user_entry::withdraw`, `operation::execute_deposit`, `operation::execute_withdraw`) with no special coordination or timing requirements.

**Probability: HIGH**

This will naturally occur whenever users interleave deposits and withdrawals on the same receipt, which is expected behavior in a vault system. Users commonly want to add funds while having pending withdrawal requests (e.g., to maintain exposure while withdrawing profits, or to rebalance positions).

## Recommendation

**Fix:** Check for existing pending withdrawals before resetting status in `update_after_execute_deposit`.

```move
public(package) fun update_after_execute_deposit(
    self: &mut VaultReceiptInfo,
    executed_deposit_balance: u64,
    new_shares: u256,
    last_deposit_time: u64,
) {
    // Only reset to NORMAL_STATUS if there are no pending withdrawals
    if (self.pending_withdraw_shares == 0) {
        self.status = NORMAL_STATUS;
    };
    self.shares = self.shares + new_shares;
    self.pending_deposit_balance = self.pending_deposit_balance - executed_deposit_balance;
    self.last_deposit_time = last_deposit_time;
}
```

**Alternative Fix:** Enhance `request_withdraw` to validate available shares after accounting for pending withdrawals:

```move
// In request_withdraw function, replace line 910 with:
assert!(
    vault_receipt.shares() >= shares + vault_receipt.pending_withdraw_shares(), 
    ERR_EXCEED_RECEIPT_SHARES
);
```

The first approach (conditional status reset) is preferred as it maintains the state machine invariant at the source, while the second approach adds defense-in-depth at the validation layer.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::balance::ENotEnough)]
public fun test_multiple_withdraw_requests_via_deposit_interleaving() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // Setup oracle
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        clock::set_for_testing(&mut clock, 1000);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        test_scenario::return_shared(oracle_config);
    };
    
    // Initial deposit: 100 shares
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(100_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let (_request_id, receipt, coin) = user_entry::deposit(&mut vault, &mut reward_manager, coin, 100_000_000, 200_000_000, option::none(), &clock, s.ctx());
        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Execute initial deposit
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault::update_free_principal_value(&mut vault, &config, &clock);
        vault.execute_deposit(&clock, &config, 0, 200_000_000);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // First withdraw request: 80 shares
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();
        clock::set_for_testing(&mut clock, 1000 + 12 * 3600_000);
        user_entry::withdraw(&mut vault, 80_000_000, 40_000_000, &mut receipt, &clock, s.ctx());
        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };
    
    // Second deposit: 10 more shares
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();
        user_entry::deposit_to_receipt(&mut vault, &mut reward_manager, &mut receipt, coin, 10_000_000, 20_000_000, &clock, s.ctx());
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        s.return_to_sender(receipt);
    };
    
    // Execute second deposit - STATUS RESET HAPPENS HERE
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault.execute_deposit(&clock, &config, 1, 20_000_000);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // Second withdraw request: 110 shares (BYPASSES STATUS CHECK)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();
        user_entry::withdraw(&mut vault, 110_000_000, 55_000_000, &mut receipt, &clock, s.ctx());
        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };
    
    // Execute first withdraw (80 shares) - SUCCESS
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        operation::execute_withdraw(&operation, &cap, &mut vault, &mut reward_manager, &clock, &config, 0, 50_000_000, s.ctx());
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(config);
    };
    
    // Execute second withdraw (110 shares) - UNDERFLOW ABORT
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        operation::execute_withdraw(&operation, &cap, &mut vault, &mut reward_manager, &clock, &config, 1, 60_000_000, s.ctx());
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

The vulnerability is particularly insidious because:

1. **Silent state corruption**: The desynchronization between `status` and `pending_withdraw_shares` is not visible to users or logged in events
2. **Natural occurrence**: Users don't need to understand the vulnerability - it happens through normal vault usage patterns
3. **Batch operation impact**: A single invalid request in a batch can cause the entire batch to fail, affecting other users' legitimate withdrawals
4. **No on-chain warnings**: The protocol provides no indication that a receipt has accumulated excessive pending withdrawals until execution fails

The fix should be implemented at the deposit execution level to maintain proper state machine invariants rather than relying solely on validation checks at the request level.

### Citations

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

**File:** volo-vault/sources/vault_receipt_info.move (L79-90)
```text
public(package) fun update_after_request_withdraw(
    self: &mut VaultReceiptInfo,
    pending_withdraw_shares: u256,
    recipient: address,
) {
    self.status = if (recipient == address::from_u256(0)) {
        PENDING_WITHDRAW_STATUS
    } else {
        PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS
    };
    self.pending_withdraw_shares = self.pending_withdraw_shares + pending_withdraw_shares;
}
```

**File:** volo-vault/sources/vault_receipt_info.move (L102-111)
```text
public(package) fun update_after_execute_withdraw(
    self: &mut VaultReceiptInfo,
    executed_withdraw_shares: u256,
    claimable_principal: u64,
) {
    self.status = NORMAL_STATUS;
    self.shares = self.shares - executed_withdraw_shares;
    self.pending_withdraw_shares = self.pending_withdraw_shares - executed_withdraw_shares;
    self.claimable_principal = self.claimable_principal + claimable_principal;
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

**File:** volo-vault/sources/volo_vault.move (L964-966)
```text
    assert!(
        withdraw_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
```

**File:** volo-vault/sources/operation.move (L481-510)
```text
public fun batch_execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_ids: vector<u64>,
    max_amount_received: vector<u64>,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);
    reward_manager.update_reward_buffers(vault, clock);

    request_ids.do!(|request_id| {
        let withdraw_request = vault.withdraw_request(request_id);
        reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

        let (_, index) = request_ids.index_of(&request_id);

        let (withdraw_balance, recipient) = vault.execute_withdraw(
            clock,
            config,
            request_id,
            max_amount_received[index],
        );

        if (recipient != address::from_u256(0)) {
            transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
        } else {
```
