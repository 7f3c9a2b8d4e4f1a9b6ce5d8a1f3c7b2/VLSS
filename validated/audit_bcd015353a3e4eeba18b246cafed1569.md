# Audit Report

## Title
Frozen Operators Can Bypass Freeze Control to Retrieve Protocol Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows operators to retrieve accumulated protocol fees without checking if the operator has been frozen, bypassing the operator freeze security control that is consistently enforced across all other operator functions.

## Finding Description

The vulnerability exists in the `retrieve_deposit_withdraw_fee_operator()` function which takes an `OperatorCap` but does not verify the operator's freeze status before allowing fee retrieval. [1](#0-0) 

The function directly calls the underlying vault method without any freeze check. The underlying implementation only validates version and vault normal status, but lacks operator freeze validation: [2](#0-1) 

In contrast, the protocol consistently enforces freeze checks across all other operator functions. The freeze check is implemented via `assert_operator_not_freezed()`: [3](#0-2) 

All operation functions in `operation.move` properly enforce this check as their first validation step: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

Administrators can freeze operators using `set_operator_freezed()`: [9](#0-8) 

The protocol collects fees during deposit operations and withdraw operations, accumulating them in the vault's `deposit_withdraw_fee_collected` balance: [10](#0-9) [11](#0-10) [12](#0-11) 

## Impact Explanation

**Direct Fund Impact**: A frozen operator can extract all accumulated deposit and withdraw fees from the vault's `deposit_withdraw_fee_collected` balance, resulting in unauthorized fund theft. The amount depends on fee accumulation since the last retrieval, which grows with deposit and withdraw activity.

**Security Integrity Impact**: This vulnerability completely bypasses the operator freeze control mechanism, which is a critical security feature. When administrators detect suspicious or malicious operator behavior and freeze them, the expectation is that all operator privileges are immediately revoked. However, frozen operators retain the ability to drain fee revenue, rendering the freeze mechanism ineffective for protecting protocol funds.

**Who is Affected**: The protocol and its users are affected through loss of rightfully collected fees that should remain under administrative control. The freeze mechanism exists precisely to handle compromised or malicious operators, making this bypass particularly severe.

## Likelihood Explanation

**Reachable Entry Point**: The `retrieve_deposit_withdraw_fee_operator()` function is a public function that can be called directly via Programmable Transaction Blocks (PTBs) in Sui by any address holding an `OperatorCap`.

**Feasible Preconditions**: The attack scenario requires an operator who has been frozen by administrators due to suspected compromise or malicious behavior. This is a realistic scenario that the freeze mechanism is designed to handle. The operator must possess the `OperatorCap` object, which they would have from their normal operator role.

**Execution Practicality**: The exploit is trivial - a single function call to `retrieve_deposit_withdraw_fee_operator()` with the frozen `OperatorCap` and desired amount. No complex transaction sequencing or state manipulation is required.

**Economic Rationality**: There are no economic barriers. The frozen operator can extract the full fee balance with no transaction cost constraints beyond standard gas fees.

The likelihood is **HIGH** because frozen operators have strong incentive to extract remaining funds before the administrator can act further, and the execution is straightforward.

## Recommendation

Add the operator freeze check at the beginning of the `retrieve_deposit_withdraw_fee_operator()` function, consistent with all other operator functions:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // Add operation parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add freeze check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This ensures frozen operators cannot retrieve fees, maintaining the security guarantee of the freeze mechanism.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and accumulate some fees
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    // ... deposit/withdraw operations to accumulate fees ...
    
    s.next_tx(OWNER);
    {
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // Admin freezes the operator
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );
        
        // Frozen operator attempts to retrieve fees - should fail but doesn't
        let fee_balance = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1000,
        );
        
        fee_balance.destroy_for_testing();
        test_scenario::return_shared(operation);
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
        s.return_to_sender(admin_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

**Notes**

The vulnerability is confirmed through code analysis showing that `retrieve_deposit_withdraw_fee_operator()` is the only operator function that does not call `assert_operator_not_freezed()`. This inconsistency creates an access control bypass that allows frozen operators to extract protocol fees, defeating the purpose of the freeze mechanism which is to immediately revoke all operator privileges in emergency situations.

### Citations

**File:** volo-vault/sources/manage.move (L88-95)
```text
public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
}
```

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

**File:** volo-vault/sources/volo_vault.move (L105-105)
```text
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

**File:** volo-vault/sources/operation.move (L105-106)
```text
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/operation.move (L391-391)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L416-416)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L444-444)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```
