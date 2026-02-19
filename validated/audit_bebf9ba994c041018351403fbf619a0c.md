# Audit Report

## Title
Frozen Operators Can Bypass Freeze Mechanism to Extract Vault Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator` function in `manage.move` does not verify that the OperatorCap has been frozen before allowing fee retrieval operations. This allows frozen operators to bypass the operator freeze security mechanism and continue extracting accumulated deposit/withdraw fees even after administrators have frozen their capabilities.

## Finding Description

The Volo vault implements an operator freeze mechanism where admins can disable specific operators via the `Operation` shared object's `freezed_operators` table. [1](#0-0) 

The freeze check function `assert_operator_not_freezed` is designed to abort with `ERR_OPERATOR_FREEZED` when a frozen operator attempts any operation. [2](#0-1) 

All operator functions in `operation.move` properly call this freeze check at their entry point. For example, `start_op_with_bag` [3](#0-2) , `execute_deposit` [4](#0-3) , `batch_execute_deposit` [5](#0-4) , and `execute_withdraw` [6](#0-5)  all follow this pattern.

Similarly, all operator functions in `reward_manager.move` properly enforce the freeze check, such as in `add_new_reward_type` [7](#0-6)  and `create_reward_buffer_distribution` [8](#0-7) .

**However, the `retrieve_deposit_withdraw_fee_operator` function in `manage.move` does NOT perform this freeze check.** [9](#0-8) 

This function:
1. Takes an `&OperatorCap` parameter but does NOT take the `Operation` shared object
2. Does NOT call `vault::assert_operator_not_freezed(operation, cap)`
3. Directly calls the vault's internal `retrieve_deposit_withdraw_fee` function [10](#0-9)  without freeze verification

The root cause is inconsistent enforcement of the freeze mechanism - while all other operator functions require the `Operation` object to check freeze status, this function omits both the parameter and the check.

The protocol explicitly tests that frozen operators should be blocked from operations with `ERR_OPERATOR_FREEZED`. [11](#0-10) 

## Impact Explanation

**Direct Fund Impact:**
When an admin freezes an operator (typically due to suspected compromise or malicious behavior), the expectation is that ALL operator privileges are immediately revoked. However, a frozen operator can still call `retrieve_deposit_withdraw_fee_operator` to extract all accumulated deposit and withdraw fees from the vault.

The vault collects fees from every deposit and withdraw operation, storing them in `deposit_withdraw_fee_collected`. [12](#0-11)  These fees can accumulate to substantial amounts depending on vault activity. A frozen operator can drain the entire fee balance.

**Security Integrity Impact:**
This violates the critical invariant that "operator freeze respected" must hold at all times. The freeze mechanism becomes unreliable as a security control, undermining the admin's ability to respond to security incidents involving compromised or malicious operators.

**Affected Parties:**
- Protocol treasury (loses rightful fee revenue)
- Vault depositors (indirectly affected by reduced protocol sustainability)  
- Admin trust in security controls

The severity is HIGH because it represents a complete bypass of an explicit security control mechanism designed to protect protocol funds.

## Likelihood Explanation

**Reachability:** The function is publicly callable by any holder of an OperatorCap. [9](#0-8) 

**Preconditions:**
1. An operator must have been created and granted an OperatorCap
2. The operator must have been frozen by admin using `set_operator_freezed` [13](#0-12) 
3. Deposit/withdraw fees must have accumulated in the vault

**Execution:** The exploit is trivially simple - a frozen operator just calls the function with their OperatorCap. No complex transaction sequences or timing requirements.

**Detection:** The freeze mechanism is intended as an emergency response to suspicious operator behavior. The window between detection and freeze action provides opportunity for exploitation. Additionally, a sophisticated attacker might act normally until frozen, then exploit this vulnerability as a final extraction.

**Probability:** MEDIUM-HIGH. While it requires the operator to be frozen (suggesting prior suspicious activity), the complete absence of the freeze check makes exploitation certain once the condition is met. Active vaults will continuously accumulate fees, making the target valuable.

## Recommendation

Add the `Operation` shared object parameter and freeze check to `retrieve_deposit_withdraw_fee_operator`:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // Add this parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add this check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This aligns the function with all other operator functions in the codebase.

## Proof of Concept

A test demonstrating the vulnerability:

```move
#[test]
// Frozen operator can still extract fees - this should fail but doesn't
public fun test_frozen_operator_extracts_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with fees
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    // ... setup that accumulates fees in vault ...
    
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
        // Admin freezes the operator
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
        s.return_to_sender(admin_cap);
    };
    
    // Frozen operator extracts fees - this succeeds but shouldn't
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This call succeeds even though operator is frozen
        let fee_retrieved = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            10_000_000,
        );
        
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
        fee_retrieved.destroy_for_testing();
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L105-105)
```text
    deposit_withdraw_fee_collected: Balance<T>,
```

**File:** volo-vault/sources/volo_vault.move (L362-378)
```text
public(package) fun set_operator_freezed(
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    if (operation.freezed_operators.contains(op_cap_id)) {
        let v = operation.freezed_operators.borrow_mut(op_cap_id);
        *v = freezed;
    } else {
        operation.freezed_operators.add(op_cap_id, freezed);
    };

    emit(OperatorFreezed {
        operator_id: op_cap_id,
        freezed: freezed,
    });
}
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

**File:** volo-vault/sources/operation.move (L105-105)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L391-391)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L416-416)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L241-241)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L283-283)
```text
    vault::assert_operator_not_freezed(operation, cap);
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

**File:** volo-vault/tests/operation/operation.test.move (L1561-1562)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
```
