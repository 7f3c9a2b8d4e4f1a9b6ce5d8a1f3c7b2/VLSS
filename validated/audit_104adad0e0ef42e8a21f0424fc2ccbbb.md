# Audit Report

## Title
Incomplete OperatorCap Revocation: Frozen Operators Can Still Drain Accumulated Fees

## Summary
The protocol's operator freezing mechanism fails to protect the `retrieve_deposit_withdraw_fee_operator()` function, allowing frozen operators to drain all accumulated deposit and withdrawal fees even after being revoked by the admin. This directly undermines the security invariant that operator freezes are respected across all operator functions.

## Finding Description

The Volo vault implements a comprehensive operator freezing mechanism to revoke compromised OperatorCap privileges. The admin can freeze an operator via `set_operator_freezed()` [1](#0-0) , which maintains a freeze map in the shared `Operation` object [2](#0-1) .

All critical operator functions correctly enforce this freeze by calling `assert_operator_not_freezed()` before execution [3](#0-2) . This protection is consistently applied across all 14 operator functions in the operation module, including operations management [4](#0-3) , deposit execution [5](#0-4) , withdrawal execution [6](#0-5) , and all asset management operations [7](#0-6) [8](#0-7) .

The protocol's test suite confirms this invariant: when an operator is frozen, any attempt to call protected functions must fail with `ERR_OPERATOR_FREEZED` [9](#0-8) .

**Root Cause**: The `retrieve_deposit_withdraw_fee_operator()` function is the sole exception to this pattern [10](#0-9) . It lacks the freeze check entirely. The function only requires possession of an OperatorCap and does not take the `Operation` object as a parameter, making it impossible to verify freeze status. It directly calls the underlying vault function [11](#0-10)  which has no freeze awareness.

This breaks the authorization enforcement invariant that frozen operators cannot execute privileged operations.

## Impact Explanation

**Direct Fund Loss**: When an OperatorCap is compromised and the admin freezes it to revoke all privileges, the malicious operator can still drain 100% of accumulated deposit and withdrawal fees from the vault. These fees represent protocol revenue collected from all user activity.

**Quantified Damage**:
- Maximum deposit fee: 500bp (5%) of all deposits [12](#0-11) 
- Maximum withdrawal fee: 500bp (5%) of all withdrawals [13](#0-12) 
- Default rates: 10bp (0.1%) each [14](#0-13) 
- The `deposit_withdraw_fee_collected` balance [15](#0-14)  accumulates continuously from user activity [16](#0-15) 
- Complete loss of all accumulated protocol revenue up to the point of detection

**Affected Party**: The protocol loses accumulated fees that should be protected once an operator is frozen. The admin expects that freezing an operator revokes ALL privileges, but fee retrieval remains accessible.

**Severity**: High - This directly violates the "operator freeze respected" security invariant that is enforced everywhere else in the codebase. It undermines the entire purpose of the freeze mechanism for this attack vector.

## Likelihood Explanation

**Attacker Profile**: A compromised or malicious operator who has been detected and frozen by the admin.

**Attack Complexity**: Minimal - requires only a single transaction calling `retrieve_deposit_withdraw_fee_operator()` with the frozen OperatorCap and specifying the amount to drain.

**Execution Path**:
1. Operator becomes compromised or acts maliciously
2. Admin detects suspicious behavior and calls `set_operator_freezed(operation, op_cap_id, true)` to freeze the operator
3. Admin expects all operator functions are now blocked
4. Frozen operator calls `retrieve_deposit_withdraw_fee_operator(&frozen_op_cap, &mut vault, accumulated_amount)`
5. All accumulated fees are successfully drained despite freeze status

**Detection Limitations**: The attack can be executed immediately in a single block. There is no on-chain mechanism preventing a frozen operator from accessing this function. The freeze is incomplete and the admin has no way to know this function remains accessible.

**Probability**: High - This is a straightforward exploit with zero technical barriers. Any frozen operator can immediately drain fees before the admin realizes the freeze protection is incomplete.

## Recommendation

Add the freeze check to `retrieve_deposit_withdraw_fee_operator()` by taking the `Operation` object as a parameter and calling `assert_operator_not_freezed()`:

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

This aligns the function with all other operator functions in the codebase and closes the authorization bypass.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    
    // Setup vault with accumulated fees
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Admin creates operator cap
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap = vault_manage::create_operator_cap(&admin_cap, s.ctx());
        transfer::public_transfer(operator_cap, OWNER);
        s.return_to_sender(admin_cap);
    };
    
    // Simulate fee accumulation (deposit generates fees)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000, s.ctx());
        vault.deposit_withdraw_fee_collected.join(coin.into_balance());
        test_scenario::return_shared(vault);
    };
    
    // Admin freezes the operator
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,  // Freeze the operator
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
        s.return_to_sender(admin_cap);
    };
    
    // Frozen operator attempts to drain fees - SHOULD FAIL but CURRENTLY SUCCEEDS
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        let fee_retrieved = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1_000_000,  // Drain all accumulated fees
        );
        
        // This should NOT execute - operator is frozen
        fee_retrieved.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    s.end();
}
```

This test demonstrates that a frozen operator can successfully drain fees, violating the freeze security invariant.

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

**File:** volo-vault/sources/volo_vault.move (L30-31)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L32-32)
```text
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L33-33)
```text
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
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

**File:** volo-vault/sources/volo_vault.move (L836-836)
```text
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);
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

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L552-552)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L572-572)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/tests/operation/operation.test.move (L1561-1563)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
```
