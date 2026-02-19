# Audit Report

## Title
Frozen Operators Can Drain Protocol Fees via Missing Freeze Check

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows frozen operators to withdraw accumulated protocol fees because it does not verify the operator's freeze status. This bypasses the operator freeze mechanism designed to revoke all permissions from compromised operators.

## Finding Description

The Volo vault implements an operator freeze mechanism to immediately revoke permissions from compromised or malicious operators. The admin can freeze any operator via the `Operation` object's `freezed_operators` table [1](#0-0) , with enforcement handled by `assert_operator_not_freezed()` [2](#0-1) .

All operator functions correctly implement this security check by requiring the `Operation` object as a parameter. For example:
- `start_op_with_bag()` checks freeze status [3](#0-2) 
- `batch_execute_deposit()` checks freeze status [4](#0-3) 
- `execute_withdraw()` checks freeze status [5](#0-4) 

However, `retrieve_deposit_withdraw_fee_operator()` does not take the `Operation` object as a parameter [6](#0-5) , making it impossible to verify freeze status. The underlying function only validates vault version and normal status [7](#0-6) , without any operator authorization checks.

This breaks the critical security guarantee that frozen operators have zero privileges, allowing them to bypass the freeze mechanism entirely for fee withdrawal operations.

## Impact Explanation

A frozen operator can drain 100% of accumulated protocol fees from `deposit_withdraw_fee_collected`. These fees represent protocol revenue collected during deposit execution [8](#0-7)  and withdrawal execution [9](#0-8) .

The impact includes:
- **Direct fund loss**: All accumulated fees can be stolen
- **Authorization system bypass**: The freeze mechanism is rendered ineffective
- **Security model violation**: Operators frozen for compromise can still access protocol funds

The protocol's test suite confirms that frozen operators should be unable to perform any operations [10](#0-9) , demonstrating this is an unintended privilege escalation.

## Likelihood Explanation

**High likelihood scenario:**
1. Admin creates legitimate `OperatorCap` for protocol operations
2. Operator's private key becomes compromised
3. Admin detects compromise and freezes the operator [11](#0-10) 
4. Attacker (with frozen operator cap) calls `retrieve_deposit_withdraw_fee_operator()` directly
5. Fees are successfully withdrawn despite operator being frozen

**Feasibility factors:**
- **Reachable entry point**: Public function with no access barriers beyond having an `OperatorCap`
- **Zero complexity**: Single transaction, no state manipulation required
- **Economic rationality**: Zero cost attack with direct financial gain
- **Realistic scenario**: Key compromise is a known threat model that the freeze mechanism is designed to address

## Recommendation

Add the `Operation` object as a parameter and enforce the freeze check:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // Add this parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add freeze check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This ensures consistency with all other operator functions that correctly implement the freeze check.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and create operator
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap = vault_manage::create_operator_cap(&admin_cap, s.ctx());
        transfer::public_transfer(operator_cap, OWNER);
        s.return_to_sender(admin_cap);
    };
    
    // Add fees to vault
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000, s.ctx());
        vault.return_free_principal(coin.into_balance().split(1_000_000));
        test_scenario::return_shared(vault);
    };
    
    // Freeze the operator
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
        s.return_to_sender(admin_cap);
    };
    
    // BUG: Frozen operator can still retrieve fees
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This should fail with ERR_OPERATOR_FREEZED but doesn't
        let fee = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1_000_000
        );
        
        fee.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test will currently **pass** (frozen operator successfully retrieves fees) but **should fail** with `ERR_OPERATOR_FREEZED`. After implementing the recommendation, the test will correctly abort when a frozen operator attempts fee withdrawal.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L830-836)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1039-1042)
```text
    // Protocol fee
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

**File:** volo-vault/sources/operation.move (L105-105)
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

**File:** volo-vault/tests/operation/operation.test.move (L1561-1563)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
```
