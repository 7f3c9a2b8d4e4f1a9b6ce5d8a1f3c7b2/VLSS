# Audit Report

## Title
Frozen Operators Can Bypass Security Controls to Retrieve Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function in `manage.move` does not verify if an operator is frozen before allowing fee retrieval. This allows frozen operators to extract accumulated deposit and withdrawal fees from the vault, completely bypassing the operator freeze mechanism designed to restrict compromised or malicious operators.

## Finding Description

The Volo vault protocol implements an operator freeze mechanism as a critical security control. When administrators detect malicious behavior or key compromise, they can freeze an operator through the `Operation` shared object that maintains a `freezed_operators` table. [1](#0-0) 

The freeze check is enforced via `assert_operator_not_freezed()`, which verifies operator status and aborts with `ERR_OPERATOR_FREEZED` if frozen. [2](#0-1) 

All operator functions in the protocol correctly implement this security check by accepting the `Operation` parameter and calling the assertion. For example, `start_op_with_bag()` checks freeze status, [3](#0-2)  `execute_deposit()` checks freeze status, [4](#0-3)  and `execute_withdraw()` checks freeze status. [5](#0-4) 

However, `retrieve_deposit_withdraw_fee_operator()` only accepts `OperatorCap` and `Vault` parameters, without the `Operation` object. [6](#0-5)  This makes it impossible to perform the freeze check, creating an authorization bypass where frozen operators can still extract fees.

The function directly calls the internal vault function that extracts fees from the `deposit_withdraw_fee_collected` balance. [7](#0-6)  These fees accumulate from user deposits [8](#0-7)  and withdrawals during normal vault operations.

## Impact Explanation

When administrators freeze an operator (typically due to detected malicious behavior, key compromise, or security incidents), the expectation is that the operator loses all vault access immediately. The freeze mechanism is implemented through `set_operator_freezed()`. [9](#0-8) 

However, a frozen operator retains the ability to extract all accumulated deposit and withdrawal fees. This completely undermines the freeze mechanism's purpose as a security control, creating the following concrete impacts:

- **Direct fund loss**: Frozen operators can drain accumulated fees (potentially significant amounts depending on vault activity)
- **Authorization bypass**: The admin's security response (freezing the operator) is ineffective for protecting fee assets
- **Security invariant violation**: Breaks the critical guarantee that frozen operators have no vault access
- **Vulnerability window**: Creates exposure between detecting malicious behavior and fully securing vault assets

The affected parties include vault users whose deposit/withdrawal fees are extracted by frozen operators, and protocol administrators who rely on freeze as an emergency security measure.

## Likelihood Explanation

**Attacker Capabilities**: An operator who has been frozen still possesses their `OperatorCap` object, which is a capability-based token that cannot be revoked except through transfer or destruction.

**Attack Complexity**: Minimal - requires only a single function call:
1. Operator is frozen by admin via `set_operator_freezed()`
2. Frozen operator calls `retrieve_deposit_withdraw_fee_operator(&operator_cap, &mut vault, amount)`
3. Fees are successfully extracted despite frozen status

**Feasibility Conditions**:
- Operator has their `OperatorCap` (always true until transfer/destruction)
- Vault has accumulated fees from user deposits/withdrawals (normal operation)
- No additional preconditions or complex state setup required

**Detection Constraints**:
- The transaction is valid and will succeed under normal conditions
- No error is thrown or event indicating security policy violation
- Admin may not detect the fee extraction until monitoring fee balances

**Probability**: High - in any scenario where an operator needs to be frozen (the exact situation where this security control matters most), they can still extract fees before or after being frozen.

## Recommendation

Add the `Operation` parameter to `retrieve_deposit_withdraw_fee_operator()` and call the freeze check before allowing fee retrieval:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This aligns the function signature and security checks with all other operator functions in the protocol.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    
    // Setup vault and operator
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Accumulate fees through deposits
    s.next_tx(USER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000, s.ctx());
        // ... execute deposit to accumulate fees ...
        test_scenario::return_shared(vault);
    };
    
    // Admin freezes operator
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        
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
    
    // Frozen operator can still retrieve fees (THIS SHOULD FAIL BUT DOESN'T)
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        let fee = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1000,
        );
        
        fee.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
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
