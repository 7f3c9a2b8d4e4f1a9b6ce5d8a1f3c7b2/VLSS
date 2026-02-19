### Title
Frozen Operator Capabilities Retain Fee Withdrawal Access

### Summary
The `vault_manage::retrieve_deposit_withdraw_fee_operator()` function validates operator authorization solely through OperatorCap ownership without checking the operator's frozen status. This creates a two-tier permission system where frozen operators lose access to vault operations but retain the ability to withdraw accumulated deposit/withdraw fees, breaking the intended access control invariant that frozen operators should have all privileges revoked.

### Finding Description
The Volo vault system implements operator freezing through `vault::set_operator_freezed()` [1](#0-0)  which tracks frozen operators in the `Operation.freezed_operators` table. Most operator functions properly validate freeze status via `vault::assert_operator_not_freezed(operation, cap)` [2](#0-1)  which checks both capability existence and freeze status.

All functions in `operation.move` consistently call this check [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) , as do all functions in `reward_manager.move` [7](#0-6) [8](#0-7) [9](#0-8) .

However, `vault_manage::retrieve_deposit_withdraw_fee_operator()` [10](#0-9)  only validates OperatorCap existence through the function signature requirement, without passing the `Operation` object or calling `assert_operator_not_freezed()`. The function directly delegates to the package-level `vault::retrieve_deposit_withdraw_fee()` [11](#0-10)  which performs no freeze check, allowing frozen operators to withdraw fees from `vault.deposit_withdraw_fee_collected`.

### Impact Explanation
A frozen operator retains the ability to drain all accumulated deposit and withdraw fees from the vault even after administrative freeze action. This undermines the security model where operator freezing is intended to immediately revoke all privileges. Fees represent real economic value extracted from user deposits/withdrawals [12](#0-11) , and unauthorized fee extraction constitutes fund misappropriation. The vulnerability creates uncertainty about which historical operator caps retain partial access, making it difficult to audit or revoke access comprehensively.

### Likelihood Explanation
The function is declared as `public fun` making it callable from transactions by any holder of an OperatorCap. The attack path is straightforward: (1) Admin creates OperatorCap via `create_operator_cap()` [13](#0-12) , (2) Admin later freezes the operator via `set_operator_freezed()` [14](#0-13)  due to malicious behavior or key compromise, (3) Frozen operator calls `retrieve_deposit_withdraw_fee_operator()` successfully despite freeze status. Test infrastructure confirms both fee retrieval [15](#0-14)  and freeze mechanisms [16](#0-15)  are functional and compatible with normal transaction flows.

### Recommendation
Modify `vault_manage::retrieve_deposit_withdraw_fee_operator()` to accept `&Operation` as an additional parameter and call `vault::assert_operator_not_freezed(operation, cap)` before delegating to the vault function:

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

This ensures consistent freeze validation across all operator functions, maintaining the security invariant that frozen operators have zero protocol access.

### Proof of Concept
1. Deploy vault with AdminCap and create OperatorCap via `vault_manage::create_operator_cap()`
2. Users deposit into vault, accumulating fees in `vault.deposit_withdraw_fee_collected` balance
3. Admin detects operator compromise and calls `vault_manage::set_operator_freezed(&admin_cap, &mut operation, operator_cap_id, true)`
4. Verify operator is frozen: `vault::operator_freezed(&operation, operator_cap_id)` returns `true`
5. Verify frozen operator cannot execute normal operations (e.g., `operation::execute_deposit()` fails with `ERR_OPERATOR_FREEZED` [17](#0-16) )
6. Frozen operator calls `vault_manage::retrieve_deposit_withdraw_fee_operator(&operator_cap, &mut vault, fee_amount)` - **succeeds despite freeze**
7. Frozen operator extracts `fee_amount` from vault's fee balance, bypassing freeze restrictions

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

**File:** volo-vault/sources/operation.move (L218-218)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L306-306)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L391-391)
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

**File:** volo-vault/sources/reward_manager.move (L349-349)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/manage.move (L84-86)
```text
public fun create_operator_cap(_: &AdminCap, ctx: &mut TxContext): OperatorCap {
    vault::create_operator_cap(ctx)
}
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

**File:** volo-vault/tests/operation/manage.test.move (L796-801)
```text
        let fee_retrieved = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            5_000_000,
        );
        assert!(fee_retrieved.value() == 5_000_000);
```

**File:** volo-vault/tests/operation/manage.test.move (L888-895)
```text
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );

        assert!(vault::operator_freezed(&operation, operator_cap.operator_id()));
```

**File:** volo-vault/tests/operation/operation.test.move (L1562-1562)
```text
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
```
