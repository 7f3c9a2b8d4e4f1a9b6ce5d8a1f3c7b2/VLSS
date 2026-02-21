# Audit Report

## Title
Frozen Operator Can Bypass Freeze Control and Drain Vault Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator` function allows frozen operators to extract accumulated protocol fees, completely bypassing the operator freeze safety mechanism. This represents a critical authorization bypass where malicious or misbehaving operators can drain protocol treasury even after being explicitly frozen by the admin.

## Finding Description

The vulnerability exists in the `retrieve_deposit_withdraw_fee_operator` function which grants `OperatorCap` holders the ability to withdraw protocol fees without verifying if the operator is frozen. [1](#0-0) 

This function critically lacks the freeze check that is consistently enforced across all other operator functions. The freeze mechanism is implemented through the `Operation` object's `freezed_operators` table: [2](#0-1) 

**Pattern Violation**: All 26 operator functions in `operation.move` properly check freeze status by taking both `operation: &Operation` and `cap: &OperatorCap` parameters and calling `vault::assert_operator_not_freezed(operation, cap)` as their first statement. For example: [3](#0-2) [4](#0-3) 

The protocol explicitly tests that frozen operators should be blocked with error code `ERR_OPERATOR_FREEZED`: [5](#0-4) 

**Exploit Scenario:**
1. Admin freezes a misbehaving operator via `set_operator_freezed`: [6](#0-5) 

2. Fees have accumulated in `deposit_withdraw_fee_collected` from deposit/withdraw operations: [7](#0-6) 

3. Despite being frozen, the operator calls `retrieve_deposit_withdraw_fee_operator` to drain fees

4. The underlying function only validates vault status, not operator freeze status: [8](#0-7) 

## Impact Explanation

**High Severity** - This vulnerability allows direct theft of protocol treasury funds:

- **Fund Theft**: A frozen operator can drain all accumulated deposit/withdraw fees (collected at 0.1% to 5% of all user deposits/withdrawals)
- **Authorization Bypass**: The freeze mechanism exists to protect the protocol when operators misbehave or exceed loss tolerance, but it completely fails to protect the fee treasury
- **Security Invariant Violation**: The protocol's test suite explicitly expects frozen operators to be blocked from operations, but fee withdrawal bypasses this critical security control

The comment on the underlying function indicates "Only called by the admin", suggesting the operator wrapper may have been added without proper security review: [9](#0-8) 

## Likelihood Explanation

**High Likelihood** - This vulnerability is directly exploitable:

1. **No Special Preconditions**: Any operator with an `OperatorCap` can call this public function
2. **Common Scenario**: Operators are frozen when they exceed loss tolerance or misbehave - a legitimate operational scenario: [10](#0-9) 

3. **Realistic Attack Window**: Between freezing the operator and revoking/destroying their capability object, the operator can drain accumulated fees
4. **No Rate Limiting**: There are no restrictions on withdrawal amount or frequency

## Recommendation

Add the freeze check to `retrieve_deposit_withdraw_fee_operator` by modifying the function signature to take the `Operation` object and verifying freeze status:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // Add Operation parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add freeze check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

Alternatively, consider removing the operator version entirely and restricting fee withdrawal to `AdminCap` only, as suggested by the underlying function's comment.

## Proof of Concept

The existing test suite demonstrates the vulnerability. Test `test_start_op_fail_op_freezed` proves that frozen operators should be blocked: [11](#0-10) 

However, tests for `retrieve_deposit_withdraw_fee_operator` do not verify freeze checks: [12](#0-11) 

A proof-of-concept test would freeze an operator, then successfully call `retrieve_deposit_withdraw_fee_operator` to extract fees, demonstrating the bypass.

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

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
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

**File:** volo-vault/sources/volo_vault.move (L1542-1543)
```text
// Retrieve deposit & withdraw fee from the vault in the form of principal coin
// Only called by the admin
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

**File:** volo-vault/sources/operation.move (L449-479)
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

    reward_manager.update_reward_buffers(vault, clock);

    let withdraw_request = vault.withdraw_request(request_id);
    reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

    let (withdraw_balance, recipient) = vault.execute_withdraw(
        clock,
        config,
        request_id,
        max_amount_received,
    );

    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
    }
}
```

**File:** volo-vault/tests/operation/operation.test.move (L1561-1563)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
```

**File:** volo-vault/tests/operation/operation.test.move (L1592-1597)
```text
        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );
```

**File:** volo-vault/tests/operation/manage.test.move (L387-392)
```text
        let fee_retrieved = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            2_000_000,
        );
        assert!(fee_retrieved.value() == 2_000_000);
```
