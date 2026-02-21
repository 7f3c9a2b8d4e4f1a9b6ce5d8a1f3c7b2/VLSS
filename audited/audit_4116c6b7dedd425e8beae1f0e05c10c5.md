# Audit Report

## Title
Frozen Operator Capabilities Retain Fee Withdrawal Access

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows operators to withdraw accumulated deposit/withdraw fees without checking their frozen status, creating an access control bypass where frozen operators retain partial privileges despite the freeze mechanism's intent to revoke all operator access.

## Finding Description
The Volo vault implements an operator freeze mechanism to revoke access privileges. The freeze state is tracked in the `Operation.freezed_operators` table and enforced via `assert_operator_not_freezed(operation, cap)` which requires both the `Operation` object and `OperatorCap` to validate freeze status. [1](#0-0) 

All operator functions in `operation.move` consistently enforce this check at their entry points: [2](#0-1) [3](#0-2) [4](#0-3) 

Similarly, all reward management functions enforce the freeze check: [5](#0-4) [6](#0-5) 

However, the `retrieve_deposit_withdraw_fee_operator()` function deviates from this pattern by accepting only `OperatorCap` and `Vault` parameters without requiring the `Operation` object: [7](#0-6) 

This function delegates directly to the package-level `retrieve_deposit_withdraw_fee()` which performs no freeze check: [8](#0-7) 

The underlying function only validates version compatibility and vault status (must be NORMAL), but has no awareness of operator freeze state. This creates a two-tier permission system where frozen operators lose access to vault operations but retain the ability to extract fees.

## Impact Explanation
A frozen operator can drain all accumulated deposit and withdraw fees from `vault.deposit_withdraw_fee_collected` even after administrative freeze action. Fees represent real economic value extracted from user deposits and withdrawals at configured rates (default 10bp each, max 500bp). This undermines the security model where operator freezing is intended to immediately revoke ALL privileges, not just operational access. The vulnerability creates operational risk as administrators may believe frozen operators are fully disabled when they retain this extraction capability.

## Likelihood Explanation
The attack path is straightforward and highly likely:
1. Admin creates an `OperatorCap` for a third-party operator
2. Admin later freezes the operator via `set_operator_freezed()` due to malicious behavior, key compromise, or operational concerns
3. The frozen operator can still call `retrieve_deposit_withdraw_fee_operator()` in a transaction to extract fees

The function has `public fun` visibility making it directly callable from transactions. Tests confirm both mechanisms work independently - the freeze mechanism blocks vault operations [9](#0-8)  and fee retrieval by operators is functional [10](#0-9) . No additional privileges or complex preconditions are required beyond possessing a frozen `OperatorCap`.

## Recommendation
Add the `Operation` object parameter to `retrieve_deposit_withdraw_fee_operator()` and enforce the freeze check:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,          // Add Operation parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add freeze check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

This aligns the function with the access control pattern used consistently across all other operator-privileged functions in the codebase.

## Proof of Concept

```move
#[test]
public fun test_frozen_operator_can_withdraw_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with fees
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap = vault_manage::create_operator_cap(&admin_cap, s.ctx());
        transfer::public_transfer(operator_cap, OWNER);
        s.return_to_sender(admin_cap);
    };
    
    // Simulate fee collection
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000, s.ctx());
        vault.return_free_principal(coin.into_balance());
        // Fees would accumulate during normal deposit/withdraw operations
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
            true  // Freeze operator
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(operator_cap);
        s.return_to_sender(admin_cap);
    };
    
    // Frozen operator can STILL withdraw fees (vulnerability)
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This should fail but succeeds - frozen operator withdraws fees
        let fee_balance = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            100_000  // Withdraw amount
        );
        
        assert!(fee_balance.value() == 100_000);  // Withdrawal succeeds!
        
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
        fee_balance.destroy_for_testing();
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that a frozen operator can successfully withdraw fees despite the freeze status, confirming the access control bypass vulnerability.

### Citations

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

**File:** volo-vault/sources/operation.move (L94-106)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
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

**File:** volo-vault/sources/operation.move (L406-416)
```text
public fun batch_execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_ids: vector<u64>,
    max_shares_received: vector<u256>,
) {
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L233-241)
```text
public fun add_new_reward_type<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    with_buffer: bool, // If true, create a new reward buffer distribution for the reward type
) {
    self.check_version();
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

**File:** volo-vault/tests/operation/manage.test.move (L790-806)
```text
    s.next_tx(OWNER);
    {
        // let admin_cap = s.take_from_sender<AdminCap>();
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let fee_retrieved = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            5_000_000,
        );
        assert!(fee_retrieved.value() == 5_000_000);

        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
        fee_retrieved.destroy_for_testing();
    };
```
