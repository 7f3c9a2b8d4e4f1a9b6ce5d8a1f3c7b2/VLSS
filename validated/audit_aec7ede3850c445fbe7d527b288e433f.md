# Audit Report

## Title
Frozen Operator Can Bypass Freeze Mechanism to Drain Collected Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator` function lacks the operator freeze check that is universally enforced across all other operator functions, allowing frozen operators to drain accumulated deposit/withdraw fees and completely bypassing the protocol's containment mechanism for compromised operators.

## Finding Description

The Volo vault protocol implements an operator freeze mechanism where administrators can freeze compromised operator capabilities to prevent further unauthorized actions. However, the `retrieve_deposit_withdraw_fee_operator` function contains a critical architectural flaw that renders this security control ineffective for fee collection.

The vulnerable function only requires an `OperatorCap` but does NOT accept an `Operation` parameter [1](#0-0) , making it architecturally impossible to call the freeze check function which requires both parameters [2](#0-1) .

The underlying implementation only performs version and vault status checks, with no freeze verification [3](#0-2) .

In stark contrast, every other operator function in the protocol includes the freeze check as the first security validation. For example, `execute_withdraw` [4](#0-3) , `start_op_with_bag` [5](#0-4) , and reward management functions [6](#0-5)  all enforce this critical check.

The freeze mechanism itself is properly implemented [7](#0-6)  and tested to block frozen operators from performing operations [8](#0-7) , confirming this is a specific oversight rather than a systemic design issue.

## Impact Explanation

**Financial Impact:**
A frozen operator retains the ability to drain 100% of the accumulated deposit/withdraw fees stored in the `deposit_withdraw_fee_collected` balance. These fees represent actual protocol revenue collected on every user deposit and withdrawal operation, which can accumulate to substantial amounts over time.

**Security Control Bypass:**
The operator freeze mechanism is a critical containment control explicitly designed to limit damage from compromised operators. This vulnerability renders the freeze mechanism completely ineffective for financial containment, as the frozen operator can immediately drain all collected fees before the admin can retrieve them, undermining the entire purpose of the freeze control.

**Severity Assessment: Medium**
- Requires operator compromise as a precondition (not exploitable by external attackers)
- Impact is limited to the fee collection balance, not total vault principal assets
- However, it completely bypasses a documented security control with direct and immediate fund loss

## Likelihood Explanation

**Attack Feasibility:**
1. An operator's private key is compromised or the operator acts maliciously
2. Administrator detects suspicious activity and freezes the operator via `set_operator_freezed`
3. The frozen operator is successfully blocked from all standard operations (deposits, withdrawals, vault operations, asset management, value updates)
4. However, the frozen operator can still call `retrieve_deposit_withdraw_fee_operator` without any restrictions
5. The operator drains all accumulated fees before the admin can retrieve them

**Technical Prerequisites:**
- Operator still possesses the `OperatorCap` object (freeze is table-based, not capability revocation)
- Vault must be in NORMAL status (standard operational state)
- Sufficient balance exists in `deposit_withdraw_fee_collected`

**Detection:**
While the attack emits a `DepositWithdrawFeeRetrieved` event, the funds are already gone by the time the event is detected, making the freeze mechanism ineffective as a containment strategy.

This represents a realistic and reproducible attack path with no technical barriers beyond the initial operator compromise, which the freeze mechanism is specifically designed to handle.

## Recommendation

Modify the `retrieve_deposit_withdraw_fee_operator` function signature to include the `Operation` parameter and add the freeze check:

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

This brings the function in line with all other operator functions and ensures the freeze mechanism works consistently across the entire protocol.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and accumulate some fees
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Accumulate fees through deposits
    s.next_tx(USER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        vault.user_deposit(coin.into_balance());
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
            true,
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
    };
    
    // Frozen operator attempts to retrieve fees - SHOULD FAIL but currently succeeds
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        let fee_balance = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1_000_000,
        );
        
        fee_balance.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

**Notes:**
The current implementation allows this test to pass (fees are retrieved successfully), but it SHOULD fail with `ERR_OPERATOR_FREEZED` after the recommended fix is applied, ensuring consistency with all other operator functions in the protocol.

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

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L349-349)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/tests/operation/operation.test.move (L1561-1675)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
public fun test_start_op_fail_op_freezed() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(
            0,
            navi_account_cap,
        );
        test_scenario::return_shared(vault);
    };

    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut operation = s.take_shared<Operation>();
        let operator_cap = s.take_from_sender<OperatorCap>();

        vault_manage::set_operator_freezed(
            &admin_cap,
            &mut operation,
            operator_cap.operator_id(),
            true,
        );

        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
    };

    // Set mock aggregator and price
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);

        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);

        test_scenario::return_shared(oracle_config);
    };

    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();

        vault.return_free_principal(coin.into_balance());

        vault::update_free_principal_value(&mut vault, &config, &clock);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let coin = coin::mint_for_testing<USDC_TEST_COIN>(100_000_000_000, s.ctx());
        // Add 100 USDC to the vault
        vault.add_new_coin_type_asset<SUI_TEST_COIN, USDC_TEST_COIN>();
        vault.return_coin_type_asset(coin.into_balance());

        let config = s.take_shared<OracleConfig>();
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        test_scenario::return_shared(config);
        test_scenario::return_shared(vault);
    };

    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();

        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];

        let (
            asset_bag,
            tx_bag,
            tx_bag_for_check_value_update,
            principal_balance,
            coin_type_asset_balance,
        ) = operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            defi_asset_ids,
            defi_asset_types,
            1_000_000_000,
            0,
            s.ctx(),
        );
```
