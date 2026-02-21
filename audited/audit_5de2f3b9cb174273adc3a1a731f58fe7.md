# Audit Report

## Title
Incomplete OperatorCap Revocation: Missing Freeze Check Allows Compromised Operators to Drain Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function does not verify operator freeze status, allowing frozen operators to continue extracting accumulated deposit and withdraw fees even after being marked as frozen by the admin.

## Finding Description

The Volo vault protocol implements a freeze mechanism to revoke operator privileges when an operator is compromised. [1](#0-0) 

The freeze mechanism stores operator freeze status in a shared `Operation` object and provides `assert_operator_not_freezed()` to enforce this security control. [2](#0-1) 

This freeze check is consistently enforced across ALL vault operations, including `start_op_with_bag`, `end_op_with_bag`, `execute_deposit`, `execute_withdraw`, and all reward manager functions. [3](#0-2) [4](#0-3) [5](#0-4) 

However, the `retrieve_deposit_withdraw_fee_operator()` function in manage.move completely bypasses this security control. [6](#0-5) 

The function directly calls the internal `retrieve_deposit_withdraw_fee()` which extracts fees from the `deposit_withdraw_fee_collected` balance without any freeze status verification. [7](#0-6) 

The `OperatorCap` struct has `key, store` abilities but no `drop` ability, meaning it cannot be destroyed. The freeze mechanism is the ONLY way to revoke operator privileges. [8](#0-7) 

## Impact Explanation

**Direct Fund Theft**: A frozen operator can drain all accumulated deposit and withdraw fees through this bypass. Fees accumulate at 0.1% to 5% per transaction. [9](#0-8) 

**Security Control Failure**: The freeze mechanism exists specifically as a security response to operator compromise, as evidenced by dedicated test cases. [10](#0-9) 

The incomplete implementation undermines the entire security control, leaving a critical authorization gap. Without the ability to destroy `OperatorCap` objects, this bypass becomes a permanent vulnerability.

**Affected Parties**: All vault depositors lose fee revenue; the protocol loses sustainability funds; admins operate under false security assumptions.

## Likelihood Explanation

**Attack Prerequisites**: Requires only possession of an `OperatorCap` through key compromise or malicious insider.

**Exploit Simplicity**: Single direct function call with no complex state manipulation, timing requirements, or vault status dependencies.

**Threat Model Alignment**: The protocol explicitly considers operator compromise as part of its threat model, evidenced by implementing the freeze mechanism and testing frozen operator scenarios. This is not a speculative threat—it's a scenario the protocol designers anticipated and attempted to mitigate.

**Detection Challenges**: Events are emitted but don't indicate frozen operator activity, making post-compromise detection difficult.

## Recommendation

Add the freeze check to `retrieve_deposit_withdraw_fee_operator()`:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    _: &OperatorCap,
    operation: &Operation,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

The function signature must be updated to accept the `&Operation` parameter and properly bind the `OperatorCap` reference to validate freeze status.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    // Setup vault and operator
    let mut s = test_scenario::begin(OWNER);
    init_vault::init_vault(&mut s);
    
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
            true
        );
        
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
        test_scenario::return_shared(operation);
    };
    
    // Frozen operator attempts fee extraction - should fail but doesn't
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI>>();
        
        let _fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            1000
        ); // Currently succeeds, should abort with ERR_OPERATOR_FREEZED
        
        _fees.destroy_for_testing();
        s.return_to_sender(operator_cap);
        test_scenario::return_shared(vault);
    };
    
    s.end();
}
```

---

**Notes**: This is a mis-scoped privilege vulnerability where the freeze mechanism—designed as a security control for operator compromise—fails to revoke fee extraction privileges. The protocol's own test suite confirms that frozen operators should be unable to perform operations, making this an inconsistent implementation of an intentional security feature rather than a theoretical concern.

### Citations

**File:** volo-vault/sources/volo_vault.move (L30-33)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L84-92)
```text
public struct OperatorCap has key, store {
    id: UID,
}

// Operation operation
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

**File:** volo-vault/sources/operation.move (L209-219)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
```

**File:** volo-vault/sources/operation.move (L381-392)
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

**File:** volo-vault/tests/operation/operation.test.move (L1561-1597)
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
```
