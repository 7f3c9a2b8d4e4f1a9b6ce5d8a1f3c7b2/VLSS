### Title
Frozen Operators Can Drain Protocol Fees via Missing Freeze Check

### Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows any operator with an `OperatorCap` to withdraw accumulated protocol fees without checking if the operator is frozen. This bypasses the operator freeze mechanism, allowing malicious or compromised operators to drain all collected deposit/withdrawal fees even after being frozen by the admin.

### Finding Description

The vulnerability exists in the `retrieve_deposit_withdraw_fee_operator()` function [1](#0-0) 

The function only requires an `OperatorCap` and directly calls the internal `retrieve_deposit_withdraw_fee()` function without any freeze check. In contrast, the underlying function only validates vault version and normal status [2](#0-1) 

The protocol implements an operator freeze mechanism where admins can freeze operators via the `Operation` object's `freezed_operators` table [3](#0-2)  with the freeze check enforced by `assert_operator_not_freezed()` [4](#0-3) 

All other operator functions correctly implement this check by requiring the `Operation` object as a parameter and calling `vault::assert_operator_not_freezed(operation, cap)`. Examples include `start_op_with_bag()` [5](#0-4) , `execute_withdraw()` [6](#0-5) , and `batch_execute_deposit()` [7](#0-6) 

The root cause is that `retrieve_deposit_withdraw_fee_operator()` does not take the `Operation` object as a parameter, making it impossible to verify the operator's freeze status.

### Impact Explanation

A frozen operator can drain 100% of accumulated protocol fees stored in `deposit_withdraw_fee_collected`. These fees represent a percentage of all user deposits and withdrawals (default 0.1% each, max 5% each) [8](#0-7) 

The fees are collected during deposit and withdrawal execution [9](#0-8)  and represent protocol revenue intended for the treasury or protocol stakeholders.

This directly violates the critical invariant that "operator freeze respected" must hold at all times, and allows complete bypass of the authorization system designed to protect protocol funds from compromised or malicious operators.

### Likelihood Explanation

**Reachable Entry Point**: The function is a public entry point callable by any operator with an `OperatorCap` [1](#0-0) 

**Feasible Preconditions**: 
- Operator has a legitimately issued `OperatorCap` (created by admin)
- Operator becomes compromised or malicious
- Admin freezes the operator to prevent further operations
- Vault contains accumulated fees in normal status

**Execution Practicality**: Single transaction call with no complex preconditions or state manipulation required.

**Economic Rationality**: Zero cost attack with direct financial gain equal to all accumulated fees. The admin's freeze action provides clear signal that the operator should no longer have access to protocol funds, making this a realistic scenario.

### Recommendation

Modify `retrieve_deposit_withdraw_fee_operator()` to require the `Operation` object and enforce the freeze check:

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

Add test case verifying that frozen operators cannot retrieve fees, similar to the existing freeze test [10](#0-9) 

### Proof of Concept

**Initial State**:
1. Admin creates `OperatorCap` for operator
2. Users deposit/withdraw, accumulating 1000 SUI in `deposit_withdraw_fee_collected`
3. Admin detects operator compromise and freezes operator via `set_operator_freezed()`
4. Vault status is NORMAL

**Attack Steps**:
1. Frozen operator calls `vault_manage::retrieve_deposit_withdraw_fee_operator(&operator_cap, &mut vault, 1000_000_000_000)`
2. Function executes without freeze check
3. Returns `Balance<SUI>` of 1000 SUI to frozen operator

**Expected Result**: Transaction aborts with `ERR_OPERATOR_FREEZED` (5_015)

**Actual Result**: Transaction succeeds, operator receives all fees despite being frozen

**Success Condition**: Frozen operator's balance increases by full fee amount, protocol loses all accumulated fees

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

**File:** volo-vault/sources/volo_vault.move (L27-33)
```text
// For rates, 1 = 10_000, 1bp = 1
const RATE_SCALING: u64 = 10_000;

const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

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

**File:** volo-vault/sources/operation.move (L94-105)
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

**File:** volo-vault/sources/operation.move (L449-460)
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
