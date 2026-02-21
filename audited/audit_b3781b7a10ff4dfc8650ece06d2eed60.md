# Audit Report

## Title
Frozen Operators Can Drain Protocol Fees via `retrieve_deposit_withdraw_fee_operator()`

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows frozen operators to drain accumulated deposit and withdrawal fees from the vault, completely bypassing the operator freeze security mechanism that is properly enforced in all other operator functions.

## Finding Description

The Volo Protocol implements an operator freeze mechanism as a critical security control. The `Operation` shared object maintains a `freezed_operators` table to track frozen operators. [1](#0-0) 

The protocol provides `assert_operator_not_freezed()` which checks if an operator's capability ID is in the frozen list and aborts with `ERR_OPERATOR_FREEZED` if frozen. [2](#0-1) 

**All operator functions consistently enforce this check:**
- `execute_deposit` checks freeze status at line 391 [3](#0-2) 
- `execute_withdraw` checks freeze status at line 460 [4](#0-3) 
- `start_op_with_bag` checks freeze status at line 105 [5](#0-4) 
- `set_reward_rate` checks freeze status at line 425 [6](#0-5) 

The test suite explicitly validates that frozen operators cannot perform operations with expected failure on `ERR_OPERATOR_FREEZED`. [7](#0-6) 

**However, `retrieve_deposit_withdraw_fee_operator()` breaks this security invariant.** This function accepts an `OperatorCap` but does NOT take the `Operation` parameter and does NOT call any freeze check before directly retrieving fees. [8](#0-7) 

The underlying fee retrieval function only checks version and vault status, then directly splits from the `deposit_withdraw_fee_collected` balance. [9](#0-8) 

The `deposit_withdraw_fee_collected` field holds protocol revenue collected from user deposits and withdrawals. [10](#0-9)  Deposit fees are collected during execution [11](#0-10)  and withdrawal fees are similarly collected. [12](#0-11) 

**Attack Scenario:**
1. Admin detects suspicious operator behavior and freezes the operator via `set_operator_freezed()`
2. The frozen operator retains their `OperatorCap` object (it's not destroyed on freeze)
3. Frozen operator calls `retrieve_deposit_withdraw_fee_operator(cap, vault, amount)`
4. Function succeeds and drains accumulated protocol fees
5. Admin's security control is completely bypassed

## Impact Explanation

**Direct Financial Loss:** The frozen operator can drain all accumulated protocol fees from `deposit_withdraw_fee_collected`. These fees represent revenue collected from every user deposit and withdrawal at the configured rate (default 0.1% as shown in tests). [13](#0-12) 

**Security Control Bypass:** The operator freeze mechanism exists specifically to handle compromised or malicious operators. When an operator is frozen, the protocol admin expects that operator to have ZERO operational capabilities. This vulnerability completely negates that security guarantee for fee extraction.

**Severity - HIGH:**
1. Complete bypass of critical security mechanism
2. Direct loss of protocol funds (protocol revenue)
3. Trivial exploitation - single function call with no preconditions
4. High exploitation probability - operators are frozen because they're untrusted

## Likelihood Explanation

**Attacker Profile:** Any operator who has been frozen by the admin. Since operators are frozen due to detected suspicious behavior or suspected key compromise, these are exactly the actors most likely to attempt malicious extraction.

**Technical Feasibility:** The attack requires only:
- A frozen `OperatorCap` (retained by the operator, not destroyed on freeze)
- Reference to the shared `Vault` object
- The amount to withdraw (up to full balance of `deposit_withdraw_fee_collected`)

**Attack Complexity:** Minimal - single transaction calling the public function with valid parameters.

**Probability - HIGH:** The freeze mechanism is invoked in emergency situations when operators are no longer trusted. These are precisely the scenarios where rational malicious actors would attempt to extract any remaining value they can access.

## Recommendation

Add the `operation: &Operation` parameter to `retrieve_deposit_withdraw_fee_operator()` and check freeze status before allowing fee retrieval:

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

This matches the pattern used consistently across all other operator functions in the codebase.

## Proof of Concept

A test demonstrating the vulnerability can be created by:
1. Creating a vault with an operator
2. Accumulating fees through deposit operations
3. Freezing the operator via `set_operator_freezed()`
4. Attempting other operator operations (should fail with `ERR_OPERATOR_FREEZED`)
5. Calling `retrieve_deposit_withdraw_fee_operator()` (succeeds and drains fees)

The test would verify that while frozen operators are blocked from operations like `execute_deposit` and `start_op_with_bag`, they can still extract protocol fees through the vulnerable function.

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

**File:** volo-vault/sources/volo_vault.move (L1040-1042)
```text
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

**File:** volo-vault/sources/operation.move (L94-107)
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

**File:** volo-vault/sources/operation.move (L449-477)
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
```

**File:** volo-vault/sources/reward_manager.move (L415-428)
```text
public fun set_reward_rate<PrincipalCoinType, RewardCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    rate: u256,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);
    vault::assert_operator_not_freezed(operation, cap);

    // assert!(rate >= DECIMALS, ERR_RATE_DECIMALS_TOO_SMALL);
    assert!(rate < std::u256::max_value!() / 86_400_000, ERR_INVALID_REWARD_RATE);
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

**File:** volo-vault/tests/operation/manage.test.move (L361-368)
```text
    // Check deposit fee (0.001 SUI)
    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let deposit_fee = vault.deposit_withdraw_fee_collected();
        assert!(deposit_fee == 10_000_000);
        test_scenario::return_shared(vault);
    };
```
