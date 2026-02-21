# Audit Report

## Title
Frozen Operators Can Drain Protocol Fees via Missing Freeze Check

## Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows frozen operators to withdraw accumulated protocol fees because it does not verify the operator's freeze status. This bypasses the operator freeze mechanism designed to revoke all permissions from compromised operators.

## Finding Description

The Volo vault implements an operator freeze mechanism to immediately revoke permissions from compromised or malicious operators. The freeze status is tracked in the shared `Operation` object's `freezed_operators` table [1](#0-0) , with enforcement handled by `assert_operator_not_freezed()` [2](#0-1) .

All operator functions in the protocol correctly implement this security check by requiring the `Operation` object as a parameter and calling the freeze verification. For example:
- `start_op_with_bag()` checks freeze status [3](#0-2) 
- `batch_execute_deposit()` checks freeze status [4](#0-3) 
- `execute_withdraw()` checks freeze status [5](#0-4) 

However, `retrieve_deposit_withdraw_fee_operator()` does not take the `Operation` object as a parameter [6](#0-5) , making it impossible to verify freeze status. The underlying `retrieve_deposit_withdraw_fee()` function only validates vault version and normal status [7](#0-6) , without any operator authorization checks.

This breaks the critical security guarantee that frozen operators have zero privileges, allowing them to bypass the freeze mechanism entirely for fee withdrawal operations.

## Impact Explanation

A frozen operator can drain 100% of accumulated protocol fees from the `deposit_withdraw_fee_collected` balance. These fees represent protocol revenue collected from deposit and withdraw operations as defined in the vault structure [8](#0-7) .

The impact includes:
- **Direct fund loss**: All accumulated fees can be stolen
- **Authorization system bypass**: The freeze mechanism is rendered ineffective  
- **Security model violation**: Operators frozen for compromise can still access protocol funds

The protocol's test suite explicitly confirms that frozen operators should be unable to perform any operations, with the test expecting an abort with `ERR_OPERATOR_FREEZED` [9](#0-8) , demonstrating this is an unintended privilege escalation.

## Likelihood Explanation

**High likelihood scenario:**
1. Admin creates legitimate `OperatorCap` for protocol operations
2. Operator's private key becomes compromised  
3. Admin detects compromise and freezes the operator using `set_operator_freezed()` [10](#0-9) 
4. Attacker (with frozen operator cap) calls `retrieve_deposit_withdraw_fee_operator()` directly
5. Fees are successfully withdrawn despite operator being frozen

**Feasibility factors:**
- **Reachable entry point**: Public function with no access barriers beyond having an `OperatorCap`
- **Zero complexity**: Single transaction, no state manipulation required  
- **Economic rationality**: Zero cost attack with direct financial gain
- **Realistic scenario**: Key compromise is a known threat model that the freeze mechanism is explicitly designed to address

## Recommendation

Add the `Operation` object as a parameter to `retrieve_deposit_withdraw_fee_operator()` and call `vault::assert_operator_not_freezed()` at the beginning of the function, consistent with all other operator functions:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // ADD THIS PARAMETER
    cap: &OperatorCap,      // EXISTING
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // ADD THIS CHECK
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and collect some fees
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        vault_manage::set_deposit_fee(&admin_cap, &mut vault, 100);
        test_scenario::return_shared(vault);
        s.return_to_sender(admin_cap);
    };
    
    // Execute deposit to collect fees
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        // ... execute deposit and collect 10_000_000 in fees
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
            true
        );
        
        test_scenario::return_shared(operation);
        s.return_to_sender(admin_cap);
        s.return_to_sender(operator_cap);
    };
    
    // BUG: Frozen operator can still retrieve fees
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This should fail but currently succeeds
        let fee_balance = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            10_000_000
        );
        
        fee_balance.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability represents a critical gap in the operator freeze security mechanism. While the freeze system correctly prevents frozen operators from performing vault operations, DeFi interactions, and deposit/withdrawal processing, it fails to prevent fee extraction. This creates a privilege escalation path where compromised operators retain the ability to steal accumulated protocol revenue even after being frozen, undermining the entire purpose of the freeze mechanism as an emergency response tool.

### Citations

**File:** volo-vault/sources/volo_vault.move (L88-92)
```text
// Operation operation
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L96-130)
```text
public struct Vault<phantom T> has key, store {
    id: UID,
    version: u64,
    // ---- Pool Info ---- //
    status: u8,
    total_shares: u256,
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
    // ---- Fee ---- //
    deposit_withdraw_fee_collected: Balance<T>,
    // ---- Principal Info ---- //
    free_principal: Balance<T>,
    claimable_principal: Balance<T>,
    // ---- Config ---- //
    deposit_fee_rate: u64,
    withdraw_fee_rate: u64,
    // ---- Assets ---- //
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
    // ---- Loss Tolerance ---- //
    cur_epoch: u64,
    cur_epoch_loss_base_usd_value: u256,
    cur_epoch_loss: u256,
    loss_tolerance: u256,
    // ---- Request Buffer ---- //
    request_buffer: RequestBuffer<T>,
    // ---- Reward Info ---- //
    reward_manager: address,
    // ---- Receipt Info ---- //
    receipts: Table<address, VaultReceiptInfo>,
    // ---- Operation Value Update Record ---- //
    op_value_update_record: OperationValueUpdateRecord,
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

**File:** volo-vault/tests/operation/operation.test.move (L1561-1564)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
public fun test_start_op_fail_op_freezed() {
```
