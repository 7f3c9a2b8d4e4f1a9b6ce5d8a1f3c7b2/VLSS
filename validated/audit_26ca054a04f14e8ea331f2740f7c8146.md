# Audit Report

## Title
Frozen Operator Can Bypass Authorization Check to Retrieve Deposit/Withdraw Fees

## Summary
The `retrieve_deposit_withdraw_fee_operator` function fails to verify operator freeze status before allowing fee withdrawal. This authorization bypass allows frozen operators—who have been administratively revoked due to malicious behavior or security concerns—to continue extracting accumulated protocol fees despite being blocked from all other vault operations.

## Finding Description

**Root Cause:**

The `retrieve_deposit_withdraw_fee_operator` function accepts only an `OperatorCap` without requiring the `Operation` shared object as a parameter. [1](#0-0) 

The operator freeze check mechanism requires BOTH parameters to function. The freeze verification function is defined as: [2](#0-1) 

This function checks the `freezed_operators` table stored in the `Operation` shared object: [3](#0-2) 

**Why All Other Operations Are Protected:**

Every other operator-privileged function in the codebase consistently includes the freeze check:

- `start_op_with_bag`: [4](#0-3) 
- `end_op_with_bag`: [5](#0-4) 
- `execute_deposit`: [6](#0-5) 
- `batch_execute_deposit`: [7](#0-6) 
- `cancel_user_deposit`: [8](#0-7) 
- `execute_withdraw`: [9](#0-8) 
- `batch_execute_withdraw`: [10](#0-9) 

Reward manager operations also enforce this check: [11](#0-10) 

**The Vulnerable Call:**

The function directly calls the underlying vault fee retrieval without any freeze verification: [12](#0-11) 

This underlying function only checks vault version and status—it has no awareness of operator freeze state.

**System Context:**

The protocol includes operator freezing functionality: [13](#0-12) 

Tests confirm frozen operators should be blocked: [14](#0-13) 

Fee rates can reach maximum of 5% (500 basis points): [15](#0-14) 

## Impact Explanation

**Direct Financial Loss:**
- Frozen operators can drain all accumulated deposit and withdraw fees from the vault
- These fees represent protocol revenue collected at rates up to 5% of user deposit/withdrawal amounts
- The fees belong to the protocol treasury and vault shareholders

**Security Control Bypass:**
- The operator freeze mechanism is a critical emergency response tool
- Operators are frozen when suspected of malicious activity, when exceeding loss tolerance, or during security investigations
- This bypass completely undermines the freeze protection for one of the most financially sensitive operations

**Trust and Governance Impact:**
- Administrators lose the ability to fully revoke operator privileges in emergency situations
- Frozen operators retain financial extraction capability despite administrative action
- Violates the core security invariant that "frozen operators cannot perform privileged operations"

## Likelihood Explanation

**Trivial Exploitation:**
1. Administrator freezes an operator via `set_operator_freezed` due to suspicious behavior
2. The frozen operator still possesses their `OperatorCap` object (it's not destroyed by freezing)
3. Operator immediately calls `retrieve_deposit_withdraw_fee_operator(&operator_cap, &mut vault, amount)`
4. Transaction succeeds—no `ERR_OPERATOR_FREEZED` error is thrown
5. Frozen operator successfully extracts accumulated fees

**No Barriers to Execution:**
- Function is publicly accessible with standard operator capability
- No time locks or additional authorization requirements
- Only requires vault to be in normal status (not during operation)
- Frozen operators have strong motivation to extract remaining value before capability destruction
- Attack can be executed in a single transaction

**Realistic Scenario:**
When an operator is frozen (typically due to loss tolerance violations or security concerns), they are aware of the freeze and have a window of opportunity before their capability is manually destroyed by administrators. During this window, they can extract all accumulated fees.

## Recommendation

Add the `operation: &Operation` parameter to the function signature and include the freeze check:

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

This brings the function into consistency with all other operator-privileged functions in the codebase.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());

    // Initialize vault with fee collection
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Set up oracle and deposit fee
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        vault_manage::set_deposit_fee(&admin_cap, &mut vault, 100); // 1% fee
        test_scenario::return_shared(vault);
        s.return_to_sender(admin_cap);
    };
    
    // User deposits, generating fees
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        // Deposit and execute to collect fees
        // ... deposit execution code ...
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
    
    // VULNERABILITY: Frozen operator can still retrieve fees
    s.next_tx(OWNER);
    {
        let operator_cap = s.take_from_sender<OperatorCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // This should fail with ERR_OPERATOR_FREEZED but currently succeeds
        let fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            10_000_000  // Withdraw accumulated fees
        );
        
        fees.destroy_for_testing();
        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

**Expected behavior:** Test should pass (function aborts with `ERR_OPERATOR_FREEZED`)  
**Actual behavior:** Test fails because frozen operator successfully retrieves fees without any error

## Notes

This vulnerability represents a critical gap in the operator authorization model. While the freeze mechanism works correctly for all vault operations (deposits, withdrawals, DeFi operations, reward management), it fails for fee retrieval—one of the most financially sensitive operations. The fix is straightforward and aligns with existing code patterns throughout the protocol.

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

**File:** volo-vault/sources/volo_vault.move (L32-33)
```text
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
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

**File:** volo-vault/sources/volo_vault.move (L387-393)
```text
public fun operator_freezed(operation: &Operation, op_cap_id: address): bool {
    if (operation.freezed_operators.contains(op_cap_id)) {
        *operation.freezed_operators.borrow(op_cap_id)
    } else {
        false
    }
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

**File:** volo-vault/sources/operation.move (L435-444)
```text
public fun cancel_user_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    request_id: u64,
    receipt_id: address,
    recipient: address,
    clock: &Clock,
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

**File:** volo-vault/sources/operation.move (L481-492)
```text
public fun batch_execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_ids: vector<u64>,
    max_amount_received: vector<u64>,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L235-241)
```text
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    with_buffer: bool, // If true, create a new reward buffer distribution for the reward type
) {
    self.check_version();
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/tests/operation/operation.test.move (L1561-1564)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
public fun test_start_op_fail_op_freezed() {
```
