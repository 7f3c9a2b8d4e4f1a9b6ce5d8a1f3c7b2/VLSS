### Title
Frozen Operators Can Bypass Freeze Control to Retrieve Fees

### Summary
The `retrieve_deposit_withdraw_fee_operator()` function allows operators to retrieve deposit and withdraw fees without checking if the operator has been frozen. This bypasses the operator freeze security control that is enforced on all other operator functions, enabling frozen operators to continue extracting protocol fees even after being explicitly frozen by administrators.

### Finding Description

The vulnerability exists in the `retrieve_deposit_withdraw_fee_operator()` function [1](#0-0) , which takes an `OperatorCap` but does not verify the operator's freeze status before allowing fee retrieval.

The function directly calls the underlying vault method without any freeze check [2](#0-1) , which only validates version and vault normal status, but lacks operator freeze validation.

In contrast, the protocol consistently enforces freeze checks across all other operator functions. The freeze check pattern is implemented via `assert_operator_not_freezed()` [3](#0-2) , which verifies the operator against the `freezed_operators` table stored in the Operation object [4](#0-3) .

All operation functions properly enforce this check, including: `start_op_with_bag()` [5](#0-4) , `end_op_with_bag()` [6](#0-5) , `end_op_value_update_with_bag()` [7](#0-6) , `execute_deposit()` [8](#0-7) , `batch_execute_deposit()` [9](#0-8) , `cancel_user_deposit()` [10](#0-9) , `execute_withdraw()` [11](#0-10) , and `batch_execute_withdraw()` [12](#0-11) .

Administrators can freeze operators using `set_operator_freezed()` [13](#0-12) , which updates the freeze status in the Operation object [14](#0-13) .

The protocol collects fees during deposit operations [15](#0-14)  and withdraw operations [16](#0-15) , accumulating them in the vault's `deposit_withdraw_fee_collected` balance [17](#0-16) .

### Impact Explanation

**Direct Fund Impact**: A frozen operator can extract all accumulated deposit and withdraw fees from the vault's `deposit_withdraw_fee_collected` balance, resulting in unauthorized fund theft. The amount depends on the fee accumulation since the last retrieval, which grows with deposit and withdraw activity (default rates: 10bp for deposits and 10bp for withdraws [18](#0-17) ).

**Security Integrity Impact**: This vulnerability completely bypasses the operator freeze control mechanism, which is a critical security feature. When administrators detect suspicious or malicious operator behavior and freeze them, the expectation is that all operator privileges are immediately revoked. However, frozen operators retain the ability to drain fee revenue, rendering the freeze mechanism ineffective for protecting protocol funds.

**Who is Affected**: The protocol and its users are affected through loss of rightfully collected fees that should remain under administrative control. The freeze mechanism exists precisely to handle compromised or malicious operators, making this bypass particularly severe.

### Likelihood Explanation

**Reachable Entry Point**: The `retrieve_deposit_withdraw_fee_operator()` function is a public function that can be called directly via Programmable Transaction Blocks (PTBs) in Sui by any address holding an `OperatorCap`.

**Feasible Preconditions**: The attack scenario requires an operator who has been frozen by administrators due to suspected compromise or malicious behavior. This is a realistic scenario that the freeze mechanism is designed to handle. The operator must possess the `OperatorCap` object, which they would have from their normal operator role.

**Execution Practicality**: The exploit is trivial - a single function call to `retrieve_deposit_withdraw_fee_operator()` with the frozen `OperatorCap` and desired amount. No complex transaction sequencing or state manipulation is required.

**Economic Rationality**: There are no economic barriers. The frozen operator can extract the full fee balance with no transaction cost constraints beyond standard gas fees. Detection would occur after the fact through event monitoring, but funds would already be extracted.

The likelihood is HIGH because frozen operators have strong incentive to extract remaining funds before the administrator can act further, and the execution is straightforward.

### Recommendation

Add the operator freeze check at the beginning of `retrieve_deposit_withdraw_fee_operator()`:

**Code-level mitigation**: Modify the function signature to accept the `Operation` object and add the freeze assertion:

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

**Invariant check**: Ensure that the freeze status is validated before any operator action that modifies vault state or extracts value.

**Test case**: Add a test case similar to the existing `test_start_op_fail_op_freezed` [19](#0-18)  that verifies frozen operators cannot retrieve fees and receive the `ERR_OPERATOR_FREEZED` error [20](#0-19) .

### Proof of Concept

**Initial State**:
1. Vault is deployed with deposit/withdraw fees configured
2. Administrator creates an `OperatorCap` using `create_operator_cap()` [21](#0-20) 
3. Users deposit and withdraw, accumulating fees in `deposit_withdraw_fee_collected`
4. Administrator detects suspicious operator behavior and freezes the operator via `set_operator_freezed()` [13](#0-12)  with `freezed=true`

**Attack Steps**:
1. Frozen operator verifies they cannot call normal operation functions (e.g., `start_op_with_bag` would abort with `ERR_OPERATOR_FREEZED`)
2. Frozen operator calls `retrieve_deposit_withdraw_fee_operator()` via PTB with their frozen `OperatorCap` and the full fee balance amount
3. Transaction succeeds without checking freeze status
4. Frozen operator receives the `Balance<PrincipalCoinType>` containing all accumulated fees

**Expected vs Actual**:
- **Expected**: Transaction should abort with `ERR_OPERATOR_FREEZED` error, consistent with all other operator functions
- **Actual**: Transaction succeeds, fee balance is transferred to frozen operator, bypassing the freeze control

**Success Condition**: Frozen operator successfully extracts fees despite being explicitly frozen by administrator, demonstrating complete bypass of the freeze security mechanism.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L30-31)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L63-63)
```text
const ERR_OPERATOR_FREEZED: u64 = 5_015;
```

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

**File:** volo-vault/sources/operation.move (L416-416)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L444-444)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L492-492)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/tests/operation/operation.test.move (L1561-1564)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
public fun test_start_op_fail_op_freezed() {
```
