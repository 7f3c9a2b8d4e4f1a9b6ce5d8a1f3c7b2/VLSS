### Title
Frozen Operator Can Bypass Freeze Restriction to Extract Deposit/Withdraw Fees

### Summary
The `retrieve_deposit_withdraw_fee_operator` function in `manage.move` fails to verify whether an operator is frozen before allowing fee extraction. While all other operator functions properly enforce the freeze restriction via `assert_operator_not_freezed`, this function omits the check, allowing frozen operators to continue extracting accumulated fees even after being frozen for security violations such as exceeding loss tolerance limits.

### Finding Description

The operator freeze mechanism is implemented through `set_operator_freezed` which sets a boolean flag in `Operation.freezed_operators` table: [1](#0-0) 

The protocol provides `assert_operator_not_freezed` to enforce this restriction: [2](#0-1) 

All operation functions correctly check the freeze status. For example, `start_op_with_bag`: [3](#0-2) 

Similarly, `execute_deposit`: [4](#0-3) 

And `execute_withdraw`: [5](#0-4) 

Reward manager functions also enforce the check: [6](#0-5) 

However, `retrieve_deposit_withdraw_fee_operator` completely omits this critical check: [7](#0-6) 

The function accepts an `OperatorCap` and directly calls the underlying vault method without verifying freeze status, creating a bypass of the security control.

### Impact Explanation

**Direct Fund Impact**: A frozen operator can continuously extract accumulated deposit and withdrawal fees from the vault, draining protocol revenue that should be inaccessible to them.

**Security Integrity Impact**: The freeze mechanism is a critical security control designed to immediately restrict compromised or malicious operators (e.g., those exceeding loss tolerance limits). This bypass defeats the entire purpose of the freeze functionality.

**Affected Parties**: The protocol loses fee revenue, and the integrity of the operator governance model is compromised. Operators who should be completely locked out can continue profiting from fee extraction.

**Severity**: This is a **CRITICAL** vulnerability because it:
1. Directly enables unauthorized fund extraction
2. Bypasses a primary security control mechanism
3. Has no operational complexity or cost to exploit
4. Contradicts the documented security invariant that "operator freeze respected"

### Likelihood Explanation

**Reachable Entry Point**: `retrieve_deposit_withdraw_fee_operator` is a public function callable by any operator with a valid `OperatorCap`. [7](#0-6) 

**Feasible Preconditions**: 
- Operator must possess an `OperatorCap` (normal operational state)
- Fees must have accumulated in the vault (occurs naturally during normal operations)
- Admin freezes the operator (this is the security response to malicious behavior)

**Execution Practicality**: Single transaction call with no complex setup required. The operator simply calls `retrieve_deposit_withdraw_fee_operator` after being frozen.

**Economic Rationality**: Zero cost to execute, direct financial gain. The operator can extract all accumulated fees before any additional security measures can be taken.

**Detection/Operational Constraints**: The vulnerability is immediately exploitable upon freeze. There is no time window for intervention between freeze and exploitation.

**Probability**: HIGH - This will occur whenever an operator is frozen while fees exist in the vault, which is the exact scenario the freeze mechanism is designed to handle.

### Recommendation

**Immediate Fix**: Add the freeze check to `retrieve_deposit_withdraw_fee_operator` in `manage.move`:

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

**Required Changes**:
1. Add `operation: &Operation` parameter
2. Change `_: &OperatorCap` to `cap: &OperatorCap` to pass the cap reference to the check
3. Add `vault::assert_operator_not_freezed(operation, cap);` before fee retrieval

**Test Case**: Add a test that verifies a frozen operator cannot call `retrieve_deposit_withdraw_fee_operator`:

```move
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
public fun test_frozen_operator_cannot_retrieve_fees() {
    // Setup vault with fees
    // Freeze operator
    // Attempt to retrieve fees - should fail
}
```

The test should follow the pattern established in: [8](#0-7) 

### Proof of Concept

**Initial State**:
1. Vault has accumulated 1,000,000 tokens in `deposit_withdraw_fee_collected`
2. Operator possesses valid `OperatorCap` with ID `0xOPERATOR_ADDRESS`
3. Admin has frozen the operator via `set_operator_freezed(operation, 0xOPERATOR_ADDRESS, true)`

**Attack Sequence**:

Transaction 1 - Admin freezes operator:
```move
vault_manage::set_operator_freezed(&admin_cap, &mut operation, operator_cap.operator_id(), true);
```

Transaction 2 - Frozen operator extracts fees:
```move
let fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
    &operator_cap,
    &mut vault,
    1_000_000
);
// Transfer fees to operator's address
transfer::public_transfer(coin::from_balance(fees, ctx), operator_address);
```

**Expected Result**: Transaction 2 should fail with `ERR_OPERATOR_FREEZED`

**Actual Result**: Transaction 2 succeeds, frozen operator receives 1,000,000 tokens in fees

**Success Condition**: Frozen operator successfully extracts fees that should be inaccessible, bypassing the freeze security control entirely.

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

**File:** volo-vault/sources/operation.move (L105-105)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L391-391)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L241-241)
```text
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

**File:** volo-vault/tests/operation/operation.test.move (L1561-1563)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
```
