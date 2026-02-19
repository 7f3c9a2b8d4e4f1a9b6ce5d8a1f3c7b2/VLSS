### Title
Frozen Operator Bypass via Fee Retrieval Function

### Summary
Frozen operators in the Volo vault system are blocked from executing all vault operations through the `assert_operator_not_freezed()` check, but can bypass this restriction by calling `retrieve_deposit_withdraw_fee_operator()` to extract accumulated deposit/withdraw fees from the vault. This mirrors the external vulnerability where soft-restricted users are blocked from direct staking but can receive tokens via transfers, bypassing the restriction entirely.

### Finding Description

The Volo vault system implements an operator freeze mechanism where administrators can freeze misbehaving operators via `set_operator_freezed()` [1](#0-0) . The freeze status is tracked in the `Operation.freezed_operators` table and checked via `assert_operator_not_freezed()` [2](#0-1) .

All operator functions in the `operation` module properly enforce this check before allowing any vault operations [3](#0-2) [4](#0-3) [5](#0-4) . Similarly, all reward manager operator functions check the freeze status [6](#0-5) [7](#0-6) .

However, the `retrieve_deposit_withdraw_fee_operator()` function in the `vault_manage` module does NOT check the operator freeze status [8](#0-7) . This function allows any OperatorCap holder to withdraw accumulated deposit/withdraw fees from the vault, which are collected during user deposits and withdrawals [9](#0-8) .

**Root Cause:** The function signature accepts `_: &OperatorCap` but does not call `vault::assert_operator_not_freezed(operation, cap)` before delegating to the underlying `vault.retrieve_deposit_withdraw_fee(amount)` function.

**Exploit Path:**
1. Admin freezes an operator by calling `set_operator_freezed(op_cap_id, true)` due to misbehavior or security concerns
2. The frozen operator can no longer execute deposits, withdrawals, or any vault operations (all abort with ERR_OPERATOR_FREEZED)
3. But the frozen operator CAN still call `retrieve_deposit_withdraw_fee_operator()` with their OperatorCap
4. The frozen operator successfully extracts accumulated fees from the vault, bypassing the freeze restriction

### Impact Explanation

A frozen operator can extract real vault funds in the form of accumulated deposit/withdraw fees, defeating the purpose of the operator freeze mechanism. Fee rates are configurable up to 5% (MAX_DEPOSIT_FEE_RATE and MAX_WITHDRAW_FEE_RATE) [10](#0-9)  with defaults of 0.1% [11](#0-10) . With substantial vault activity, these fees can accumulate to significant amounts stored in `vault.deposit_withdraw_fee_collected` [12](#0-11) .

The operator freeze mechanism exists to completely stop a potentially malicious or compromised operator from taking any actions on the vault. This bypass allows value extraction despite the freeze, undermining the security control.

### Likelihood Explanation

The likelihood is HIGH because:

1. **Public Access:** `retrieve_deposit_withdraw_fee_operator()` is a public entry function callable by any address holding an OperatorCap [8](#0-7) 

2. **No Additional Checks:** The function performs NO validation beyond accepting an OperatorCap reference - it does not check freeze status, vault status beyond normal/disabled, or any other restriction

3. **Realistic Scenario:** Operators are frozen for legitimate security reasons (detected misbehavior, compromised keys, protocol upgrade issues). A frozen operator retains possession of their OperatorCap object and can immediately call this function

4. **Confirmed by Tests:** The test suite verifies that frozen operators cannot execute operations [13](#0-12) , but there is no test verifying that frozen operators cannot retrieve fees, indicating this bypass was not considered during development

### Recommendation

Add the operator freeze check to `retrieve_deposit_withdraw_fee_operator()` in `manage.move`:

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

This ensures consistency with all other operator functions that properly check the freeze status before allowing any vault interactions.

### Proof of Concept

**Setup:**
1. Admin creates vault and OperatorCap via `create_operator_cap()`
2. Vault accumulates deposit/withdraw fees from user activity (e.g., 10 SUI in fees)
3. Admin freezes the operator via `set_operator_freezed(op_cap_id, true)` due to detected issues

**Exploit:**
1. Frozen operator attempts `execute_deposit()` → Aborts with ERR_OPERATOR_FREEZED ✗
2. Frozen operator attempts `execute_withdraw()` → Aborts with ERR_OPERATOR_FREEZED ✗  
3. Frozen operator attempts `start_op_with_bag()` → Aborts with ERR_OPERATOR_FREEZED ✗
4. Frozen operator calls `retrieve_deposit_withdraw_fee_operator(&cap, &mut vault, 10_000_000_000)` → Success, extracts 10 SUI ✓

**Result:** Frozen operator successfully bypasses freeze restriction and extracts vault funds, demonstrating the same vulnerability class as the external report where restrictions on direct actions can be bypassed through alternative unchecked paths.

### Citations

**File:** volo-vault/sources/volo_vault.move (L30-31)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L32-33)
```text
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
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

**File:** volo-vault/sources/operation.move (L105-106)
```text
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/operation.move (L391-391)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L416-416)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L241-241)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/reward_manager.move (L283-283)
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

**File:** volo-vault/tests/operation/operation.test.move (L1562-1564)
```text
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
public fun test_start_op_fail_op_freezed() {
```
