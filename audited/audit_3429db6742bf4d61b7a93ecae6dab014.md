### Title
Frozen Operators Can Bypass Freeze Mechanism to Drain All Collected Fees

### Summary
The `retrieve_deposit_withdraw_fee_operator()` function in `manage.move` allows operators to retrieve deposit/withdraw fees without verifying operator freeze status, completely bypassing the protocol's operator freeze security mechanism. A frozen operator can drain all accumulated fees in a single transaction, violating the critical invariant that frozen operators cannot perform any operations.

### Finding Description

The vulnerable function is located at: [1](#0-0) 

This function takes an `OperatorCap` but does NOT:
1. Accept the `Operation` shared object as a parameter (required for freeze checks)
2. Call `assert_operator_not_freezed()` to verify the operator is not frozen
3. Impose any amount limits beyond what exists in the balance

The function directly calls the underlying vault method: [2](#0-1) 

This underlying method only checks version and vault status (must be NORMAL), but contains no operator freeze validation. It allows splitting any requested amount from `deposit_withdraw_fee_collected` via: [3](#0-2) 

In contrast, ALL other operator functions properly enforce freeze checks. For example, `start_op_with_bag()` in `operation.move` correctly validates: [4](#0-3) 

The freeze check function itself is defined as: [5](#0-4) 

The protocol includes a test demonstrating that frozen operators should fail operations with `ERR_OPERATOR_FREEZED`: [6](#0-5) 

The admin version of fee retrieval exists separately and does not need freeze checks since `AdminCap` cannot be frozen: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:** A frozen operator can extract 100% of accumulated deposit and withdraw fees from the vault. Given that fees are collected on every deposit and withdrawal at rates up to 5% (500 bps max), this represents a significant value theft vector.

**Security Integrity Impact:** This completely bypasses the operator freeze mechanism, which is a critical security control designed to immediately revoke operator privileges when malicious activity is detected or during security incidents. The freeze mechanism is explicitly documented in the critical invariants under "Authorization & Enablement" as a protection that must be respected at all times.

**Who is affected:** All vault depositors whose fees are stolen, and the protocol treasury that should receive these fees. The impact scales with vault TVL and fee accumulation period.

**Severity justification:** This is CRITICAL because:
- It violates a fundamental security invariant (operator freeze must be respected)
- It enables direct fund theft with no technical barriers
- It undermines the protocol's ability to respond to security incidents
- The freeze mechanism exists specifically to prevent this type of unauthorized access

### Likelihood Explanation

**Attacker capabilities:** Only requires possession of an `OperatorCap` that has been frozen by the admin. This is a realistic scenario where:
- An operator is discovered to be malicious
- An operator key is compromised
- Protocol needs to emergency-revoke operator privileges during an incident

**Attack complexity:** Trivial - single function call with the frozen `OperatorCap` and desired amount.

**Feasibility conditions:** 
- Vault must be in NORMAL status (not during operation)
- Fees must have accumulated in `deposit_withdraw_fee_collected`
- No other preconditions required

**Detection/operational constraints:** The attack leaves an event trail via `DepositWithdrawFeeRetrieved`, but by the time it's detected, funds are already stolen. The entire balance can be drained in one transaction before any response.

**Probability reasoning:** HIGH probability in practice because:
- Operator freezing is a standard security response mechanism
- Once an operator is compromised or suspected malicious, they have nothing to lose by attempting fee extraction before losing access
- The window of opportunity exists from the moment of freeze until the `OperatorCap` is somehow revoked (which may require social recovery)

### Recommendation

**Code-level mitigation:**

Modify `retrieve_deposit_withdraw_fee_operator()` to require the `Operation` object and perform freeze check:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // ADD THIS PARAMETER
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // ADD THIS CHECK
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

**Invariant checks to add:**
- Add an assertion in the underlying `retrieve_deposit_withdraw_fee()` that documents it should only be called after authorization checks
- Consider adding maximum withdrawal limits per transaction for operators (e.g., time-locked withdrawals or multi-sig for large amounts)

**Test cases to prevent regression:**
1. Test that frozen operator calling `retrieve_deposit_withdraw_fee_operator()` aborts with `ERR_OPERATOR_FREEZED`
2. Test that unfrozen operator can successfully retrieve fees
3. Test that admin can always retrieve fees regardless of operator freeze status
4. Integration test showing freeze → attempted fee retrieval → abort sequence

### Proof of Concept

**Required initial state:**
1. Vault created with deposit/withdraw fees configured
2. OperatorCap issued to operator address
3. Users make deposits/withdrawals, accumulating fees in `deposit_withdraw_fee_collected`
4. Admin freezes the operator via `set_operator_freezed(operation, operator_cap_id, true)`

**Transaction steps:**
```
// Step 1: Admin freezes the operator (legitimate security response)
vault_manage::set_operator_freezed(&admin_cap, &mut operation, operator_cap.id(), true);

// Step 2: Frozen operator drains all fees (SHOULD FAIL BUT DOESN'T)
let all_fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
    &operator_cap,  // frozen operator cap
    &mut vault,
    vault.deposit_withdraw_fee_collected()  // entire balance
);
// Transaction succeeds - operator receives all accumulated fees

// Step 3: Operator transfers stolen fees to their address
transfer::public_transfer(coin::from_balance(all_fees, ctx), operator_address);
```

**Expected vs actual result:**
- **Expected:** Transaction aborts with `ERR_OPERATOR_FREEZED` at step 2
- **Actual:** Transaction succeeds, frozen operator drains all fees

**Success condition:** The frozen operator successfully withdraws fees that should be inaccessible, proven by checking their balance increased by the fee amount and vault's `deposit_withdraw_fee_collected` decreased to zero.

### Citations

**File:** volo-vault/sources/manage.move (L142-148)
```text
public fun retrieve_deposit_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
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

**File:** volo-vault/tests/operation/operation.test.move (L1561-1563)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_OPERATOR_FREEZED, location = vault)]
// [TEST-CASE: Should do op fail if operator is freezed.] @test-case OPERATION-012
```
