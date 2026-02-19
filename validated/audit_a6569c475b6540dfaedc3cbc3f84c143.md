### Title
Frozen Operator Bypass Allows Unauthorized Protocol Fee Withdrawal

### Summary
The Volo Vault system maps the Vercel "excessive team permissions" vulnerability class to an authorization bypass where operators can withdraw all protocol fee revenue without freeze mechanism enforcement. Any operator holding an `OperatorCap` can drain accumulated deposit and withdraw fees via `retrieve_deposit_withdraw_fee_operator()`, and critically, even frozen operators can bypass the freeze control to extract protocol revenue.

### Finding Description

**External Vulnerability Class Mapping:**
The Vercel report identifies excessive team access permissions as a security control gap. In Volo smart contracts, this maps to operators (`OperatorCap` holders) having unauthorized access to protocol revenue withdrawal, analogous to team members having access to billing/revenue controls they shouldn't possess.

**Root Cause:**
The `vault_manage` module provides two fee withdrawal functions - one for admins and one for operators: [1](#0-0) 

Both functions call the same underlying vault function that splits fees from the collected balance: [2](#0-1) 

**Critical Flaw - Missing Freeze Check:**
All operator functions in the `operation` module enforce frozen operator checks as the first validation: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

However, `retrieve_deposit_withdraw_fee_operator()` does NOT require the `Operation` shared object parameter and therefore cannot check frozen status. The underlying vault function only validates version and vault status: [7](#0-6) 

**Exploit Path:**
1. Admin creates `OperatorCap` via `create_operator_cap()` and distributes to strategy operator
2. Protocol accumulates fees in `deposit_withdraw_fee_collected` during user deposits/withdrawals
3. Operator calls `vault_manage::retrieve_deposit_withdraw_fee_operator(&operator_cap, &mut vault, amount)` with any amount up to total balance
4. Vault splits and returns the fee balance without checking if operator is frozen
5. If admin attempts to freeze the operator for malicious behavior, the freeze mechanism is bypassed - frozen operator can still drain fees

**Why Current Protections Fail:**
- The freeze mechanism is implemented via `Operation.freezed_operators` table and enforced by `assert_operator_not_freezed()`
- Management functions in `vault_manage` do not take `Operation` parameter and cannot enforce freeze checks
- This creates an inconsistent security model where operators are frozen from operational functions but NOT from management/revenue functions

### Impact Explanation

**Direct Financial Impact:**
Any operator can drain 100% of accumulated protocol fee revenue. Fees are collected at rates up to 5% on deposits and 5% on withdrawals: [8](#0-7) 

For a vault with significant TVL and transaction volume, accumulated fees represent substantial protocol revenue.

**Freeze Mechanism Bypass:**
The operator freeze mechanism exists to prevent malicious operators who exceed loss tolerance from continuing operations: [9](#0-8) 

However, frozen operators can still extract protocol revenue, defeating the purpose of the freeze control. This breaks the invariant that "operator freeze is respected" across all operator privileges.

**Severity:** High - Complete bypass of intended access control, enabling unauthorized protocol revenue extraction.

### Likelihood Explanation

**Attack Preconditions:**
- Attacker must possess an `OperatorCap` (created by admin for legitimate strategy execution)
- No additional preconditions - function is callable at any time
- Does not require compromised admin keys - this is about excessive operator privileges by design

**Execution Feasibility:**
The function is directly callable by any `OperatorCap` holder: [10](#0-9) 

Tests confirm this functionality is intentionally available to operators: [11](#0-10) 

**Realistic Threat Model:**
- Malicious operator extracts fees before being detected
- Compromised operator key used to drain fees
- Operator who exceeded loss tolerance and was frozen can still extract revenue before admin revokes capability

**Likelihood:** High - No technical barriers, directly exploitable by any operator.

### Recommendation

**Primary Fix - Add Freeze Check:**
Modify `retrieve_deposit_withdraw_fee_operator()` to require `Operation` parameter and enforce freeze validation:

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

**Alternative Fix - Remove Operator Fee Withdrawal:**
If operators should not have fee withdrawal permissions, remove `retrieve_deposit_withdraw_fee_operator()` entirely and restrict fee withdrawal to `AdminCap` holders only. This aligns with the principle of least privilege.

**Additional Hardening:**
Consider adding withdrawal limits or multi-sig requirements for large fee withdrawals to add defense-in-depth even if operator capabilities are legitimate.

### Proof of Concept

**Setup:**
1. Admin creates vault via `create_vault<SUI>()`
2. Admin creates operator capability via `create_operator_cap()` 
3. Users deposit 1000 SUI with 1% deposit fee (10 SUI collected as fees)
4. Operator executes deposit requests, accumulating fees in `deposit_withdraw_fee_collected`

**Exploit Scenario 1 - Unauthorized Fee Drain:**
```
operator_calls: vault_manage::retrieve_deposit_withdraw_fee_operator(
    &operator_cap,
    &mut vault,
    10_000_000_000  // drain all 10 SUI of fees
)
// Returns full fee balance to operator
// No authorization check prevents this
```

**Exploit Scenario 2 - Frozen Operator Bypass:**
```
// Admin detects malicious operator behavior
admin_calls: vault_manage::set_operator_freezed(
    &admin_cap,
    &mut operation,
    operator_cap_id,
    true  // freeze the operator
)

// Operator is now frozen from operational functions
// But can STILL withdraw fees:
operator_calls: vault_manage::retrieve_deposit_withdraw_fee_operator(
    &operator_cap,  // still works even when frozen!
    &mut vault,
    10_000_000_000
)
// Successfully drains fees despite being frozen
// Function does not check Operation.freezed_operators
```

**Verification:**
Compare with any operational function which correctly enforces freeze: [12](#0-11) 

The fee withdrawal path lacks this critical validation.

---

**Notes:**

This vulnerability represents a direct analog to the Vercel "excessive team permissions" issue. Just as the external report identifies team members having unauthorized access to production controls, Volo operators have unauthorized access to protocol revenue controls. The freeze mechanism bypass compounds this by allowing even sanctioned operators to extract value, breaking the intended access control model. The vulnerability is architectural - not requiring key compromise - making it distinct from trust assumptions about admin/operator key security.

### Citations

**File:** volo-vault/sources/manage.move (L142-156)
```text
public fun retrieve_deposit_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
}

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

**File:** volo-vault/sources/operation.move (L391-391)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L416-416)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L460-460)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L529-543)
```text
public fun deposit_by_operator<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    coin: Coin<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.deposit_by_operator(
        clock,
        config,
        coin,
    );
}
```

**File:** volo-vault/tests/operation/manage.test.move (L387-396)
```text
        let fee_retrieved = vault_manage::retrieve_deposit_withdraw_fee_operator(
            &operator_cap,
            &mut vault,
            2_000_000,
        );
        assert!(fee_retrieved.value() == 2_000_000);

        test_scenario::return_shared(vault);
        s.return_to_sender(operator_cap);
        fee_retrieved.destroy_for_testing();
```
