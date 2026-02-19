# Audit Report

## Title
Operator Freeze Mid-Operation Causes Permanent Vault Deadlock

## Summary
The operator freeze mechanism enforces freeze checks at both the start AND end of vault operations. When an admin freezes an operator mid-operation, the frozen operator cannot complete the operation, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`. This blocks all user deposits, withdrawals, and vault operations indefinitely, with no admin emergency recovery function available.

## Finding Description

The freeze state is stored persistently in the shared `Operation` object. [1](#0-0) 

When an operator starts a vault operation, the freeze check passes and the vault status is set to `VAULT_DURING_OPERATION_STATUS`. [2](#0-1) [3](#0-2) 

The critical flaw is that freeze checks are ALSO enforced when ending operations. [4](#0-3) [5](#0-4) 

The freeze check aborts with `ERR_OPERATOR_FREEZED` if the operator is frozen. [6](#0-5) [7](#0-6) 

**Deadlock Scenario:**
1. Operator calls `start_op_with_bag` → vault enters `VAULT_DURING_OPERATION_STATUS`
2. Admin freezes operator via `set_operator_freezed(operation, op_cap_id, true)` 
3. Operator tries to call `end_op_with_bag` or `end_op_value_update_with_bag` → **ABORTS** with `ERR_OPERATOR_FREEZED`
4. Vault stuck in `VAULT_DURING_OPERATION_STATUS`
5. Only status reset is at operation completion, which cannot occur

All user operations require `VAULT_NORMAL_STATUS` or `assert_not_during_operation`, blocking:
- Deposit requests [8](#0-7) 
- Withdrawal requests [9](#0-8) 
- Execute deposits [10](#0-9) 
- Execute withdrawals [11](#0-10) 
- Cancel deposits [12](#0-11) 
- Cancel withdrawals [13](#0-12) 

Critically, the only admin function that modifies vault status (`set_enabled`) explicitly prevents status changes during operations. [14](#0-13) 

The ONLY recovery path is for the admin to unfreeze the operator, let them complete the operation, then re-freeze - defeating the entire purpose of emergency operator freezing.

## Impact Explanation

**Critical Protocol DoS:**
- All user deposit/withdrawal requests completely blocked
- All pending request executions blocked
- All request cancellations blocked
- Vault's entire TVL (potentially millions of dollars) becomes inaccessible to all users
- No new operations can be started

**Fund Impact:**
While funds are not stolen, they are completely locked and inaccessible. For high-TVL vaults, even temporary inaccessibility represents severe operational risk and loss of user confidence.

**Security Control Failure:**
The freeze mechanism, designed as a security control to immediately stop a compromised operator, becomes counterproductive - creating total vault lockup rather than protecting users.

## Likelihood Explanation

**High Likelihood:**

1. **Expected Use Case**: Admin detecting suspicious operator behavior and immediately freezing them is THE intended use case for the freeze feature. The admin may not know the operator is mid-operation, making this scenario highly likely.

2. **Natural Race Condition**: Vault operations can be long-running (involving multiple DeFi protocol interactions across Navi/Cetus/Suilend/Momentum). During execution, if admin detects anomalies and freezes the operator, the deadlock occurs.

3. **No Warning**: The freeze action succeeds without error. The deadlock only becomes apparent when subsequent operations fail, so the admin may not realize the mistake until user complaints arrive.

**Feasibility:**
- Requires only normal admin and operator capabilities (both explicitly trusted roles)
- No special timing requirements
- Admin freeze is a legitimate security response
- Operation duration provides natural window for race condition

## Recommendation

Add an emergency admin function to force-complete or abort stuck operations. For example:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Allow admin to reset vault to normal status even during operations
    // This should only be used in emergency scenarios like operator freeze deadlock
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

Alternatively, modify freeze checks to allow frozen operators to COMPLETE (but not START) operations:

```move
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    // ... parameters
) {
    // Remove freeze check here - allow completion even if frozen
    // vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
    // ... rest of function
}
```

## Proof of Concept

```move
#[test]
fun test_operator_freeze_deadlock() {
    let mut scenario = test_scenario::begin(@admin);
    
    // Setup: Create vault, operator cap, and operation object
    let admin_cap = create_admin_cap(&mut scenario);
    let operator_cap = create_operator_cap(&admin_cap, &mut scenario);
    let mut vault = create_test_vault(&mut scenario);
    let mut operation = create_operation(&mut scenario);
    
    // Step 1: Operator starts operation
    let op_cap_id = object::id_address(&operator_cap);
    start_op_with_bag(&mut vault, &operation, &operator_cap, &clock, ...);
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS);
    
    // Step 2: Admin freezes operator mid-operation
    set_operator_freezed(&admin_cap, &mut operation, op_cap_id, true);
    assert!(operator_freezed(&operation, op_cap_id) == true);
    
    // Step 3: Operator tries to end operation - ABORTS with ERR_OPERATOR_FREEZED
    end_op_with_bag(&mut vault, &operation, &operator_cap, ...); // ABORTS here
    
    // Step 4: Vault stuck - all user operations fail
    request_deposit(&mut vault, coin, ...); // ABORTS: requires VAULT_NORMAL_STATUS
    request_withdraw(&mut vault, ...); // ABORTS: requires VAULT_NORMAL_STATUS
    
    // Step 5: Admin cannot fix via set_enabled
    set_vault_enabled(&admin_cap, &mut vault, false); // ABORTS: ERR_VAULT_DURING_OPERATION
}
```

**Notes:**
This vulnerability represents a fundamental design flaw where a security mechanism (operator freeze) inadvertently creates a worse security state (complete protocol lockup). The lack of any emergency admin override for vault status during operations leaves no recovery path except unfreezing the operator, which defeats the security purpose of the freeze mechanism.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L769-769)
```text
    self.assert_not_during_operation();
```

**File:** volo-vault/sources/volo_vault.move (L814-814)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L952-952)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1002-1002)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L105-106)
```text
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/operation.move (L218-218)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L306-306)
```text
    vault::assert_operator_not_freezed(operation, cap);
```
