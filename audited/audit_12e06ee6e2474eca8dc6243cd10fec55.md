### Title
Operator Freeze During Operation Causes Permanent Vault DoS

### Summary
The operator freeze mechanism checks freeze status at operation start, end, and value update finalization. When an admin freezes an operator during an ongoing operation, the operator cannot complete the operation, leaving the vault permanently stuck in DURING_OPERATION status with no recovery mechanism. Users cannot deposit or withdraw, causing complete protocol DoS.

### Finding Description

The freeze state is stored in the `Operation` shared object's `freezed_operators` table and persists indefinitely across operations until explicitly unfrozen by admin. [1](#0-0) 

The `set_operator_freezed` function updates this persistent state without any automatic clearing: [2](#0-1) 

The critical issue is that freeze checks occur at THREE separate points in the operation lifecycle:

1. At operation start: [3](#0-2) 

2. At operation end: [4](#0-3) 

3. At operation value update finalization: [5](#0-4) 

When an operation starts, the vault status changes to DURING_OPERATION: [6](#0-5) 

If an operator is frozen after starting but before ending an operation, they fail the freeze check when attempting to end the operation. The vault remains stuck in DURING_OPERATION status, which only gets reset to NORMAL at the end of `end_op_value_update_with_bag`: [7](#0-6) 

The admin `set_enabled` function cannot recover the vault because it explicitly prevents status changes during operations: [8](#0-7) 

User deposits and withdrawals require NORMAL status and will permanently fail: [9](#0-8) [10](#0-9) 

### Impact Explanation

**Operational DoS - Complete Vault Lockup:**
- Vault stuck in DURING_OPERATION status indefinitely
- All user deposit requests fail with ERR_VAULT_NOT_NORMAL
- All user withdrawal requests fail with ERR_VAULT_NOT_NORMAL
- Existing pending requests cannot be processed
- No admin recovery mechanism exists

**Who is affected:**
- All vault users cannot access their funds
- Protocol reputation severely damaged
- TVL effectively locked until operator unfrozen

**Severity:** HIGH - Complete protocol DoS requiring either (1) unfreezing a potentially malicious operator, defeating the security mechanism's purpose, or (2) contract upgrade/migration.

### Likelihood Explanation

**High Likelihood - Natural Admin Action:**

This vulnerability triggers through legitimate admin operations, not attacker manipulation:

1. **Realistic scenario:** Admin detects suspicious operator behavior during an ongoing operation
2. **Expected admin response:** Immediately freeze the operator for security
3. **Unintended consequence:** Vault permanently locked
4. **No special conditions required:** Any operation in progress when freeze occurs

The vulnerability is particularly insidious because the freeze mechanism appears to work as intended (checking at all operation stages), but the interaction with vault status creates an unrecoverable state.

**Attack complexity:** Zero - happens through normal admin security response
**Detection:** Obvious after the fact, vault stops functioning
**Probability:** High in any security incident requiring operator freeze during operations

### Recommendation

**Solution 1 (Recommended): Add Admin Emergency Status Reset**

Add to `volo-vault/sources/manage.move`:
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

This allows admin to force-reset vault status when an operation cannot complete due to operator freeze.

**Solution 2: Only Check Freeze at Operation Start**

Remove freeze checks from `end_op_with_bag` and `end_op_value_update_with_bag`. This allows started operations to complete even if operator is frozen mid-execution, preventing DoS while still blocking new operations.

**Solution 3: Add Operation Timeout**

Implement time-based operation expiry after which admin can forcibly reset vault status, providing automatic recovery mechanism.

**Test cases to add:**
1. Freeze operator during ongoing operation, verify vault recovers
2. Verify frozen operator cannot start new operations
3. Test emergency reset function only callable by admin
4. Verify unfreezing and emergency reset both work for recovery

### Proof of Concept

**Initial State:**
- Vault in NORMAL status with TVL
- Operator has valid OperatorCap
- Operation shared object exists

**Attack Sequence:**

1. **Operator starts operation** (vault status → DURING_OPERATION):
```
operation::start_op_with_bag(vault, operation, operator_cap, ...)
```

2. **Admin freezes operator mid-operation**:
```
vault_manage::set_operator_freezed(admin_cap, operation, operator_cap_id, true)
```

3. **Operator attempts to end operation** → FAILS with ERR_OPERATOR_FREEZED:
```
operation::end_op_with_bag(vault, operation, operator_cap, ...)
// Aborts at assert_operator_not_freezed check
```

4. **Admin attempts to enable/disable vault** → FAILS with ERR_VAULT_DURING_OPERATION:
```
vault_manage::set_vault_enabled(admin_cap, vault, true)
// Aborts due to status check
```

5. **User attempts deposit** → FAILS with ERR_VAULT_NOT_NORMAL:
```
vault.request_deposit(...)
// Aborts at assert_normal check
```

**Expected:** Vault recovers to NORMAL status
**Actual:** Vault permanently stuck in DURING_OPERATION status, all user operations blocked

**Success condition:** Vault remains in DURING_OPERATION status indefinitely, all deposit/withdraw requests fail, with no recovery path except unfreezing the operator (defeating the freeze mechanism's security purpose).

### Citations

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
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

**File:** volo-vault/sources/volo_vault.move (L715-716)
```text
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L904-905)
```text
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L105-106)
```text
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/operation.move (L218-219)
```text
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
```

**File:** volo-vault/sources/operation.move (L306-307)
```text
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
```

**File:** volo-vault/sources/operation.move (L375-376)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```
