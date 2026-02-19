### Title
Operator Freeze Mechanism Ineffective for In-Progress Operations Creating Vault Hostage Scenario

### Summary
The operator freeze mechanism cannot prevent malicious operators from completing operations already in progress. When an operator is frozen mid-operation, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no admin recovery mechanism, forcing the admin to unfreeze the potentially malicious operator to restore vault functionality. This creates a hostage situation where operators can compel their own unfreezing.

### Finding Description

The vulnerability stems from the interaction between operator freezing and vault operation lifecycle: [1](#0-0) 

When an operator calls `start_op_with_bag()`, the freeze check occurs at the function entry, then the vault status changes to `VAULT_DURING_OPERATION_STATUS`: [2](#0-1) 

If the admin freezes the operator after this point via `set_operator_freezed()`: [3](#0-2) [4](#0-3) 

The operator cannot complete the operation because `end_op_with_bag()` and `end_op_value_update_with_bag()` both check freeze status at entry: [5](#0-4) [6](#0-5) 

**Critical Design Flaw:** The admin has NO mechanism to restore vault functionality without unfreezing the operator:

1. `set_enabled()` explicitly rejects status changes during operations: [7](#0-6) 

2. `set_status()` is `package` visibility only and not exposed to admin: [8](#0-7) 

3. No admin function exists to force-complete or cancel operations

4. The vault cannot accept new user operations while in `VAULT_DURING_OPERATION_STATUS`: [9](#0-8) 

### Impact Explanation

**Operational Impact:**
- Vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` when operator is frozen mid-operation
- All user deposits/withdrawals blocked (require `VAULT_NORMAL_STATUS`)
- Complete vault DoS until operator is unfrozen

**Security Impact:**
- Admin forced to unfreeze potentially malicious operator to restore functionality
- Operator can complete malicious operations constrained only by loss tolerance (default 0.1% per epoch)
- Freeze mechanism ineffective for in-progress operations, creating false sense of security

**Hostage Scenario:**
- Malicious operator can deliberately trigger freeze detection after starting operation
- Admin must choose between permanent vault DoS or allowing operation completion
- Operator effectively controls their own unfreeze through vault hostage

**Affected Parties:**
- All vault users (unable to access funds during DoS)
- Protocol (reputation damage, loss up to tolerance limits)
- Admin (forced into no-win decision)

### Likelihood Explanation

**Attack Preconditions:**
- Operator has valid `OperatorCap` (requires prior admin trust)
- Operator starts operation via `start_op_with_bag()`
- Admin detects malicious behavior and freezes operator mid-operation

**Realistic Scenarios:**
1. Operator key compromise detected after operation starts
2. Operator exhibits malicious behavior during operation execution  
3. Operator deliberately triggers freeze to hold vault hostage
4. Admin accidentally freezes wrong operator during active operation

**Execution Complexity:** Low
- Standard operation lifecycle (start → freeze → forced unfreeze)
- No special timing or race conditions required
- Operator controls initiation timing

**Detection Challenges:**
- Admin may not detect malicious intent until mid-operation
- Once detected, admin has no safe response (DoS vs. allow completion)

**Probability:** Medium
- Depends on operator becoming malicious/compromised after receiving OperatorCap
- Attack provides clear benefit (completion guarantee) with minimal cost
- No alternative admin recovery path increases likelihood of exploitation

### Recommendation

**Immediate Mitigation:**
Add admin emergency function to force-complete operations and reset vault status:

```move
public fun admin_force_complete_operation<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.check_version();
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, ERR_VAULT_NOT_DURING_OPERATION);
    
    // Reset operation state
    vault.clear_op_value_update_record();
    vault.set_status(VAULT_NORMAL_STATUS);
    
    // Reset tolerance to prevent accumulated state issues
    vault.try_reset_tolerance(true, ctx);
    
    emit(AdminForceCompletedOperation { vault_id: vault.vault_id() });
}
```

**Alternative Approach:**
Implement operation timeout mechanism:

```move
public struct Operation {
    id: UID,
    freezed_operators: Table<address, bool>,
    operation_start_time: Table<address, u64>, // Track when each vault started operation
}

public fun admin_cancel_stale_operation<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    clock: &Clock,
    max_operation_time: u64, // e.g., 1 hour
) {
    vault.check_version();
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, ERR_VAULT_NOT_DURING_OPERATION);
    
    let vault_id = vault.vault_id();
    assert!(operation.operation_start_time.contains(vault_id), ERR_NO_OPERATION_RECORD);
    
    let start_time = *operation.operation_start_time.borrow(vault_id);
    assert!(clock.timestamp_ms() - start_time > max_operation_time, ERR_OPERATION_NOT_STALE);
    
    // Force complete
    vault.clear_op_value_update_record();
    vault.set_status(VAULT_NORMAL_STATUS);
    operation.operation_start_time.remove(vault_id);
}
```

**Invariant Checks:**
- Add `max_operation_duration` check in all operation completion functions
- Emit events when operations exceed expected duration
- Add monitoring for vaults stuck in `DURING_OPERATION` status

**Testing:**
- Test freeze during each operation phase (start, mid, end)
- Verify admin can recover vault without unfreezing operator
- Test operation timeout triggers correctly
- Verify loss tolerance still enforced on forced completion

### Proof of Concept

**Initial State:**
- Vault in `VAULT_NORMAL_STATUS`
- Operator has valid `OperatorCap` (ID: `0xOPERATOR`)
- Admin has `AdminCap`

**Attack Sequence:**

1. **Operator starts malicious operation:**
```
start_op_with_bag<USDC, SUI, NaviObligation>(
    vault,
    operation,
    operator_cap, // freeze check passes
    clock,
    defi_asset_ids,
    defi_asset_types,
    principal_amount,
    coin_type_asset_amount,
    ctx
)
// Vault status → VAULT_DURING_OPERATION_STATUS
```

2. **Admin detects malicious behavior and freezes operator:**
```
set_operator_freezed(
    admin_cap,
    operation,
    0xOPERATOR, // operator cap ID
    true // freeze
)
```

3. **Operator attempts to complete (fails):**
```
end_op_with_bag(..., operator_cap, ...) 
// Aborts with ERR_OPERATOR_FREEZED (5_015)
```

4. **Vault is now stuck:**
```
// Users cannot deposit:
request_deposit(...) // Aborts: ERR_VAULT_NOT_NORMAL

// Users cannot withdraw:  
request_withdraw(...) // Aborts: ERR_VAULT_NOT_NORMAL

// Admin cannot re-enable:
set_vault_enabled(admin_cap, vault, true)
// Aborts: ERR_VAULT_DURING_OPERATION
```

5. **Admin forced to unfreeze to restore vault:**
```
set_operator_freezed(
    admin_cap,
    operation,  
    0xOPERATOR,
    false // unfreeze - ONLY option to unstick vault
)
```

6. **Operator completes malicious operation:**
```
end_op_with_bag(...) // Now succeeds
end_op_value_update_with_bag(...) // Completes with loss up to tolerance
// Vault status → VAULT_NORMAL_STATUS
```

**Expected Result:** Admin can force-complete or cancel operation without unfreezing

**Actual Result:** Admin must unfreeze operator, allowing malicious operation completion

**Success Condition:** Malicious operator completes operation despite being frozen, causing loss up to tolerance limit while holding vault hostage until unfrozen

### Citations

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

**File:** volo-vault/sources/operation.move (L209-218)
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
```

**File:** volo-vault/sources/operation.move (L299-307)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
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

**File:** volo-vault/sources/volo_vault.move (L518-523)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L533-535)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;
```

**File:** volo-vault/sources/volo_vault.move (L645-651)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}

public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```
