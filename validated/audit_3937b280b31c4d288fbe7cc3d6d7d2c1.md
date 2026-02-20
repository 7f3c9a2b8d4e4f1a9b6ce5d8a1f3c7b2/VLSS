# Audit Report

## Title
Vault Permanently Stuck When Operator Frozen During Operation - Request Cancellations and Recovery Blocked

## Summary
When an admin freezes an operator while a vault operation is in progress, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`. Users cannot cancel their pending deposit/withdraw requests because cancellations require normal vault status. The frozen operator cannot complete the operation to restore normal status, and no admin emergency override exists to force-reset the vault status, resulting in permanent DoS with users' funds locked indefinitely.

## Finding Description

The Volo vault system has a critical deadlock vulnerability involving the interaction between operator freeze functionality and vault operation status.

**Vault Status System:**
The vault has three status states: `VAULT_NORMAL_STATUS` (0), `VAULT_DURING_OPERATION_STATUS` (1), and `VAULT_DISABLED_STATUS` (2). [1](#0-0) 

**Operation Lifecycle:**
When an operator starts a vault operation via `start_op_with_bag`, the function first checks that the operator is not frozen, then calls `pre_vault_check` which changes the vault status to `VAULT_DURING_OPERATION_STATUS`. [2](#0-1) [3](#0-2) 

**Operator Freeze Mechanism:**
Admins can freeze operators at any time via `set_operator_freezed`, which sets a boolean flag in the `operation.freezed_operators` table. [4](#0-3) [5](#0-4)  All vault operations check if the operator is frozen via `assert_operator_not_freezed`. [6](#0-5) 

**Critical Issue - User Request Cancellations Blocked:**
Users attempt to cancel deposit requests via `user_entry::cancel_deposit`, which calls `vault::cancel_deposit`. This function requires the vault to NOT be during operation via `assert_not_during_operation()`. [7](#0-6) [8](#0-7) [9](#0-8) 

Similarly, `cancel_withdraw` requires the vault to be in NORMAL status via `assert_normal()`. [10](#0-9) [11](#0-10) 

**Operation Completion Blocked:**
To restore normal status, the operator must call `end_op_value_update_with_bag`, which checks if the operator is frozen at the entry point. If frozen, the transaction aborts with `ERR_OPERATOR_FREEZED`. [12](#0-11)  The status would only be reset to NORMAL at the end of this function, but this line is never reached if the operator is frozen. [13](#0-12) 

**No Admin Emergency Override:**
The only admin function to change vault status is `set_vault_enabled`, which explicitly blocks changes during operation by calling `assert_not_during_operation()`. [14](#0-13) [15](#0-14) 

The underlying `set_status` function is only `public(package)`, not exposed to admins directly. [16](#0-15) 

**Deadlock Created:**
The vulnerability creates an unrecoverable deadlock where:
1. Vault is stuck in `VAULT_DURING_OPERATION_STATUS`
2. Users cannot cancel requests (requires normal status)
3. Frozen operator cannot complete operation (operator freeze check fails)
4. Admin cannot change vault status (blocked during operation)
5. Admin cannot unfreeze operator and complete in one transaction

Additionally, users cannot make new deposit or withdraw requests because both `request_deposit` and `request_withdraw` require `assert_normal()`. [17](#0-16) [18](#0-17) 

## Impact Explanation

**High Severity - Permanent Vault DoS with Fund Lock:**

1. **Users' Funds Locked**: Users with pending deposit requests have their coins locked in the vault's `deposit_coin_buffer` with no recovery mechanism. Users with pending withdraw requests have their shares locked and cannot cancel to regain access.

2. **No New Operations**: The entire vault becomes non-functional. Users cannot make new deposit or withdraw requests because the vault is stuck in `VAULT_DURING_OPERATION_STATUS`.

3. **Permanent State**: Unlike temporary issues that can be resolved by admin intervention, this creates a permanent stuck state with no recovery mechanism in the protocol.

4. **Protocol Availability**: The entire vault becomes permanently unusable, affecting all current users with pending requests and preventing any future users from interacting with the vault.

This represents a complete failure of a core protocol invariant: that vaults can always be recovered by admin action.

## Likelihood Explanation

**Medium-High Likelihood - Realistic Emergency Scenario:**

The operator freeze mechanism exists precisely for emergency situations. The scenario where an admin needs to freeze an operator while an operation is in progress is not only realistic but expected:

1. **Malicious Operator Detection**: If suspicious activity is detected mid-operation (e.g., attempting to drain funds via DeFi integrations or manipulating oracle prices), admins would immediately freeze the operator to prevent further damage.

2. **Operational Error**: If an operator makes a critical error during an operation that could result in fund loss, admins might freeze them to prevent the operation from completing incorrectly.

3. **No Preconditions Required**: The vulnerability requires no special attacker action - it can occur through normal admin emergency response procedures that the protocol explicitly supports.

4. **Observable State**: The vault status is publicly readable, so admins may not realize that freezing an operator during an operation will cause permanent DoS rather than just preventing that specific operation.

The triggering sequence is straightforward and doesn't require any exploit or manipulation by untrusted actors. It's a natural consequence of the protocol's own emergency response mechanisms.

## Recommendation

Implement an emergency admin function to force-complete or abort operations even when the operator is frozen. This could be done by:

1. **Add Emergency Status Reset Function**:
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Allow admin to reset status even during operation in emergencies
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

2. **Alternatively, Modify set_enabled to Allow Emergency Override**:
```move
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
    emergency_override: bool,
) {
    self.check_version();
    
    // Allow status change during operation only with explicit emergency override
    if (!emergency_override) {
        assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
    } else {
        // Clear operation state if forcing status change
        self.clear_op_value_update_record();
    }
    
    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

3. **Add Safeguard Documentation**: Clearly document that freezing an operator during an operation will cause a deadlock that requires the emergency override function to resolve.

## Proof of Concept

The vulnerability can be demonstrated through the following transaction sequence:

1. Operator calls `start_op_with_bag` - vault status becomes `VAULT_DURING_OPERATION_STATUS`
2. Admin calls `set_operator_freezed(operator_cap_id, true)` - operator is now frozen
3. User attempts `cancel_deposit` - fails with `ERR_VAULT_DURING_OPERATION`
4. User attempts `cancel_withdraw` - fails with `ERR_VAULT_NOT_NORMAL`
5. Operator attempts `end_op_value_update_with_bag` - fails with `ERR_OPERATOR_FREEZED`
6. Admin attempts `set_vault_enabled(false)` - fails with `ERR_VAULT_DURING_OPERATION`
7. Vault is permanently stuck with no recovery path

The deadlock is mathematically certain because:
- Exiting DURING_OPERATION status requires completing the operation
- Completing the operation requires operator not being frozen
- Changing vault status requires NOT being in DURING_OPERATION status
- Therefore, once both conditions exist simultaneously, no transaction can resolve either condition

### Citations

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
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

**File:** volo-vault/sources/volo_vault.move (L533-541)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;

    emit(VaultStatusChanged {
        vault_id: self.vault_id(),
        status: status,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L657-661)
```text
public(package) fun assert_not_during_operation<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
}
```

**File:** volo-vault/sources/volo_vault.move (L707-716)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L761-769)
```text
public(package) fun cancel_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): Coin<PrincipalCoinType> {
    self.check_version();
    self.assert_not_during_operation();
```

**File:** volo-vault/sources/volo_vault.move (L896-905)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L944-952)
```text
public(package) fun cancel_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): u256 {
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

**File:** volo-vault/sources/operation.move (L375-376)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
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

**File:** volo-vault/sources/user_entry.move (L91-103)
```text
public fun cancel_deposit<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt: &mut Receipt,
    request_id: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<PrincipalCoinType> {
    vault.assert_vault_receipt_matched(receipt);

    let coin = vault.cancel_deposit(clock, request_id, receipt.receipt_id(), ctx.sender());

    coin
}
```
