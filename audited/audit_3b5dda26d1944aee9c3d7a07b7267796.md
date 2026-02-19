### Title
Operator Freeze During Active Operation Causes Vault Denial of Service with No Automatic Recovery

### Summary
The Volo vault system exhibits a time-of-check vs time-of-use authorization flaw where freezing an operator mid-operation permanently locks the vault in DURING_OPERATION status. This maps to the external report's vulnerability class where authorization status changes between initiation and completion create an exploitable state. The vault becomes completely inaccessible to users until manual admin intervention, causing protocol-wide denial of service.

### Finding Description

The vulnerability occurs in the three-phase operation flow where operator authorization is checked at operation start but status changes during execution are not handled properly.

**Phase 1 - Operation Start:** [1](#0-0) 

The operator freeze check passes and vault transitions to DURING_OPERATION status: [2](#0-1) 

**Phase 2 - Admin Freezes Operator:** [3](#0-2) 

**Phase 3 - Operation Cannot Complete:**
Both completion functions check operator not frozen, blocking the frozen operator: [4](#0-3) [5](#0-4) 

Only these functions can transition vault back to NORMAL status: [6](#0-5) 

**No Recovery Path Exists:**
The admin cannot force-disable the vault because set_enabled explicitly blocks DURING_OPERATION status: [7](#0-6) 

The set_status function has package-only visibility, preventing direct admin access: [8](#0-7) 

**User Impact:**
All user operations are blocked when vault is DURING_OPERATION:
- request_deposit requires NORMAL status: [9](#0-8) 
- request_withdraw requires NORMAL status: [10](#0-9) 
- cancel_deposit requires NOT DURING_OPERATION: [11](#0-10) 
- execute_deposit requires NORMAL status: [12](#0-11) 
- execute_withdraw requires NORMAL status: [13](#0-12) 

### Impact Explanation

**Severity: High - Protocol-Wide Denial of Service**

When an operator is frozen during an active operation, the vault enters an irrecoverable locked state where:
1. All user deposit requests are blocked (cannot call request_deposit)
2. All user withdrawal requests are blocked (cannot call request_withdraw)  
3. Pending requests cannot be cancelled (cancel functions require non-DURING_OPERATION status)
4. Operators cannot execute pending deposits/withdrawals
5. Admin cannot disable the vault to prevent further damage

The vault remains completely non-functional until the admin manually unfreezes the operator to allow operation completion. During this period, all user funds are locked and inaccessible. This directly maps to the external report's impact where authorization state changes create exploitable protocol states, except here it manifests as DoS rather than bypass.

### Likelihood Explanation

**Likelihood: Medium - Legitimate Operational Scenario**

This vulnerability triggers through a valid administrative workflow, not a compromised admin:

1. **Precondition:** Operator initiates a legitimate operation (common in normal protocol operation)
2. **Trigger:** Admin detects operator misbehavior or needs to revoke access (legitimate administrative action)
3. **Result:** Admin freezes the operator via set_operator_freezed, causing immediate protocol DoS

The scenario is realistic because:
- Operators regularly perform vault operations as part of normal protocol function
- Admins must be able to freeze misbehaving operators for security reasons
- The protocol provides the freeze mechanism specifically for this purpose
- Nothing prevents admin from freezing an operator with an active operation

The vulnerability is NOT blocked by existing checks - the freeze mechanism is working as designed, but the protocol fails to handle the state transition properly, leaving no recovery path except manual unfreeze.

### Recommendation

Implement an administrative emergency recovery function that allows forced completion or cancellation of operations when the operator is frozen:

```move
// Add to manage.move
public fun emergency_complete_operation<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Allow admin to force vault back to NORMAL status
    // Should verify all assets are returned or accept potential loss
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

Alternatively, enhance the freeze mechanism to prevent freezing operators with active operations, or automatically complete pending operations before freeze takes effect.

### Proof of Concept

**Step 1:** Operator starts operation
- Operator calls `start_op_with_bag()` with valid OperatorCap
- Vault transitions from NORMAL (0) to DURING_OPERATION (1) status
- Operator borrows assets from vault

**Step 2:** Admin freezes operator mid-operation
- Admin detects operator misbehavior
- Admin calls `set_operator_freezed(operation, operator_cap_id, true)`
- Operator is now frozen in Operation.freezed_operators table

**Step 3:** Operation cannot complete - DoS occurs
- Frozen operator attempts `end_op_with_bag()` → aborts with ERR_OPERATOR_FREEZED
- Frozen operator attempts `end_op_value_update_with_bag()` → aborts with ERR_OPERATOR_FREEZED
- Vault remains stuck in DURING_OPERATION status

**Step 4:** All user operations blocked
- Users attempt `request_deposit()` → aborts with ERR_VAULT_NOT_NORMAL
- Users attempt `request_withdraw()` → aborts with ERR_VAULT_NOT_NORMAL
- Users attempt `cancel_deposit()` → aborts with ERR_VAULT_DURING_OPERATION

**Step 5:** Admin cannot recover
- Admin attempts `set_vault_enabled(vault, false)` → aborts with ERR_VAULT_DURING_OPERATION

**Recovery:** Admin must unfreeze operator, let them complete operation, then re-freeze. Vault remains in DoS state throughout this manual intervention period.

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

**File:** volo-vault/sources/operation.move (L375-377)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
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

**File:** volo-vault/sources/volo_vault.move (L806-814)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();
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

**File:** volo-vault/sources/volo_vault.move (L994-1002)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
```
