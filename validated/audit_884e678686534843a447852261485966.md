### Title
Vault Permanent DoS via Incomplete Operation - No Admin Recovery Mechanism

### Summary
The Volo vault can become permanently stuck in `VAULT_DURING_OPERATION_STATUS` if an operator initiates an operation via `start_op_with_bag` but fails to complete the three-step operation flow. This maps to external report Issue #2 (state transition causing DoS). Once stuck, all user deposits and withdrawals are permanently blocked, and no admin function exists to reset the vault status back to normal.

### Finding Description

The vulnerability stems from the vault's three-step operation pattern and inadequate recovery mechanisms:

**Root Cause:**

When `operation::start_op_with_bag` is called, the vault status is set to `VAULT_DURING_OPERATION_STATUS` via `pre_vault_check`: [1](#0-0) 

The status can only be reset back to `VAULT_NORMAL_STATUS` in `end_op_value_update_with_bag`: [2](#0-1) 

**Why Current Protections Fail:**

User deposit and withdraw requests both require `assert_normal()`, which checks `status == VAULT_NORMAL_STATUS`: [3](#0-2) [4](#0-3) [5](#0-4) 

The admin's `set_enabled` function explicitly prevents status changes when vault is in `VAULT_DURING_OPERATION_STATUS`: [6](#0-5) 

The `set_status` function is `public(package)` and has no admin wrapper in the manage module: [7](#0-6) 

**Exploit Path:**

1. Operator calls `start_op_with_bag` in transaction T1 → status set to `VAULT_DURING_OPERATION_STATUS` → T1 succeeds
2. Operator never calls `end_op_with_bag` and `end_op_value_update_with_bag` (malicious, compromised account, or operational error)
3. Vault remains stuck with `status = VAULT_DURING_OPERATION_STATUS`
4. All user `request_deposit` calls abort at `assert_normal()` 
5. All user `request_withdraw` calls abort at `assert_normal()`
6. Admin cannot call `set_enabled` to recover (aborts with `ERR_VAULT_DURING_OPERATION`)
7. No other admin function can reset the status
8. Vault and all user funds are permanently inaccessible

### Impact Explanation

**Critical Protocol DoS:**
- All user deposit requests permanently blocked
- All user withdraw requests permanently blocked  
- All user funds locked in vault with no recovery path
- No existing request processing can proceed
- Vault effectively bricked until status reset mechanism added

**Severity: Critical** - Complete loss of vault availability and user fund accessibility with no recovery mechanism.

### Likelihood Explanation

**High Likelihood:**

The vulnerability can be triggered through multiple realistic scenarios:

1. **Operator Error**: Operator initiates operation but transaction sequence interrupted (network issues, wallet disconnection, gas estimation failure in subsequent steps)

2. **Malicious Operator**: Rogue operator intentionally triggers DoS before operator freeze can be activated

3. **Compromised Operator Key**: Attacker gains operator credentials and intentionally bricks vault

4. **Operational Mistakes**: Operator calls `start_op_with_bag` in wrong sequence or with incorrect parameters, causing subsequent steps to fail

The operator freeze mechanism exists but provides no protection once status is already set to `VAULT_DURING_OPERATION_STATUS`: [8](#0-7) 

### Recommendation

**Add Admin Emergency Status Reset Function:**

Add to `volo-vault/sources/manage.move`:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Allow admin to forcibly reset status to NORMAL
    // Should only be used in emergency when operation is stuck
    vault.set_status(VAULT_NORMAL_STATUS);
}
```

**Alternative: Modify set_enabled to allow override:**

Update the check in `set_enabled` to allow admin override: [9](#0-8) 

Change from:
```move
assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

To allow admin to force-enable even during operations (with appropriate safeguards).

### Proof of Concept

**Setup:**
- Vault deployed with normal configuration
- Operator has valid `OperatorCap`
- Users have deposited funds and hold receipts

**Exploit Steps:**

```move
// Step 1: Operator starts operation (Transaction 1)
let (defi_assets, tx, tx_check, principal, coin_asset) = operation::start_op_with_bag<SUI, USDC, NaviAccountCap>(
    &mut vault,
    &operation,
    &operator_cap,
    &clock,
    vector[1u8], // defi_asset_ids
    vector[type_name::get<NaviAccountCap>()],
    1000000, // principal_amount
    0,
    ctx
);
// Transaction succeeds, vault.status = VAULT_DURING_OPERATION_STATUS

// Step 2: Operator STOPS (malicious/error/compromised)
// Never calls end_op_with_bag or end_op_value_update_with_bag

// Step 3: User attempts deposit
vault_user_entry::deposit<SUI>(
    &mut vault,
    receipt,
    coin,
    &clock,
    1000000,
    ctx
);
// ABORTS: ERR_VAULT_NOT_NORMAL (vault.status != VAULT_NORMAL_STATUS)

// Step 4: User attempts withdraw
vault_user_entry::request_withdraw<SUI>(
    &mut vault,
    receipt,
    shares,
    expected_amount,
    recipient,
    &clock,
    ctx
);
// ABORTS: ERR_VAULT_NOT_NORMAL (vault.status != VAULT_NORMAL_STATUS)

// Step 5: Admin attempts recovery
vault_manage::set_vault_enabled<SUI>(
    &admin_cap,
    &mut vault,
    true
);
// ABORTS: ERR_VAULT_DURING_OPERATION (vault.status == VAULT_DURING_OPERATION_STATUS)

// Result: Vault permanently stuck, no recovery possible
```

The vault remains in `VAULT_DURING_OPERATION_STATUS` indefinitely with no code path to reset it back to `VAULT_NORMAL_STATUS` without completing the full operation sequence, which the operator has abandoned.

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

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
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

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```
