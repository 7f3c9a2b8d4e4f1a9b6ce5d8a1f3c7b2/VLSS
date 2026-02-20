# Audit Report

## Title
Operator Freeze Mid-Operation Causes Permanent Vault Deadlock

## Summary
The operator freeze mechanism enforces freeze checks at both the start AND end of vault operations. When an admin freezes an operator mid-operation, the frozen operator cannot complete the operation, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`. This blocks all user deposits, withdrawals, and vault operations indefinitely, with no admin emergency recovery function available.

## Finding Description

The freeze state is stored persistently in the shared `Operation` object with a table mapping operator cap IDs to freeze status. [1](#0-0)  The Operation object is created at module initialization and shared globally. [2](#0-1) 

When an operator starts a vault operation via `start_op_with_bag`, the freeze check passes if the operator is not frozen. [3](#0-2)  The function then calls `pre_vault_check` which sets the vault status to `VAULT_DURING_OPERATION_STATUS`. [4](#0-3) 

**The critical flaw:** Freeze checks are ALSO enforced when ending operations. Both `end_op_with_bag` [5](#0-4)  and `end_op_value_update_with_bag` [6](#0-5)  call `assert_operator_not_freezed` at their entry points.

The freeze check aborts with `ERR_OPERATOR_FREEZED` if the operator is frozen. [7](#0-6) [8](#0-7) 

**Deadlock Scenario:**
1. Operator calls `start_op_with_bag` → vault enters `VAULT_DURING_OPERATION_STATUS`
2. Admin freezes operator via `set_operator_freezed` [9](#0-8) 
3. Operator tries to call `end_op_with_bag` or `end_op_value_update_with_bag` → **ABORTS** with `ERR_OPERATOR_FREEZED`
4. Vault stuck in `VAULT_DURING_OPERATION_STATUS`
5. The ONLY way to reset vault status back to `VAULT_NORMAL_STATUS` is via `end_op_value_update_with_bag` [10](#0-9) , which cannot be called

All user operations require `VAULT_NORMAL_STATUS` or `assert_not_during_operation`, blocking:
- Deposit requests [11](#0-10) 
- Withdrawal requests [12](#0-11) 
- Execute deposits [13](#0-12) 
- Execute withdrawals [14](#0-13) 
- Cancel deposits [15](#0-14) 
- Cancel withdrawals [16](#0-15) 

Critically, the only admin function that modifies vault status (`set_enabled`) explicitly prevents status changes during operations. [17](#0-16)  The `set_status` function itself is package-only (`public(package)`) and cannot be called directly by admin. [18](#0-17) 

The ONLY recovery path is for the admin to unfreeze the operator, let them complete the operation, then re-freeze - completely defeating the purpose of emergency operator freezing.

## Impact Explanation

**Critical Protocol DoS:**
- All user deposit/withdrawal requests completely blocked
- All pending request executions blocked  
- All request cancellations blocked (deposit cancels check `assert_not_during_operation`, withdraw cancels check `assert_normal`)
- Vault's entire TVL becomes inaccessible to all users indefinitely
- No new vault operations can be started

**Fund Impact:**
While funds are not stolen, they become completely locked and inaccessible. For high-TVL vaults (potentially millions of dollars), even temporary inaccessibility represents severe operational risk, loss of user confidence, and potential liquidation risks if users have positions elsewhere dependent on vault access.

**Security Control Failure:**
The freeze mechanism, designed as a security control to immediately stop a compromised operator, becomes counterproductive - creating total vault lockup rather than protecting users. This is a fundamental design flaw where the "security feature" causes more harm than the threat it's meant to prevent.

## Likelihood Explanation

**High Likelihood:**

1. **Expected Use Case**: Admin detecting suspicious operator behavior and immediately freezing them is THE intended use case for the freeze feature. The admin may not know the operator is mid-operation when making this legitimate security decision, making this scenario highly likely.

2. **Natural Race Condition**: Vault operations are inherently long-running, involving multiple DeFi protocol interactions across Navi, Cetus, Suilend, and Momentum. During this execution window (which could be minutes), if the admin detects anomalies and freezes the operator, the deadlock occurs.

3. **No Warning or Prevention**: The freeze action succeeds without error or warning. The deadlock only becomes apparent when subsequent operations fail, so the admin may not realize the mistake until user complaints arrive and significant damage has occurred.

**Feasibility:**
- Requires only normal admin and operator capabilities (both explicitly trusted roles per the threat model)
- No special timing requirements beyond natural operation duration
- Admin freeze is a legitimate security response to suspicious activity
- The operation duration window provides ample opportunity for this race condition

## Recommendation

**Option 1 (Recommended): Remove freeze check from operation end functions**
Remove the `assert_operator_not_freezed` calls from `end_op_with_bag` and `end_op_value_update_with_bag`. This allows frozen operators to complete their current in-flight operation but prevents them from starting new ones. This is the safest approach as it:
- Allows vault to recover from VAULT_DURING_OPERATION_STATUS
- Still prevents frozen operators from initiating new operations
- Maintains funds safety (operation completion returns all borrowed assets)

**Option 2: Add admin emergency recovery function**
Add an admin-only function to force-reset vault status:
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

However, this is less secure as it bypasses operation completion checks and may leave assets in inconsistent states.

**Option 3: Add status check before allowing freeze**
Prevent freezing operators who are currently mid-operation by checking if any vault is in VAULT_DURING_OPERATION_STATUS. This is complex and doesn't solve the fundamental design issue.

## Proof of Concept

```move
#[test]
fun test_freeze_mid_operation_deadlock() {
    let mut scenario = test_scenario::begin(@admin);
    
    // Setup: Create vault, operation, admin cap, operator cap
    {
        let ctx = test_scenario::ctx(&mut scenario);
        vault::init(ctx);
    };
    test_scenario::next_tx(&mut scenario, @admin);
    
    let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
    let mut operation = test_scenario::take_shared<Operation>(&scenario);
    let operator_cap = vault::create_operator_cap(&admin_cap, test_scenario::ctx(&mut scenario));
    let op_cap_id = object::id_address(&operator_cap);
    
    // Create vault
    vault::create_vault<SUI>(&admin_cap, test_scenario::ctx(&mut scenario));
    test_scenario::next_tx(&mut scenario, @operator);
    let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
    
    // Step 1: Operator starts operation - vault enters VAULT_DURING_OPERATION_STATUS
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    let (bag, tx_bag, tx_value_bag, principal, coin_asset) = operation::start_op_with_bag<SUI, USDC, Obligation>(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[],
        vector[],
        0,
        0,
        test_scenario::ctx(&mut scenario)
    );
    
    // Verify vault is in VAULT_DURING_OPERATION_STATUS
    assert!(vault.status() == 1, 0); // VAULT_DURING_OPERATION_STATUS = 1
    
    test_scenario::next_tx(&mut scenario, @admin);
    
    // Step 2: Admin freezes operator (legitimate security response)
    vault::set_operator_freezed(&mut operation, op_cap_id, true);
    
    test_scenario::next_tx(&mut scenario, @operator);
    
    // Step 3: Operator tries to end operation - THIS WILL ABORT
    // This test proves the vulnerability exists
    operation::end_op_with_bag<SUI, USDC, Obligation>(
        &mut vault,
        &operation,
        &operator_cap,
        bag,
        tx_bag,
        principal,
        coin_asset
    ); // This will abort with ERR_OPERATOR_FREEZED
    
    // Vault is now permanently stuck in VAULT_DURING_OPERATION_STATUS
    // All user operations (deposit, withdraw, cancel, execute) will fail
    
    clock::destroy_for_testing(clock);
    test_scenario::return_shared(vault);
    test_scenario::return_shared(operation);
    test_scenario::return_to_sender(&scenario, admin_cap);
    test_scenario::return_to_sender(&scenario, operator_cap);
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability demonstrates a critical design flaw in the operator freeze mechanism. The security control (operator freeze) creates a denial-of-service condition worse than the threat it's meant to prevent. The only recovery requires unfreezing the potentially compromised operator, defeating the entire purpose of the security feature.

The vulnerability is exacerbated by the fact that vault operations are inherently long-running due to external DeFi protocol interactions, creating a large window for this race condition to occur during normal protocol operation.

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

**File:** volo-vault/sources/volo_vault.move (L353-357)
```text
    let operation = Operation {
        id: object::new(ctx),
        freezed_operators: table::new(ctx),
    };
    transfer::share_object(operation);
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

**File:** volo-vault/sources/operation.move (L105-105)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L218-218)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L306-306)
```text
    vault::assert_operator_not_freezed(operation, cap);
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
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
