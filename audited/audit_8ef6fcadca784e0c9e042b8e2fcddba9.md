# Audit Report

## Title
Missing Admin Emergency Function to Reset Vault Status Causes Permanent DoS When Operator Frozen During Operation

## Summary
The Volo vault system lacks an admin emergency function to reset vault status from `DURING_OPERATION` back to `NORMAL`. When an operator starts an operation but becomes frozen or unavailable before completing it, the vault becomes permanently stuck because the frozen operator cannot complete the operation and admin cannot force-reset the vault status. This creates an irrecoverable deadlock, completely blocking all user operations and trapping funds.

## Finding Description

**Vault Status State Machine:**

The vault operates with three distinct statuses defined in the system: [1](#0-0) 

**Operation Lifecycle and the Deadlock:**

When an operator initiates an operation via `start_op_with_bag`, the vault transitions to `DURING_OPERATION` status through the `pre_vault_check` function: [2](#0-1) 

To complete the operation and return the vault to `NORMAL` status, the operator must successfully call both `end_op_with_bag` and `end_op_value_update_with_bag`. However, both functions check that the operator is not frozen: [3](#0-2)  and [4](#0-3) 

The critical status reset to `NORMAL` only happens at the end of `end_op_value_update_with_bag`: [5](#0-4) 

**The Deadlock Mechanism:**

Admin can freeze any operator at any time through the `set_operator_freezed` function: [6](#0-5)  This function is accessible to admin via: [7](#0-6) 

When an operator is frozen, the `assert_operator_not_freezed` check will abort with `ERR_OPERATOR_FREEZED`: [8](#0-7) 

**No Admin Recovery Path:**

The admin's `set_vault_enabled` function explicitly cannot be used when the vault is in `DURING_OPERATION` status: [9](#0-8) 

All user operations require `NORMAL` status or explicitly check against `DURING_OPERATION`:
- Deposit requests: [10](#0-9) 
- Withdraw requests: [11](#0-10) 
- Cancel deposit: [12](#0-11) 
- Cancel withdraw: [13](#0-12) 
- Execute deposit: [14](#0-13) 
- Execute withdraw: [15](#0-14) 

The admin interface provides no emergency status reset function. While other admin functions exist for configuration changes, none can bypass the `DURING_OPERATION` status lock: [16](#0-15) 

The `set_status` function itself is package-private and cannot be called directly by admin: [17](#0-16) 

**Important Note on Mitigation:**

While technically any non-frozen operator can complete an operation (the `TxBag` structure doesn't tie operations to specific operators), this does not fully mitigate the vulnerability because:
1. Many protocol deployments use a single operator
2. Security incidents may require freezing all operators simultaneously
3. Admin may want to ABORT (not complete) a suspicious operation, but lacks that capability
4. Other operators may lack context or authorization to safely complete a partially-executed operation

## Impact Explanation

**Critical Protocol Denial of Service:**

The impact is severe and measurable:

- **Vault Lockout**: The vault becomes permanently stuck in `DURING_OPERATION` status with no recovery mechanism
- **User Fund Trapping**: All user operations (deposits, withdrawals, cancellations) are blocked indefinitely
- **Request Buffer Lock**: Pending requests cannot be executed or cancelled, trapping user funds in request buffers
- **Principal Custody**: User principal and fees remain locked in the vault with no withdrawal path
- **Admin Powerless**: Even admin with `AdminCap` cannot disable/enable the vault or force status reset
- **Protocol Reputation**: Complete unavailability damages protocol reputation and user trust

This breaks the fundamental protocol invariant that admin should always have emergency control over vault operations. The vault becomes a permanent denial-of-service with no on-chain recovery path short of a protocol upgrade.

## Likelihood Explanation

**Realistic Operational Scenarios:**

Multiple realistic scenarios can trigger this deadlock:

1. **Security Response**: Admin detects suspicious operator behavior mid-operation (unusual transaction patterns, attempted exploit) and immediately freezes the operator to protect protocol assets. The vault is now stuck.

2. **Compromised Operator**: Operator private key is compromised, admin freezes to prevent asset theft, but the operation was already started and cannot be completed.

3. **Operational Bug Discovery**: A critical bug is discovered in the operator's transaction flow after an operation has started. Admin freezes to prevent further damage, causing deadlock.

4. **Infrastructure Failure**: Single operator deployment experiences server crash, network partition, or key management system failure during operation. Admin may freeze the unresponsive operator.

5. **Multiple Operator Freeze**: In security incidents, admin may need to freeze all operators simultaneously, leaving no one to complete ongoing operations.

**Preconditions:**
- Operator legitimately starts an operation (normal protocol activity)
- Operator becomes frozen or unavailable before calling both completion functions
- No other trusted, unfrozen operator available (common in single-operator deployments)

These preconditions are trivial and require no special privileges or complex setup. The operator freeze mechanism is a standard admin security control, making this scenario highly realistic in production deployments.

## Recommendation

Add an admin emergency function to force-reset vault status from `DURING_OPERATION` back to `NORMAL`:

```move
// In vault_manage.move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.force_reset_status();
}

// In volo_vault.move
public(package) fun force_reset_status<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
) {
    self.check_version();
    // Only allow reset from DURING_OPERATION to NORMAL
    assert!(self.status() == VAULT_DURING_OPERATION_STATUS, ERR_VAULT_NOT_DURING_OPERATION);
    
    // Clear operation value update record
    self.clear_op_value_update_record();
    
    // Reset status to normal
    self.set_status(VAULT_NORMAL_STATUS);
    
    emit(EmergencyVaultStatusReset {
        vault_id: self.vault_id(),
        previous_status: VAULT_DURING_OPERATION_STATUS,
        new_status: VAULT_NORMAL_STATUS,
    });
}
```

This provides admin with emergency recovery capability while maintaining security through the `AdminCap` requirement. The function should only be used when an operation cannot be completed normally (frozen/unavailable operator).

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Operator calls `start_op_with_bag` → vault status becomes `DURING_OPERATION`
2. Admin calls `set_operator_freezed(operator_cap_id, true)` → operator is frozen
3. Operator attempts to call `end_op_with_bag` → transaction aborts with `ERR_OPERATOR_FREEZED`
4. Operator attempts to call `end_op_value_update_with_bag` → transaction aborts with `ERR_OPERATOR_FREEZED`
5. Admin attempts to call `set_vault_enabled(false)` → transaction aborts with `ERR_VAULT_DURING_OPERATION`
6. User attempts any operation (deposit/withdraw/cancel) → transaction aborts with `ERR_VAULT_NOT_NORMAL` or `ERR_VAULT_DURING_OPERATION`
7. Vault remains permanently stuck with no recovery path

The vulnerability is confirmed by code inspection showing:
- No admin function exists to reset status from `DURING_OPERATION` to `NORMAL`
- All status-changing paths are blocked when vault is `DURING_OPERATION` and operator is frozen
- All user operations are gated by vault status checks that fail during operation

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

**File:** volo-vault/sources/operation.move (L209-220)
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

**File:** volo-vault/sources/operation.move (L299-308)
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

**File:** volo-vault/sources/manage.move (L1-176)
```text
module volo_vault::vault_manage;

use std::ascii::String;
use sui::balance::Balance;
use sui::clock::Clock;
use switchboard::aggregator::Aggregator;
use volo_vault::reward_manager::{Self, RewardManager};
use volo_vault::vault::{Self, Operation, Vault, AdminCap, OperatorCap};
use volo_vault::vault_oracle::OracleConfig;

// ------------------------ Vault Status ------------------------ //

public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}

#[allow(unused_variable)]
public fun upgrade_vault<PrincipalCoinType>(_: &AdminCap, vault: &mut Vault<PrincipalCoinType>) {
    vault.upgrade_vault();
}

public fun upgrade_reward_manager<PrincipalCoinType>(
    _: &AdminCap,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
) {
    reward_manager.upgrade_reward_manager();
}

public fun upgrade_oracle_config(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
) {
    oracle_config.upgrade_oracle_config();
}

// ------------------------ Setters ------------------------ //

public fun set_deposit_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    deposit_fee: u64,
) {
    vault.set_deposit_fee(deposit_fee);
}

public fun set_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    withdraw_fee: u64,
) {
    vault.set_withdraw_fee(withdraw_fee);
}

public fun set_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    loss_tolerance: u256,
) {
    vault.set_loss_tolerance(loss_tolerance);
}

public fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_cancel_request(locking_time);
}

public fun set_locking_time_for_withdraw<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_withdraw(locking_time);
}

// ------------------------ Operator ------------------------ //

public fun create_operator_cap(_: &AdminCap, ctx: &mut TxContext): OperatorCap {
    vault::create_operator_cap(ctx)
}

public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
}

// ------------------------ Oracle ------------------------ //

public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}

public fun remove_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    asset_type: String,
) {
    oracle_config.remove_switchboard_aggregator(asset_type);
}

public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}

public fun set_update_interval(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    update_interval: u64,
) {
    oracle_config.set_update_interval(update_interval);
}

public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}

// ------------------------ Fees ------------------------ //

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

// ------------------------ Reward Manager ------------------------ //

public fun create_reward_manager<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &mut TxContext,
) {
    reward_manager::create_reward_manager<PrincipalCoinType>(vault, ctx);
}

// ------------------------ Reset Loss Tolerance ------------------------ //

public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.try_reset_tolerance(true, ctx);
}
```
