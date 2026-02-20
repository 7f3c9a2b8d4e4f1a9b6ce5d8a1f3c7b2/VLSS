# Audit Report

## Title
Oracle Dependency DoS: Vault Operations Permanently Stuck When Receipt Valuation Fails

## Summary
The vault's operation lifecycle requires all borrowed DeFi assets to have their USD values updated before completion. When a Receipt asset is borrowed and oracle valuation fails (due to missing aggregator or stale price), the operation cannot complete, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no admin recovery mechanism. This blocks all user deposits and withdrawals indefinitely.

## Finding Description

The vulnerability exists in the receipt valuation flow during vault operations. During the operation lifecycle, when `update_receipt_value()` is called, it invokes `get_receipt_value()` which fetches the oracle price for the receipt's underlying vault principal coin type [1](#0-0) 

This oracle call chains to `get_asset_price()` which can abort for two critical reasons:

1. **Missing aggregator**: If no oracle aggregator exists for the asset type [2](#0-1) 

2. **Stale price**: If the price hasn't been updated within the configured interval [3](#0-2) 

The default update interval is aggressively set to 60 seconds [4](#0-3) 

**Attack Path:**

1. Operator initiates an operation via `start_op_with_bag()`, which transitions the vault status to `VAULT_DURING_OPERATION_STATUS` [5](#0-4) 

2. When a Receipt is borrowed as a DeFi asset, it's automatically tracked in the operation value update record [6](#0-5) 

3. After assets are returned via `end_op_with_bag()`, the operator must call `update_receipt_value()` which internally calls `get_receipt_value()`. If the oracle price fetch aborts (missing aggregator or stale price beyond 60 seconds), the transaction fails and the Receipt's value remains unupdated.

4. When attempting to complete the operation via `end_op_value_update_with_bag()`, it validates that all borrowed assets were successfully updated [7](#0-6)  The validation iterates through all borrowed assets and asserts each was marked as updated [8](#0-7) 

5. This check fails because the Receipt asset was never successfully updated, aborting the operation completion and leaving the vault stuck.

**No Admin Recovery:**

The protocol lacks any emergency recovery mechanism:

- The admin's `set_enabled()` function explicitly prevents status changes during operations [9](#0-8) 

- The `clear_op_value_update_record()` function is package-scoped and cannot be called externally by admins [10](#0-9) 

- The admin management interface in `manage.move` provides no emergency vault status reset function [11](#0-10) 

## Impact Explanation

**Complete Vault DoS:**

While the vault is stuck in `VAULT_DURING_OPERATION_STATUS`, all user operations are blocked because they require the vault to be in `VAULT_NORMAL_STATUS`:

- User deposit requests are blocked [12](#0-11) 

- User withdrawal requests are blocked [13](#0-12) 

- The `assert_normal()` check enforces that vault status equals `VAULT_NORMAL_STATUS` (value 0), which fails when status is `VAULT_DURING_OPERATION_STATUS` (value 1) [14](#0-13) 

**Concrete Impact:**
- All user deposit requests permanently blocked
- All user withdrawal requests permanently blocked  
- Pending deposit/withdrawal requests cannot be executed by operators
- User funds effectively locked in vault with no access path
- No new operations can start (requires NORMAL status)
- No admin emergency recovery mechanism available

The vault remains non-operational until the underlying oracle issue is resolved (aggregator added or price updated), during which all user funds are inaccessible.

## Likelihood Explanation

**Scenario A: Missing Aggregator (Medium Likelihood)**
During multi-vault deployments, an admin may add a Receipt asset pointing to a vault with principal coin type X, but forget to configure an oracle aggregator for type X in the OracleConfig. Any operation borrowing that receipt will permanently fail. This is realistic during rapid protocol expansion or integration of new asset types where configuration steps may be missed.

**Scenario B: Stale Price (Medium-High Likelihood)**
The 60-second staleness threshold is aggressive for production DeFi systems. Network congestion, Switchboard oracle keeper delays, or deliberate griefing during high gas periods can prevent timely price updates. Multi-phase operations exacerbate this - a price may be fresh when the operation starts but become stale during the external DeFi operations before value updates are called. This is a known operational risk in DeFi protocols, especially on congested networks.

**Attack Complexity:** Low - Can occur naturally through operational errors (misconfiguration) or network conditions (congestion). No special privileges required beyond normal operator capabilities. Easy to detect vault stuck state via status query, but no recovery path exists without resolving the root oracle issue.

**Preconditions:**
- Vault has Receipt asset configured as borrowable DeFi asset
- Either: (1) Oracle misconfiguration (missing aggregator for receipt's principal coin type), OR (2) Price staleness exceeding 60-second threshold during the operation window

## Recommendation

Implement multiple layers of protection:

1. **Emergency Admin Recovery Function**: Add an admin-callable function to force-reset vault status and clear operation records in emergency situations:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
    // Emit emergency event for monitoring
}
```

2. **Increase Oracle Staleness Threshold**: Consider increasing the default `update_interval` from 60 seconds to 120-180 seconds to account for network congestion and multi-phase operation duration.

3. **Graceful Degradation for Receipt Valuation**: Add try-catch logic or fallback mechanisms for receipt value updates:
   - Allow operations to complete with last known receipt value if oracle temporarily unavailable
   - Skip receipt value validation if receipt was not modified during operation
   - Add operator override capability with caps on maximum override duration

4. **Pre-Operation Validation**: Add checks in `start_op_with_bag()` to verify all oracle aggregators exist for borrowed assets before allowing operation to proceed.

## Proof of Concept

```move
#[test]
fun test_vault_stuck_on_receipt_oracle_failure() {
    // Setup: Create vault A with principal type X
    // Setup: Create vault B with Receipt asset pointing to vault A
    // Setup: Oracle config has NO aggregator for type X
    
    // Step 1: Operator starts operation, borrows Receipt
    let (bag, tx, tx_update, principal, coin) = operation::start_op_with_bag(
        vault_b, operation, op_cap, clock, 
        vector[RECEIPT_IDX], vector[type_name::get<Receipt>()],
        0, 0, ctx
    );
    // Vault B now in VAULT_DURING_OPERATION_STATUS
    
    // Step 2: Return assets
    operation::end_op_with_bag(vault_b, operation, op_cap, bag, tx, principal, coin);
    
    // Step 3: Attempt to update receipt value - ABORTS
    // receipt_adaptor::update_receipt_value() calls oracle which aborts with ERR_AGGREGATOR_NOT_FOUND
    // Transaction fails, receipt value not updated
    
    // Step 4: Attempt to complete operation - ABORTS  
    // operation::end_op_value_update_with_bag() calls check_op_value_update_record()
    // Validation fails: receipt not in asset_types_updated table
    // Aborts with ERR_USD_VALUE_NOT_UPDATED
    
    // Result: Vault B permanently stuck in VAULT_DURING_OPERATION_STATUS
    // All user deposits/withdrawals blocked indefinitely
    // No admin recovery available
}
```

### Citations

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-63)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );
```

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
```

**File:** volo-vault/sources/oracle.move (L129-129)
```text
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
```

**File:** volo-vault/sources/oracle.move (L135-135)
```text
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L649-650)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1215-1217)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/volo_vault.move (L1222-1222)
```text
public(package) fun clear_op_value_update_record<PrincipalCoinType>(
```

**File:** volo-vault/sources/volo_vault.move (L1424-1425)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
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
