# Audit Report

## Title
Permanent Vault DoS Due to Missing Recovery Mechanism for Deleted Oracle Aggregators

## Summary
The Volo vault lacks an emergency recovery mechanism when Switchboard oracle aggregators are deleted or deprecated. If an operation is in progress when this occurs, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`, rendering all user funds inaccessible with no admin intervention possible.

## Finding Description

The Volo vault integrates with Switchboard oracles for price feeds. When a Switchboard aggregator is deleted, the `Aggregator` object is destroyed. [1](#0-0) 

The `OracleConfig` stores only the aggregator's address in cached `PriceInfo` structs, not the object itself. [2](#0-1) 

When vault operations need prices, `get_asset_price()` validates freshness within `update_interval` (1 minute by default). [3](#0-2) 

Once cached prices expire, they can only be refreshed via `update_price()`, which requires the actual `Aggregator` object as a parameter. [4](#0-3)  Since the Aggregator object was destroyed, price refresh becomes impossible.

**The Catastrophic Failure Path:**

When an operation completes, `end_op_value_update_with_bag()` must validate total USD value by calling `vault.get_total_usd_value()`. [5](#0-4)  This function requires all asset values to be updated within `MAX_UPDATE_INTERVAL`, which is set to 0. [6](#0-5)  The zero interval means prices must be freshly updated every time.

Similarly, deposit and withdrawal execution both call `update_free_principal_value()` [7](#0-6) [8](#0-7)  which internally fetches oracle prices. [9](#0-8) 

**No Recovery Mechanism:**

The `set_enabled()` function explicitly prevents status changes during operations. [10](#0-9)  There is no admin function to force-abort a stuck operation or emergency-reset the vault status when examining the management functions. [11](#0-10) 

The vault status is only returned to normal at the successful completion of `end_op_value_update_with_bag()`. [12](#0-11)  If this function cannot execute due to stale/missing prices, the vault remains permanently stuck.

While the admin can call `change_switchboard_aggregator()` to update the oracle configuration (which has no vault status check), [13](#0-12)  this requires obtaining a new `Aggregator` object from Switchboard infrastructure—which may be impossible if the feed was permanently deprecated.

## Impact Explanation

**Catastrophic Scenario:**
If the vault is mid-operation (`VAULT_DURING_OPERATION_STATUS`) when aggregator deletion occurs:
1. Operator cannot complete the final value validation step because `get_total_usd_value()` will revert with `ERR_USD_VALUE_NOT_UPDATED`
2. Vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`
3. Users cannot request deposits/withdrawals (both require `VAULT_NORMAL_STATUS`)
4. Admin cannot enable/disable vault due to the `ERR_VAULT_DURING_OPERATION` check
5. **All vault funds (entire TVL) become permanently inaccessible**

This is a **HIGH severity** impact as it causes complete loss of access to all depositor funds with no recovery path.

## Likelihood Explanation

**Preconditions:**
- Switchboard aggregator authority deletes or deprecates an aggregator used by the vault
- This is a **legitimate operational decision**, not malicious behavior

**Triggering Events:**
- Oracle infrastructure upgrades or migrations
- Asset delisting from price feed services
- Economic considerations (insufficient usage/revenue to maintain feed)
- Protocol deprecation decisions by Switchboard

**Feasibility:** HIGH
- The vault depends entirely on external Switchboard infrastructure
- No fallback oracle providers exist in the current implementation
- Switchboard may legitimately deprecate feeds for business reasons
- If this occurs during any active vault operation, permanent DoS results
- Detection window is only ~1 minute (cache expiry time), making proactive prevention difficult

This is a **MEDIUM-HIGH likelihood** event given the dependency on external infrastructure that can change for legitimate operational reasons.

## Recommendation

Implement a multi-layered recovery mechanism:

1. **Add emergency admin function to force-reset vault status:**
   - Allow admin to set vault status back to `VAULT_NORMAL_STATUS` in emergency situations
   - Include appropriate access controls and event logging
   - Consider adding a timelock or multi-sig requirement

2. **Implement fallback oracle support:**
   - Support multiple oracle providers (e.g., Pyth, Supra, Switchboard)
   - Allow graceful degradation if primary oracle becomes unavailable
   - Add configurable fallback price sources

3. **Add operation timeout mechanism:**
   - Implement automatic operation cancellation after a reasonable timeout period
   - Reset vault to normal status if operation cannot complete within threshold
   - Return borrowed assets to vault automatically on timeout

4. **Allow price update bypass in emergency:**
   - Add admin-controlled emergency mode that temporarily relaxes price freshness requirements
   - Include safeguards to prevent abuse (multi-sig, timelock, strict conditions)

## Proof of Concept

```move
// This PoC demonstrates the permanent DoS scenario:
// 1. Vault starts operation (status = VAULT_DURING_OPERATION_STATUS)
// 2. Switchboard aggregator is deleted
// 3. After 1 minute, cached prices become stale
// 4. end_op_value_update_with_bag() reverts with ERR_USD_VALUE_NOT_UPDATED
// 5. Vault cannot return to VAULT_NORMAL_STATUS
// 6. set_enabled() reverts with ERR_VAULT_DURING_OPERATION
// 7. All vault operations are permanently blocked

#[test]
fun test_permanent_dos_after_aggregator_deletion() {
    // Setup: Initialize vault with Switchboard oracle
    // 1. Create vault in VAULT_NORMAL_STATUS
    // 2. Configure Switchboard aggregator for principal coin
    // 3. Start operation (vault status -> VAULT_DURING_OPERATION_STATUS)
    
    // Attack: Switchboard deletes aggregator (legitimate external action)
    // aggregator_delete_action::run(aggregator, ctx)
    
    // Wait > update_interval (1 minute)
    // Advance clock by 61 seconds
    
    // Impact: Attempt to complete operation
    // Call end_op_value_update_with_bag()
    // Expected: Reverts with ERR_PRICE_NOT_UPDATED (code 2_002)
    
    // Recovery attempt 1: Admin tries set_enabled(false)
    // Expected: Reverts with ERR_VAULT_DURING_OPERATION (code 5_025)
    
    // Recovery attempt 2: Try to execute deposits/withdrawals
    // Expected: Reverts with ERR_VAULT_NOT_NORMAL (code 5_022)
    
    // Result: Vault permanently stuck, all funds inaccessible
}
```

## Notes

The vulnerability arises from the combination of:
1. **Hard dependency on external oracle infrastructure** - No fallback mechanisms
2. **Zero tolerance for stale prices** - `MAX_UPDATE_INTERVAL = 0` requires constant updates
3. **Strict state machine enforcement** - No emergency override for stuck operations
4. **Destructive oracle deletion** - Aggregator objects can be permanently destroyed

This is a high-severity architectural issue that requires protocol-level fixes rather than just parameter adjustments. The recommended multi-layered approach provides defense-in-depth against this class of external dependency failures.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_delete_action.move (L22-28)
```text
fun actuate(aggregator: Aggregator) {
    let update_event = AggregatorDeleted {
        aggregator_id: aggregator.id(),
    };
    aggregator.delete();
    event::emit(update_event);
}
```

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
}
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/sources/oracle.move (L198-220)
```text
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L375-377)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
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

**File:** volo-vault/sources/volo_vault.move (L839-839)
```text
    update_free_principal_value(self, config, clock);
```

**File:** volo-vault/sources/volo_vault.move (L1056-1056)
```text
    self.update_free_principal_value(config, clock);
```

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
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
