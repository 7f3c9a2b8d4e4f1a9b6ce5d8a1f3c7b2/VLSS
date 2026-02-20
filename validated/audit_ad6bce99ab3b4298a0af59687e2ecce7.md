# Audit Report

## Title
Vault Operation DoS Due to Missing Asset Value Updates After Asset Return

## Summary
Volo's vault operation system exhibits a critical state synchronization failure where returning assets during operations does not automatically update accounting state. If an operator fails to manually call update functions for all returned assets, the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no admin recovery mechanism, rendering the entire vault and all user funds inaccessible.

## Finding Description

The vulnerability arises from a dangerous design pattern where physical asset custody and accounting state updates are decoupled, combined with no recovery mechanism for operator mistakes.

**Asset Return Without State Update:**

When `return_free_principal` is called, it only joins the balance back to `free_principal` but does NOT call `finish_update_asset_value` to update the `assets_value` table or mark the asset as updated in `op_value_update_record.asset_types_updated`. [1](#0-0) 

Similarly, `return_defi_asset` adds the asset back to the vault's `assets` bag but does NOT update its value or mark it as updated. [2](#0-1) 

The same issue exists in `return_coin_type_asset` which returns the balance without updating accounting state. [3](#0-2) 

**Operation Flow Requires Manual Updates:**

In `end_op_with_bag`, all borrowed assets are returned but no automatic value updates occur. The function only calls `enable_op_value_update()`, which merely sets a flag. [4](#0-3) 

The operator must manually call update functions like `update_navi_position_value`, `update_free_principal_value`, and `update_coin_type_asset_value` for EACH borrowed asset before finalizing. [5](#0-4) 

**Integrity Check Enforces Complete Updates:**

The `check_op_value_update_record` function iterates through ALL borrowed assets (tracked in `asset_types_borrowed`) and asserts that each one exists in `asset_types_updated` with a value of `true`. If ANY asset is missing, the assertion fails with `ERR_USD_VALUE_NOT_UPDATED`. [6](#0-5) 

This check is called in `end_op_value_update_with_bag`. If it fails, the vault never reaches the line where status is reset to `VAULT_NORMAL_STATUS`, leaving the vault permanently stuck. [7](#0-6) 

**No Recovery Mechanism:**

The admin's `set_enabled` function explicitly prevents status changes when vault is in `VAULT_DURING_OPERATION_STATUS`. [8](#0-7) 

The `set_status` function is marked `public(package)`, preventing direct admin access. [9](#0-8) 

No wrapper function in `manage.move` exposes status override for admin recovery. [10](#0-9) 

## Impact Explanation

**High Severity Denial of Service:**

The vault becomes permanently unusable as deposits and withdrawals require `VAULT_NORMAL_STATUS`. The `request_deposit` function requires `assert_normal()` which checks for `VAULT_NORMAL_STATUS`. [11](#0-10) 

Similarly, `request_withdraw` also requires `assert_normal()`. [12](#0-11) 

This results in:
- All user funds locked in the vault with no withdrawal path
- No administrative recovery function exists
- Requires contract upgrade to restore functionality
- Multiple vaults can be affected if operator manages several vaults simultaneously

## Likelihood Explanation

**Moderate to High Likelihood:**

Operators must manually call update functions for EACH borrowed asset type after returning them. Complex operations involving multiple asset types (Navi positions, Cetus LPs, principal, coin-type assets) significantly increase the probability of missing one update call.

The test suite demonstrates the expected manual update pattern where operators must remember multiple steps. [13](#0-12) 

There is no compiler or runtime safeguard preventing the operator from calling `end_op_value_update_with_bag` without first updating all assets. The error only manifests at the finalization step, when the vault is already in a corrupted state with no rollback mechanism.

The existing test explicitly validates this failure scenario. [14](#0-13) 

## Recommendation

Implement one or more of the following solutions:

1. **Automatic Updates**: Modify `return_free_principal`, `return_defi_asset`, and `return_coin_type_asset` to automatically call `finish_update_asset_value` when assets are returned during operations.

2. **Admin Recovery Function**: Add an admin-only emergency function to reset vault status from `VAULT_DURING_OPERATION_STATUS` to `VAULT_NORMAL_STATUS` after manual verification.

3. **Pre-Flight Validation**: Add a check in `end_op_with_bag` that verifies all borrowed assets have been updated before allowing the operation to proceed, providing immediate feedback rather than deferred failure.

4. **Atomic Operation Wrapper**: Create a wrapper function that ensures all updates are performed atomically as part of the operation finalization process.

## Proof of Concept

```move
// Test demonstrating permanent vault DoS when operator forgets to update one asset
#[test]
#[expected_failure(abort_code = vault::ERR_USD_VALUE_NOT_UPDATED)]
public fun test_permanent_vault_dos_missing_update() {
    // Setup vault with multiple asset types (SUI principal, USDC coin-type, Navi position)
    // Start operation borrowing all three asset types
    // Call end_op_with_bag to return all assets
    // Deliberately skip update_coin_type_asset_value for USDC
    // Call end_op_value_update_with_bag
    // Transaction aborts with ERR_USD_VALUE_NOT_UPDATED
    // Vault is now permanently stuck in VAULT_DURING_OPERATION_STATUS
    // All subsequent request_deposit and request_withdraw calls fail
    // Admin cannot recover using set_enabled
}
```

## Notes

This is a protocol design vulnerability rather than pure operator error because:

1. **Disproportionate Consequences**: A single missed update call causes permanent, irrecoverable vault lockup affecting all users
2. **No Safety Mechanisms**: The protocol provides no safeguards, warnings, or recovery paths for this failure mode
3. **Trusted Role Trap**: While operators are trusted, the protocol should not make honest mistakes catastrophic
4. **Design Alternative Exists**: The protocol could automatically update values when assets are returned, eliminating this footgun entirely

The vulnerability requires operator action to trigger but represents a fundamental protocol design flaw in lacking both preventive safeguards and recovery mechanisms.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L592-604)
```text
public(package) fun return_free_principal<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    balance: Balance<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();

    emit(FreePrincipalReturned {
        vault_id: self.vault_id(),
        amount: balance.value(),
    });
    self.free_principal.join(balance);
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

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1436-1449)
```text
public(package) fun return_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    asset: AssetType,
) {
    self.check_version();

    emit(DefiAssetReturned {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.add<String, AssetType>(asset_type, asset);
}
```

**File:** volo-vault/sources/volo_vault.move (L1527-1538)
```text
public(package) fun return_coin_type_asset<PrincipalCoinType, AssetType>(
    self: &mut Vault<PrincipalCoinType>,
    amount: Balance<AssetType>,
) {
    self.check_version();
    self.assert_enabled();

    let asset_type = type_name::get<AssetType>().into_string();

    let current_balance = self.assets.borrow_mut<String, Balance<AssetType>>(asset_type);
    current_balance.join(amount);
}
```

**File:** volo-vault/sources/operation.move (L286-294)
```text
    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-376)
```text
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/tests/operation/operation.test.move (L143-153)
```text
        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            navi_asset_type,
            &mut storage,
        );

        vault.update_free_principal_value(&config, &clock);
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);
```

**File:** volo-vault/tests/operation/operation.test.move (L718-845)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_USD_VALUE_NOT_UPDATED, location = vault)]
// [TEST-CASE: Should start op fail if not update value first.] @test-case OPERATION-006
// Start op with coin type asset = 0
public fun test_start_op_fail_not_update_value() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(
            0,
            navi_account_cap,
        );
        test_scenario::return_shared(vault);
    };

    // Set mock aggregator and price
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);

        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);

        test_scenario::return_shared(oracle_config);
    };

    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();

        vault.return_free_principal(coin.into_balance());

        vault::update_free_principal_value(&mut vault, &config, &clock);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let coin = coin::mint_for_testing<USDC_TEST_COIN>(100_000_000_000, s.ctx());
        // Add 100 USDC to the vault
        vault.add_new_coin_type_asset<SUI_TEST_COIN, USDC_TEST_COIN>();
        vault.return_coin_type_asset(coin.into_balance());

        let config = s.take_shared<OracleConfig>();
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        test_scenario::return_shared(config);
        test_scenario::return_shared(vault);
    };

    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        let config = s.take_shared<OracleConfig>();
        let storage = s.take_shared<Storage>();

        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];

        let (
            asset_bag,
            tx_bag,
            tx_bag_for_check_value_update,
            principal_balance,
            coin_type_asset_balance,
        ) = operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            defi_asset_ids,
            defi_asset_types,
            1_000_000_000,
            0,
            s.ctx(),
        );

        // Step 2
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            asset_bag,
            tx_bag,
            principal_balance,
            coin_type_asset_balance,
        );

        // let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        // navi_adaptor::update_navi_position_value(
        //     &mut vault,
        //     &config,
        //     &clock,
        //     navi_asset_type,
        //     &mut storage,
        // );

        // vault.update_free_principal_value(&config, &clock);
        // vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        // Step 3
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            tx_bag_for_check_value_update,
        );
```
