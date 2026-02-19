# Audit Report

## Title
Oracle Aggregator Removal Causes Vault Operation DoS Through Runtime Panics

## Summary
The `remove_switchboard_aggregator()` function lacks validation to check if removed oracle aggregators are still actively used by vaults. When vault operations attempt to query prices for removed aggregators, they abort with `ERR_AGGREGATOR_NOT_FOUND`, causing complete denial-of-service for all vault operations including deposits, withdrawals, and position updates. [1](#0-0) 

## Finding Description

The vulnerability stems from the architectural separation between oracle configuration and vault asset management, with no cross-module validation to maintain consistency.

The `remove_switchboard_aggregator()` function in the oracle module only verifies the aggregator exists before removing it, with no checks for active vault dependencies: [1](#0-0) 

This admin function is exposed through the vault management interface: [2](#0-1) 

When vault operations need asset prices, they call `get_asset_price()` which aborts if the aggregator is not found: [3](#0-2) 

This price query is invoked throughout critical vault operations:

1. **During deposit execution**: When updating free principal value, the vault calls `update_free_principal_value()` which queries the oracle for the principal coin price: [4](#0-3) [5](#0-4) 

2. **During withdrawal execution**: The vault directly queries the principal coin price to calculate withdrawal amounts: [6](#0-5) 

3. **During coin-type asset updates**: Non-principal assets also require oracle prices: [7](#0-6) 

4. **In DeFi adaptors**: The Navi adaptor queries prices for all reserves in the lending position: [8](#0-7) 

5. **In Cetus adaptor**: Both coins in the liquidity pool require price queries: [9](#0-8) [10](#0-9) 

6. **In receipt adaptor**: Recursive vault compositions require principal coin pricing: [11](#0-10) 

The vault maintains its asset types independently in the `asset_types` vector with no linkage to oracle configuration: [12](#0-11) 

## Impact Explanation

**Critical Denial-of-Service with Fund Inaccessibility:**

1. **Complete Vault Operation Blockage**: All vault operations requiring asset value updates will abort when querying prices for removed aggregators. This affects deposit execution, withdrawal execution, and all adaptor position updates.

2. **Vault Lock-in During Operations**: If an aggregator is removed while a vault is in `VAULT_DURING_OPERATION_STATUS`, the vault becomes stuck. Operations cannot complete because `end_op_value_update_with_bag()` requires calling `get_total_usd_value()` which iterates through all assets: [13](#0-12) [14](#0-13) 

   The vault can only return to `VAULT_NORMAL_STATUS` after successful value update: [15](#0-14) 

3. **User Fund Inaccessibility**: Users with pending deposit/withdrawal requests cannot execute or cancel them. The vault must be in normal status for most user operations: [16](#0-15) 

4. **Protocol-Wide Impact**: The issue affects all vaults using the removed asset type, including recursive vault compositions and multi-asset strategies.

**Severity: HIGH** - While not direct fund theft, this creates critical operational failure making vault funds inaccessible and operations impossible to complete, effectively freezing user assets until admin intervention.

## Likelihood Explanation

**Likelihood: MEDIUM**

This vulnerability represents a realistic operational risk rather than an intentional attack:

1. **Operational Context**: Oracle configuration changes are routine maintenance activities. Admins may remove aggregators when migrating to new oracle providers or updating price feeds.

2. **Lack of Visibility**: The protocol provides no mechanism for admins to query which vaults are actively using a given asset type before removal. The `OracleConfig` and `Vault` are separate shared objects with no cross-reference.

3. **Immediate Impact**: The error manifests during the next vault operation after removal, not at removal time, making cause-effect relationship non-obvious.

4. **Common Scenario**: Admins may reasonably believe an asset is deprecated when it's still actively used in vault positions.

While this requires admin privileges, the issue qualifies as a design flaw in privilege scoping - the `remove_switchboard_aggregator()` function has more power than it should have (ability to create critical protocol-level inconsistency) without corresponding safeguards.

## Recommendation

Add dependency validation to the `remove_switchboard_aggregator()` function. Since the protocol architecture doesn't provide a registry of which vaults use which assets, consider these approaches:

1. **Soft Removal with Grace Period**: Mark aggregators as "deprecated" rather than immediate removal, allowing vault operators time to migrate.

2. **Multi-step Removal Process**: Require a two-transaction process where first transaction marks for removal, and second transaction (after delay) completes removal.

3. **Admin Responsibility Documentation**: At minimum, document the risk and require admins to manually verify no vault dependencies before removal.

4. **Add Re-add Function**: Ensure `add_switchboard_aggregator()` works even if asset type previously existed (currently it checks `!config.aggregators.contains(asset_type)`), allowing quick recovery.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault_oracle::ERR_AGGREGATOR_NOT_FOUND)]
public fun test_remove_aggregator_causes_vault_dos() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Create vault and oracle with SUI aggregator
    init_vault(&mut scenario, &mut clock);
    
    scenario.next_tx(ADMIN);
    {
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        let admin_cap = scenario.take_from_sender<AdminCap>();
        
        // Admin removes SUI aggregator (configuration error)
        vault_manage::remove_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            type_name::get<SUI>().into_string(),
        );
        
        test_scenario::return_shared(oracle_config);
        scenario.return_to_sender(admin_cap);
    };
    
    // Attempt deposit operation - will abort due to missing aggregator
    scenario.next_tx(USER);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let oracle_config = scenario.take_shared<OracleConfig>();
        let operation = scenario.take_shared<Operation>();
        let op_cap = scenario.take_from_sender<OperatorCap>();
        
        // This will abort with ERR_AGGREGATOR_NOT_FOUND
        operation::execute_deposit(
            &operation,
            &op_cap,
            &mut vault,
            &mut reward_manager,
            &clock,
            &oracle_config,
            request_id,
            max_shares,
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
        test_scenario::return_shared(operation);
        scenario.return_to_sender(op_cap);
    };
    
    clock::destroy_for_testing(clock);
    scenario.end();
}
```

## Notes

The vulnerability is valid despite requiring admin privileges because it represents a **design flaw in privilege scoping** - the admin function lacks necessary validation to prevent creating protocol-level inconsistent state. The missing validation enables honest operational errors to cause critical system failures, which qualifies as a security issue even when triggered by trusted roles.

Recovery is possible (admin can re-add the aggregator), but the temporary DoS impact is severe, particularly if the vault becomes stuck in `VAULT_DURING_OPERATION_STATUS`.

### Citations

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

**File:** volo-vault/sources/oracle.move (L186-196)
```text
public(package) fun remove_switchboard_aggregator(config: &mut OracleConfig, asset_type: String) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    emit(SwitchboardAggregatorRemoved {
        asset_type,
        aggregator: config.aggregators[asset_type].aggregator,
    });

    config.aggregators.remove(asset_type);
}
```

**File:** volo-vault/sources/manage.move (L110-116)
```text
public fun remove_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    asset_type: String,
) {
    oracle_config.remove_switchboard_aggregator(asset_type);
}
```

**File:** volo-vault/sources/volo_vault.move (L113-116)
```text
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L839-839)
```text
    update_free_principal_value(self, config, clock);
```

**File:** volo-vault/sources/volo_vault.move (L1017-1021)
```text
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
```

**File:** volo-vault/sources/volo_vault.move (L1109-1113)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );
```

**File:** volo-vault/sources/volo_vault.move (L1146-1150)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-69)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-63)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```
