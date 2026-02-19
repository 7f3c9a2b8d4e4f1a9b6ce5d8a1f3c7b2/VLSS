# Audit Report

## Title
Oracle Aggregator Can Be Changed Mid-Operation Causing Inconsistent Price Sources for Loss Tolerance Validation

## Summary
The `change_switchboard_aggregator()` function lacks vault status validation, allowing the oracle price source to be changed while the vault is in `VAULT_DURING_OPERATION_STATUS`. This causes loss tolerance validation to compare total USD values computed from different price sources, breaking a critical security invariant.

## Finding Description

The `change_switchboard_aggregator()` function in the vault management module only requires `AdminCap` and performs no vault status validation: [1](#0-0) 

This function delegates to the oracle implementation which immediately updates both the aggregator address and the stored price: [2](#0-1) 

During vault operations, the loss tolerance mechanism relies on price consistency:

1. **Operation Start:** `start_op_with_bag()` sets the vault status to `VAULT_DURING_OPERATION_STATUS` [3](#0-2)  and captures the initial total USD value [4](#0-3) 

2. **Mid-Operation Vulnerability:** An admin can call `change_switchboard_aggregator()` during the operation, which immediately updates the oracle's stored price without any vault status check.

3. **Operation End:** `end_op_value_update_with_bag()` recalculates the total USD value and compares it to the initial value to detect losses [5](#0-4) 

The USD value calculation reads from the oracle config's stored prices: [6](#0-5) 

Asset value updates use `get_normalized_asset_price()` which reads the stored price from the oracle config [7](#0-6)  and [8](#0-7) 

**Root Cause:** The absence of vault status validation creates an inconsistent security model. Other critical admin functions like `set_enabled()` explicitly prevent modifications during operations: [9](#0-8) 

This protection is tested and enforced: [10](#0-9) 

## Impact Explanation

This vulnerability directly compromises the loss_tolerance mechanism, which is a critical safety feature protecting vault shareholders from excessive operational losses.

**Concrete Harm Scenarios:**

1. **Loss Tolerance Bypass:** If the new aggregator reports higher prices than the old one, real operational losses can be masked. For example, if the vault loses 100,000 SUI tokens in a failed strategy, but the new aggregator values SUI 20% higher, the loss calculation will underestimate or completely hide the actual loss, allowing it to bypass the loss_tolerance check.

2. **Loss Tolerance Exhaustion:** If the new aggregator reports lower prices, artificial losses are created. A vault with no actual loss could show a significant USD value decrease purely from the price source change, consuming the epoch's loss_tolerance budget and potentially causing legitimate future operations to fail.

3. **Protocol Invariant Violation:** The loss_tolerance per epoch is designed to limit operator risk by ensuring that vault value changes stay within acceptable bounds. This mechanism is rendered ineffective when before/after comparisons use inconsistent price sources.

**Severity Justification:** This is a HIGH severity issue because it:
- Directly impacts a critical security mechanism protecting user funds
- Can lead to either fund loss (scenario 1) or denial of service (scenario 2)
- Requires no complex exploit - just a single admin function call
- Impact scales with vault TVL and price divergence between aggregators

## Likelihood Explanation

This vulnerability has HIGH likelihood of occurrence due to multiple factors:

**Feasibility:**
- Only requires a single function call with AdminCap
- No complex transaction ordering or timing precision needed
- Operations can run for extended periods during complex DeFi interactions
- Multiple potential oracle aggregators exist for common assets

**Realistic Scenarios:**

1. **Unintentional Trigger:** Administrators may legitimately need to switch oracle aggregators for operational reasons (e.g., provider reliability issues, better data quality, cost optimization). Without any vault status check or warning, an admin could unknowingly make this change while an operation is in progress, especially since operations can be long-running.

2. **Intentional Manipulation:** Even with trusted admins, the design flaw allows deliberate timing of aggregator changes to influence loss calculations, which shouldn't be possible for a critical safety mechanism.

**Contributing Factors:**
- The function is part of normal admin operations (not an exotic edge case)
- There's no on-chain prevention mechanism
- Event emission (`SwitchboardAggregatorChanged`) requires off-chain monitoring to detect
- The inconsistency with `set_enabled()` suggests this protection was simply overlooked rather than intentionally omitted

## Recommendation

Add vault status validation to `change_switchboard_aggregator()` to prevent aggregator changes during operations, consistent with the protection in `set_enabled()`.

**Fix in `volo-vault/sources/oracle.move`:**

Add a status check before updating the aggregator. The function should take a vault reference to check its status, or the check should be added in the manage.move wrapper. The simpler approach is to document that aggregator changes should only occur when vaults are in NORMAL status, and add a check in the oracle config function:

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    // Add check: This operation should not occur during vault operations
    // Note: Since oracle config is shared, this check should be coordinated
    // with vault status through the manage module wrapper
    
    let init_price = get_current_price(config, clock, aggregator);
    // ... rest of function
}
```

**Better fix in `volo-vault/sources/manage.move`:**

Add vault status check in the management wrapper if the vault uses this oracle config:

```move
public fun change_switchboard_aggregator(
    _: &AdminCap,
    vault: &Vault<PrincipalCoinType>,  // Add vault reference
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    vault.assert_not_during_operation();  // Add this check
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
```

This ensures consistent protection across all admin functions that could affect ongoing operations.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION)]
public fun test_change_aggregator_during_operation_should_fail() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault, oracle config, and aggregators
    setup_vault_and_oracle(&mut scenario, &mut clock);
    
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let operation = scenario.take_shared<Operation>();
        let cap = scenario.take_from_sender<OperatorCap>();
        
        // Start an operation - vault enters DURING_OPERATION status
        let (bag, tx_bag, tx_bag_update, principal, coin_balance) = 
            operation::start_op_with_bag<SUI, USDC, SUI>(
                &mut vault,
                &operation,
                &cap,
                &clock,
                vector[],
                vector[],
                1_000_000,
                0,
                scenario.ctx()
            );
        
        // Attempt to change aggregator during operation - should fail
        let admin_cap = scenario.take_from_sender<AdminCap>();
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        let new_aggregator = scenario.take_shared<Aggregator>();
        
        // This call should abort with ERR_VAULT_DURING_OPERATION
        vault_manage::change_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            &clock,
            b"SUI".to_ascii_string(),
            &new_aggregator
        );
        
        // Cleanup (unreachable)
        // ...
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

**Notes:**

This vulnerability represents a mis-scoped privilege issue where even honest admin operations can break critical protocol invariants. The comparison with `set_enabled()` demonstrates that the protocol designers intended to protect operation integrity from admin interference, but this protection was inconsistently applied. The loss_tolerance mechanism is specifically designed to protect users from operator mistakes, and allowing admin actions to compromise its correctness defeats its purpose entirely.

### Citations

**File:** volo-vault/sources/manage.move (L118-126)
```text
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
```

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
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

**File:** volo-vault/sources/operation.move (L178-193)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
    let total_usd_value_before = total_usd_value;
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

**File:** volo-vault/sources/volo_vault.move (L1109-1113)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
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

**File:** volo-vault/tests/operation/operation.test.move (L3797-3799)
```text
#[test]
#[expected_failure(abort_code = vault::ERR_VAULT_DURING_OPERATION, location = vault)]
// [TEST-CASE: Should set vault disabled fail if vault is during operation.] @test-case OPERATION-022
```
