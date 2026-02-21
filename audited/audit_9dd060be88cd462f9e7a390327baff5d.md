# Audit Report

## Title
Division by Zero Vulnerability in Momentum Position Valuation Due to Unchecked Oracle Prices

## Summary
The `get_position_value()` function in the Momentum adaptor performs division operations using oracle prices without validating they are non-zero. When the oracle returns a zero price, the function aborts with division by zero, causing the vault to become stuck in operation status and rendering user deposits and withdrawals completely blocked.

## Finding Description

The vulnerability exists in two critical division operations within the `get_position_value()` function that lack zero-value validation:

**Division by price_b (Location 1):** [1](#0-0) 

The function fetches oracle prices and immediately divides by `price_b` without validation. If `price_b = 0`, this causes a division by zero abort.

**Division by relative_price_from_oracle (Location 2):** [2](#0-1) 

The assertion divides by `relative_price_from_oracle`. Since `relative_price_from_oracle = price_a * DECIMAL / price_b`, if `price_a = 0`, then `relative_price_from_oracle = 0`, causing division by zero.

**Root Cause - Missing Oracle Price Validation:**

The oracle module returns prices without zero-value validation: [3](#0-2) 

The `get_asset_price` function only validates timestamp freshness but never checks if the returned price is greater than zero.

The underlying Switchboard price extraction also lacks zero validation: [4](#0-3) 

The Switchboard Decimal type explicitly supports zero values: [5](#0-4) 

**Execution Path:**

The vulnerable function is called during vault operations: [6](#0-5) 

This function is public and callable during the operation lifecycle. The vault enters operation status via `pre_vault_check`: [7](#0-6) 

After assets are returned via `end_op_with_bag`, the vault remains in `VAULT_DURING_OPERATION_STATUS` until value updates complete and `end_op_value_update_with_bag` is successfully called: [8](#0-7) 

The `finish_update_asset_value` function is callable during operation status (only checking `assert_enabled` which allows operation status): [9](#0-8) 

## Impact Explanation

**Critical Operational DoS with Complete Fund Lockup:**

When division by zero occurs during the value update phase, the transaction aborts, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`. This causes:

1. **Vault Freeze**: The vault cannot transition back to `VAULT_NORMAL_STATUS` because the value update transaction cannot complete. The only path back to normal status is through `end_op_value_update_with_bag` completing successfully. [10](#0-9) 

2. **User Deposits Blocked**: All deposit requests require normal status: [11](#0-10) 

3. **User Withdrawals Blocked**: All withdrawal requests require normal status: [12](#0-11) 

4. **No Emergency Recovery**: Even the admin cannot override the vault status when it's in operation mode: [13](#0-12) 

**Who Is Affected:**
- All vault depositors whose funds are locked
- Operators unable to complete operations
- Dependent protocols holding vault receipts
- Protocol revenue generation stops completely

**Severity Justification:**
This is CRITICAL because it causes complete protocol freeze with all user funds locked, triggered by a realistic oracle failure condition (zero price), with no automatic recovery mechanism.

## Likelihood Explanation

**High Likelihood - Realistic Trigger Conditions:**

1. **Oracle Can Return Zero**: Switchboard Decimal explicitly supports zero values and there is no validation preventing zero prices from being stored or returned by the oracle system.

2. **Realistic Failure Scenarios**: Production oracles can return zero prices during:
   - Switchboard aggregator initialization periods
   - Oracle maintenance or updates  
   - Market conditions where assets lose all value (stablecoin depegs, token failures)
   - Insufficient oracle responses failing to meet minimum sample size

3. **Public Entry Point**: The `update_momentum_position_value` function is public and called during normal operation flows by operators.

4. **No Special Capabilities Required**: This is a defensive programming flaw that occurs naturally when oracle conditions deteriorate - no attacker manipulation needed.

5. **Direct Execution Path**: 
   - Vault enters operation status (normal flow)
   - Operator calls value update function
   - Oracle returns zero price
   - Transaction aborts
   - Vault permanently stuck

## Recommendation

Add zero-value validation for oracle prices in the `get_position_value()` function:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    // ... existing code ...
    
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    
    // Add validation
    assert!(price_a > 0, ERR_INVALID_ORACLE_PRICE);
    assert!(price_b > 0, ERR_INVALID_ORACLE_PRICE);
    
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
    
    // ... rest of the function ...
}
```

Additionally, consider adding zero-value validation at the oracle level in `get_asset_price()` to prevent this class of errors across all adaptors.

## Proof of Concept

```move
#[test]
fun test_division_by_zero_on_zero_oracle_price() {
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Setup vault in operation status
    setup_vault_in_operation_status(&mut scenario);
    
    // Setup oracle with zero price for one asset
    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let mut config = test_scenario::take_shared<OracleConfig>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        
        // Set price_b to zero
        vault_oracle::set_current_price(&mut config, &clock, asset_type_b, 0);
        
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };
    
    // Attempt to update momentum position value - should abort with division by zero
    test_scenario::next_tx(&mut scenario, OPERATOR);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let config = test_scenario::take_shared<OracleConfig>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let mut pool = test_scenario::take_shared<MomentumPool<CoinA, CoinB>>(&scenario);
        
        // This will abort due to division by zero
        momentum_adaptor::update_momentum_position_value(
            &mut vault,
            &config,
            &clock,
            asset_type,
            &mut pool
        );
        
        // Vault will be stuck in operation status after abort
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
        test_scenario::return_shared(pool);
    };
    
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L51-51)
```text
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L56-56)
```text
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
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

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
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

**File:** volo-vault/sources/operation.move (L299-377)
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

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

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

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1174-1181)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();
```
