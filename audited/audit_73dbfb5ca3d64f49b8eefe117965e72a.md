# Audit Report

## Title
Momentum Adaptor Incompatible with Non-Uniform Oracle Decimal Configurations

## Summary
The momentum adaptor's price slippage validation incorrectly assumes uniform decimal precision across all oracle price feeds, causing vault operations to fail with `ERR_INVALID_POOL_PRICE` when legitimate non-uniform decimal configurations are used. This creates an operational DoS for vaults holding Momentum positions.

## Finding Description

The momentum adaptor calculates a relative price between two assets for DEX pool slippage validation. The code explicitly assumes "Oracle price has 18 decimals" but fetches raw prices with their native decimal precision: [1](#0-0) 

The `get_asset_price` function returns raw prices without normalization, preserving each asset's configured decimal precision: [2](#0-1) 

The OracleConfig system explicitly supports different decimal configurations per asset through the `decimals` parameter in the `PriceInfo` struct: [3](#0-2) [4](#0-3) 

The system's own test configurations demonstrate this flexibility, configuring assets with different decimals (SUI=9, USDC=6, BTC=8): [5](#0-4) 

**Mathematical Error:**

When oracle feeds have non-uniform decimals:
- SUI with 9 decimals returns `2×10⁹` for $2
- USDC with 6 decimals returns `1×10⁶` for $1

The flawed calculation produces:
```
relative_price_from_oracle = (2×10⁹) × 10¹⁸ / (1×10⁶) = 2×10²¹
```

Expected value: `2×10¹⁸` (representing ratio 2.0)
Error magnitude: `10³` (three orders of magnitude)

The pool price calculation correctly accounts for decimal differences via `sqrt_price_x64_to_price`, producing approximately `2×10¹⁸`. The slippage check then compares these vastly different values, causing the assertion at line 55-58 to fail.

The system explicitly provides `get_normalized_asset_price` for handling different decimals, indicating intentional design support for this flexibility: [6](#0-5) 

## Impact Explanation

**Operational DoS on Vault Operations:**

When the momentum adaptor's slippage validation fails, the transaction aborts with `ERR_INVALID_POOL_PRICE`. This prevents completion of vault operations because the operation flow requires all borrowed assets to have their values updated: [7](#0-6) 

The `check_op_value_update_record` function validates that all borrowed assets were updated during the operation: [8](#0-7) 

When the momentum adaptor aborts before reaching `finish_update_asset_value`, the asset remains unupdated, causing `check_op_value_update_record` to fail with `ERR_USD_VALUE_NOT_UPDATED`.

**Affected Operations:**
- Position value updates during vault operations
- Operation finalization requiring accurate asset valuation
- Vault rebalancing activities
- Any vault management function involving momentum positions

**Severity:** Medium - Causes significant operational disruption and DoS but does not directly enable fund theft. The impact blocks legitimate vault functionality and can prevent operators from managing positions properly.

## Likelihood Explanation

**High Likelihood - Normal System Configuration:**

The vulnerability triggers under legitimate admin behavior when configuring oracle feeds with their native Switchboard decimal precisions. Switchboard aggregators naturally have varying decimals (e.g., 6 for USDC, 8 for BTC, 9 for SUI, 18 for ETH).

**No System Validation:**

The OracleConfig provides no validation or warning against non-uniform decimals. The `add_switchboard_aggregator` function accepts any decimal value: [9](#0-8) 

**System Design Supports Flexibility:**

The existence of `get_normalized_asset_price` and the test configurations using different decimals demonstrate that non-uniform decimal configurations are intentionally supported by the oracle system design, but the momentum adaptor failed to account for this.

**Realistic Scenario:** During system evolution or when adding new assets, admins add oracle feeds matching their Switchboard feed specifications. The momentum adaptor then becomes incompatible, causing immediate operation failures.

## Recommendation

Replace the raw price calculation with normalized prices:

```move
// Use normalized prices (9 decimals) instead of raw prices
let price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

This ensures both prices have consistent 9-decimal precision before computing the ratio, making the calculation compatible with the pool price which also accounts for decimal differences.

## Proof of Concept

```move
#[test]
fun test_momentum_adaptor_decimal_mismatch() {
    // Setup: Configure oracle with non-uniform decimals
    // SUI: 9 decimals, price = 2×10^9 ($2)
    // USDC: 6 decimals, price = 1×10^6 ($1)
    
    // Expected oracle relative price: 2×10^18 (ratio 2.0)
    // Actual calculation: (2×10^9) × 10^18 / (1×10^6) = 2×10^21
    
    // Pool price correctly accounts for decimals: ~2×10^18
    
    // Slippage check compares:
    // |2×10^18 - 2×10^21| / 2×10^21 = ~1.0 (100%)
    // This exceeds any reasonable slippage threshold (typically 1%)
    
    // Result: Transaction aborts with ERR_INVALID_POOL_PRICE
    // Vault operation cannot complete
}
```

The test would set up a vault with a momentum position, configure the oracle with different decimals matching the test_helpers configuration, then attempt to update the position value during an operation. The transaction would abort at the slippage assertion, preventing the operation from completing.

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L48-51)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
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

**File:** volo-vault/sources/oracle.move (L158-184)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);

    emit(SwitchboardAggregatorAdded {
        asset_type,
        aggregator: aggregator.id().to_address(),
    });
}
```

**File:** volo-vault/sources/oracle.move (L270-272)
```text
public fun coin_decimals(config: &OracleConfig, asset_type: String): u8 {
    config.aggregators[asset_type].decimals
}
```

**File:** volo-vault/tests/test_helpers.move (L27-47)
```text
        vault_oracle::set_aggregator(
            config,
            clock,
            sui_asset_type,
            9,
            MOCK_AGGREGATOR_SUI,
        );
        vault_oracle::set_aggregator(
            config,
            clock,
            usdc_asset_type,
            6,
            MOCK_AGGREGATOR_USDC,
        );
        vault_oracle::set_aggregator(
            config,
            clock,
            btc_asset_type,
            8,
            MOCK_AGGREGATOR_BTC,
        );
```

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
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
