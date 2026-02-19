# Audit Report

## Title
Decimal Mismatch in Oracle Price Comparison Causes Position Update Failures

## Summary
The Momentum and Cetus adaptors use raw oracle prices with different decimal precisions when calculating relative prices for slippage validation, while using normalized prices for USD valuation. This inconsistency causes legitimate position value updates to fail when token pairs have different oracle decimal configurations (e.g., SUI with 9 decimals, USDC with 6 decimals), creating a denial-of-service condition for vault operations.

## Finding Description

The vulnerability exists in the price validation logic of both Momentum and Cetus adaptors. When calculating the relative oracle price for slippage validation, the code retrieves raw prices using `get_asset_price()` which returns prices with their configured decimal precision: [1](#0-0) 

The oracle system allows each asset to have different decimal configurations: [2](#0-1) 

This shows SUI uses 9 decimals, USDC uses 6 decimals, and BTC uses 8 decimals.

When `price_a` has 9 decimals and `price_b` has 6 decimals, the calculation `price_a * DECIMAL / price_b` produces a result inflated by 10^3 (1000x) compared to the correct relative price.

Meanwhile, the USD valuation correctly uses normalized prices that are converted to a consistent 9-decimal format: [3](#0-2) 

The `get_normalized_asset_price` function normalizes all prices to 9 decimals: [4](#0-3) 

This creates an inconsistency where the slippage validation uses incorrect relative prices (from raw prices with different decimals) while valuation uses correct normalized prices (consistent 9 decimals). The pool price calculation does account for decimal differences: [5](#0-4) 

But the oracle relative price does not, causing the comparison to fail: [6](#0-5) 

The same vulnerability exists in the Cetus adaptor: [7](#0-6) 

The Cetus adaptor even contains a comment suggesting prices should be in consistent 18-decimal format, but the implementation uses raw prices: [8](#0-7) 

## Impact Explanation

**Operational Denial of Service:**

For token pairs with different oracle decimal configurations (e.g., SUI/USDC where SUI has 9 decimals and USDC has 6 decimals):

- The relative oracle price is inflated by 10^(decimals_a - decimals_b)
- For a 3-decimal difference, this creates a 1000x error
- The slippage check calculates: `|pool_price - 1000×pool_price| / (1000×pool_price) ≈ 99.9%`
- With the default 1% slippage tolerance, this causes `ERR_INVALID_POOL_PRICE` abort
- Legitimate position value updates fail

**Affected Operations:**
- Vault operators cannot call `update_momentum_position_value` or `update_cetus_position_value`
- Position valuations cannot be updated for affected LP positions
- If withdrawals require accurate position valuations, users cannot withdraw funds
- Vault operations become stuck for any vault holding affected LP positions

**Workaround Limitations:**
While the admin could increase `dex_slippage` to 100%, this completely defeats the purpose of the slippage protection and would allow any pool price (including manipulated ones) to pass validation.

## Likelihood Explanation

**High Likelihood:**

1. **Reachable Entry Point:** The vulnerability is triggered through the public `update_momentum_position_value` function during normal vault operations: [9](#0-8) 

2. **Common Preconditions:** 
   - Vault holds Momentum or Cetus LP positions with token pairs having different oracle decimal configurations
   - Common pairs like SUI/USDC meet this condition based on test evidence
   - No attacker action required - this is a passive bug in normal operations

3. **No Special Privileges:** While operator capability is required, this is a trusted role performing legitimate operations

4. **No Economic Cost:** This is a protocol defect that manifests during regular vault operations without any attack or manipulation

## Recommendation

Use normalized prices (with consistent decimals) for the slippage validation instead of raw prices. Replace lines 49-51 in momentum.adaptor.move:

```move
// Instead of:
let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = price_a * DECIMAL / price_b;

// Use:
let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a * DECIMAL / normalized_price_b;
```

Apply the same fix to cetus_adaptor.move at lines 50-52.

This ensures both slippage validation and USD valuation use prices with consistent decimal precision.

## Proof of Concept

```move
#[test]
fun test_decimal_mismatch_causes_position_update_failure() {
    let mut scenario = test_scenario::begin(@0xa);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Create vault and oracle config
    init_vault::init_vault(&mut scenario, &mut clock);
    
    scenario.next_tx(@0xa);
    {
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        
        // Configure SUI with 9 decimals, USDC with 6 decimals (as in production)
        vault_oracle::set_aggregator(&mut oracle_config, &mut clock, 
            type_name::get<SUI>().into_string(), 9, @0xaggregator_sui);
        vault_oracle::set_aggregator(&mut oracle_config, &mut clock,
            type_name::get<USDC>().into_string(), 6, @0xaggregator_usdc);
        
        // Set realistic prices: SUI=$2 with 9 decimals, USDC=$1 with 6 decimals
        vault_oracle::set_current_price(&mut oracle_config, &clock,
            type_name::get<SUI>().into_string(), 2 * 1_000_000_000); // 2*10^9
        vault_oracle::set_current_price(&mut oracle_config, &clock,
            type_name::get<USDC>().into_string(), 1 * 1_000_000); // 1*10^6
            
        test_scenario::return_shared(oracle_config);
    };
    
    scenario.next_tx(@0xa);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let oracle_config = scenario.take_shared<OracleConfig>();
        let mut pool = create_test_momentum_pool<SUI, USDC>();
        
        // Add a position to the vault
        let position = create_test_position(&mut pool);
        vault.add_momentum_position(position, b"test_position".to_ascii());
        
        // Attempt to update position value - THIS WILL FAIL with ERR_INVALID_POOL_PRICE
        // because relative_price = (2*10^9 * 10^18) / (1*10^6) = 2*10^21
        // but pool_price ≈ 2*10^18, causing ~99.9% apparent slippage
        momentum_adaptor::update_momentum_position_value(
            &mut vault,
            &oracle_config,
            &clock,
            b"test_position".to_ascii(),
            &mut pool
        ); // Expected: aborts with ERR_INVALID_POOL_PRICE (7_001)
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
        pool.destroy_for_testing();
    };
    
    clock.destroy_for_testing();
    scenario.end();
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-66)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L93-103)
```text
fun sqrt_price_x64_to_price(sqrt_price_x64: u128, decimals_a: u8, decimals_b: u8): u256 {
    let sqrt_price_u256_with_decimals = (sqrt_price_x64 as u256) * DECIMAL / pow(2, 64);
    let price_u256_with_decimals =
        sqrt_price_u256_with_decimals * sqrt_price_u256_with_decimals / DECIMAL;

    if (decimals_a > decimals_b) {
        price_u256_with_decimals * pow(10, (decimals_a - decimals_b))
    } else {
        price_u256_with_decimals / pow(10, (decimals_b - decimals_a))
    }
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-52)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L54-58)
```text
    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18
```
