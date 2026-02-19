# Audit Report

## Title
Decimal Mismatch in Oracle Price Comparison Causes Position Update Failures

## Summary
The Momentum and Cetus adaptors calculate relative oracle prices for slippage validation using raw prices with different decimal precisions, while USD valuation uses normalized prices. This decimal mismatch causes legitimate position updates to fail with `ERR_INVALID_POOL_PRICE` when token pairs have different oracle decimal configurations (e.g., SUI with 9 decimals and USDC with 6 decimals), resulting in operational DoS.

## Finding Description

The vulnerability exists in the `get_position_value()` function where raw oracle prices are retrieved and used to calculate a relative price without accounting for decimal differences. [1](#0-0) 

The oracle system stores each asset's price with a `decimals` field that indicates the decimal precision of that specific price feed. [2](#0-1) 

When `get_asset_price()` is called, it returns the raw price value without any decimal normalization. [3](#0-2) 

The issue manifests when calculating `relative_price_from_oracle = price_a * DECIMAL / price_b`. If `price_a` has 9 decimals (e.g., SUI: 2 * 10^9 representing $2) and `price_b` has 6 decimals (e.g., USDC: 1 * 10^6 representing $1), the result is (2 * 10^9) * 10^18 / (1 * 10^6) = 2 * 10^21, which is 1000x higher than the correct value of 2 * 10^18.

Meanwhile, the actual USD valuation correctly uses normalized prices which are converted to a consistent 9-decimal format. [4](#0-3) [5](#0-4) 

Test evidence confirms that different assets use different decimal configurations: [6](#0-5) 

The same vulnerability exists in the Cetus adaptor: [7](#0-6) 

## Impact Explanation

**Operational DoS with High Severity:**

When a vault holds Momentum or Cetus LP positions with token pairs having different oracle decimal configurations, the decimal mismatch causes:

1. **For decimals_a > decimals_b (e.g., SUI/USDC with 9 vs 6 decimals):**
   - Relative price inflated by 10^(decimals_a - decimals_b) = 10^3 = 1000x
   - For legitimate pool with price ~2 * 10^18, calculated slippage = |2*10^21 - 2*10^18| / 2*10^21 ≈ 99.9%
   - Default 1% slippage tolerance causes validation failure with `ERR_INVALID_POOL_PRICE`
   - Position value updates become impossible

2. **For decimals_a < decimals_b:**
   - Relative price deflated by similar factor
   - Allows manipulated pool prices to pass validation

**Who is affected:**
- Vault operators cannot update position values during normal operations
- Users cannot withdraw if position valuation is required
- Vault becomes effectively stuck for that position type

This breaks the **Oracle & Valuation** invariant domain where decimal conversions must be consistent between validation and valuation logic.

## Likelihood Explanation

**High Likelihood - This is a Passive Bug:**

1. **Reachable Entry Point:** The vulnerability triggers through the public `update_momentum_position_value()` function during normal vault operations. [8](#0-7) 

2. **Trivial Preconditions:**
   - Vault holds Momentum/Cetus LP positions (normal vault operation)
   - Token pairs have different oracle decimal configs (SUI=9, USDC=6, BTC=8 as shown in tests)
   - Common pairs like SUI/USDC meet this condition
   - No attacker action required

3. **No Special Privileges:** Anyone can call the update function with the vault, oracle config, and pool references.

4. **Inevitable Occurrence:** Oracle decimals reflect actual Switchboard aggregator configurations and asset on-chain decimals. Different assets naturally have different decimal precisions.

## Recommendation

Fix the relative price calculation to use normalized prices instead of raw prices:

```move
// In get_position_value() function:
// Replace lines 49-51 with:
let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a * DECIMAL / normalized_price_b;
```

This ensures the relative price calculation uses the same normalized prices (9-decimal format) as the USD valuation, eliminating the decimal mismatch.

Apply the same fix to `calculate_cetus_position_value()` in cetus_adaptor.move.

## Proof of Concept

```move
#[test]
public fun test_decimal_mismatch_causes_position_update_failure() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with oracle config
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Set different decimals: SUI=9, USDC=6
        vault_oracle::set_aggregator(&mut oracle_config, &clock, 
            type_name::get<SUI_TEST_COIN>().into_string(), 9, @0x1);
        vault_oracle::set_aggregator(&mut oracle_config, &clock,
            type_name::get<USDC_TEST_COIN>().into_string(), 6, @0x2);
        
        // Set prices: SUI=$2 with 9 decimals, USDC=$1 with 6 decimals
        vault_oracle::set_current_price(&mut oracle_config, &clock,
            type_name::get<SUI_TEST_COIN>().into_string(), 2_000_000_000); // 2*10^9
        vault_oracle::set_current_price(&mut oracle_config, &clock,
            type_name::get<USDC_TEST_COIN>().into_string(), 1_000_000); // 1*10^6
        
        // Create momentum pool with legitimate 2:1 price
        let pool = create_test_pool<SUI_TEST_COIN, USDC_TEST_COIN>(2 * 10^18);
        
        // This should succeed but will fail due to decimal mismatch
        // Expected: relative_price_from_oracle = 2*10^18
        // Actual: relative_price_from_oracle = 2*10^21 (1000x off)
        // Slippage = 99.9% > 1% tolerance -> ERR_INVALID_POOL_PRICE
        update_momentum_position_value<SUI_TEST_COIN, SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault, &oracle_config, &clock, asset_type, &mut pool
        ); // This will abort with ERR_INVALID_POOL_PRICE
        
        test_scenario::return_shared(oracle_config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability represents a critical design flaw in how decimal precision is handled between oracle price retrieval and slippage validation. The normalized price function exists and is used correctly for USD valuation, but the slippage validation logic incorrectly uses raw prices. This creates an inconsistency that makes the protocol unusable for common token pairs with different decimal configurations.

The fix is straightforward: use `get_normalized_asset_price()` instead of `get_asset_price()` when calculating the relative oracle price for slippage validation, ensuring consistency with the USD valuation logic.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-66)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-52)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```
