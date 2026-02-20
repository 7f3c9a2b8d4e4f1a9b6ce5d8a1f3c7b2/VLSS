# Audit Report

## Title
Decimal Mismatch in Oracle Price Comparison Causes Position Update Failures

## Summary
The Momentum and Cetus adaptors incorrectly use raw oracle prices with different decimal precisions when calculating relative prices for slippage validation, while correctly using normalized prices for USD valuation. This decimal mismatch causes legitimate position value updates to fail with `ERR_INVALID_POOL_PRICE` when token pairs have different oracle decimal configurations (e.g., SUI with 9 decimals, USDC with 6 decimals), creating a denial-of-service condition that blocks critical vault operations.

## Finding Description

The vulnerability exists in the price validation logic of both Momentum and Cetus adaptors where they compute relative oracle prices for slippage checks.

**Root Cause - Raw Prices with Different Decimals:**

In the Momentum adaptor, when calculating the relative oracle price, the code retrieves raw prices using `get_asset_price()`: [1](#0-0) 

The `get_asset_price()` function returns prices stored with their configured decimal precision without normalization: [2](#0-1) 

The oracle system allows each asset to have different decimal configurations, as evidenced by the test setup: [3](#0-2) 

This shows SUI uses 9 decimals, USDC uses 6 decimals, and BTC uses 8 decimals.

**The Decimal Mismatch:**

When `price_a` (SUI) has 9 decimals and `price_b` (USDC) has 6 decimals, the calculation `price_a * DECIMAL / price_b` produces:
- Example: (1.5 × 10^9) × 10^18 / (1.0 × 10^6) = 1.5 × 10^21

This is inflated by 10^3 (1000x) compared to the correct relative price of 1.5 × 10^18.

**Correct Normalization Exists But Not Used:**

The oracle provides a `get_normalized_asset_price()` function that correctly normalizes all prices to 9 decimals: [4](#0-3) 

The adaptors correctly use this normalized pricing for USD valuation: [5](#0-4) 

However, the slippage validation uses the incorrect raw prices, causing a mismatch.

**Pool Price Calculation is Correct:**

The pool price calculation properly accounts for decimal differences: [6](#0-5) 

This produces a correctly scaled pool price (e.g., 1.5 × 10^18), but the oracle relative price is inflated (e.g., 1.5 × 10^21), causing the comparison to fail.

**Slippage Check Fails:**

The slippage validation compares these mismatched values: [7](#0-6) 

With a 1000x inflation, the slippage calculation yields approximately 99.9%, far exceeding the default 1% tolerance, causing the transaction to abort with `ERR_INVALID_POOL_PRICE`.

**Same Vulnerability in Cetus Adaptor:**

The Cetus adaptor contains identical vulnerable code: [8](#0-7) 

Notably, the Cetus adaptor includes a comment stating "Oracle price has 18 decimals", revealing the developer's incorrect assumption that all prices are stored with uniform precision: [9](#0-8) 

## Impact Explanation

**Operational Denial of Service:**

For any vault holding LP positions with token pairs having different oracle decimal configurations:

1. **Position Updates Fail**: Operators cannot call `update_momentum_position_value` or `update_cetus_position_value` [10](#0-9) 

2. **Vault Operations Blocked**: Without accurate position valuations, the vault cannot:
   - Process withdrawals that depend on total USD value calculations
   - Perform rebalancing operations
   - Update accounting for LP positions

3. **Widespread Impact**: Common trading pairs like SUI/USDC, SUI/BTC, and USDC/BTC all have different decimal configurations, making this a high-probability scenario for any vault using these pairs.

4. **No Viable Workaround**: While an admin could increase `dex_slippage` to 100%, this completely defeats the purpose of slippage protection and would allow manipulated pool prices to pass validation.

## Likelihood Explanation

**High Likelihood - Occurs During Normal Operations:**

1. **Directly Reachable**: The vulnerability is triggered through the public `update_momentum_position_value` entry point during routine vault maintenance.

2. **Common Preconditions**: 
   - Vault holds Momentum or Cetus LP positions (normal operational state)
   - Token pairs have different oracle decimal configurations (verified for major pairs)
   - No special market conditions or price manipulation required

3. **Trusted Role Execution**: While `OperatorCap` is required, operators are trusted roles performing legitimate vault operations. This is a protocol defect, not an attack vector.

4. **Test Evidence**: The test configuration explicitly shows different decimals (SUI: 9, USDC: 6, BTC: 8), confirming this is the intended production configuration.

5. **No Attack Required**: This is a passive bug manifesting during regular position value updates, not requiring any attacker action or economic cost.

## Recommendation

Normalize both oracle prices before computing the relative price for slippage validation:

```move
// In momentum_adaptor.move and cetus_adaptor.move, replace lines 49-51 with:
let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a * DECIMAL / normalized_price_b;
```

This ensures the oracle relative price uses the same 9-decimal precision as the pool price calculation, allowing proper comparison.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = 7_001)] // ERR_INVALID_POOL_PRICE
public fun test_decimal_mismatch_causes_update_failure() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        
        // Set prices matching actual decimal configurations
        // SUI: 2 USD with 9 decimals = 2 * 10^9
        // USDC: 1 USD with 6 decimals = 1 * 10^6
        let prices = vector[2_000_000_000, 1_000_000, 100000_00000000];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        
        test_scenario::return_shared(oracle_config);
    };
    
    s.next_tx(OWNER);
    {
        let momentum_position = mock_momentum::create_mock_position<SUI_TEST_COIN, USDC_TEST_COIN>(s.ctx());
        transfer::public_transfer(momentum_position, OWNER);
    };
    
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let position = s.take_from_sender<MockMomentumPosition<SUI_TEST_COIN, USDC_TEST_COIN>>();
        vault.add_new_defi_asset(0, position);
        test_scenario::return_shared(vault);
    };
    
    // This will abort with ERR_INVALID_POOL_PRICE due to decimal mismatch
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let position_type = vault_utils::parse_key<MockMomentumPosition<SUI_TEST_COIN, USDC_TEST_COIN>>(0);
        
        mock_momentum::update_mock_momentum_position_value<SUI_TEST_COIN, SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault, &config, &clock, position_type
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw where the same oracle system provides both raw and normalized price functions, but the adaptors inconsistently use raw prices for slippage validation and normalized prices for valuation. The existing tests mask this bug by setting all prices with uniform 18-decimal precision, contradicting the configured decimal settings. In production, with correctly formatted prices matching each asset's decimal configuration, this bug would immediately manifest for any LP position involving token pairs with different decimals.

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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L49-66)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18

    // pool price = price_a / price_b (not consider decimals)
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```
