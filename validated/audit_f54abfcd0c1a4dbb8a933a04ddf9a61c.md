# Audit Report

## Title
Mismatched Oracle Price Decimals Cause DoS in DEX Position Value Updates

## Summary
The DEX adaptors (Momentum and Cetus) incorrectly use raw oracle prices with potentially different decimal formats when calculating relative prices for slippage validation. This causes the slippage check to fail with mathematically incorrect results when two assets in a pool have different oracle decimal configurations, preventing all position value updates for affected pools.

## Finding Description

The vulnerability exists in both `get_position_value()` and `calculate_cetus_position_value()` functions in the DEX adaptors.

**Root Cause:**

The adaptors calculate a relative price between two assets using raw oracle prices without decimal normalization: [1](#0-0) 

The comment "Oracle price has 18 decimals" is merely an assumption. The `get_asset_price()` function returns the raw price with whatever decimal format was configured when the aggregator was added: [2](#0-1) 

The oracle system stores a `decimals` field in `PriceInfo` that can have any value per asset: [3](#0-2) 

This decimals value is set when adding aggregators with no validation that different assets use matching decimal formats: [4](#0-3) 

**Why Existing Protections Fail:**

While the system provides `get_normalized_asset_price()` that normalizes prices to 9 decimals: [5](#0-4) 

The adaptors incorrectly use `get_asset_price()` (non-normalized) for the slippage check calculation, while only using `get_normalized_asset_price()` for the final USD value calculation: [6](#0-5) 

**Mathematical Impact:**

The slippage check compares the non-normalized relative price against the pool price that always has 18 decimals: [7](#0-6) 

When assets have different oracle decimals (e.g., ETH=18, BTC=8), the calculation produces:
- `relative_price_from_oracle = (2000 * 10^18) * 10^18 / (40000 * 10^8) = 5 * 10^26`
- `pool_price = 0.05 * 10^18 = 5 * 10^16`
- Magnitude difference of 10^10 causes ~100% calculated slippage, always failing the assertion

**Evidence from Test Suite:**

The test helpers confirm different decimal formats are expected and used in production: [8](#0-7) 

## Impact Explanation

**Severity: HIGH**

This causes complete operational DoS for affected DEX pools:

1. **Position Value Update Failure**: The vault cannot update Momentum or Cetus position values when pool assets have different oracle price decimal formats. The assertion will always abort with `ERR_INVALID_POOL_PRICE`.

2. **Inaccurate Total Valuation**: Without updated position values, the vault cannot track its total USD value accurately, breaking the core accounting invariant.

3. **Blocked Operations**: All vault operations depending on accurate position valuation are prevented, including deposits, withdrawals, and strategy adjustments.

4. **No Workaround**: Once triggered, there is no way to update position values without modifying the oracle decimal configuration or redeploying fixed contract code.

The functions are public and directly callable: [9](#0-8) [10](#0-9) 

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will naturally occur in any production deployment with diverse oracle feeds:

1. **Natural Occurrence**: Different oracle providers use different decimal formats for different asset types. BTC price feeds commonly use 8 decimals, ETH typically uses 18 decimals, and stablecoins may use 6 or 9 decimals.

2. **No Malicious Action Required**: This is not an attack scenario - it's a natural consequence of integrating with real oracle providers that use asset-appropriate decimal formats.

3. **Expected in Production**: Multi-asset DEX vaults integrating with diverse Switchboard oracle feeds will inevitably encounter this issue when assets in the same pool have different decimal configurations.

4. **Direct Reachability**: The vulnerable functions are public entry points that operators call during normal vault operation workflows.

## Recommendation

Modify the DEX adaptors to use `get_normalized_asset_price()` instead of `get_asset_price()` for the slippage check calculation. This ensures both prices are normalized to the same decimal format (9 decimals) before computing the relative price.

In `momentum.adaptor.move` and `cetus_adaptor.move`, replace lines 49-51 with:

```move
let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a * DECIMAL / normalized_price_b;
```

Note: Since normalized prices use 9 decimals but `DECIMAL` is 18 decimals, you may also need to adjust the calculation or use a different constant for consistency.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = momentum_adaptor::ERR_INVALID_POOL_PRICE)]
public fun test_mismatched_decimals_dos() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut config = s.take_shared<OracleConfig>();
        
        // Set BTC with 8 decimals, ETH with 18 decimals (mimicking real oracles)
        vault_oracle::set_aggregator(&mut config, &clock, 
            type_name::get<BTC_TEST_COIN>().into_string(), 8, @0xBTC);
        vault_oracle::set_aggregator(&mut config, &clock,
            type_name::get<ETH_TEST_COIN>().into_string(), 18, @0xETH);
        
        // Set prices: BTC=$40000 with 8 decimals, ETH=$2000 with 18 decimals
        vault_oracle::set_current_price(&mut config, &clock,
            type_name::get<BTC_TEST_COIN>().into_string(), 40000 * 100000000); // 8 decimals
        vault_oracle::set_current_price(&mut config, &clock,
            type_name::get<ETH_TEST_COIN>().into_string(), 2000 * 1000000000000000000); // 18 decimals
        
        test_scenario::return_shared(config);
    };
    
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let mut pool = mock_momentum::create_btc_eth_pool(s.ctx());
        
        // This will ABORT due to decimal mismatch even though pool price matches oracle
        momentum_adaptor::update_momentum_position_value<SUI_TEST_COIN, BTC_TEST_COIN, ETH_TEST_COIN>(
            &mut vault, &config, &clock, utf8(b"momentum_position_0"), &mut pool
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        pool.destroy();
    };
    
    clock.destroy_for_testing();
    s.end();
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-61)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
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

**File:** volo-vault/sources/oracle.move (L158-178)
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```
