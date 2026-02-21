# Audit Report

## Title
Navi Position Valuation Uses Raw Oracle Prices Instead of Normalized Prices, Causing Systematic Misvaluation

## Summary
The Navi adaptor incorrectly uses raw oracle prices without normalization when calculating position USD values, while all other vault adaptors (Cetus, Momentum) properly normalize prices to 9 decimals before the same calculation. This causes systematic 10x to 1000x undervaluation of Navi positions when oracle decimals are configured as anything other than 9, corrupting vault share pricing and loss tolerance enforcement.

## Finding Description

The vulnerability exists in the Navi adaptor's position valuation logic. The adaptor fetches raw oracle prices and directly passes them to the USD value calculation function: [1](#0-0) 

The `get_asset_price()` function returns the raw stored price value without any normalization: [2](#0-1) 

Oracle prices are stored with configurable decimal precision per asset: [3](#0-2) 

The `mul_with_oracle_price()` function always divides by a fixed constant of 10^18: [4](#0-3) 

However, the oracle provides `get_normalized_asset_price()` which properly adjusts prices to a consistent 9-decimal format before calculation: [5](#0-4) 

All other vault adaptors correctly use the normalized price function. The Cetus adaptor demonstrates the proper pattern: [6](#0-5) 

The Momentum adaptor follows the same correct pattern: [7](#0-6) 

The vault's own coin asset valuation also uses normalized prices: [8](#0-7) 

Standard test configurations explicitly use 6, 8, and 9 decimal configurations: [9](#0-8) 

The test suite validates the correct normalization behavior and demonstrates proper USD value calculations: [10](#0-9) [11](#0-10) 

**Root Cause:** The normalization function adjusts prices to 9-decimal equivalent representation. When `mul_with_oracle_price()` divides by 10^18, it expects prices in this normalized format. Without normalization:
- **6 decimals configured:** Result is 10^3 (1000x) too small
- **8 decimals configured:** Result is 10^1 (10x) too small
- **9 decimals configured:** Result is correct (by accident)

## Impact Explanation

This vulnerability has **CRITICAL** impact on vault integrity:

1. **Systematic Position Undervaluation:** All Navi positions are systematically undervalued when oracle decimals ≠ 9. For a vault holding $1M in Navi positions with USDC configured at 6 decimals (standard configuration), the positions would be valued at only $1,000 - a 1000x undervaluation.

2. **Share Price Corruption:** Vault shares are priced based on `total_usd_value`. Undervalued Navi positions artificially deflate this value, causing:
   - New depositors receive MORE shares than deserved (share inflation)
   - Withdrawers can extract MORE value than their fair share (value extraction from other users)
   - Complete breakdown of share-to-value accounting invariant

3. **Loss Tolerance Bypass:** The vault enforces maximum loss per epoch by comparing USD values before and after operations: [12](#0-11) 

Incorrect Navi valuations corrupt these calculations, allowing operators to bypass safety limits. Real losses may appear smaller than actual, or gains may appear as losses.

4. **Cascading Impact:** This affects ALL Navi positions systematically across all operations, not isolated edge cases. Every value update, every deposit/withdrawal calculation, and every loss tolerance check is corrupted.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of occurrence:

**Entry Point:** The vulnerable function is publicly accessible and called during standard vault operations: [13](#0-12) 

**Preconditions:**
1. Admin configures oracle with non-9 decimals (explicitly supported by design - the decimals parameter accepts any `u8` value)
2. Vault holds Navi positions
3. Operator performs routine value updates during Phase 3 of operations

All preconditions are part of normal protocol operation. The test suite itself demonstrates that 6 and 8 decimal configurations are expected valid setups, not edge cases.

**Execution:** No attack required - this triggers automatically during normal vault operations. The bug manifests whenever position values are updated with non-9 decimal oracle configurations.

## Recommendation

Fix the Navi adaptor to use normalized prices like all other adaptors:

```move
// In calculate_navi_position_value() at line 63:
// Change from:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// To:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This aligns Navi with the Cetus and Momentum adaptors, ensuring consistent decimal handling across all position types.

## Proof of Concept

```move
#[test]
public fun test_navi_price_normalization_bug() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Configure USDC with 6 decimals (standard config)
        vault_oracle::set_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
            6,  // 6 decimals
            @0xe,
        );
        
        // Set price to 1 USD (in 10^18 format)
        vault_oracle::set_current_price(
            &mut oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
            1_000_000_000_000_000_000, // 1 * 10^18
        );
        
        test_scenario::return_shared(oracle_config);
    };
    
    s.next_tx(OWNER);
    {
        let config = s.take_shared<OracleConfig>();
        
        // Get raw price (what Navi uses)
        let raw_price = vault_oracle::get_asset_price(
            &config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
        );
        
        // Get normalized price (what Cetus/Momentum use)
        let normalized_price = vault_oracle::get_normalized_asset_price(
            &config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
        );
        
        // Calculate USD value for 1000 USDC (10^6 native units)
        let amount = 1_000_000_000; // 1000 USDC in 6 decimals
        
        let navi_value = vault_utils::mul_with_oracle_price(amount, raw_price);
        let correct_value = vault_utils::mul_with_oracle_price(amount, normalized_price);
        
        // Navi calculates: 1000 * 10^6 instead of 1000 * 10^9
        // This is 1000x too small!
        assert!(navi_value == 1_000_000_000, 0); // Wrong: 1000 * 10^6
        assert!(correct_value == 1_000_000_000_000, 1); // Correct: 1000 * 10^9
        assert!(correct_value == navi_value * 1000, 2); // 1000x difference
        
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
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

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-72)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-64)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/volo_vault.move (L1146-1151)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);
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

**File:** volo-vault/tests/oracle.test.move (L597-605)
```text
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, sui_asset_type) == 2 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, usdc_asset_type) == 1 * ORACLE_DECIMALS * 1_000,
        );
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, btc_asset_type) == 100_000 * ORACLE_DECIMALS * 10,
        );
```

**File:** volo-vault/tests/oracle.test.move (L614-631)
```text
        let sui_usd_value_for_1_sui = vault_utils::mul_with_oracle_price(
            1_000_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, sui_asset_type),
        );

        let usdc_usd_value_for_1_usdc = vault_utils::mul_with_oracle_price(
            1_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, usdc_asset_type),
        );

        let btc_usd_value_for_1_btc = vault_utils::mul_with_oracle_price(
            100_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, btc_asset_type),
        );

        assert!(sui_usd_value_for_1_sui == 2 * DECIMALS);
        assert!(usdc_usd_value_for_1_usdc == 1 * DECIMALS);
        assert!(btc_usd_value_for_1_btc == 100_000 * DECIMALS);
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
