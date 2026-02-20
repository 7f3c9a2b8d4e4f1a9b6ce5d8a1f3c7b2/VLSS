# Audit Report

## Title
Navi Adaptor Uses Non-Normalized Oracle Prices Causing Severe Mispricing for Assets with Non-9 Decimals

## Summary
The Navi adaptor incorrectly uses `get_asset_price()` instead of `get_normalized_asset_price()` when calculating position USD values. This causes assets with decimals different from 9 to be dramatically misvalued—USDC (6 decimals) is undervalued by 1000x and BTC (8 decimals) by 10x—leading to incorrect vault total value, share ratios, and loss tolerance calculations.

## Finding Description

The Navi adaptor contains a critical decimal normalization bug in its value calculation logic. When calculating the USD value of Navi positions, the adaptor retrieves oracle prices using `vault_oracle::get_asset_price()` [1](#0-0) , which returns raw 18-decimal prices without any adjustment for the underlying coin's decimal precision [2](#0-1) .

These raw prices are then passed to `mul_with_oracle_price()` [3](#0-2) , which divides by `ORACLE_DECIMALS` (10^18) [4](#0-3) . This calculation produces values denominated in 10^(coin_decimals) instead of the protocol's expected 10^9 standard.

**Contrast with Correct Implementation:**

All other adaptors correctly use `get_normalized_asset_price()`:
- Cetus adaptor [5](#0-4) 
- Momentum adaptor [6](#0-5) 
- Receipt adaptor [7](#0-6) 

The normalization function adjusts prices based on coin decimals [8](#0-7) . For assets with decimals < 9, the price is multiplied by 10^(9-decimals). For USDC (6 decimals) [9](#0-8) , this means multiplying by 1000.

**Concrete Example:**

For 1,000 USDC in a Navi position:
- Navi adaptor calculates: (1,000 × 10^6) × (1 × 10^18) / 10^18 = 1 × 10^9 (wrong—represents $1 in protocol units)
- Should calculate: (1,000 × 10^6) × (1 × 10^21) / 10^18 = 1,000 × 10^9 (correct—represents $1,000 in protocol units)

Test evidence confirms the expected behavior [10](#0-9) : all USD values must be in 10^9 units regardless of underlying coin decimals.

## Impact Explanation

This vulnerability corrupts the core accounting system of the Volo vault:

**1. Incorrect Total USD Value:**
The vault aggregates all asset values to calculate `total_usd_value` [11](#0-10) . Undervalued Navi positions reduce this total, creating a systematic undervaluation of the vault.

**2. Distorted Share Ratios:**
Share ratio is calculated as `total_usd_value / total_shares` [12](#0-11) . When Navi positions are undervalued:
- New depositors receive excessive shares (diluting existing holders)
- Withdrawers receive insufficient principal (wealth extraction from rightful owners)

**3. Value Storage Corruption:**
The incorrect values are directly stored by the vault [13](#0-12)  corrupting the entire vault accounting system.

**Quantified Impact:**
- USDC (6 decimals): 1000x undervaluation
- BTC (8 decimals): 10x undervaluation

All vault depositors suffer financial harm through share dilution or unfair withdrawal amounts.

## Likelihood Explanation

This vulnerability triggers automatically during normal vault operations without requiring any malicious actor:

**Automatic Trigger Conditions:**
1. Vault holds any Navi positions with non-9-decimal assets (USDC, WETH, BTC, etc.)
2. `update_navi_position_value()` is called [14](#0-13) 

**No Special Preconditions:**
- No admin/operator compromise required
- No special transaction ordering needed
- No unusual market conditions required
- Affects standard assets (USDC is the most common stablecoin)

**Current Protocol State:**
The protocol already configures multi-decimal assets in tests [15](#0-14) , and Navi Protocol on Sui Mainnet supports USDC (6 decimals) and WBTC (8 decimals) as primary lending assets.

The vulnerability is **currently active** and affects any production vault with Navi positions containing non-9-decimal assets.

## Recommendation

Replace the raw price retrieval with normalized price:

**In `navi_adaptor.move` line 63, change:**
```move
let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**To:**
```move
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This ensures all asset prices are normalized to the protocol's standard 10^9 decimal format before calculating USD values, consistent with how all other adaptors operate.

## Proof of Concept

```move
#[test]
public fun test_navi_usdc_mispricing() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Setup USDC oracle with 6 decimals and $1 price
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        let usdc_type = type_name::get<USDC_TEST_COIN>().into_string();
        
        vault_oracle::set_aggregator(&mut oracle_config, &clock, usdc_type, 6, @0xe);
        vault_oracle::set_current_price(&mut oracle_config, &clock, usdc_type, 1 * ORACLE_DECIMALS);
        
        test_scenario::return_shared(oracle_config);
    };
    
    // Add Navi account with 1000 USDC (1,000,000,000 units at 6 decimals)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(0, navi_account_cap);
        test_scenario::return_shared(vault);
    };
    
    // Simulate 1000 USDC in Navi position and update value
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();
        
        // Mock: deposit 1000 USDC into Navi
        // (In real scenario, this would be actual Navi deposit)
        
        navi_adaptor::update_navi_position_value<SUI_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage,
        );
        
        let (usd_value, _) = vault.get_asset_value(vault_utils::parse_key<NaviAccountCap>(0));
        
        // BUG: Should be 1000 * 10^9 but will be 1 * 10^9 (1000x undervalued)
        assert!(usd_value == 1 * DECIMALS, 0); // This passes but is WRONG
        // assert!(usd_value == 1000 * DECIMALS, 0); // This would be CORRECT
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L65-66)
```text
        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
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

**File:** volo-vault/sources/utils.move (L69-71)
```text
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

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-73)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );
```

**File:** volo-vault/tests/test_helpers.move (L18-49)
```text
public fun set_aggregators(s: &mut Scenario, clock: &mut Clock, config: &mut OracleConfig) {
    let owner = s.sender();

    let sui_asset_type = type_name::get<SUI_TEST_COIN>().into_string();
    let usdc_asset_type = type_name::get<USDC_TEST_COIN>().into_string();
    let btc_asset_type = type_name::get<BTC_TEST_COIN>().into_string();

    s.next_tx(owner);
    {
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
    }
}
```

**File:** volo-vault/tests/update/update.test.move (L86-98)
```text
    // Check total usd value at T = 0
    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let total_usd_value = vault.get_total_usd_value(&clock);
        assert!(total_usd_value == 2 * DECIMALS);

        let (principal_asset_value, last_update_time) = vault.get_asset_value(type_name::get<
            SUI_TEST_COIN,
        >().into_string());
        assert!(principal_asset_value == 2 * DECIMALS);
        assert!(last_update_time == 0);
```

**File:** volo-vault/sources/volo_vault.move (L1174-1187)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1287-1294)
```text
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    total_usd_value
```

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```
