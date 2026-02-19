# Audit Report

## Title
Navi Adaptor Uses Non-Normalized Oracle Prices Causing Systematic Asset Misvaluation

## Summary
The Navi adaptor retrieves raw oracle prices without decimal normalization, unlike all other adaptors (Cetus, Momentum). For assets with decimals ≠ 9 (e.g., USDC with 6 decimals), this causes systematic valuation errors of up to 1000x, corrupting vault accounting, share ratios, and loss tolerance checks.

## Finding Description

The Navi adaptor's `calculate_navi_position_value()` function uses `vault_oracle::get_asset_price()` to retrieve oracle prices for valuation calculations. [1](#0-0) 

This contrasts sharply with other adaptors. The Cetus adaptor uses `get_normalized_asset_price()` for its value calculations. [2](#0-1) 

The Momentum adaptor follows the same correct pattern. [3](#0-2) 

The `get_normalized_asset_price()` function performs critical decimal adjustment based on the `decimals` field stored in `PriceInfo`. For assets with decimals < 9, it multiplies the price by 10^(9-decimals); for decimals > 9, it divides by 10^(decimals-9). [4](#0-3) 

Test configurations confirm that different assets use different decimal values: SUI=9, USDC=6, BTC=8. [5](#0-4) 

The root cause lies in how `mul_with_oracle_price()` processes prices. It assumes all prices have been normalized to work correctly with the 18-decimal division. [6](#0-5) 

**Concrete Example (USDC with 6 decimals)**:
- 1000 USDC borrowed = 1,000,000,000 (in native 6 decimals)
- Oracle raw price = 1 × 10^18 (representing $1)
- **Wrong calculation (Navi)**: (1,000,000,000 × 1×10^18) / 10^18 = 1,000,000,000 = **$1** (in 9 decimals)
- **Correct calculation (normalized price 1×10^21)**: (1,000,000,000 × 1×10^21) / 10^18 = 1,000,000,000,000 = **$1000** (in 9 decimals)
- **Result**: 1000x undervaluation

The wrong USD value is stored in the vault's asset value map. [7](#0-6) 

This corrupted value propagates to `get_total_usd_value()`, which sums all individual asset values. [8](#0-7) 

## Impact Explanation

**Critical Vault Accounting Corruption:**

1. **Share Ratio Manipulation**: The share ratio calculation divides `total_usd_value` by `total_shares`. [9](#0-8)  When Navi positions with USDC are undervalued by 1000x, the total vault value appears lower than reality, causing an artificially low share ratio. New depositors receive excessive shares for their deposits because `user_shares = new_usd_value_deposited / share_ratio_before`. [10](#0-9) 

2. **Loss Tolerance Bypass**: During operation value updates, losses are calculated as the difference between USD values before and after. [11](#0-10)  If borrowed USDC amounts are undervalued, actual losses may be 1000x higher than calculated. The `update_tolerance()` function checks if accumulated losses exceed the limit, but with undervalued losses, this check can be bypassed. [12](#0-11) 

3. **Vault Insolvency Risk**: The vault's accounting shows higher net worth than reality. During redemptions, the vault may be unable to honor withdrawals at the inflated share price, leading to insolvency.

4. **Unfair Value Distribution**: Users depositing during undervaluation periods receive excessive shares, diluting existing shareholders. Users withdrawing extract value based on corrupted ratios.

**Severity**: Critical - systematic accounting error affecting all core vault operations with USDC/USDT positions.

## Likelihood Explanation

**Entry Point**: The vulnerability triggers whenever operators call `update_navi_position_value()` during vault operations. [13](#0-12) 

**Preconditions**:
- Vault has Navi positions with non-9-decimal assets (USDC, USDT are common)
- Operators perform value updates during operation lifecycle
- No special privileges or state manipulation required

**Execution Practicality**: The three-phase operation lifecycle mandates value updates for all borrowed assets before completing operations. [14](#0-13)  During `end_op_value_update_with_bag()`, the vault checks that all borrowed assets have been updated and calculates losses. The misvaluation occurs automatically in this standard flow.

**Probability**: High - occurs every operation cycle involving Navi positions with USDC, USDT, or other non-9-decimal assets. These are among the most common DeFi assets.

## Recommendation

Replace `vault_oracle::get_asset_price()` with `vault_oracle::get_normalized_asset_price()` in the Navi adaptor's `calculate_navi_position_value()` function:

```move
// Line 63 in navi_adaptor.move - CHANGE FROM:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// TO:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This ensures Navi adaptor follows the same normalization pattern as Cetus and Momentum adaptors, correctly accounting for different decimal configurations across assets.

## Proof of Concept

```move
#[test]
public fun test_navi_usdc_valuation_bug() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and oracle with USDC (6 decimals)
    init_vault::init_vault(&mut s, &mut clock);
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Add USDC with 6 decimals and price = 1 USD (1e18)
        test_helpers::set_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
            6,  // USDC has 6 decimals
            @0x123
        );
        vault_oracle::set_current_price(
            &mut oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
            1_000_000_000_000_000_000  // 1 USD in 18 decimals
        );
        
        test_scenario::return_shared(oracle_config);
    };
    
    s.next_tx(OWNER);
    {
        let oracle_config = s.take_shared<OracleConfig>();
        
        // Simulate 1000 USDC (1,000,000,000 in 6 decimals)
        let usdc_amount = 1_000_000_000_u256;
        
        // Get raw price (what Navi adaptor uses)
        let raw_price = vault_oracle::get_asset_price(
            &oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string()
        );
        let wrong_value = vault_utils::mul_with_oracle_price(usdc_amount, raw_price);
        
        // Get normalized price (what should be used)
        let normalized_price = vault_oracle::get_normalized_asset_price(
            &oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string()
        );
        let correct_value = vault_utils::mul_with_oracle_price(usdc_amount, normalized_price);
        
        // Verify the bug: wrong_value should be 1000x smaller than correct_value
        assert!(wrong_value == 1_000_000_000, 0); // $1 in 9 decimals
        assert!(correct_value == 1_000_000_000_000, 1); // $1000 in 9 decimals
        assert!(correct_value == wrong_value * 1000, 2); // 1000x difference
        
        test_scenario::return_shared(oracle_config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test proves that for USDC with 6 decimals, the Navi adaptor's approach produces valuations that are 1000x lower than correct, confirming the systematic misvaluation vulnerability.

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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-69)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-61)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
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

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/volo_vault.move (L629-635)
```text
    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L361-363)
```text
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
```
