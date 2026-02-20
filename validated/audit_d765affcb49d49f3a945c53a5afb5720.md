# Audit Report

## Title
Navi Adaptor Decimal Mismatch Causes Systematic Undervaluation of Non-9-Decimal Assets in Vault USD Calculations

## Summary
The Navi adaptor incorrectly uses `get_asset_price()` instead of `get_normalized_asset_price()` when calculating position USD values. This causes systematic undervaluation for all coins with non-9 decimals: USDC (6 decimals) is undervalued by 1000x, BTC (8 decimals) by 10x. This critical bug affects vault share pricing, can cause operational DoS through false loss detection, and defeats loss tolerance protections.

## Finding Description

The Navi adaptor uses the wrong oracle price function when calculating position values. While all other adaptors correctly use `get_normalized_asset_price()`, the Navi adaptor uses the raw `get_asset_price()` function. [1](#0-0) 

In contrast, other adaptors correctly use the normalized price: [2](#0-1) [3](#0-2) [4](#0-3) 

The oracle system provides price normalization that adjusts for coin decimals to match the vault's 9-decimal standard: [5](#0-4) 

The normalization multiplies prices by `10^(9 - coin_decimals)` for coins with fewer than 9 decimals. When USD values are calculated using `mul_with_oracle_price()`, this ensures the result is correctly scaled to 9 decimals: [6](#0-5) 

**Mathematical Impact:**
- For USDC (6 decimals) at $1.00 with 1,000,000 units (= 1 USDC):
  - **Correct**: 1,000,000 × (1e18 × 1000) / 1e18 = 1,000,000,000 (= $1.00 in 9 decimals)
  - **Navi (Wrong)**: 1,000,000 × 1e18 / 1e18 = 1,000,000 (= $0.001 in 6 decimals)
  - **Error: 1000x undervaluation**

This is verified by existing tests showing expected normalized price behavior: [7](#0-6) [8](#0-7) 

The incorrect USD values from Navi positions feed directly into the vault's total USD value calculation: [9](#0-8) 

This total USD value is used to calculate the share ratio: [10](#0-9) 

And is critical for loss tolerance enforcement during operations: [11](#0-10) [12](#0-11) 

## Impact Explanation

**Critical Impacts:**

1. **Massive Share Dilution**: If a vault holds $100,000 USDC on Navi, it appears as only $100. The share ratio becomes artificially low (1000x). New depositors receive approximately 1000x more shares than they should, massively diluting existing shareholders and effectively stealing value from them.

2. **Operational DoS via False Loss Detection**: A vault with $1M USDC on Navi appears to have only $1K. When position values fluctuate or are recalculated, the apparent change can be $999K, triggering `ERR_EXCEED_LOSS_LIMIT` even when no real loss occurred. This bricks vault operations until Navi positions are unwound.

3. **Loss Tolerance Bypass**: Real losses can be hidden by the undervaluation error. If a vault loses $50K but has $1M USDC undervalued by $999K, the net apparent change masks the real loss, defeating the epoch-based loss protection mechanism.

4. **Incorrect Withdrawal Calculations**: Users withdrawing assets receive incorrect amounts based on the distorted share ratio, either receiving far less than deserved (if they deposited before the bug) or far more (if they deposited during the bug period).

The severity is **CRITICAL** because:
- USDC is a primary lending asset on Navi Protocol
- The error is 1000x for the most common stablecoin
- Affects core accounting: share pricing and loss detection
- Impacts all vault participants

## Likelihood Explanation

**Likelihood: HIGH (Automatic Trigger)**

This vulnerability triggers automatically during normal vault operations:

1. **Common Preconditions**: Vaults holding Navi positions with non-9-decimal tokens (USDC, BTC, USDT, etc.) - these are the most common lending assets.

2. **Normal Operation Flow**: When operators update asset values during vault operations by calling `update_navi_position_value()`, the bug executes automatically. No malicious input or special privileges required.

3. **No Attacker Needed**: This is a systematic accounting bug, not an exploitable attack. It happens through normal protocol usage.

4. **Detection Difficulty**: Off-chain systems see incorrect USD values but have no on-chain indication that values are wrong. The bug appears as legitimate valuation until manually compared with other adaptors' pricing logic.

5. **Wide Impact**: Every vault operation involving Navi positions with non-9-decimal assets is affected.

## Recommendation

Replace `get_asset_price()` with `get_normalized_asset_price()` in the Navi adaptor to align with all other adaptors:

```move
// In calculate_navi_position_value() at line 63, change from:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// To:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This single-line fix ensures Navi position values are calculated with the same decimal normalization as all other adaptors (Cetus, Momentum, Receipt), maintaining consistency across the vault accounting system.

## Proof of Concept

```move
#[test]
fun test_navi_adaptor_decimal_mismatch_undervalues_usdc() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault and oracle with USDC (6 decimals)
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(OWNER);
    {
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        let mut aggregator = mock_aggregator::create_mock_aggregator(scenario.ctx());
        
        // Set USDC price to $1.00 (1e18 with 18 decimals)
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, 0);
        
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
            6, // USDC has 6 decimals
            &aggregator,
        );
        
        // Get prices
        let raw_price = vault_oracle::get_asset_price(&oracle_config, &clock, 
            type_name::get<USDC_TEST_COIN>().into_string());
        let normalized_price = vault_oracle::get_normalized_asset_price(&oracle_config, &clock,
            type_name::get<USDC_TEST_COIN>().into_string());
        
        // Calculate USD value for 1 USDC (1,000,000 units with 6 decimals)
        let usdc_amount = 1_000_000u256;
        let wrong_value = vault_utils::mul_with_oracle_price(usdc_amount, raw_price);
        let correct_value = vault_utils::mul_with_oracle_price(usdc_amount, normalized_price);
        
        // Verify 1000x undervaluation when using raw price
        assert!(wrong_value == 1_000_000); // Only $0.001 in 6 decimals
        assert!(correct_value == 1_000_000_000); // $1.00 in 9 decimals
        assert!(correct_value == wrong_value * 1000); // 1000x difference
        
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

### Citations

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

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-63)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
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

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
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

**File:** volo-vault/tests/oracle.test.move (L619-631)
```text
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

**File:** volo-vault/sources/volo_vault.move (L629-635)
```text
    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
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

**File:** volo-vault/sources/operation.move (L361-363)
```text
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
```
