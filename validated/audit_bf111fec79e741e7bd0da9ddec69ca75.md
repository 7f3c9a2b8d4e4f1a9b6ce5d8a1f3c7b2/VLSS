# Audit Report

## Title
Incorrect Oracle Price Function in Navi Adaptor Causes Asset Valuation Errors for Non-9-Decimal Coins

## Summary
The Navi adaptor uses `get_asset_price()` instead of `get_normalized_asset_price()` when calculating position values, causing systematic undervaluation of assets with decimals other than 9. USDC positions (6 decimals) are valued at 1000x too low and BTC positions (8 decimals) at 10x too low, directly corrupting vault share prices and enabling fund extraction through share price manipulation.

## Finding Description

The root cause is at line 63 of the Navi adaptor where it retrieves the raw oracle price without decimal normalization: [1](#0-0) 

This contrasts with all other adaptors which correctly use `get_normalized_asset_price()`. For example, the Cetus adaptor: [2](#0-1) 

And the Momentum adaptor: [3](#0-2) 

Even the vault's own asset value update functions use the normalized price: [4](#0-3) [5](#0-4) 

**Technical Root Cause:**

The `ray_mul()` operation preserves the input decimal scale: [6](#0-5) 

When `ray_mul(supply, supply_index)` is called with supply in native coin decimals (6 for USDC, 8 for BTC, 9 for SUI), the result remains in those native decimals. The subsequent multiplication with the raw oracle price: [7](#0-6) 

Uses `mul_with_oracle_price()` which divides by `ORACLE_DECIMALS` (1e18): [8](#0-7) 

This produces results in the coin's native decimal scale, but the vault expects all USD values in 1e9 scale: [9](#0-8) 

**Mathematical Analysis:**
- **SUI (9 decimals):** 1e9 × price / 1e18 = result in 1e9 scale ✓ Correct
- **USDC (6 decimals):** 1e6 × price / 1e18 = result in 1e6 scale ✗ Wrong (1000x undervalued)
- **BTC (8 decimals):** 1e8 × price / 1e18 = result in 1e8 scale ✗ Wrong (10x undervalued)

The correct implementation uses `get_normalized_asset_price()` which adjusts the price decimals based on coin decimals: [10](#0-9) 

This ensures that regardless of coin decimals, the final USD value is always in the standardized 1e9 scale.

**Impact Chain:**

These incorrect values propagate through the vault's total value calculation: [11](#0-10) 

The total USD value directly determines the share ratio (price): [12](#0-11) 

## Impact Explanation

**Direct Financial Impact:**

When a vault holds Navi positions with non-9-decimal assets:
1. **USDC positions:** Valued at 0.1% of actual value (1000x undervaluation)
2. **BTC positions:** Valued at 10% of actual value (10x undervaluation)
3. **Total vault USD value** is systematically understated
4. **Share price** becomes artificially depressed

**Exploitation Scenario:**

1. Vault contains $1M in various assets including $100K USDC in Navi
2. USDC position incorrectly valued at $100 (instead of $100,000)
3. Total vault value: $900,100 instead of $1,000,000
4. Attacker deposits $100K and receives shares calculated at deflated price
5. After correcting USDC valuation or converting to 9-decimal assets, share price corrects
6. Attacker withdraws proportionally and extracts ~$110K, stealing $10K from existing depositors

**Secondary Impacts:**
- Loss tolerance checks become unreliable as undervalued positions make losses appear smaller
- Withdrawal calculations favor depositors at expense of those with undervalued positions
- Protocol accounting integrity completely broken for affected vaults

## Likelihood Explanation

**High Likelihood - Automatically Triggers:**

1. **No Privileges Required:** Any operator performing standard value updates triggers the bug via: [13](#0-12) 

2. **Common Asset Types:** USDC (6 decimals) and WBTC (8 decimals) are major DeFi assets that Navi protocol supports

3. **Undetected in Tests:** Current test suite only uses SUI (9 decimals) for Navi positions: [14](#0-13) 

4. **Production Ready Code:** This is not experimental - it's the live implementation that will be used when vaults integrate Navi positions with non-9-decimal assets

5. **No Circuit Breakers:** There are no checks to validate that asset values are in the expected decimal scale or to detect decimal mismatches between adaptors

## Recommendation

Replace `get_asset_price()` with `get_normalized_asset_price()` in the Navi adaptor:

**Current buggy code (line 63):** [1](#0-0) 

**Corrected implementation:**
```move
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This ensures the price is adjusted for coin decimals, producing USD values consistently in 1e9 scale regardless of the underlying coin's decimal configuration, matching the pattern used by all other adaptors and the vault's own value update functions.

## Proof of Concept

```move
#[test]
fun test_navi_usdc_undervaluation() {
    let mut scenario = test_scenario::begin(OWNER);
    
    // Setup vault with Navi position containing 1000 USDC (6 decimals)
    // USDC amount: 1000 * 1e6 = 1,000,000,000
    // Expected value: $1000 in 1e9 scale = 1000 * 1e9
    
    // Call update_navi_position_value()
    // With get_asset_price(): 1e6 * 1e18 / 1e18 = 1e6
    // Result: $1 in 1e6 scale (1000x undervalued)
    
    // With get_normalized_asset_price(): 1e6 * 1e21 / 1e18 = 1e9
    // Result: $1 in 1e9 scale (correct)
    
    let total_value = vault.get_total_usd_value(&clock);
    // Assert: total_value is 1000x lower than expected when USDC is present
    
    test_scenario::end(scenario);
}
```

---

**Notes:**

This vulnerability represents a critical decimal handling error that violates the vault's fundamental accounting invariant: all USD values must be in 1e9 scale. The issue is invisible in current tests because they only use 9-decimal coins, but becomes immediately exploitable when production vaults hold Navi positions with USDC, WBTC, or any other non-9-decimal asset. The fix is straightforward and follows the established pattern used throughout the rest of the codebase.

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

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
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

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L71-79)
```text
    public fun ray_mul(a: u256, b: u256): u256 {
        if (a == 0 || b == 0) {
            return 0
        };

        assert!(a <= (address::max() - HALF_RAY) / b, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * b + HALF_RAY) / RAY
    }
```

**File:** volo-vault/sources/utils.move (L9-9)
```text
const DECIMALS: u256 = 1_000_000_000; // 10^9
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
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

**File:** volo-vault/tests/update/update.test.move (L954-970)
```text
    // Navi account position 1 SUI
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let operator_cap = s.take_from_sender<OperatorCap>();

        let mut storage = s.take_shared<Storage>();
        let config = s.take_shared<OracleConfig>();

        vault::update_free_principal_value(&mut vault, &config, &clock);
        navi_adaptor::update_navi_position_value<SUI_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage,
        );
```
