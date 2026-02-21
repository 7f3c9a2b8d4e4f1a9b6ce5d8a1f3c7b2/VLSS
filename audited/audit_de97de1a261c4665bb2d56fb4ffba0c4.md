# Audit Report

## Title
Incorrect Oracle Price Function in Navi Adaptor Causes Asset Valuation Errors for Non-9-Decimal Coins

## Summary
The Navi adaptor uses the wrong oracle price function (`get_asset_price()` instead of `get_normalized_asset_price()`), causing systematic undervaluation of assets with non-9-decimal precision. USDC positions (6 decimals) are valued at 0.1% of actual value and BTC positions (8 decimals) at 10% of actual value, directly corrupting vault share prices and enabling fund extraction through share price manipulation.

## Finding Description

The root cause is that the Navi adaptor retrieves the raw oracle price without decimal normalization: [1](#0-0) 

This contrasts with all other adaptors which correctly use `get_normalized_asset_price()`. The Cetus adaptor correctly uses: [2](#0-1) 

The Momentum adaptor also uses the normalized price: [3](#0-2) 

Even the vault's own coin-type asset value updates use the normalized price: [4](#0-3) 

**Technical Root Cause:**

The `ray_mul()` operation preserves the input decimal scale: [5](#0-4) 

When `ray_mul(supply, supply_index)` is called at line 53 of the Navi adaptor, the result remains in the coin's native decimals (6 for USDC, 8 for BTC, 9 for SUI). The subsequent price multiplication uses: [6](#0-5) 

Which calls `mul_with_oracle_price()` that divides by ORACLE_DECIMALS (1e18): [7](#0-6) 

This produces results in the coin's native decimal scale, but the vault expects all USD values in 1e9 scale.

**Mathematical Analysis:**
- **SUI (9 decimals):** `1e9 × price / 1e18 = result in 1e9 scale` ✓ Correct
- **USDC (6 decimals):** `1e6 × price / 1e18 = result in 1e6 scale` ✗ Wrong (1000x undervalued)
- **BTC (8 decimals):** `1e8 × price / 1e18 = result in 1e8 scale` ✗ Wrong (10x undervalued)

The correct implementation uses `get_normalized_asset_price()` which adjusts the price based on coin decimals: [8](#0-7) 

This ensures that regardless of coin decimals, the final USD value is always in the standardized 1e9 scale.

**Impact Chain:**

These incorrect values are stored via `finish_update_asset_value()`: [9](#0-8) 

The incorrect values then propagate through the vault's total value calculation: [10](#0-9) 

The total USD value directly determines the share ratio (price): [11](#0-10) 

## Impact Explanation

**Direct Financial Impact:**

When a vault holds Navi positions with non-9-decimal assets:
1. **USDC positions:** Valued at 0.1% of actual value (1000x undervaluation)
2. **BTC positions:** Valued at 10% of actual value (10x undervaluation)
3. **Total vault USD value** is systematically understated
4. **Share price** becomes artificially depressed

**Exploitation Scenario:**

1. Vault contains $1M in assets including $100K USDC in Navi
2. USDC position incorrectly valued at $100 (instead of $100,000)
3. Total vault value calculated as $900,100 instead of $1,000,000
4. Attacker deposits $100K and receives shares at deflated price
5. After bug correction or asset conversion, share price corrects upward
6. Attacker withdraws proportionally and extracts profit from existing depositors

**Secondary Impacts:**
- Loss tolerance checks become unreliable as undervalued positions make losses appear smaller
- Withdrawal calculations systematically disadvantage depositors with undervalued positions
- Protocol accounting integrity completely broken for affected vaults

## Likelihood Explanation

**High Likelihood - Automatically Triggers:**

1. **No Privileges Required:** Any operator performing standard value updates triggers the bug through normal operations: [12](#0-11) 

2. **Common Asset Types:** USDC (6 decimals) and WBTC (8 decimals) are major DeFi assets that Navi protocol supports on Sui

3. **Undetected in Tests:** Current test suite only uses 9-decimal coins for testing, missing this issue entirely: [13](#0-12) 

The test USDC coin uses 9 decimals instead of the realistic 6 decimals, which is why the bug went undetected.

4. **Production Ready Code:** This is not experimental - it's the live implementation that will be used when vaults integrate Navi positions with non-9-decimal assets

5. **No Circuit Breakers:** There are no checks to validate that asset values are in the expected decimal scale or to detect decimal mismatches between adaptors

## Recommendation

Change line 63 of the Navi adaptor from:
```
let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

To:
```
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This ensures the price is adjusted for the coin's decimal precision before multiplication, producing USD values in the standardized 1e9 scale regardless of the underlying coin's decimals.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a vault with free principal in SUI (9 decimals)
2. Adding a Navi position with USDC (6 decimals) 
3. Calling `update_navi_position_value()` and observing the stored USD value
4. Comparing against the expected value using `get_normalized_asset_price()`
5. Calculating the resulting share ratio to show it's depressed by ~1000x for the USDC portion

The mathematical proof shows:
- USDC balance: 1,000,000,000 (1000 USDC in 6 decimals)
- Raw price: 1e18 (from `get_asset_price`)
- Result: 1,000,000,000 * 1e18 / 1e18 = 1,000,000,000
- Interpreted as 9-decimal value: $1.00 instead of $1,000.00
- Undervaluation: 999x

This directly impacts share pricing since the share ratio = total_usd_value / total_shares, and the total_usd_value is artificially deflated by the misvalued USDC position.

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

**File:** volo-vault/sources/volo_vault.move (L1146-1150)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
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

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
}
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

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L71-78)
```text
    public fun ray_mul(a: u256, b: u256): u256 {
        if (a == 0 || b == 0) {
            return 0
        };

        assert!(a <= (address::max() - HALF_RAY) / b, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * b + HALF_RAY) / RAY
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

**File:** volo-vault/tests/test_coins.move (L38-39)
```text
    fun init(witness: USDC_TEST_COIN, ctx: &mut TxContext) {
        let decimals = 9;
```
