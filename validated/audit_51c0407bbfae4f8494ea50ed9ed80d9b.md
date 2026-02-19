# Audit Report

## Title
Navi Adaptor Incorrectly Uses Non-Normalized Oracle Prices Leading to Mispriced Asset Valuations

## Summary
The `navi_adaptor.move` module uses `get_asset_price()` instead of `get_normalized_asset_price()` when calculating Navi position USD values, causing incorrect valuations for tokens with non-9 decimals. This breaks the critical pricing invariant that all vault USD values must be standardized to 9 decimals, leading to severe share price manipulation and potential fund loss.

## Finding Description

The Volo vault system requires all asset valuations to be expressed in USD with exactly 9 decimal places for consistent accounting across different token types. The `mul_with_oracle_price()` utility function is designed to work with **normalized** oracle prices that have been adjusted based on token decimals to ensure this 9-decimal output invariant. [1](#0-0) [2](#0-1) 

The oracle module provides two distinct price functions:
1. `get_asset_price()` - Returns raw 18-decimal prices from Switchboard
2. `get_normalized_asset_price()` - Adjusts prices based on token decimals to ensure 9-decimal USD output [3](#0-2) [4](#0-3) 

**All other adaptors correctly use the normalized price function:**

Cetus adaptor: [5](#0-4) 

Momentum adaptor: [6](#0-5) 

**However, the Navi adaptor uses the non-normalized price:** [7](#0-6) 

**Root Cause Analysis:**

The `supply_scaled` and `borrow_scaled` values after `ray_mul` represent token amounts in their native decimals. This is confirmed by the Navi lending core implementation: [8](#0-7) 

When these native-decimal amounts are multiplied by a raw 18-decimal price and divided by 1e18, the result has the same decimal precision as the token, NOT the required 9 decimals for USD values.

**Mathematical Breakdown:**

For USDC (6 decimals):
- Token amount: `1_000_000` (1 USDC)
- Raw price: `1e18` (1 USD per USDC)
- Calculation: `(1_000_000 * 1e18) / 1e18 = 1_000_000`
- Result: `1_000_000` with 6 decimals = $0.001 (should be `1_000_000_000` with 9 decimals = $1.00)
- **Error: 1000x undervaluation**

For tokens with 9 decimals (like SUI), the bug doesn't manifest, which may have masked this issue during testing.

## Impact Explanation

This vulnerability causes critical accounting failures in vaults that hold Navi positions with non-9-decimal tokens:

**1. Share Price Manipulation:**
The mispriced Navi position values corrupt the vault's `total_usd_value` calculation: [9](#0-8) [10](#0-9) 

This incorrect total directly affects share pricing: [11](#0-10) 

**2. Direct Fund Loss Scenario:**
- Vault has $1M USDC in Navi (reported as $1,000) + $1M in other assets
- Total reported: ~$1,001,000 (should be $2,000,000)
- Share price: 50% of actual value
- Attacker deposits $1M worth of assets
- Receives shares worth $2M in actual vault value
- Immediately withdraws for ~$2M
- **Net theft: ~$1M per transaction**

**3. Loss Tolerance Bypass:**
With systematically undervalued assets, operators could trigger actual losses that don't breach the `loss_tolerance` threshold because the baseline is artificially low.

**4. Cascading Accounting Failures:**
The incorrect `total_usd_value` affects reward distribution, receipt valuations, and all vault accounting operations.

## Likelihood Explanation

**High Likelihood due to:**

1. **Confirmed Token Support:** Test files demonstrate Navi protocol supports USDC and USDT with 6 decimals, matching real-world stablecoin standards that are extremely common in DeFi.

2. **Normal Operations Trigger:** The bug activates through standard vault operations - operators adding Navi positions and updating values via `update_navi_position_value()`, which is part of normal vault management.

3. **No Special Permissions Required:** Any vault with a Navi position containing non-9-decimal tokens will exhibit this behavior. Users can then exploit via standard deposit/withdraw flows.

4. **No Detection Mechanism:** The protocol lacks validation to ensure all adaptor-returned USD values are in 9-decimal format. The bug is silent until funds are drained.

5. **Economic Incentive:** With potential 1000x mispricing for USDC and 10x for BTC-like tokens, attackers have massive profit incentives (millions per transaction) with only gas fee costs.

The vulnerability will automatically manifest whenever common stablecoins (USDC, USDT) are used in Navi positions, making exploitation highly probable.

## Recommendation

Replace `get_asset_price()` with `get_normalized_asset_price()` in the Navi adaptor:

```move
// Line 63 in navi_adaptor.move - CHANGE FROM:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// TO:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This ensures the price is adjusted for token decimals, producing consistent 9-decimal USD values regardless of the underlying token's decimal precision, matching the behavior of all other adaptors.

## Proof of Concept

The existing test file demonstrates the vulnerability - it only tests with SUI (9 decimals), where the bug doesn't manifest. A test with USDC (6 decimals) in a Navi position would reveal the 1000x valuation error when comparing expected vs actual USD values from `calculate_navi_position_value()`.

## Notes

This is a critical decimal precision bug that violates the vault's fundamental accounting invariant. The consistency issue (Cetus/Momentum use normalized prices while Navi doesn't) indicates this was an oversight rather than intentional design. The fix is trivial (one-line change) but the impact is severe, enabling direct theft of vault funds through share price manipulation.

### Citations

**File:** volo-vault/sources/utils.move (L9-10)
```text
const DECIMALS: u256 = 1_000_000_000; // 10^9
const ORACLE_DECIMALS: u256 = 1_000_000_000_000_000_000; // 10^18
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L53-66)
```text
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L486-490)
```text
    public fun user_collateral_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (supply_balance, _) = storage::get_user_balance(storage, asset, user);
        let (supply_index, _) = storage::get_index(storage, asset);
        ray_math::ray_mul(supply_balance, supply_index) // scaled_amount
    }
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
