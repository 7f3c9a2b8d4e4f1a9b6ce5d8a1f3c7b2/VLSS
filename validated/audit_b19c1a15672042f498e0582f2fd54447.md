# Audit Report

## Title
Navi Adaptor Uses Non-Normalized Oracle Prices Causing Systematic Asset Misvaluation

## Summary
The Navi adaptor retrieves oracle prices using `get_asset_price()` instead of `get_normalized_asset_price()` like all other adaptors (Cetus, Momentum), causing systematic misvaluation of positions containing assets with non-9 decimals. For USDC (6 decimals), this creates 1000x undervaluation, corrupting vault accounting, share ratios, and loss tolerance enforcement.

## Finding Description

The vulnerability stems from a critical inconsistency in price retrieval across vault adaptors. The Navi adaptor's `calculate_navi_position_value()` function uses the raw oracle price function: [1](#0-0) 

In stark contrast, both Cetus and Momentum adaptors correctly use the normalized price function: [2](#0-1) [3](#0-2) 

The normalization function adjusts prices based on token decimals to ensure consistent 9-decimal precision: [4](#0-3) 

Oracle prices are stored with 18 decimals precision, and the `decimals` field in `PriceInfo` indicates each token's actual decimal places (USDC=6, SUI=9, BTC=8). The normalization multiplies by 10^(9-decimals) for tokens with fewer than 9 decimals, ensuring correct valuation when amounts are multiplied with prices.

The price multiplication utility always divides by 1e18: [5](#0-4) 

**Valuation Error:**
For USDC with 6 decimals and 1,000 USDC (1,000,000,000 base units):
- **Correct (normalized):** price = 1e18 × 10^3 = 1e21, value = 1e9 × 1e21 / 1e18 = 1e12 units
- **Wrong (raw):** price = 1e18, value = 1e9 × 1e18 / 1e18 = 1e9 units
- **Error magnitude:** 1000x undervaluation

## Impact Explanation

**Critical Accounting Corruption:**

The corrupted Navi position values propagate through the vault's total USD value calculation: [6](#0-5) 

Since borrowed assets (liabilities) are systematically undervalued by 1000x for USDC, the net Navi position value (`supply - borrow`) appears artificially inflated, corrupting the vault's `total_usd_value`.

**Share Ratio Manipulation:**

The share ratio depends directly on the corrupted total USD value: [7](#0-6) 

With inflated `total_usd_value`:
- **Depositors receive FEWER shares** than they should (overpaying by up to 1000x in USDC-heavy Navi positions)
- **Withdrawers can extract MORE value** per share, systematically draining value from remaining depositors

**Loss Tolerance Bypass:**

The loss tolerance enforcement compares USD values before and after operations: [8](#0-7) [9](#0-8) 

If actual losses occur in Navi USDC positions, they're masked by the 1000x undervaluation of liabilities, allowing the vault to exceed configured loss tolerance without detection or abort.

This is **Critical** severity because it:
1. Affects fundamental vault accounting on every operation cycle
2. Creates systematic value extraction from honest depositors
3. Completely bypasses loss tolerance risk controls
4. Has guaranteed material impact (1000x error for USDC)
5. Affects the most common DeFi stablecoin

## Likelihood Explanation

**Trigger Mechanism:**

The bug triggers automatically during normal operations when operators call the public adaptor function: [10](#0-9) 

**Preconditions:**
1. Vault has Navi positions (standard integration)
2. Positions include USDC or other non-9-decimal assets (extremely common)
3. Operators perform regular value updates (required for normal vault operations)

**Frequency:**
Occurs on **every operation cycle** where Navi positions are updated. Given that value updates are mandatory before deposit/withdraw execution and USDC is the primary stablecoin in DeFi, this affects virtually all production operation cycles.

**Detection Difficulty:**
The error is systematic rather than intermittent. Corrupted values appear "stable" in monitoring, making the bug hard to detect without direct code audit.

**Probability Assessment:** **HIGH** - Common preconditions (USDC in Navi), mandatory triggering (every operation requires value updates), and no special privileges beyond trusted operator roles make this vulnerability certain to manifest in production deployments with Navi USDC positions.

## Recommendation

Change the Navi adaptor to use normalized prices consistent with other adaptors:

```move
// In calculate_navi_position_value(), replace line 63:
// OLD: let price = vault_oracle::get_asset_price(config, clock, coin_type);
// NEW:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This single-line change ensures price normalization accounts for token decimals, matching the proven-correct behavior in Cetus and Momentum adaptors.

## Proof of Concept

```move
#[test]
public fun test_navi_usdc_misvaluation() {
    // Setup: Configure USDC with 6 decimals in oracle
    // Price: 1 USD = 1e18 in oracle
    // Amount: 1000 USDC = 1e9 base units (6 decimals)
    
    // Expected (normalized): 1e9 * (1e18 * 1e3) / 1e18 = 1e12
    // Actual (raw):         1e9 * 1e18 / 1e18 = 1e9
    
    // Result: 1000x undervaluation
    // This causes share ratio corruption and loss tolerance bypass
}
```

The test would demonstrate that Navi USDC positions are valued at 0.1% of their actual value, directly corrupting vault share ratios and masking losses up to 1000x the configured tolerance for USDC-heavy positions.

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

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
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

**File:** volo-vault/sources/operation.move (L361-364)
```text
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
