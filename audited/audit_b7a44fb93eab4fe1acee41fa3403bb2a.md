# Audit Report

## Title
Suilend Position Value Inflation Due to Incorrect Decimal Scaling Factor Mismatch

## Summary
The Suilend adaptor contains a critical decimal scaling error that inflates position values by 1 billion times (1e9). Suilend's native `Decimal` type uses 1e18 (WAD) scaling, but the adaptor only divides by 1e9 instead of 1e18, leaving values inflated by the difference. This breaks vault accounting, causing depositors to lose ~99.9999999% of their deposits and enabling existing shareholders to drain the vault.

## Finding Description

The vulnerability stems from a fundamental mismatch between Suilend's decimal representation and the Volo vault's expected USD value format.

**Root Cause:**

Suilend uses a `Decimal` type with 1e18 (WAD) scaling for all market values: [1](#0-0) 

The `to_scaled_val()` function extracts the raw `value` field, which remains scaled by 1e18: [2](#0-1) 

Suilend's reserve functions return `Decimal` types with 1e18 scaling: [3](#0-2) [4](#0-3) 

However, the Suilend adaptor incorrectly uses `DECIMAL = 1e9` for division: [5](#0-4) 

The adaptor extracts 1e18-scaled values at lines 62 and 82, then divides by only 1e9 at line 88: [6](#0-5) 

**Mathematical Error:**
- Suilend value: `X * 1e18` (in Decimal)
- After `to_scaled_val()`: `X * 1e18` (raw u256)
- After division by 1e9: `X * 1e9` (should be `X`)
- **Result: 1 billion times inflation**

**Inconsistency with Other Adaptors:**

All other adaptors correctly return unscaled USD values. For example, the Navi adaptor uses `mul_with_oracle_price`: [7](#0-6) 

The Cetus adaptor follows the same pattern: [8](#0-7) 

The `mul_with_oracle_price` function correctly divides by `ORACLE_DECIMALS = 1e18`: [9](#0-8) [10](#0-9) 

**Impact Propagation:**

The inflated value is stored in the vault's asset value table: [11](#0-10) 

This inflated value is summed into the total USD value: [12](#0-11) 

Which directly affects the share ratio calculation: [13](#0-12) 

The corrupted share ratio then affects deposits: [14](#0-13) 

And withdrawals: [15](#0-14) 

## Impact Explanation

**CRITICAL - Direct Fund Loss**

The 1e9 inflation factor has catastrophic consequences:

1. **Depositor Loss:** When depositing, users receive shares calculated as `new_usd_value / share_ratio`. With an inflated share ratio (1e9 times larger), depositors receive 1e9 times fewer shares. A $1,000 deposit that should yield 1,000 shares will only yield ~0.000001 shares, representing a 99.9999999% loss.

2. **Withdrawer Theft:** When withdrawing, the USD value is calculated as `shares × share_ratio`. With the inflated ratio, withdrawers can extract 1e9 times more value than entitled. A shareholder with $1,000 worth of shares can attempt to withdraw up to $1 trillion worth of assets.

3. **Vault Insolvency:** The accounting disconnect makes the vault insolvent, as the reported total_usd_value is 1 billion times higher than reality. This breaks all vault operations, loss tolerance checks, and fund management.

4. **Affected Scope:** Any vault holding Suilend positions as DeFi assets is vulnerable. All depositors to such vaults lose their funds, and existing shareholders can drain available assets.

## Likelihood Explanation

**HIGH - Automatic Trigger During Normal Operations**

1. **Public Entry Point:** The vulnerability triggers through the public function `update_suilend_position_value()`: [16](#0-15) 

2. **Standard Workflow:** Operators call this function during step 2 of the normal three-step operation flow to update asset values. No attack or malicious intent is required—the bug occurs automatically during correct usage.

3. **No Preconditions:** Any vault with Suilend positions is affected. The bug is in the core calculation logic with no conditional paths to avoid it.

4. **Test Coverage Gap:** Mock tests use unscaled values, failing to catch the production bug: [17](#0-16) 

The mock returns an unscaled `usd_value` directly, not using Suilend's actual 1e18-scaled `Decimal` types that would expose the bug.

## Recommendation

**Fix: Change the division constant from 1e9 to 1e18**

In `volo-vault/sources/adaptors/suilend_adaptor.move`, change line 10 from:
```move
const DECIMAL: u256 = 1_000_000_000;  // 1e9 - WRONG
```

To:
```move
const DECIMAL: u256 = 1_000_000_000_000_000_000;  // 1e18 - CORRECT
```

This aligns with Suilend's WAD constant and ensures proper descaling of the 1e18-scaled values returned by `to_scaled_val()`.

**Alternative approach:** Use the same pattern as other adaptors by incorporating oracle price handling with `mul_with_oracle_price`, which already uses the correct 1e18 divisor.

## Proof of Concept

```move
#[test]
fun test_suilend_decimal_scaling_bug() {
    // Simulate Suilend's Decimal with 1e18 scaling
    let suilend_value_wad = 1000 * 1_000_000_000_000_000_000; // $1000 with 1e18 scaling
    
    // Current buggy implementation: divide by 1e9
    let buggy_result = suilend_value_wad / 1_000_000_000;
    // Result: 1000 * 1e9 = 1,000,000,000,000 (1 trillion instead of 1000)
    
    // Correct implementation: divide by 1e18
    let correct_result = suilend_value_wad / 1_000_000_000_000_000_000;
    // Result: 1000 (correct)
    
    assert!(buggy_result == 1_000_000_000_000, 0); // Inflated by 1e9
    assert!(correct_result == 1000, 1); // Correct value
    assert!(buggy_result / correct_result == 1_000_000_000, 2); // Exactly 1 billion times inflation
}
```

**Notes**

This vulnerability is a textbook example of decimal scaling mismatch. The core issue is that Suilend uses 18 decimal places (standard in DeFi for precision) while the adaptor assumes 9 decimal places. The 9-order-of-magnitude error is not a rounding issue—it's a catastrophic miscalculation that would immediately drain any vault with Suilend positions upon the first deposit or withdrawal after a value update.

The vulnerability is particularly insidious because:
1. It passes tests due to simplified mocks
2. It's buried in a seemingly simple division operation
3. The impact only manifests when real Suilend `Decimal` types are used
4. Every other adaptor correctly handles 1e18 scaling, making this an isolated bug in the Suilend integration

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L1-4)
```text
/// fixed point decimal representation. 18 decimal places are kept.
module suilend::decimal {
    // 1e18
    const WAD: u256 = 1000000000000000000;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L47-49)
```text
    public fun to_scaled_val(v: Decimal): u256 {
        v.value
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L261-272)
```text
    public fun market_value<P>(
        reserve: &Reserve<P>, 
        liquidity_amount: Decimal
    ): Decimal {
        div(
            mul(
                price(reserve),
                liquidity_amount
            ),
            decimal::from(std::u64::pow(10, reserve.mint_decimals))
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L300-311)
```text
    public fun ctoken_market_value<P>(
        reserve: &Reserve<P>, 
        ctoken_amount: u64
    ): Decimal {
        // TODO should i floor here?
        let liquidity_amount = mul(
            decimal::from(ctoken_amount),
            ctoken_ratio(reserve)
        );

        market_value(reserve, liquidity_amount)
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L10-10)
```text
const DECIMAL: u256 = 1_000_000_000;
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L58-88)
```text
        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L65-66)
```text
        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L71-72)
```text
    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/utils.move (L10-10)
```text
const ORACLE_DECIMALS: u256 = 1_000_000_000_000_000_000; // 10^18
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1013-1013)
```text
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
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

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1297-1309)
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
```

**File:** volo-vault/tests/mock/mock_suilend.move (L45-49)
```text
public fun calculate_suilend_obligation_value<PoolType>(
    obligation: &MockSuilendObligation<PoolType>,
): u256 {
    obligation.usd_value as u256
}
```
