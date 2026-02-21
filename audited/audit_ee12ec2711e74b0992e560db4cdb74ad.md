# Audit Report

## Title
Underwater Navi Positions Valued at Zero Instead of Negative Equity, Hiding Losses and Inflating Vault Share Price

## Summary
The `calculate_navi_position_value` function contains a critical accounting flaw: when a leveraged Navi position becomes underwater (borrows exceed supplies), it returns 0 instead of recognizing negative net value as a liability. This causes the vault's total USD value to exclude underwater liabilities, artificially inflating the share ratio and resulting in unfair loss distribution among vault participants.

## Finding Description

**Root Cause - Critical Accounting Logic:**

When `total_borrow_usd_value` exceeds `total_supply_usd_value`, the function returns 0 instead of a negative value representing the liability: [1](#0-0) 

This zero value is then stored in the vault's `assets_value` table: [2](#0-1) [3](#0-2) 

**How Losses Propagate to Share Pricing:**

The vault's `get_total_usd_value` function aggregates all asset values from the `assets_value` table, summing the 0 value instead of accounting for negative equity: [4](#0-3) 

The share ratio is then calculated by dividing this inflated `total_usd_value` by `total_shares`: [5](#0-4) 

**Why Existing Protections Fail:**

While the Navi protocol enforces health factor checks during borrow and withdraw operations: [6](#0-5) [7](#0-6) 

These checks only prevent unhealthy operations **at transaction time**. Positions can become underwater **post-creation** through market price movements, interest accrual, or oracle price updates between transactions.

The loss tolerance mechanism detects value drops but has a critical limitation: [8](#0-7) 

It only captures the drop from positive value to 0, but does not account for continued negative equity beyond that point. For example, if a position goes from $100,000 to -$10,000:
- Loss detected: $100,000 (drop to $0)
- Actual loss: $110,000 (including -$10k negative equity)
- Hidden liability: $10,000

**Navi AccountCap Storage:**

The Navi `AccountCap` has `key, store` abilities allowing it to be stored in the vault: [9](#0-8) 

## Impact Explanation

**Direct Financial Harm:**

1. **Hidden Liabilities**: A position with -$10,000 net equity (e.g., $90k collateral, $100k debt) is reported as $0 value, hiding the $10k liability from vault accounting

2. **Inflated Share Pricing**: The vault's `total_usd_value` excludes underwater position liabilities, causing the share ratio to be artificially high

3. **Unfair Loss Distribution**: New depositors purchase shares at inflated prices, unknowingly buying into hidden losses

4. **Liquidation Penalties**: When underwater positions are eventually liquidated, the liquidation bonus creates additional unexpected losses: [10](#0-9) 

5. **Wealth Transfer**: Early withdrawers extract value at inflated share prices while remaining shareholders absorb the realized losses

**Quantified Example:**

For a vault holding a single underwater Navi position:
- Position: $80,000 collateral, $100,000 debt = -$20,000 actual value
- Reported value: $0
- Vault's other assets: $200,000
- **Actual total value**: $180,000
- **Reported total value**: $200,000  
- **Share price inflation**: 11% overvalued
- Users depositing during this period overpay by 11%

## Likelihood Explanation

**High Likelihood** - This vulnerability is triggered by normal market conditions without requiring any attacker action:

**Natural Exploitation:**
- Vaults using Navi positions with any leverage (>1x exposure) are susceptible
- Normal crypto market volatility (20-50% price swings) can trigger underwater states
- No active attack needed - passive market movements suffice

**Feasibility Conditions (All Realistic):**
- Vault holds Navi AccountCap with leveraged positions (borrow > 0)
- Market prices move adversely: collateral ↓ or debt ↑
- Position health factor drops below 1.0 (underwater)
- Vault operator calls `update_navi_position_value` during normal operations

**Historical Precedent:**
The 2022 crypto market crash saw 40-60% drawdowns on major assets - sufficient to push leveraged positions underwater. Even modest 2-3x leverage becomes underwater with 33-50% collateral depreciation, which occurs regularly in crypto markets.

## Recommendation

Modify `calculate_navi_position_value` to handle negative equity properly. Since Move does not support signed integers natively, implement one of these approaches:

**Option 1: Return tuple with sign flag**
```move
public fun calculate_navi_position_value(...): (u256, bool) {
    // ... existing calculation ...
    
    if (total_supply_usd_value < total_borrow_usd_value) {
        let negative_value = total_borrow_usd_value - total_supply_usd_value;
        return (negative_value, true) // true indicates negative
    };
    
    (total_supply_usd_value - total_borrow_usd_value, false)
}
```

**Option 2: Abort on underwater positions**
Prevent underwater positions from being held by the vault by checking health factor before operations and aborting if a position becomes underwater:
```move
public fun calculate_navi_position_value(...): u256 {
    // ... existing calculation ...
    
    assert!(
        total_supply_usd_value >= total_borrow_usd_value, 
        ERR_UNDERWATER_POSITION
    );
    
    total_supply_usd_value - total_borrow_usd_value
}
```

Additionally, implement proactive health monitoring and automatic deleveraging when positions approach underwater thresholds.

## Proof of Concept

```move
#[test]
fun test_underwater_position_returns_zero() {
    // Setup: Create vault with Navi position
    // Position has $80k collateral, $100k debt = -$20k actual value
    
    let ctx = tx_context::dummy();
    let clock = clock::create_for_testing(&mut ctx);
    
    // Mock storage with underwater position
    // total_supply_usd_value = 80,000 * 1e18
    // total_borrow_usd_value = 100,000 * 1e18
    
    let usd_value = calculate_navi_position_value(
        account_address,
        &mut storage,
        &config,
        &clock,
    );
    
    // VULNERABILITY: Returns 0 instead of error or negative value
    assert!(usd_value == 0, 1);
    
    // Expected behavior: Should either:
    // 1) Abort with error for underwater position
    // 2) Return signed representation of -$20k
    // Actual behavior: Silently returns 0, hiding $20k liability
}
```

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L28-28)
```text
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L91-91)
```text
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L150-155)
```text
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L531-534)
```text
                liquidation_ratio = 35%, liquidation_bonus = 5%
                treasury_factor = 10%
        */
        let (liquidation_ratio, liquidation_bonus, _) = storage::get_liquidation_factors(storage, collateral_asset);
```

**File:** volo-vault/sources/operation.move (L360-364)
```text
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L8-8)
```text
    struct AccountCap has key, store {
```
