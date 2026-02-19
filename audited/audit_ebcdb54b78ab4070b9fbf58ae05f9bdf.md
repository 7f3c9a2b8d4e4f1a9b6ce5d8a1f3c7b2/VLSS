# Audit Report

## Title
Underwater Navi Positions Valued at Zero Instead of Negative Equity, Hiding Losses and Inflating Vault Share Price

## Summary
The `calculate_navi_position_value` function in the Navi adaptor contains a critical accounting flaw: when a leveraged Navi lending position becomes underwater (borrows exceed supplies), the function returns 0 instead of recognizing the negative net value as a liability. This causes the vault's `total_usd_value` to exclude underwater position liabilities, artificially inflating the share ratio and resulting in unfair loss distribution among vault participants.

## Finding Description

**Root Cause - Critical Accounting Logic:**

The `calculate_navi_position_value` function incorrectly handles underwater positions. When `total_borrow_usd_value` exceeds `total_supply_usd_value`, the function returns 0 instead of a negative value representing the liability: [1](#0-0) 

This zero value is then stored in the vault's `assets_value` table via `finish_update_asset_value`: [2](#0-1) 

**How Losses Propagate to Share Pricing:**

The vault's `get_total_usd_value` function aggregates all asset values from the `assets_value` table: [3](#0-2) 

The share ratio is then calculated by dividing this inflated `total_usd_value` by `total_shares`: [4](#0-3) 

**Why Existing Protections Fail:**

While the Navi protocol enforces health factor checks during borrow and withdraw operations: [5](#0-4) [6](#0-5) 

These checks only prevent unhealthy operations **at transaction time**. Positions can still become underwater **post-creation** through:
- Market price movements (collateral depreciation or debt appreciation)
- Interest accrual on borrowed amounts  
- Oracle price updates between transactions

The loss tolerance mechanism detects value drops but has a critical limitation: [7](#0-6) 

It only captures the drop from positive value to 0, but does not account for continued negative equity beyond that point. For example, if a position goes from $100,000 to -$10,000:
- Loss detected: $100,000 (drop to $0)
- Actual loss: $110,000 (including -$10k negative equity)
- Hidden liability: $10,000

**Navi AccountCap is Stored as Vault Asset:**

The Navi `AccountCap` has `key, store` abilities allowing it to be stored in the vault: [8](#0-7) 

## Impact Explanation

**Direct Financial Harm:**

1. **Hidden Liabilities**: A position with -$10,000 net equity (e.g., $90k collateral, $100k debt) is reported as $0 value, hiding the $10k liability from vault accounting

2. **Inflated Share Pricing**: The vault's `total_usd_value` excludes underwater position liabilities, causing the share ratio to be artificially high

3. **Unfair Loss Distribution**: New depositors purchase shares at inflated prices, unknowingly buying into hidden losses

4. **Liquidation Penalties**: When underwater positions are eventually liquidated, the 5% liquidation bonus creates additional unexpected losses: [9](#0-8) 

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

Modify `calculate_navi_position_value` to recognize underwater positions as liabilities rather than zero value. Since Sui Move's `u256` type is unsigned, the vault accounting system needs to be enhanced to track liabilities separately:

**Option 1: Separate Liability Tracking**
- Add `assets_liabilities: Table<String, u256>` field to vault
- When position is underwater, store absolute value in liabilities table
- Modify `get_total_usd_value` to subtract liabilities from assets

**Option 2: Prevent Underwater Positions**
- Add continuous health factor monitoring
- Automatically trigger position closure when health factor approaches 1.0
- Implement emergency unwinding mechanism before positions go underwater

**Option 3: Mark-to-Market with Penalties**
- When detecting underwater position, immediately recognize full loss including liquidation penalty (5% + treasury factor)
- Store negative equity as vault loss requiring immediate tolerance check
- Prevent new deposits until position is resolved

The recommended approach is Option 1 as it provides accurate accounting while allowing vaults to manage underwater positions appropriately.

## Proof of Concept

A proof of concept would demonstrate:

1. **Setup**: Create vault with Navi AccountCap holding leveraged position (e.g., 100 SUI collateral, 80 USDC borrowed)

2. **Trigger**: Simulate market movement where SUI price drops 50% (collateral becomes worth 50 USDC in USD terms while debt remains 80 USDC)

3. **Value Update**: Call `update_navi_position_value` which returns 0 for the now-underwater position

4. **Share Calculation**: Call `get_share_ratio` which uses inflated `total_usd_value` (excluding the -30 USDC liability)

5. **Unfair Withdrawal**: Early withdrawer receives shares valued at inflated ratio, while late withdrawer discovers the hidden loss when position liquidates

The test would verify that the share ratio is incorrectly inflated and that the vault's reported `total_usd_value` excludes the negative equity of underwater positions.

## Notes

This is a **valid high-severity vulnerability** affecting vault accounting integrity. The issue breaks the fundamental invariant that vault's `total_usd_value` should accurately reflect all assets and liabilities. The vulnerability requires no privileged access and is triggered by normal market conditions, making it highly likely to occur in production deployments using leveraged Navi positions.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L1268-1269)
```text
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L155-155)
```text
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L531-534)
```text
                liquidation_ratio = 35%, liquidation_bonus = 5%
                treasury_factor = 10%
        */
        let (liquidation_ratio, liquidation_bonus, _) = storage::get_liquidation_factors(storage, collateral_asset);
```

**File:** volo-vault/sources/operation.move (L360-363)
```text
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L8-8)
```text
    struct AccountCap has key, store {
```
