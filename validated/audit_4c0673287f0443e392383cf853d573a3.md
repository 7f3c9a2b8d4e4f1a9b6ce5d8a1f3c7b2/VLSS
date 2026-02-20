# Audit Report

## Title
Underwater Navi Positions Valued at Zero Enable Loss Tolerance Bypass and Vault Insolvency Concealment

## Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position becomes underwater (debt exceeds collateral), rather than recognizing it as a liability that reduces vault value. This allows operators to hide true losses, bypass per-epoch loss tolerance limits, manipulate share prices, and conceal vault insolvency.

## Finding Description

The vulnerability exists in the Navi position valuation logic where underwater positions (liabilities exceeding assets) are valued at 0 instead of being treated as negative contributions to vault value. [1](#0-0) 

When `total_supply_usd_value < total_borrow_usd_value`, the position is underwater, but the function returns 0. This 0 value is then stored in the vault's `assets_value` table through the `finish_update_asset_value()` call: [2](#0-1) 

The vault's `assets_value` table uses unsigned u256, which cannot represent negative values: [3](#0-2) 

The stored value is directly assigned without validation: [4](#0-3) 

The vault's total USD value calculation simply sums all asset values without accounting for the hidden liabilities: [5](#0-4) 

At operation end, loss is calculated as the difference between total USD value before and after: [6](#0-5) 

This understated loss is then checked against the per-epoch loss tolerance limit: [7](#0-6) 

**Why Protections Fail:**

1. The health limiter module exists with functions like `verify_navi_position_healthy`: [8](#0-7) 

However, this module is **never invoked** during vault operations. Verification via codebase search confirms no calls to health verification functions exist in the operation code.

2. When returning Navi positions at operation end, no health verification occurs: [9](#0-8) 

The check only verifies asset presence, not position health. [10](#0-9) 

The position is returned without any health factor validation.

## Impact Explanation

**Loss Tolerance Bypass**: If a Navi position worth $100k becomes underwater by $50k (true value: -$50k), the loss appears as only $100k instead of $150k. An operator with 10% loss tolerance ($100k limit on $1M vault) could cause $150k actual loss while only triggering a $100k recorded loss, bypassing the protection mechanism.

**Share Price Manipulation**: The `get_share_ratio()` function uses `get_total_usd_value()` for calculations: [11](#0-10) 

Since hidden liabilities inflate the total USD value, share prices become inflated. New depositors receive fewer shares than deserved (overpaying), while early withdrawers extract more value than entitled (draining the vault before insolvency is recognized).

**Insolvency Concealment**: A vault could have total liabilities exceeding assets (technically insolvent) but still appear healthy because underwater positions contribute 0 instead of negative values to the total.

**Affected Parties**: All vault depositors lose funds through share price manipulation and the inability to detect vault insolvency until it's too late.

## Likelihood Explanation

**High Likelihood** due to multiple realistic scenarios:

1. **Market Volatility**: During normal operations, collateral asset prices can drop or borrowed asset prices can rise, pushing healthy positions underwater. This is common in volatile DeFi markets.

2. **Interest Accrual**: Navi positions accrue borrow interest over time. Extended operations combined with high utilization rates can push positions underwater through interest accumulation alone.

3. **Strategic Exploitation**: An operator can deliberately borrow maximum amounts while maintaining minimum health factor, wait for unfavorable market conditions, allow the position to go underwater, then complete the operation with understated loss.

**Execution Practicality**:
- Entry point: Operator-controlled operations (semi-trusted role)
- Preconditions: Normal market conditions or strategic timing
- No special privileges beyond operator role
- Detection difficult as loss appears within tolerance limits
- No Move semantic violations

## Recommendation

1. **Prevent Underwater Positions**: Integrate the existing health limiter module into the operation flow. Before returning Navi positions, verify health factor:

```move
// In operation.move end_op_with_bag, before returning NaviAccountCap:
limiter::navi_adaptor::verify_navi_position_healthy(
    clock,
    storage,
    oracle,
    navi_account_cap.account_owner(),
    min_health_factor
);
```

2. **Accurate Loss Accounting**: Modify `calculate_navi_position_value()` to abort if position is underwater instead of returning 0, forcing operators to restore health before completing operations:

```move
if (total_supply_usd_value < total_borrow_usd_value) {
    abort ERR_UNDERWATER_POSITION
};
```

3. **Pre-Operation Health Check**: Add health verification before borrowing Navi positions at operation start to ensure only healthy positions are used.

4. **Monitoring**: Emit events when position health degrades during operations to enable off-chain monitoring and intervention.

## Proof of Concept

```move
#[test]
fun test_underwater_position_loss_concealment() {
    // Setup: Create vault with $1M value and $100k loss tolerance
    let vault = setup_vault_with_1m_value();
    let navi_position = create_navi_position_100k();
    
    // Start operation
    let total_value_before = vault.get_total_usd_value(clock); // $1M
    
    // Simulate market movement: position goes underwater by $50k
    // Debt = $150k, Collateral = $100k, Net = -$50k
    simulate_underwater_navi_position(navi_position, -50000);
    
    // Update position value - returns 0 instead of negative
    let position_value = calculate_navi_position_value(...);
    assert!(position_value == 0); // Should be negative but returns 0
    
    // End operation
    let total_value_after = vault.get_total_usd_value(clock); // $900k
    let recorded_loss = total_value_before - total_value_after; // $100k
    
    // Actual loss should be $150k (position went from $100k to -$50k)
    // But recorded loss is only $100k, bypassing tolerance check
    assert!(recorded_loss == 100_000); // Passes
    assert!(actual_loss == 150_000); // True loss concealed
    
    // Loss tolerance check passes with understated loss
    vault.update_tolerance(recorded_loss); // Should fail but doesn't
}
```

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L21-28)
```text
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/volo_vault.move (L115-115)
```text
    assets_value: Table<String, u256>, // Assets value in USD
```

**File:** volo-vault/sources/volo_vault.move (L629-635)
```text
    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
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

**File:** volo-vault/sources/operation.move (L235-238)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
```

**File:** volo-vault/sources/operation.move (L326-328)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
```

**File:** volo-vault/sources/operation.move (L353-363)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-49)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);

    emit(NaviHealthFactorVerified {
        account,
        health_factor,
        safe_check_hf: min_health_factor,
    });

    let is_healthy = health_factor > min_health_factor;

    // hf_normalized has 9 decimals
    // e.g. hf = 123456 (123456 * 1e27)
    //      hf_normalized = 123456 * 1e9
    //      hf = 0.5 (5 * 1e26)
    //      hf_normalized = 5 * 1e8 = 0.5 * 1e9
    //      hf = 1.356 (1.356 * 1e27)
    //      hf_normalized = 1.356 * 1e9
    let mut hf_normalized = health_factor / DECIMAL_E18;

    if (hf_normalized > DECIMAL_E9) {
        hf_normalized = DECIMAL_E9;
    };

    assert!(is_healthy, hf_normalized as u64);
}
```
