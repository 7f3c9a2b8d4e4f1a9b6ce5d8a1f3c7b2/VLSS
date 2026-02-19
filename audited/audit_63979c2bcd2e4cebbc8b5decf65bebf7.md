# Audit Report

## Title
Underwater Navi Positions Valued at Zero Instead of Negative, Causing Overstated Vault Value and Unfair Loss Distribution

## Summary
The `calculate_navi_position_value()` function incorrectly returns 0 for underwater Navi positions (where debt exceeds collateral) instead of preventing such positions or accounting for negative value. This causes the vault's total USD value to be overstated, inflating share prices and unfairly distributing losses to remaining users. The designed protection mechanism (`verify_navi_position_healthy()`) exists but is never invoked in the codebase.

## Finding Description

The vulnerability exists in the Navi position valuation flow where underwater positions are indistinguishable from empty positions.

**The Core Issue:**

In `calculate_navi_position_value()`, when a position's total borrow value exceeds its collateral value, the function returns 0 [1](#0-0) . This 0 value is then passed to `finish_update_asset_value()` [2](#0-1) , which stores it in the vault's `assets_value` table [3](#0-2) .

**How Positions Become Underwater:**

While Navi's protocol enforces health factor checks during borrow and withdraw operations [4](#0-3) , these are point-in-time checks. Positions can become underwater through:
- Market price movements after operations complete
- Continuous interest accumulation on borrowed amounts

**Impact on Vault Valuation:**

When calculating total vault value, the system simply sums all asset values from the `assets_value` table [5](#0-4) . An underwater position contributing $0 causes the total value to be overstated by the actual deficit amount.

**Loss Calculation Bypass:**

During operation completion, the loss calculation compares `total_usd_value_before` and `total_usd_value_after` [6](#0-5) . An underwater position valued at $0 instead of its actual negative value understates the true loss, potentially allowing operations to pass loss tolerance checks that should fail.

**Missing Protection:**

A health verification function `verify_navi_position_healthy()` exists in the health limiter module [7](#0-6) , but grep search confirms it is never called anywhere in the Volo vault codebase, meaning the designed protection is not implemented.

## Impact Explanation

**Direct Economic Harm:**

1. **Share Price Inflation**: When underwater position reports $0 instead of negative value, `share_ratio = total_usd_value / total_shares` is calculated with an inflated numerator, giving each share artificially high value [8](#0-7) 

2. **Unfair Loss Distribution**: 
   - Early withdrawers receive more principal than their true share value
   - Remaining users bear the full deficit when position must be liquidated or closed
   - Loss is not proportionally distributed as shares are withdrawn

3. **Loss Tolerance Bypass**: The vault's loss tolerance mechanism is designed to limit losses per epoch, but underwater positions valued at $0 don't contribute to the loss calculation, allowing tolerance limits to be exceeded.

**Example Scenario:**

- Vault with $100k total value, 100k shares (ratio: $1/share)
- Navi position becomes underwater by $10k (should be -$10k, reported as $0)
- Overstated total value: $100k (actual: $90k)
- User withdraws 10k shares expecting $10k, receives $10k (should receive $9k)
- Remaining users now have 90k shares for $80k actual value = $0.889/share
- Loss of $1k distributed unfairly to remaining users

## Likelihood Explanation

**Medium Likelihood** - This vulnerability can occur through natural market conditions without requiring an attacker:

1. **Market Volatility**: DeFi lending markets experience price volatility regularly. A position healthy at time T can become underwater at time T+1 due to collateral price drops or borrowed asset price increases.

2. **Interest Accumulation**: Borrowed amounts accrue interest continuously, increasing debt without corresponding collateral increase. Over time, positions near health factor limits can drift underwater.

3. **No Monitoring**: The vault has no mechanism to monitor position health between operations or alert when positions approach underwater status.

4. **No Prevention**: While the health limiter module was designed to prevent this, it is never invoked, leaving positions unprotected.

5. **Detection Difficulty**: The system treats underwater positions as legitimately $0-valued, making the issue invisible in normal operations until liquidation or closure reveals the deficit.

The probability increases with:
- Volatile market periods
- Long time between position updates
- Positions operating near maximum leverage
- High interest rate environments

## Recommendation

**Immediate Fix:**

1. **Implement Health Checks**: Call `verify_navi_position_healthy()` before updating Navi position values:

```move
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
    oracle: &PriceOracle,  // Add oracle parameter
    min_health_factor: u256,  // Add threshold parameter
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let account = account_cap.account_owner();
    
    // CRITICAL: Verify health BEFORE calculating value
    limiter::navi_adaptor::verify_navi_position_healthy(
        clock,
        storage,
        oracle,
        account,
        min_health_factor
    );
    
    let usd_value = calculate_navi_position_value(
        account,
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

2. **Alternative: Abort on Underwater**: If health check fails, abort the update rather than storing 0:

```move
public fun calculate_navi_position_value(...): u256 {
    // ... existing calculation logic ...
    
    if (total_supply_usd_value < total_borrow_usd_value) {
        // CRITICAL: Abort instead of returning 0
        abort ERR_NAVI_POSITION_UNDERWATER
    };
    
    total_supply_usd_value - total_borrow_usd_value
}
```

3. **Add Monitoring**: Implement periodic health checks on all Navi positions and emit warning events when positions approach underwater status.

## Proof of Concept

```move
#[test]
fun test_underwater_navi_position_valued_at_zero() {
    // Setup vault with Navi position
    let vault = create_test_vault();
    let storage = create_navi_storage();
    
    // Initial state: healthy position
    // Supply: $10,000, Borrow: $8,000, Net: $2,000
    setup_navi_position(storage, account, 10000, 8000);
    
    // Calculate and store initial value
    let value_1 = calculate_navi_position_value(account, storage, config, clock);
    assert!(value_1 == 2000, 0); // Net positive value
    
    // Simulate market crash: collateral drops 25%
    update_oracle_prices(config, -25%);
    
    // New state: underwater position  
    // Supply: $7,500, Borrow: $8,000, Net: -$500
    let value_2 = calculate_navi_position_value(account, storage, config, clock);
    
    // VULNERABILITY: Returns 0 instead of preventing/handling negative value
    assert!(value_2 == 0, 1); // Should abort or handle negative
    
    // This $0 gets stored and inflates vault total value
    // Share price becomes overstated
    // Loss is hidden from tolerance checks
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L384-390)
```text
        if (health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(health_collateral_value, health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
```

**File:** volo-vault/sources/operation.move (L353-364)
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
    };
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
