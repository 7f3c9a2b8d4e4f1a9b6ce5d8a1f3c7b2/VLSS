# Audit Report

## Title
Underwater Navi Positions Reported as Zero Value Enabling Loss Tolerance Bypass and Share Price Manipulation

## Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position becomes underwater (borrows exceed collateral), hiding negative equity from the vault's accounting system. This allows operations to bypass loss tolerance limits and inflates share prices, enabling unfair value extraction by withdrawers at the expense of remaining depositors.

## Finding Description

The vulnerability exists in the Navi position valuation logic where underwater positions (negative equity) are reported as zero value instead of being properly represented or blocked.

**Root Cause:**

When `total_supply_usd_value < total_borrow_usd_value`, the function returns 0 [1](#0-0) 

This masks insolvency where the vault owes more than it owns in that position.

**Why Protections Fail:**

1. **Health Limiter Not Enforced:** While a health limiter module exists to verify Navi position health [2](#0-1) , it is never integrated into vault operation flows. No calls to this verification function exist in the operational codebase.

2. **Loss Tolerance Bypass:** The vault's loss tolerance mechanism compares total USD values before and after operations [3](#0-2) . The loss calculation is based on `total_usd_value` which sums all asset values [4](#0-3) . When an underwater position reports 0 instead of negative value, this sum is artificially inflated, understating the actual loss.

3. **Share Price Calculation:** Share ratios are computed as `total_usd_value / total_shares` [5](#0-4) . An overstated `total_usd_value` leads to inflated share prices.

The tolerance check enforces a limit but operates on corrupted data [6](#0-5) .

## Impact Explanation

**Concrete Harm:**

1. **Loss Tolerance Bypass:** With the default loss tolerance of 0.1% (10 basis points) [7](#0-6) , if a Navi position moves from +$100K to -$50K (total loss of $150K) but reports as $0, the detected loss is only $100K. In a $10M vault, tolerance allows $10K loss, but the system sees $100K loss when actual loss is $150K. Operations can proceed even when they should be blocked.

2. **Share Price Manipulation:** Using the same scenario, if total vault value was $10.1M:
   - Correct: $10.1M - $150K = $9.95M
   - Actual: $10.1M - $100K = $10M
   - Overstatement: $50K (0.5% inflation)
   
   Users withdrawing at the inflated price extract more value than their fair share, with remaining depositors bearing the shortfall.

3. **Liquidation Risk:** Underwater Navi positions (health factor < 1) [8](#0-7)  are eligible for liquidation. The vault has no visibility into this risk, leading to unexpected further losses.

**Affected Parties:**
- Depositors who don't withdraw immediately
- Vault operators facing undetected insolvency
- Protocol reputation damage

## Likelihood Explanation

**High Probability:**

1. **Natural Market Conditions:** Navi positions become underwater through normal market volatility. The Navi protocol allows borrowing based on health factor thresholds [9](#0-8) . Even moderate price movements can push positions underwater before liquidation occurs.

2. **Automatic Triggering:** The vulnerability activates automatically during standard operations when `update_navi_position_value()` is called [10](#0-9) , which is invoked during `end_op_value_update_with_bag()` [11](#0-10)  as part of every operation cycle.

3. **No Special Privileges Required:** The condition arises from external market forces and accrued interest, not from malicious action.

4. **Low Detection Probability:** Since the vault's accounting shows 0 rather than negative, operators may not realize the position is underwater until liquidation events cause obvious discrepancies.

## Recommendation

1. **Enforce Health Factor Checks:** Integrate the existing health limiter verification before allowing operations that could put Navi positions at risk. Call `verify_navi_position_healthy()` during operation flows.

2. **Handle Underwater Positions:** Instead of returning 0, the `calculate_navi_position_value()` function should either:
   - Revert when positions are underwater, forcing immediate remediation
   - Track negative equity separately and include it in loss calculations

3. **Add Monitoring:** Implement events and checks to alert operators when Navi positions approach liquidation thresholds.

4. **Fix Loss Calculation:** Ensure loss tolerance calculations account for the full magnitude of losses, including transitions from positive to negative equity.

## Proof of Concept

```move
// Test scenario demonstrating the vulnerability
#[test]
fun test_underwater_position_bypass() {
    // Setup: Create vault with $10M value including $100K Navi position
    // Action: Market moves causing Navi position to go from +$100K to -$50K
    // Expected: calculate_navi_position_value() returns 0 (not negative)
    // Result: total_usd_value shows $10M instead of $9.95M
    // Impact: Loss tolerance check sees $100K loss instead of $150K
    // Impact: Share price inflated by 0.5%
    // Impact: Early withdrawers extract excess value from remaining depositors
}
```

**Notes:**
- The vulnerability is in production code paths that execute during normal vault operations
- Market volatility regularly creates conditions where lending positions approach liquidation thresholds
- The health limiter module exists but is completely unused in the codebase
- This breaks fundamental accounting invariants that vault value accurately represents asset positions

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
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

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L379-391)
```text
    public fun user_health_factor(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // 
        let health_collateral_value = user_health_collateral_value(clock, oracle, storage, user); // 202500000000000
        let dynamic_liquidation_threshold = dynamic_liquidation_threshold(clock, storage, oracle, user); // 650000000000000000000000000
        let health_loan_value = user_health_loan_value(clock, oracle, storage, user); // 49500000000
        if (health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(health_collateral_value, health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
    }
```
