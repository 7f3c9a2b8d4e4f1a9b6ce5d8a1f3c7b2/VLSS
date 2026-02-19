# Audit Report

## Title
Underwater Suilend Positions Indistinguishable from Zero-Value Positions Enabling Loss Tolerance Bypass

## Summary
The `parse_suilend_obligation()` function returns 0 when a Suilend position becomes underwater (debt exceeds collateral), making it indistinguishable from legitimately zero-valued positions. This causes systematic loss underreporting during vault operations, allowing operators to bypass per-epoch loss tolerance limits and continue operating with insolvent positions that risk liquidation.

## Finding Description

The root cause lies in how underwater Suilend positions are handled during value calculation. When `parse_suilend_obligation()` determines that borrowed value exceeds deposited value, it returns 0 without any indication that the position is actually underwater with negative equity: [1](#0-0) 

This 0 value is then stored directly in the vault's asset tracking system without validation: [2](#0-1) [3](#0-2) 

During operation value updates, the vault calculates loss by comparing total USD values before and after operations. The `get_total_usd_value()` function simply sums all asset values, treating the 0 from underwater positions as legitimate zero value rather than recognizing negative equity: [4](#0-3) 

The loss calculation then compares these totals: [5](#0-4) 

This underreported loss is checked against the tolerance limit: [6](#0-5) 

**Critical Gap**: Unlike Navi positions which have dedicated health factor enforcement through `navi_limiter.move`, there is no equivalent health check module for Suilend positions. The health-limiter directory contains only: [7](#0-6) 

No such `suilend_limiter.move` exists, leaving Suilend positions without health factor validation.

## Impact Explanation

**Loss Tolerance Bypass**: If a Suilend position with 50 USD net equity becomes underwater with −10 USD actual equity, the vault records only 50 USD loss (the equity that disappeared) instead of 60 USD (the true economic loss including the 10 USD of negative equity now owed). With the default tolerance of 10 basis points (0.1%), a vault with 100,000 USD can lose up to 100 USD per epoch. The hidden 10 USD negative equity allows operations that should fail the loss limit to succeed. [8](#0-7) 

**Custody Risk**: Underwater positions remain undetected in the vault, exposing it to liquidation risk on Suilend. The share price becomes incorrect as vault value is overstated by the absolute value of negative equity. All vault shareholders bear these hidden losses proportionally.

**Operational Integrity**: Operators can continue operations with underwater positions that should trigger safety mechanisms. The vault may accept additional losses beyond configured tolerance without alerting stakeholders. There is no distinction between normal zero-value positions and critical underwater states requiring immediate intervention.

## Likelihood Explanation

**Highly Likely**: The entry point is the standard operation flow accessible to any operator via `update_suilend_position_value()`. The preconditions are natural market events—price volatility, interest rate accrual, or changes in collateral/debt ratios on Suilend. No special manipulation is required; underwater positions occur through normal DeFi mechanics.

**Practical Execution**: The exploit path follows the normal operation sequence defined in the operation module. No special privileges beyond normal operator capabilities are needed. All steps are standard Move function calls with no complex preconditions. [9](#0-8) 

**Economic Rationality**: Zero cost to trigger—occurs naturally through market movements. High impact relative to no attack cost. Can be repeated across multiple epochs if undetected. The operator doesn't need malicious intent; the vulnerability manifests automatically when Suilend positions become underwater.

## Recommendation

1. **Implement Health Factor Verification**: Create a `suilend_limiter.move` module similar to the existing Navi implementation to verify Suilend position health before allowing operations:

```move
public fun verify_suilend_position_healthy(
    obligation: &Obligation,
    lending_market: &LendingMarket,
    min_health_factor: u256,
) {
    // Calculate health factor from obligation
    // Assert health_factor > min_health_factor
}
```

2. **Modify parse_suilend_obligation()**: Instead of returning 0 for underwater positions, either:
   - Abort with a specific error code indicating underwater state
   - Return a signed value or use an Option type to distinguish underwater positions
   - Set a flag in the vault to mark the position as requiring immediate attention

3. **Add Validation in finish_update_asset_value()**: Check if the value represents an underwater position and handle it explicitly rather than treating it as zero.

4. **Enhance Loss Calculation**: Account for the absolute value of negative equity when calculating true losses during operations.

## Proof of Concept

```move
#[test]
fun test_underwater_suilend_position_loss_bypass() {
    // Setup vault with 100,000 USD total value
    // Default tolerance: 10 bps = 100 USD max loss per epoch
    let vault = create_test_vault(100_000);
    
    // Create Suilend position with 100 USD collateral, 50 USD debt
    // Net equity: 50 USD
    let suilend_position = create_suilend_position(100, 50);
    add_to_vault(&mut vault, suilend_position);
    
    // Start operation - record initial value
    let initial_value = vault.get_total_usd_value(); // 100,000 USD
    
    // Simulate market movement: collateral drops to 90 USD
    // Debt increases to 100 USD (with interest)
    // Position is now underwater: 90 - 100 = -10 USD equity
    simulate_market_crash(&mut suilend_position, 90, 100);
    
    // Operator updates Suilend position value
    // parse_suilend_obligation() returns 0 (instead of indicating -10 USD)
    update_suilend_position_value(&mut vault);
    
    // End operation and check loss
    let final_value = vault.get_total_usd_value(); // 99,950 USD
    let reported_loss = initial_value - final_value; // 50 USD
    
    // Assertion: Loss tolerance check passes
    // But TRUE loss should be 60 USD (50 USD equity + 10 USD underwater)
    assert!(reported_loss == 50, 0); // Only 50 USD recorded
    assert!(reported_loss < 100, 1); // Passes tolerance check
    
    // The 10 USD negative equity is hidden from loss tracking
    // Vault is now insolvent but continues operating
}
```

### Citations

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L37-39)
```text
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L85-88)
```text
    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
```

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
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
