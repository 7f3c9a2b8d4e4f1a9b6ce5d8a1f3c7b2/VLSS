# Audit Report

## Title
Navi Position Negative Equity Clamping Bypasses Loss Tolerance Mechanism

## Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position has negative equity (debt exceeds collateral), instead of accurately reflecting the loss. This causes the vault's loss tolerance mechanism to systematically undercount losses, allowing operators to exceed per-epoch loss limits and leaving the vault insolvent on underwater positions.

## Finding Description

The vulnerability exists in the Navi position valuation logic where underwater positions are incorrectly handled. When a position's debt exceeds its collateral value, the function clamps the result to 0 instead of reflecting the true negative value. [1](#0-0) 

This 0 value is then stored in the vault's asset valuation table via `finish_update_asset_value()`: [2](#0-1) 

The vault calculates its total USD value by summing all asset values from the `assets_value` table, including these incorrectly clamped-to-zero underwater positions: [3](#0-2) 

During operation completion, the loss tolerance check compares `total_usd_value_before` and `total_usd_value_after`: [4](#0-3) 

**The critical flaw**: When a position declines from positive equity to negative equity (e.g., +$100k to -$50k), the measured loss only captures the decline to zero ($100k), not the full economic loss ($150k). The $50k of negative equity is completely hidden from the loss tolerance enforcement.

The loss tolerance mechanism then validates this understated loss: [5](#0-4) 

**Why existing protections fail:**
- The health factor limiter exists in a separate module but is **not enforced automatically** in the operation flow [6](#0-5) 

- Market movements between operations can turn healthy positions underwater
- The loss tolerance mechanism relies on accurate position valuations, which are corrupted by the zero-clamping logic

## Impact Explanation

**Direct Vault Insolvency**: A position with negative equity represents an uncloseable liability. If a Navi position has -$50k equity ($70k collateral, $120k debt), the vault needs $50k additional capital to repay the debt and recover collateral. This creates a permanent insolvency that cannot be resolved without external capital injection.

**Loss Tolerance Bypass**: The default loss tolerance is 0.1% per epoch. [7](#0-6) 

When negative equity is hidden, operators can exceed this limit without detection. For a $10M vault, a -$500k underwater position reports as $0, hiding $500k of losses that should trigger tolerance violations.

**Share Ratio Manipulation**: The `total_usd_value` used for share price calculations is artificially inflated because underwater positions show as $0 instead of their true negative value. [8](#0-7) 

This causes:
- Depositors to receive fewer shares than they should (paying for phantom value)
- Withdrawers to receive more principal than the vault can sustainably provide
- Progressive drain of healthy assets while underwater liabilities remain

**Cumulative Damage**: Over multiple epochs, hidden negative equity compounds vault insolvency while appearing within tolerance limits.

## Likelihood Explanation

**High Probability - No Malicious Intent Required**: This vulnerability triggers automatically during normal market volatility when leveraged Navi positions move against the vault. The operator doesn't need to act maliciously; standard market conditions create the exposure.

**Low Complexity**: The issue occurs whenever `update_navi_position_value` is called on an underwater position during the standard operation flow (`start_op_with_bag` → manage position → `end_op_value_update_with_bag`). No complex transaction sequences or precise timing required.

**Realistic Market Conditions**: 
- Volatile crypto markets regularly create underwater leveraged positions
- Flash crashes, oracle delays, or rapid interest rate accrual can trigger negative equity
- Leveraged lending positions (the explicit purpose of Navi integration) amplify market movements
- Historical DeFi incidents demonstrate this is a common occurrence, not a theoretical edge case

**Silent Failure**: No error is thrown when negative equity is clamped to 0, making the issue invisible to operators and users until withdrawal attempts fail or audits reveal insolvency.

## Recommendation

1. **Track negative equity explicitly**: Since Move's u256 cannot represent negative values, introduce a separate tracking mechanism for underwater positions or use a signed integer representation with appropriate handling.

2. **Enforce health factor checks**: Integrate `verify_navi_position_healthy` calls into the operation flow before position value updates to prevent underwater positions from persisting.

3. **Enhanced loss calculation**: When a position value drops to 0, implement additional logic to calculate and record the true economic loss including negative equity, using the Navi protocol's debt/collateral data directly.

4. **Emergency handling**: Implement position liquidation or forced closure mechanisms when positions approach or enter negative equity territory.

## Proof of Concept

The vulnerability is demonstrated through the standard operation flow:

1. Vault has a Navi position worth $5M (collateral: $6M, debt: $1M)
2. Market crash occurs: collateral drops to $800k, debt remains $1M
3. Operator calls `update_navi_position_value()` during routine operation
4. Function returns 0 instead of -$200k (actual equity)
5. `total_usd_value` is inflated by $200k
6. Loss tolerance check sees smaller loss than reality
7. Share price remains artificially high
8. Vault is insolvent but continues operating normally

The code path is fully reachable through normal vault operations and requires no special privileges beyond the standard OperatorCap.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
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
