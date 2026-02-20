# Audit Report

## Title
Insolvent Lending Position Returns Zero Value, Masking Losses and Inflating Vault Share Ratio

## Summary
The Navi and Suilend adaptors incorrectly return 0 when lending positions become underwater (borrows exceed deposits), instead of properly handling the insolvency. This masks actual losses from vault accounting, inflates the share ratio, bypasses loss tolerance checks, and allows users to withdraw more than their fair share of principal.

## Finding Description

Both the Navi and Suilend adaptors contain identical flawed logic when calculating position net value. When a lending position becomes insolvent (total borrowed value exceeds total supplied collateral), the adaptors return 0 instead of reverting or properly recording the negative equity.

**Root Cause:**

In the Navi adaptor, when calculating position value, the function returns 0 if borrows exceed supplies: [1](#0-0) 

The Suilend adaptor contains identical logic: [2](#0-1) 

**Exploit Chain:**

1. During normal vault operations, the operator borrows Navi or Suilend lending positions to deploy capital into lending protocols via the operation lifecycle.

2. Market volatility, oracle price changes, or liquidation failures cause the position to become underwater (total_borrow_usd > total_supply_usd).

3. When the operator calls `update_navi_position_value` or `update_suilend_position_value` during Phase 3 of operations, the adaptor returns 0 instead of handling the insolvency.

4. This 0 value is stored in the vault's `assets_value` table, omitting the actual loss: [3](#0-2) 

5. When calculating total USD value, all asset values (including the 0 from underwater positions) are summed: [4](#0-3) 

6. The inflated total USD value artificially increases the share ratio: [5](#0-4) 

7. The loss tolerance check calculates loss as the difference between before and after values, understating actual loss because the 0 masks the negative value: [6](#0-5) 

8. Users withdraw based on the inflated share ratio, receiving more principal than their proportional ownership: [7](#0-6) 

**Why Protections Fail:**

The health limiter module exists but is never called during value updates. A grep search of the codebase confirms that `verify_navi_position_healthy` and `is_navi_position_healthy` are only defined but never invoked in the operation flow: [8](#0-7) 

The health check is optional and separate from value reporting—an insolvent position can still report 0 value to the vault even if health checks could theoretically be performed elsewhere.

## Impact Explanation

**Critical Severity - Multiple Impact Vectors:**

1. **Direct Fund Drain**: Users can withdraw more principal than entitled because the share ratio calculation doesn't reflect actual losses from underwater positions. Early withdrawers extract value while later users absorb hidden losses, creating a run-on-the-bank scenario.

2. **Accounting Invariant Violation**: The vault's core invariant (`total_usd_value = sum(all_asset_values)`) is fundamentally broken. The reported total value is artificially inflated by the amount of underwater positions that should be negative but are reported as 0.

3. **Loss Tolerance Bypass**: The per-epoch `loss_tolerance` mechanism is designed to prevent excessive losses per operation by checking if `loss <= cur_epoch_loss_base_usd_value * loss_tolerance / RATE_SCALING`. By reporting 0 instead of the actual negative value, the true magnitude of losses is hidden, allowing unbounded losses to accumulate beyond the intended safety limits.

4. **Unfair Distribution Among Users**: The fundamental share-based accounting model is corrupted. Users' withdrawal amounts no longer correspond to their proportional ownership of actual vault assets, violating the fairness guarantee of the vault system.

## Likelihood Explanation

**High Likelihood - Realistic and Unblocked:**

1. **Realistic Market Conditions**: Lending positions becoming underwater is a common occurrence in volatile crypto markets through:
   - Rapid market downturns causing collateral value drops
   - Oracle price lag or front-running
   - Liquidation mechanism failures during high volatility periods
   - Interest rate accrual pushing borrow amounts above collateral value over time

2. **Normal Operation Flow**: Value updates are required in Phase 3 of the standard three-phase operation lifecycle. Operators must call value update functions like `update_navi_position_value` before completing operations, making this a frequently-executed code path.

3. **No Circuit Breakers**: The code contains no checks to:
   - Detect when position net value would be negative
   - Revert transactions when insolvency is detected
   - Flag insolvent positions for manual intervention
   - Require position liquidation before allowing value updates

4. **Observable Externally**: The vulnerability is triggered by on-chain market conditions that are visible to all participants. Any observer can identify when lending positions become underwater and time their withdrawal requests to exploit the inflated share ratio before losses are properly reflected.

5. **Operator Incentives**: Operators have economic incentive to continue reporting 0 values rather than handling insolvency properly, as doing so avoids triggering loss tolerance limits that would halt operations.

## Recommendation

**Immediate Fixes Required:**

1. **Revert on Insolvency**: Instead of returning 0, the adaptors should revert when positions become underwater:

```move
// In navi_adaptor.move and suilend_adaptor.move
if (total_supply_usd_value < total_borrow_usd_value) {
    abort E_POSITION_INSOLVENT  // Add new error code
};
```

2. **Mandatory Health Checks**: Integrate health limiter checks as required validations before allowing value updates:

```move
// In update_navi_position_value
verify_navi_position_healthy(clock, storage, oracle, account, MIN_HEALTH_FACTOR);
let usd_value = calculate_navi_position_value(...);
```

3. **Emergency Circuit Breaker**: Add vault-level checks to pause operations when negative net asset values are detected, requiring admin intervention.

4. **Separate Tracking**: Maintain separate accounting for underwater positions to ensure losses are properly reflected in total value calculations and loss tolerance enforcement.

## Proof of Concept

The vulnerability is demonstrated through the following execution flow:

1. Vault operator calls `operation::start_op_with_bag()` to begin Phase 1, borrowing Navi/Suilend positions
2. Operator deploys capital to lending protocols, creating supply and borrow positions
3. Market moves cause position to become underwater (borrows > supplies)
4. Operator calls `operation::end_op_with_bag()` to return assets and enter Phase 3
5. Operator calls `navi_adaptor::update_navi_position_value()` which returns 0 for underwater position
6. The 0 value is stored via `vault::finish_update_asset_value()`
7. Operator calls `operation::end_op_value_update_with_bag()` which:
   - Calculates `total_usd_value_after` including the 0 (inflated)
   - Calculates loss as `total_usd_value_before - total_usd_value_after` (understated)
   - Passes loss tolerance check with hidden losses
8. Users call `user_entry::request_withdraw()` and `operation::execute_withdraw()`
9. Withdrawal amount calculated using inflated share ratio from step 7
10. Users receive more principal than deserved, draining vault faster than actual value

The test would verify:
- Position with 100 USDC supplied, 120 USDC borrowed reports value as 0 (not -20)
- Total vault USD value is inflated by 20 USDC
- Share ratio is incorrectly calculated as higher than actual
- Loss tolerance check only sees small loss instead of full 20 USDC loss
- Withdrawal amounts exceed proportional share of actual vault value

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L85-87)
```text
    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
```

**File:** volo-vault/sources/volo_vault.move (L1006-1013)
```text
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
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

**File:** volo-vault/sources/operation.move (L361-363)
```text
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
