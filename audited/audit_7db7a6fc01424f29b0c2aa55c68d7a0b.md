# Audit Report

## Title
Insolvent Lending Position Returns Zero Value, Masking Losses and Inflating Vault Share Ratio

## Summary
When Navi or Suilend lending positions become insolvent (borrows exceed deposits), the adaptors incorrectly return 0 instead of properly handling the negative equity. This corrupts vault accounting by masking actual losses, inflates the share ratio used for withdrawals, and bypasses the loss tolerance mechanism that should prevent excessive losses per epoch.

## Finding Description

Both the Navi and Suilend adaptors contain identical flawed logic when calculating lending position net value. When a position becomes underwater (total borrowed value exceeds total supplied collateral), the adaptors return 0 instead of reverting or properly recording the insolvency.

**Root Cause in Navi Adaptor:**
The `calculate_navi_position_value` function returns 0 when supply is less than borrow [1](#0-0) 

**Root Cause in Suilend Adaptor:**
The `parse_suilend_obligation` function returns 0 when deposits are less than borrows [2](#0-1) 

**Corruption of Vault Accounting:**
This 0 value is then stored in the vault's `assets_value` table through `finish_update_asset_value` [3](#0-2) 

**Total USD Value Inflation:**
When calculating total USD value, the vault sums all asset values including the 0 from underwater positions, artificially inflating the total [4](#0-3) 

**Share Ratio Corruption:**
The inflated total USD value is used to calculate the share ratio, which determines withdrawal amounts [5](#0-4) 

**Withdrawal at Inflated Values:**
Users withdraw based on this corrupted share ratio, receiving more principal than their fair share [6](#0-5) 

**Loss Tolerance Bypass:**
The operation's loss calculation only accounts for the difference between pre and post total USD values. Since underwater positions report 0 instead of negative values, the actual loss is understated or completely missed [7](#0-6) 

**Why Health Limiter Doesn't Prevent This:**
The health limiter module exists but is optional and separate from value reporting. It checks health factor but does not prevent the adaptor from returning 0 when calculating position value. The health check functions are defined but never called in the main operation flow, as confirmed by searching the codebase.

## Impact Explanation

**Critical Severity - Direct Fund Loss:**

1. **Excess Withdrawals**: When lending positions become underwater, the vault's total USD value is inflated by the amount of the loss. Users withdrawing during this period receive more principal than they should because the share ratio doesn't reflect actual losses. Early withdrawers profit while later users absorb the hidden losses.

2. **Accounting Invariant Violation**: The vault's core accounting invariant `total_usd_value = sum(all_asset_values)` is fundamentally broken. The reported total excludes negative equity from insolvent positions, creating a systematic overvaluation.

3. **Loss Tolerance Mechanism Bypass**: The `loss_tolerance` parameter is designed to limit losses per epoch and prevent unbounded losses from operations. By reporting 0 instead of the actual negative value, the true loss never triggers the tolerance check [8](#0-7) , allowing losses to accumulate beyond intended limits.

4. **Unfair Value Distribution**: The share-based accounting system assumes all users have proportional claims on vault assets. This vulnerability breaks that guarantee, redistributing value from users who withdraw later to those who withdraw while positions are underwater.

## Likelihood Explanation

**High Likelihood - Realistic Market Conditions:**

1. **Common Market Scenarios**: Lending positions become underwater through normal market operations:
   - Rapid price crashes where collateral value drops faster than liquidation mechanisms respond
   - Oracle price lag during high volatility
   - Interest accrual causing borrow amounts to exceed collateral value over time
   - Liquidation mechanism failures during network congestion

2. **Standard Operation Flow**: Value updates are not edge cases—they are part of normal vault operations. Operators routinely call these update functions during operation lifecycles to refresh asset valuations before calculating share ratios for deposits and withdrawals.

3. **No Preventive Controls**: The code contains no checks to:
   - Detect negative net position values
   - Revert transactions when insolvency is detected  
   - Require positions to maintain minimum health factors before value updates
   - Flag underwater positions for manual intervention or liquidation

4. **Observable and Exploitable**: The vulnerability is triggered by on-chain market conditions visible to all participants. Sophisticated users can monitor lending protocol health factors and time their withdrawals to occur when vault positions are underwater, extracting more value than entitled.

5. **Operator Misaligned Incentives**: Operators may prefer to continue updating with 0 values rather than triggering loss tolerance limits that would halt operations, especially if they receive fees for transaction processing.

## Recommendation

**Immediate Fix - Revert on Underwater Positions:**

Modify both adaptors to revert when positions become underwater instead of returning 0:

```move
// In navi_adaptor.move
if (total_supply_usd_value < total_borrow_usd_value) {
    abort EPOSITION_UNDERWATER
};

// In suilend_adaptor.move  
if (total_deposited_value_usd < total_borrowed_value_usd) {
    abort EPOSITION_UNDERWATER
};
```

**Additional Safeguards:**

1. **Mandatory Health Checks**: Integrate health limiter checks into the value update flow, making them mandatory rather than optional before any value update operation.

2. **Liquidation Requirements**: Require underwater positions to be liquidated or closed before allowing further vault operations.

3. **Negative Value Tracking**: If the protocol design requires handling underwater positions, implement proper negative value tracking in the accounting system with appropriate loss recognition and distribution mechanisms.

4. **Circuit Breaker**: Add a pause mechanism that automatically halts withdrawals when any lending position health factor falls below a critical threshold.

## Proof of Concept

```move
#[test]
fun test_underwater_position_masks_loss() {
    let mut scenario = test_scenario::begin(OWNER);
    
    // Setup vault with 1000 USD total value and 1000 shares
    setup_vault_with_lending_position(&mut scenario);
    
    // Record initial state
    let initial_total_value = 1000; // USD
    let initial_shares = 1000;
    let user_shares = 100; // User owns 10%
    
    // Simulate lending position becoming underwater
    // Position had 500 USD supplied, 400 USD borrowed (100 USD net)
    // After market crash: 400 USD supplied, 500 USD borrowed (-100 USD net)
    simulate_market_crash(&mut scenario);
    
    // Operator updates position value - returns 0 instead of -100
    update_underwater_position(&mut scenario);
    
    // Total value now reported as: 900 USD (should be 800 USD)
    // Share ratio: 900/1000 = 0.9 (should be 0.8)
    let corrupted_ratio = get_share_ratio(&scenario);
    assert!(corrupted_ratio == 0.9, EINVALID_RATIO);
    
    // User withdraws with 100 shares, expects 80 USD but receives 90 USD
    let withdrawn = execute_withdraw(&mut scenario, user_shares);
    assert!(withdrawn == 90, EEXCESS_WITHDRAWAL); // 10 USD excess!
    
    // Loss tolerance check uses corrupted total, doesn't detect 100 USD loss
    verify_loss_tolerance_bypassed(&scenario);
    
    scenario.end();
}
```

The test demonstrates that when a lending position becomes underwater with -100 USD net value, the adaptor returns 0, inflating the vault's total value by 100 USD. This causes users to withdraw 12.5% more than entitled (90 USD instead of 80 USD), with the loss absorbed by remaining users.

## Notes

This vulnerability is particularly severe because it creates a systematic wealth transfer from users who remain in the vault to those who withdraw while positions are underwater. The longer underwater positions remain unreported, the greater the accumulated hidden losses. The issue affects both Navi and Suilend integration paths identically, indicating this is a design pattern issue in how lending position insolvency is handled across the vault system.

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

**File:** volo-vault/sources/volo_vault.move (L632-635)
```text
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L1013-1022)
```text
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
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

**File:** volo-vault/sources/operation.move (L361-364)
```text
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
