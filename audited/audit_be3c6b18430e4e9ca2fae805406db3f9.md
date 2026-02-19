# Audit Report

## Title
Navi Position Insolvency Masking Allows Continued Operations with Hidden Debt Exposure

## Summary
When a Navi lending position becomes underwater (debt exceeds collateral), the `calculate_navi_position_value()` function returns 0 instead of recognizing the negative equity, masking the true insolvency from the vault's accounting system. This allows vault operations to continue with incomplete loss accounting, enabling unfair withdrawal distributions where early withdrawers receive inflated share values while hidden debt falls on remaining users.

## Finding Description

**Root Cause - Underwater Position Returns Zero:**

When a Navi position's total borrows exceed total supplied collateral, the valuation function returns 0 instead of reflecting the true negative equity or halting operations: [1](#0-0) 

This masked 0 value is propagated through the vault's valuation system via `update_navi_position_value()`: [2](#0-1) 

The vault's total USD value calculation aggregates all asset values including the masked 0: [3](#0-2) 

**Why Existing Protections Fail:**

1. **Health Factor Checks Completely Bypassed**: The health limiter module contains safety functions designed to enforce minimum health factors: [4](#0-3) 

However, comprehensive grep search confirms these functions are **never invoked** anywhere in vault operations, rendering this critical safety mechanism completely inactive.

2. **Loss Tolerance Only Captures Visible Loss**: During operation value updates, the loss tolerance mechanism only sees the position dropping to 0, not the true underwater debt: [5](#0-4) 

With the tolerance enforcement capping losses per epoch: [6](#0-5) 

And the default tolerance set to only 0.1% per epoch: [7](#0-6) 

3. **Share Ratio Calculation Uses Understated Value**: The share ratio directly depends on the understated total_usd_value, affecting all withdrawal calculations: [8](#0-7) 

**Security Invariant Violation:**

The Navi protocol's health factor system is designed to prevent underwater positions from harming the protocol. The `is_health()` function determines when a position becomes underwater (health factor < 1): [9](#0-8) 

This check is enforced in the underlying Navi protocol for withdrawals to protect position integrity: [10](#0-9) 

However, the Volo vault system completely bypasses this protection by never invoking the health limiter checks, violating the fundamental security guarantee of health-factor enforcement.

## Impact Explanation

**Concrete Financial Harm:**

1. **Incomplete Loss Recognition**: If a $100k Navi position goes to -$20k underwater (owing $20k more than collateral value), the vault records only a $100k loss (position value dropping to 0) rather than the true $120k total exposure. The $20k debt obligation remains completely hidden from accounting.

2. **Unfair Withdrawal Distribution**: During the window between going underwater and eventual liquidation, the vault's share ratio calculation uses the understated total USD value. Early withdrawers receive withdrawals calculated with inflated share values, while the hidden debt burden falls disproportionately on remaining depositors who cannot detect the true insolvency.

3. **Continued Operations Despite Insolvency**: If the visible loss (e.g., $100k on a $1M vault = 10% visible loss) stays within the admin-configured tolerance limit, vault operations continue accepting deposits and processing withdrawals despite being technically insolvent with hidden underwater debt.

4. **Critical Invariant Violation**: The protocol's documented security invariant "Health-factor enforcement for Navi positions" is completely violated as the health check functions exist but are never invoked in any operation flow.

**Affected Parties**: All vault depositors suffer from this accounting failure, with late withdrawers and remaining users bearing disproportionate losses from the masked insolvency that was not properly recognized or disclosed.

## Likelihood Explanation

**High Probability - Market-Driven Automatic Trigger:**

1. **No Attacker Capability Required**: This is a passive vulnerability automatically triggered by normal market conditions. No malicious actor coordination, special privileges, or attack transactions are needed—standard market volatility in leveraged Navi positions naturally creates underwater scenarios during price crashes.

2. **Feasible and Common Preconditions**: 
   - Vault operates Navi lending positions with leverage (supplied collateral + borrowed assets)
   - Market crash causes collateral asset values to drop below outstanding debt values
   - This scenario is common in DeFi during high volatility periods (e.g., 50%+ rapid asset price drops seen in crypto markets)

3. **Automatic Execution During Standard Operations**: The vulnerability manifests automatically during routine vault value updates that occur with every operation: [11](#0-10) 

4. **Detection Difficulty**: The hidden debt is not visible in emitted events or public state queries. The position appears to have 0 value rather than exposing negative value, making it nearly impossible for users to detect the true insolvency before withdrawal attempts.

**Risk Assessment**: HIGH - Leveraged lending positions commonly go underwater during market stress periods, making this a realistic and recurring scenario rather than a theoretical edge case.

## Recommendation

**Immediate Fixes Required:**

1. **Invoke Health Factor Checks Before Risky Operations**: Call the existing health limiter functions before any operation that could be affected by underwater positions:

```move
// In operation.move, before end_op_value_update_with_bag:
if (vault.contains_navi_position()) {
    navi_limiter::verify_navi_position_healthy(
        clock,
        storage,
        oracle,
        navi_account_address,
        min_health_factor_threshold
    );
}
```

2. **Handle Underwater Positions Explicitly**: Modify `calculate_navi_position_value()` to either revert when underwater or return a sentinel value that triggers emergency procedures rather than silently masking the insolvency:

```move
if (total_supply_usd_value < total_borrow_usd_value) {
    // Option 1: Revert to prevent operations with underwater positions
    assert!(false, ERR_POSITION_UNDERWATER);
    
    // Option 2: Return sentinel and mark vault for emergency mode
    // vault.mark_insolvency_detected();
    // return 0
};
```

3. **Implement Insolvency Detection and Emergency Mode**: Add vault state tracking for detected insolvency that halts new deposits and requires admin intervention to resolve the underwater position before resuming normal operations.

## Proof of Concept

```move
#[test]
fun test_underwater_navi_position_masks_insolvency() {
    let mut scenario = test_scenario::begin(OWNER);
    
    // Setup: Create vault with $100k Navi position (50k collateral, 40k borrowed)
    setup_vault_with_navi_position(&mut scenario, 50_000_000_000, 40_000_000_000);
    
    // Market crash: Collateral drops 60% ($50k → $20k), debt stays $40k
    // Position is now underwater: $20k collateral < $40k debt = -$20k equity
    crash_collateral_price(&mut scenario, 60); // 60% drop
    
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let mut storage = scenario.take_shared<Storage>();
        let config = scenario.take_shared<OracleConfig>();
        let clock = scenario.take_shared<Clock>();
        
        // Update position value - should detect -$20k but returns 0
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage,
        );
        
        let total_value = vault.get_total_usd_value(&clock);
        
        // BUG: total_value does not reflect the $20k hidden debt
        // Vault appears to have lost only $30k ($50k original collateral → $20k)
        // But true loss is $50k ($50k → -$20k underwater with $20k debt obligation)
        
        // Early withdrawer gets inflated share value due to understated loss
        let share_ratio = vault.get_share_ratio(&clock);
        
        // Verify vulnerability: share_ratio is calculated with masked loss
        // This means early withdrawer extracts more value than fair share
        assert!(share_ratio > true_fair_ratio_with_debt_included, 0);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(storage);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
    };
    
    scenario.end();
}
```

## Notes

This vulnerability represents a critical failure in the vault's accounting and risk management system. The Navi health factor enforcement mechanism exists in the codebase but is never activated, creating a false sense of security while allowing underwater positions to silently accumulate hidden debt that is unfairly distributed among vault participants. The issue requires no attacker action—it manifests automatically during normal market volatility, making it a high-priority systemic risk to address immediately.

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

**File:** volo-vault/sources/operation.move (L353-357)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L91-91)
```text
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```
