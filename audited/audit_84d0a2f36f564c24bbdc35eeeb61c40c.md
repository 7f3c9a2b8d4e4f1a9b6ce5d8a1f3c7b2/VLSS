### Title
Navi Position Insolvency Masking Allows Continued Operations with Hidden Debt Exposure

### Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position becomes underwater (debt exceeds collateral), masking the true extent of insolvency and allowing vault operations to continue with incomplete loss accounting. This enables unfair withdrawal distributions and bypasses intended health factor enforcement mechanisms that exist but are never invoked.

### Finding Description

**Root Cause Location:** [1](#0-0) 

When a Navi lending position becomes underwater (total borrows exceed total supplied collateral), the function returns 0 instead of recognizing the negative equity or triggering an error. This masks the true insolvency from the vault's accounting system.

**Valuation Flow:**
The underwater position value of 0 is propagated through the vault's valuation system: [2](#0-1) 

This 0 value is then stored in the vault's asset value table: [3](#0-2) 

The vault's total USD value calculation sums all asset values including the masked 0: [4](#0-3) 

**Why Protections Fail:**

1. **Health Factor Checks Never Invoked:** The health limiter module contains `verify_navi_position_healthy()` and `is_navi_position_healthy()` functions designed to enforce minimum health factors: [5](#0-4) 

However, grep search confirms these functions are **never called** anywhere in the vault operation flows or tests, rendering this safety mechanism completely bypassed.

2. **Loss Tolerance Only Sees Visible Loss:** During operation value updates, the loss tolerance check only captures the visible loss (position value dropping to 0), not the hidden underwater debt: [6](#0-5) 

The tolerance enforcement: [7](#0-6) 

With default tolerance of only 0.1% per epoch: [8](#0-7) 

### Impact Explanation

**Concrete Harm:**

1. **Incomplete Loss Recognition:** If a $100k Navi position goes to -$20k underwater (owing $20k more than collateral value), the vault records only a $100k loss (position → 0) rather than the true $120k exposure. The $20k debt obligation is completely hidden from accounting.

2. **Unfair Withdrawal Distribution:** During the window between going underwater and liquidation, the vault's share ratio calculation uses the understated total USD value: [9](#0-8) 

Early withdrawers receive inflated share values while the hidden debt burden falls disproportionately on remaining users or late withdrawers.

3. **Continued Operations During Insolvency:** If the visible loss stays within tolerance limits (e.g., 10% visible loss on a $1M vault with 10% tolerance set by admin), operations continue despite the vault being technically insolvent with hidden underwater debt.

4. **Security Invariant Violation:** The critical invariant "Health-factor enforcement for Navi" is completely violated as health checks are never invoked despite existing in the codebase.

**Affected Parties:** All vault depositors, with late withdrawers and remaining users bearing disproportionate losses from the masked insolvency.

### Likelihood Explanation

**Realistic Exploitability:**

1. **No Attacker Capability Required:** This is a passive vulnerability triggered by market conditions. No malicious actor coordination is needed—normal market volatility in leveraged Navi positions naturally creates underwater scenarios.

2. **Feasible Preconditions:** 
   - Vault operates Navi lending positions with leverage (collateral + borrows)
   - Market crash causes collateral value to drop below debt value
   - Common in DeFi during high volatility periods (e.g., 50%+ asset price drops)

3. **Automatic Execution:** The vulnerability manifests automatically during standard vault operations when position values are updated: [10](#0-9) 

4. **Detection Difficulty:** The hidden debt is not visible in events or state queries, as the position appears to have 0 value rather than negative value. Users cannot easily detect the true insolvency.

**Probability:** HIGH - Leveraged lending positions commonly go underwater during market stress, making this a realistic and recurring scenario rather than an edge case.

### Recommendation

**Immediate Mitigations:**

1. **Add Insolvency Check and Abort:**
```move
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    // ... existing calculation ...
    
    // CRITICAL: Abort if position is underwater instead of masking
    assert!(
        total_supply_usd_value >= total_borrow_usd_value, 
        ERR_NAVI_POSITION_UNDERWATER
    );
    
    total_supply_usd_value - total_borrow_usd_value
}
```

2. **Integrate Health Factor Checks:** Invoke the existing health limiter functions during operations:
```move
// In operation::end_op_with_bag or before update_navi_position_value
limiter::navi_adaptor::verify_navi_position_healthy(
    clock,
    storage,
    oracle,
    account,
    MIN_HEALTH_FACTOR  // e.g., 1.1e27 for 10% safety margin
);
```

3. **Add Emergency Circuit Breaker:** Implement a mechanism to halt operations when any position value returns 0 unexpectedly, as this indicates potential insolvency.

4. **Enhanced Loss Reporting:** Emit detailed events when positions approach underwater status (health factor < 1.2) to enable proactive risk management.

**Test Cases to Add:**
- Test underwater position calculation aborts correctly
- Test health factor checks trigger before position goes underwater
- Test loss tolerance correctly accounts for full exposure including underwater debt
- Test withdrawal fairness when position approaches insolvency

### Proof of Concept

**Initial State:**
- Vault has $1M total value with 100k shares (ratio: $10/share)
- Navi position: $150k collateral, $50k borrowed = $100k net value
- Total vault value: $1M ($900k other assets + $100k Navi position)

**Execution Steps:**

1. **Market Crash:** Collateral assets drop 70% in value
   - Navi position becomes: $45k collateral, $50k debt = -$5k underwater
   - True loss: $105k ($100k position value lost + $5k underwater debt)

2. **Value Update During Operation:** [11](#0-10) 
   - Function calculates: total_supply_usd_value ($45k) < total_borrow_usd_value ($50k)
   - Returns: 0 (masks the -$5k underwater debt)

3. **Vault Records Incomplete Loss:**
   - Visible loss: $100k (position $100k → $0)
   - If tolerance is 10%, this passes: $1M * 10% = $100k limit
   - Hidden loss: $5k underwater debt not captured

4. **Unfair Withdrawal:**
   - Alice withdraws 10k shares
   - Share ratio calculated on understated $900k total value: $90/share
   - Alice receives $900 worth
   - Actual fair value should be based on $895k (accounting for -$5k debt): $89.5/share
   - Alice extracts $5 more than fair share

**Expected vs Actual Result:**
- **Expected:** Operations should abort when position goes underwater, or health factor checks should prevent this scenario
- **Actual:** Operations continue with masked insolvency, enabling unfair withdrawals and hidden debt accumulation

**Success Condition:** The vulnerability is confirmed when `calculate_navi_position_value()` returns 0 for an underwater position without aborting, and this value propagates through vault accounting without triggering health checks.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-28)
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
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
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

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/tests/operation/operation.test.move (L545-554)
```text
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            navi_asset_type,
            &mut storage,
        );

        vault.update_free_principal_value(&config, &clock);
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);
```
