### Title
Underwater Navi Positions Valued at Zero Without Health Factor Enforcement Causing Incorrect Share Valuations

### Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position becomes underwater (total_borrow > total_supply), but the vault has no health factor checks to prevent operations with such positions. Despite a health limiter module existing specifically for Navi positions, it is never invoked during vault operations. This allows the vault to operate with insolvent positions valued at 0, corrupting share ratio calculations and potentially enabling value extraction through mispriced deposits/withdrawals.

### Finding Description

The vulnerability exists in the Navi position valuation logic where underwater positions are assigned zero value without any health factor enforcement: [1](#0-0) 

When `total_borrow_usd_value > total_supply_usd_value`, the function returns 0 instead of reverting or checking position health. This zero value is then stored in the vault's asset valuation tables: [2](#0-1) [3](#0-2) 

The vault uses these asset values to calculate `total_usd_value`, which directly determines the share ratio for deposits and withdrawals: [4](#0-3) [5](#0-4) 

**Root Cause:** Despite the existence of a dedicated health limiter module with `verify_navi_position_healthy()` and `is_navi_position_healthy()` functions: [6](#0-5) 

These health checks are **never called** in the vault operation flow. The operation value update process completes without verifying that Navi positions maintain healthy collateralization: [7](#0-6) 

When a position becomes underwater (health factor < 1.0 in Navi's lending protocol), it should be rejected or liquidated, but instead the vault:
1. Accepts the 0 valuation from `calculate_navi_position_value()`
2. Records it via `finish_update_asset_value()`
3. Calculates artificially deflated `total_usd_value`
4. Proceeds with operations using incorrect share ratios

### Impact Explanation

**Direct Financial Impact:**

1. **Share Ratio Corruption**: When an underwater Navi position is valued at 0, the vault's `total_usd_value` becomes artificially low. Users depositing after this point receive inflated shares (more shares for the same USD value), directly diluting existing shareholders. Conversely, users withdrawing receive fewer principal tokens than their shares are actually worth.

2. **Value Extraction Vector**: An attacker monitoring Navi positions can:
   - Wait for a vault's Navi position to approach underwater status (health factor ~1.0)
   - Submit a deposit request when market conditions push the position underwater
   - Execute the deposit via operator, receiving inflated shares due to 0 position valuation
   - Wait for position recovery or liquidation settlement
   - Withdraw at corrected share ratio, extracting value from other depositors

3. **Loss Tolerance Manipulation**: The zero valuation creates false loss signals in the tolerance mechanism: [8](#0-7) 

If `total_usd_value_after` is artificially reduced by zero-valued positions, the vault may incorrectly trigger loss tolerance limits or conversely, hide actual losses by not accurately reflecting position value.

4. **Liquidation Risk Without Protection**: An underwater position (total_borrow > total_supply) in Navi means the position has health factor < 1.0 and is subject to liquidation. The vault holds such positions without any safeguards, exposing depositors to liquidation losses that are not reflected in share valuations until after liquidation occurs.

**Quantified Impact Example:**
- Vault has $1M in principal + $500K Navi position (healthy)
- Navi position becomes underwater: -$50K net value
- Vault calculates total value as $1M (position now 0) instead of actual ~$450K recoverable
- User deposits $100K, expects ~6.25% of shares
- Actually receives ~9.09% of shares (inflated due to undervaluation)
- This represents a 45% excess in share allocation, directly extracted from existing depositors

### Likelihood Explanation

**High Likelihood - Practical and Realistic Exploitation:**

1. **Reachable Entry Point**: The vulnerability is triggered through the standard operation flow that any authorized operator can execute. The operator calls `update_navi_position_value()` during Phase 3 of operations, which is a required step: [9](#0-8) 

2. **Feasible Market Conditions**: Positions become underwater through natural market dynamics:
   - Interest rate accrual on borrowings
   - Collateral price depreciation
   - Borrowed asset price appreciation
   - High utilization periods in Navi protocol
   
   These are normal DeFi lending conditions, not requiring attacker manipulation.

3. **No Special Permissions Required**: While operations require `OperatorCap`, the vulnerability manifests from legitimate operator actions during normal vault operations. The issue is not operator malice but lack of position health validation.

4. **Detection Difficulty**: The zero valuation appears as a legitimate position update in vault events. Without external monitoring of Navi health factors, the issue is invisible until users notice share ratio discrepancies.

5. **Race Condition Window**: Between operation start (capturing `total_usd_value_before`) and value update (Phase 3), market movements can push positions underwater. This window exists in every operation cycle.

6. **Practical Probability**: Given crypto market volatility, leveraged positions in lending protocols frequently approach liquidation thresholds. The probability of a vault's Navi position touching underwater status over the protocol's lifetime is substantial.

### Recommendation

**Immediate Fix:**

1. **Integrate Health Factor Checks**: Call the existing health limiter before completing operations:

```move
// In volo-vault/sources/adaptors/navi_adaptor.move
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
    oracle: &PriceOracle,  // Add parameter
    min_health_factor: u256,  // Add parameter
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let account = account_cap.account_owner();
    
    // CRITICAL: Verify position health before valuation
    limiter::navi_adaptor::verify_navi_position_healthy(
        clock,
        storage,
        oracle,
        account,
        min_health_factor,
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

2. **Alternative: Assert Non-Zero for Critical Positions**: If health factor checks cannot be integrated immediately, add assertion that position value must be non-negative:

```move
// In calculate_navi_position_value()
assert!(
    total_supply_usd_value >= total_borrow_usd_value,
    ERR_POSITION_UNDERWATER
);
total_supply_usd_value - total_borrow_usd_value
```

3. **Add Invariant Check**: In `operation::end_op_value_update_with_bag()`, verify no asset values are zero before completing operations.

4. **Enhanced Monitoring**: Emit events when Navi positions approach critical health factors (< 1.2) for operator monitoring.

**Test Cases to Add:**

1. Test operation failure when Navi position health factor < minimum threshold
2. Test underwater position rejection during value update phase
3. Test share ratio calculation with positions at various health factors
4. Test loss tolerance with near-liquidation positions

### Proof of Concept

**Initial State:**
- Vault has 1,000,000 principal tokens (1M USD at 1:1 price)
- Vault has Navi position: 600K supplied, 400K borrowed (healthy, HF = 1.5)
- Total vault value = 1.2M USD
- Total shares = 1,200,000 (1 share = 1 USD)
- User A holds all 1,200,000 shares

**Exploit Sequence:**

1. **Market Movement**: Supplied asset price drops OR borrowed asset price rises
   - Navi position becomes: 550K supplied, 600K borrowed
   - Position is now underwater (net -50K)
   - Health factor < 1.0 (liquidatable in Navi)

2. **Operation Start**: Operator calls `start_op_with_bag()`
   - Captures `total_usd_value_before = 1.2M`
   - Borrows Navi AccountCap

3. **Operation Execution**: Operator performs DeFi operations, returns assets

4. **Value Update**: Operator calls `update_navi_position_value()`
   - `calculate_navi_position_value()` detects underwater: 600K borrow > 550K supply
   - Returns 0 (instead of reverting or checking health)
   - Vault stores Navi position value = 0

5. **Operation Complete**: Operator calls `end_op_value_update_with_bag()`
   - `total_usd_value_after = 1M + 0 = 1M` (incorrect, ignores actual position)
   - Appears as 200K loss, may trigger tolerance check
   - BUT vault continues operating with 0-valued underwater position

6. **User B Deposits**: User B deposits 100K principal
   - Vault calculates share ratio = 1M / 1.2M shares = 0.833 USD per share
   - User B should get ~120K shares (for 100K deposit)
   - **Actual**: User B gets inflated shares due to undervalued position

7. **Position Recovery/Liquidation**: Market recovers OR position gets liquidated
   - If recovered: Position value returns, but User B already has excess shares
   - If liquidated: Vault realizes actual loss, but User B's shares unaffected
   - User A (original depositor) bears the loss through dilution

**Expected Behavior**: Operation should fail at step 4 with health factor verification error.

**Actual Behavior**: Operation completes with corrupted share accounting, enabling value extraction.

**Success Condition**: New depositor receives more shares than entitled based on true vault value, extracting value from existing shareholders when position recovers or settles.

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
