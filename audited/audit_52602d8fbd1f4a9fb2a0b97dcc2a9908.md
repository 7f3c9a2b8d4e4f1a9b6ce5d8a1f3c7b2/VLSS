### Title
Underwater Navi Positions Valued at Zero Enable Loss Tolerance Bypass and Vault Insolvency Concealment

### Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position becomes underwater (debt exceeds collateral), rather than recognizing it as a liability that reduces vault value. This allows operators to hide true losses, bypass per-epoch loss tolerance limits, manipulate share prices, and conceal vault insolvency.

### Finding Description

The vulnerability exists in the Navi position valuation logic: [1](#0-0) 

When `total_supply_usd_value < total_borrow_usd_value`, the position is underwater (liabilities exceed assets), but the function returns 0 instead of representing this as a negative contribution to vault value.

This 0 value is then recorded in the vault's `assets_value` table: [2](#0-1) 

The vault's total USD value calculation simply sums all asset values without considering hidden liabilities: [3](#0-2) 

At operation end, loss is calculated as the difference between total_usd_value before and after: [4](#0-3) 

This understated loss is then checked against the per-epoch loss tolerance limit: [5](#0-4) 

**Why Protections Fail:**

1. Health factor checks exist only at borrow/withdraw time, not continuously: [6](#0-5) 

2. Positions can become underwater between health checks due to market price movements, interest accrual, or poor trading decisions during operations.

3. The health limiter module is never invoked during vault operations: [7](#0-6) 

4. No health verification occurs when returning Navi positions at operation end: [8](#0-7) 

### Impact Explanation

**Direct Financial Impact:**

1. **Loss Tolerance Bypass**: If a Navi position worth $100k becomes underwater by $50k (true value: -$50k), the loss appears as only $100k instead of $150k. An operator configured with 10% loss tolerance ($100k limit on $1M vault) could cause $150k actual loss while only triggering a $100k recorded loss.

2. **Share Price Manipulation**: Since `get_total_usd_value()` is used for share ratio calculations, hidden liabilities inflate share prices:
   - New depositors receive fewer shares than deserved (overpaying for vault shares)
   - Early withdrawers extract more value than entitled (draining vault before insolvency is recognized)

3. **Insolvency Concealment**: A vault could have total liabilities exceeding assets (technically insolvent) but still appear healthy because underwater positions are valued at 0 rather than negative.

4. **Permanent Loss Hiding**: The vault's `assets_value` table uses unsigned u256: [9](#0-8) 

The architecture cannot represent negative values, so underwater positions remain valued at 0 indefinitely, permanently concealing the liability.

**Affected Parties:**
- All vault depositors lose funds through share price manipulation
- Protocol reputation damaged if insolvency is later discovered
- Loss tolerance mechanism becomes ineffective

### Likelihood Explanation

**High Likelihood - Multiple Realistic Scenarios:**

1. **Market Volatility (Passive)**: During normal operations, collateral asset prices can drop or borrowed asset prices can rise, pushing healthy positions underwater. Volatile DeFi markets make this common.

2. **Interest Accrual**: Navi positions accrue borrow interest over time. Extended operations combined with high utilization rates can push positions underwater through interest alone.

3. **Strategic Exploitation (Active)**: An operator can:
   - Borrow maximum amounts while maintaining minimum health factor
   - Wait for or create unfavorable market conditions
   - Allow position to go underwater
   - Complete operation with understated loss
   - Repeat until vault is significantly underwater

**Execution Practicality:**
- Entry point: Operator-controlled operations (semi-trusted role, not admin)
- Preconditions: Normal market conditions or strategic timing
- No special privileges needed beyond operator role
- Detection difficult: Loss appears within tolerance limits
- No Move semantic violations: Function correctly handles u256 underflow by returning 0

**Economic Rationality:**
- Operators have incentive to hide losses to avoid being frozen
- Depositors unaware of hidden liabilities continue depositing
- First withdrawers can exit before insolvency recognized (bank run scenario)

### Recommendation

**Immediate Mitigations:**

1. **Enforce Health Checks at Operation End**: Add mandatory health factor verification when returning Navi positions:

```move
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
    storage: &mut Storage,  // Add
    oracle: &PriceOracle,   // Add
    clock: &Clock,          // Add
    min_health_factor: u256 // Add from config
) {
    // ... existing code ...
    
    if (defi_asset_type == type_name::get<NaviAccountCap>()) {
        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
        let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
        
        // Add health check before returning
        limiter::navi_adaptor::verify_navi_position_healthy(
            clock,
            storage,
            oracle,
            navi_account_cap.account_owner(),
            min_health_factor
        );
        
        vault.return_defi_asset(navi_asset_type, navi_account_cap);
    };
    // ... rest of code ...
}
```

2. **Abort on Underwater Positions**: Modify `calculate_navi_position_value()` to abort rather than return 0:

```move
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    // ... existing calculation code ...
    
    assert!(
        total_supply_usd_value >= total_borrow_usd_value, 
        ERR_NAVI_POSITION_UNDERWATER
    );
    
    total_supply_usd_value - total_borrow_usd_value
}
```

3. **Add Continuous Health Monitoring**: Implement checks that prevent operations from completing if any position becomes underwater during the operation.

**Additional Safeguards:**

- Implement conservative buffer above minimum health factor for all Navi operations
- Add emergency liquidation mechanisms for vault-owned positions
- Emit events when positions approach health factor thresholds
- Add admin function to force-close underwater positions with loss recognition

**Testing Requirements:**

- Test scenario where market prices cause position to go underwater mid-operation
- Test loss tolerance calculation with underwater positions
- Test share price calculations with hidden liabilities
- Verify operations abort when positions become unhealthy

### Proof of Concept

**Initial State:**
- Vault total value: $1,000,000
- Navi position: $100,000 collateral (e.g., SUI), $50,000 borrowed (e.g., USDC)
- Position net value: $50,000
- Loss tolerance: 10% per epoch = $100,000 maximum loss

**Exploit Sequence:**

1. **Operation Starts:**
   - Operator calls `start_op_with_bag()`
   - Total USD value recorded: $1,000,000
   - Navi position contributes $50,000 to total

2. **Market Conditions Change:**
   - SUI price drops 60% (or USDC borrowing cost rises)
   - Navi position now: $40,000 collateral, $50,000 borrowed
   - Position is underwater by $10,000 (true value: -$10,000)

3. **Operation Ends:**
   - Operator calls `end_op_with_bag()` - position returned without health check
   - Operator calls `update_navi_position_value()`
   - `calculate_navi_position_value()` returns 0 (lines 74-76 triggered)
   - Vault records Navi position value as $0

4. **Value Update Check:**
   - `end_op_value_update_with_bag()` calculates loss
   - Total value before: $1,000,000
   - Total value after: $950,000 ($1M - $50k original position value)
   - Recorded loss: $50,000
   - **Actual loss: $60,000** (should account for -$10k underwater position)

5. **Loss Tolerance Check:**
   - Check: $50,000 < $100,000 ✓ PASSES
   - **Should have been: $60,000 vs $100,000**
   - Operator successfully hides $10,000 in losses

**Expected vs Actual Result:**

Expected: Operation should abort when Navi position becomes underwater, or loss should be calculated as $60,000

Actual: Operation completes successfully, loss recorded as only $50,000, $10,000 liability hidden and carried forward indefinitely

**Success Condition:** 
Operator can repeat this process across multiple operations, progressively hiding more debt until vault is significantly insolvent while appearing healthy to depositors.

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

**File:** volo-vault/sources/volo_vault.move (L115-116)
```text
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
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

**File:** volo-vault/sources/operation.move (L235-239)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L127-159)
```text
    public(friend) fun execute_borrow<CoinType>(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_borrow<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_borrow_balance(storage, asset, user, amount);
        
        /////////////////////////////////////////////////////
        // Add the asset to the user's list of loan assets //
        /////////////////////////////////////////////////////
        if (!is_loan(storage, asset, user)) {
            storage::update_user_loans(storage, asset, user)
        };

        //////////////////////////////////
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
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
