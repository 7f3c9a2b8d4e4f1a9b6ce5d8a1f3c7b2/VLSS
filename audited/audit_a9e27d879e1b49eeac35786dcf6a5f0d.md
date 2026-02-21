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
- The health factor limiter exists in a separate module but is **not enforced automatically** in the operation flow. The limiter module defines `verify_navi_position_healthy` [6](#0-5)  but this function is never called in the main vault operation sources.
- Market movements between operations can turn healthy positions underwater
- The loss tolerance mechanism relies on accurate position valuations, which are corrupted by the zero-clamping logic

## Impact Explanation

**Direct Vault Insolvency**: A position with negative equity represents an uncloseable liability. If a Navi position has -$50k equity ($70k collateral, $120k debt), the vault needs $50k additional capital to repay the debt and recover collateral. This creates a permanent insolvency that cannot be resolved without external capital injection.

**Loss Tolerance Bypass**: The default loss tolerance is 0.1% per epoch [7](#0-6) . When negative equity is hidden, operators can exceed this limit without detection. For a $10M vault, a -$500k underwater position reports as $0, hiding $500k of losses that should trigger tolerance violations.

**Share Ratio Manipulation**: The `total_usd_value` used for share price calculations is artificially inflated because underwater positions show as $0 instead of their true negative value [8](#0-7) . This causes:
- Depositors to receive fewer shares than they should (paying for phantom value)
- Withdrawers to receive more principal than the vault can sustainably provide
- Progressive drain of healthy assets while underwater liabilities remain

**Cumulative Damage**: Over multiple epochs, hidden negative equity compounds vault insolvency while appearing within tolerance limits.

## Likelihood Explanation

**High Probability - No Malicious Intent Required**: This vulnerability triggers automatically during normal market volatility when leveraged Navi positions move against the vault. The operator doesn't need to act maliciously; standard market conditions create the exposure.

**Low Complexity**: The issue occurs whenever `update_navi_position_value` is called on an underwater position during the standard operation flow. The operation flow is clearly defined [9](#0-8)  followed by value updates [10](#0-9) . No complex transaction sequences or precise timing required.

**Realistic Market Conditions**: 
- Volatile crypto markets regularly create underwater leveraged positions
- Flash crashes, oracle delays, or rapid interest rate accrual can trigger negative equity
- Leveraged lending positions (the explicit purpose of Navi integration) amplify market movements
- Historical DeFi incidents demonstrate this is a common occurrence, not a theoretical edge case

**Silent Failure**: No error is thrown when negative equity is clamped to 0, making the issue invisible to operators and users until withdrawal attempts fail or audits reveal insolvency.

## Recommendation

The protocol should not attempt to represent negative equity using unsigned integers. Instead:

1. **Prevent underwater positions proactively**: Enforce the health factor limiter before allowing operations that could result in negative equity. Call `verify_navi_position_healthy` from the health-limiter module during the operation flow.

2. **Handle underwater positions explicitly**: If a position becomes underwater, the protocol should:
   - Revert the operation with a clear error indicating position health violation
   - Or mark the position for emergency liquidation/closure
   - Or require immediate capital injection to restore solvency

3. **Add validation in `calculate_navi_position_value`**: Instead of silently returning 0, the function should abort when debt exceeds collateral:

```move
if (total_supply_usd_value < total_borrow_usd_value) {
    abort ERR_UNDERWATER_POSITION
};
```

4. **Integrate health checks in operation flow**: Add mandatory health factor verification in `end_op_value_update_with_bag` before completing the operation, similar to how asset returns are verified.

## Proof of Concept

The vulnerability is demonstrated through the following execution trace:

1. **Setup**: Vault has a Navi position with positive equity (e.g., $150k collateral, $50k debt = $100k equity)

2. **Operation Start**: Operator calls `start_op_with_bag` which records `total_usd_value_before` including the Navi position at $100k value

3. **Market Movement**: During the operation, market conditions deteriorate. The collateral value drops to $70k while debt grows to $120k due to interest accrual. The position now has -$50k equity.

4. **Value Update**: When `update_navi_position_value` is called:
   - `calculate_navi_position_value` computes: collateral ($70k) - debt ($120k) = -$50k
   - The check at line 74 detects `total_supply_usd_value < total_borrow_usd_value`
   - Instead of properly handling this insolvency, it returns 0
   - This 0 is stored in `assets_value[navi_position]`

5. **Loss Calculation**: In `end_op_value_update_with_bag`:
   - `total_usd_value_after` sums all assets including the Navi position at 0
   - Measured loss = `total_usd_value_before` ($100k from Navi) - `total_usd_value_after` (0 from Navi) = $100k
   - **Actual economic loss** = $150k (from +$100k to -$50k)
   - **Hidden loss** = $50k of negative equity

6. **Loss Tolerance Bypass**: The $100k measured loss might be within the 0.1% tolerance for a large vault, but the true $150k loss exceeds it. The vault appears healthy while actually being insolvent by $50k on this position alone.

**Direct Code Evidence**:
- Zero clamping: [1](#0-0) 
- Value storage: [11](#0-10) 
- Loss calculation: [4](#0-3) 
- No health check enforcement: Health limiter exists [6](#0-5)  but is never called in operation flow [10](#0-9) 

## Notes

This vulnerability represents a fundamental accounting flaw where the protocol's safety mechanism (loss tolerance) relies on corrupted data (zero-clamped underwater positions). The issue is particularly severe because:

1. It creates **actual insolvency** - the vault owes more than it owns on underwater positions
2. It **bypasses critical safety limits** - loss tolerance enforcement becomes ineffective
3. It operates **silently** - no errors or warnings when positions go underwater
4. It has **cascading effects** - corrupted share prices harm all depositors and withdrawers
5. It requires **no malicious actor** - normal market volatility triggers it automatically

The health limiter module was clearly intended to prevent such scenarios but is not integrated into the mandatory operation flow, making it an optional safety feature rather than an enforced protection.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L28-28)
```text
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/operation.move (L94-207)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);

    let mut defi_assets = bag::new(ctx);

    let defi_assets_length = defi_asset_ids.length();
    assert!(defi_assets_length == defi_asset_types.length(), ERR_ASSETS_LENGTH_MISMATCH);

    let mut i = 0;
    while (i < defi_assets_length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = vault.borrow_defi_asset<T, CetusPosition>(cetus_asset_type);
            defi_assets.add<String, CetusPosition>(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let obligation_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = vault.borrow_defi_asset<T, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
            );
            defi_assets.add<String, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
                obligation,
            );
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = vault.borrow_defi_asset<T, Receipt>(receipt_asset_type);
            defi_assets.add<String, Receipt>(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    let principal_balance = if (principal_amount > 0) {
        vault.borrow_free_principal(principal_amount)
    } else {
        balance::zero<T>()
    };

    let coin_type_asset_balance = if (coin_type_asset_amount > 0) {
        vault.borrow_coin_type_asset<T, CoinType>(
            coin_type_asset_amount,
        )
    } else {
        balance::zero<CoinType>()
    };

    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };

    emit(OperationStarted {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount,
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount,
        total_usd_value,
    });

    (defi_assets, tx, tx_for_check_value_update, principal_balance, coin_type_asset_balance)
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
