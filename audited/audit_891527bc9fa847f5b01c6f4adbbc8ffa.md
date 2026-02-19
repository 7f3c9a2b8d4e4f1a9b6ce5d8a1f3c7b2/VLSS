### Title
Zero-Liquidity Momentum Position Causes Vault DoS Through Unnecessary Price Validation

### Summary
The `get_position_value()` function in the Momentum adaptor performs pool-oracle price validation even when a position has zero liquidity (amount_a = 0, amount_b = 0). When the pool price deviates beyond the slippage tolerance from oracle prices, the function aborts, preventing value updates for empty positions. This blocks completion of vault operations, leaving the vault stuck in `VAULT_DURING_OPERATION_STATUS` and preventing all user deposits and withdrawals until prices realign or manual intervention occurs.

### Finding Description

The root cause is in the `get_position_value()` function where price validation occurs unconditionally, regardless of position liquidity: [1](#0-0) 

The function retrieves token amounts (which will be 0,0 for zero-liquidity positions), then fetches oracle prices and pool prices, and performs an assertion that the pool price is within slippage tolerance of the oracle price. If this assertion fails, the function aborts with `ERR_INVALID_POOL_PRICE` before ever returning the zero value.

When an operator borrows a Momentum position during an operation: [2](#0-1) 

The position must have its value updated before the operation can complete. The update process calls the adaptor: [3](#0-2) 

If the price validation fails, `finish_update_asset_value` is never called, meaning the asset is not marked as updated. Subsequently, when attempting to finalize the operation, the validation check fails: [4](#0-3) 

This prevents the vault from returning to normal status: [5](#0-4) 

### Impact Explanation

**Operational DoS Impact:**
- The vault becomes stuck in `VAULT_DURING_OPERATION_STATUS` (status = 1)
- All user deposits and withdrawals are blocked because they require `VAULT_NORMAL_STATUS`: [6](#0-5) [7](#0-6) 

**Who is Affected:**
- All vault users cannot deposit or withdraw funds
- Operator cannot complete operations or start new ones
- Protocol functionality is completely halted for this vault

**Severity Justification:**
This is Medium severity because:
1. It causes complete operational disruption but no direct fund loss
2. Recovery requires either waiting for market prices to realign (time-dependent) or admin intervention to remove the position
3. Users' funds remain safe but inaccessible during the DoS period
4. The condition is realistic (zero-liquidity positions exist, price deviations occur naturally)

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is triggered through normal operator workflow calling `update_momentum_position_value` during operation value updates - a standard required operation.

**Feasible Preconditions:**
1. A Momentum position with zero liquidity exists in the vault (realistic - occurs after full withdrawal or if liquidity was never added)
2. The Momentum pool's price deviates from oracle prices beyond the configured slippage tolerance (realistic - occurs due to market volatility, MEV activity, or oracle update delays)

**Execution Practicality:**
No special attacker actions required. Natural market conditions can trigger this:
- Volatile markets cause pool prices to deviate
- Oracle update timing doesn't align with pool price movements
- High-frequency trading or MEV causes temporary price dislocations

**Economic Rationality:**
An attacker doesn't need to spend anything - they can wait for natural price deviations. The attack doesn't require maintaining any position or ongoing costs.

**Probability Reasoning:**
Medium-to-High probability given:
- Zero-liquidity positions are common in AMM protocols
- Price deviations occur regularly in DeFi, especially for volatile pairs
- The same issue affects Cetus adaptor (same code pattern)

### Recommendation

Add an early return check in `get_position_value()` to skip price validation when position has zero liquidity:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
    
    // Early return for zero liquidity positions - no validation needed
    if (amount_a == 0 && amount_b == 0) {
        return 0
    };
    
    // ... rest of function with price validation
}
```

**Invariant Check to Add:**
Price validation should only occur when there are actual funds at risk (non-zero liquidity).

**Test Cases to Prevent Regression:**
1. Test updating a zero-liquidity Momentum position value when pool price deviates significantly
2. Test completing full operation cycle with zero-liquidity positions
3. Test that zero-liquidity positions return value of 0 without aborting
4. Apply same fix to `calculate_cetus_position_value()` in cetus_adaptor.move (lines 63-66)

### Proof of Concept

**Initial State:**
1. Vault has a Momentum position with liquidity = 0 (amount_a = 0, amount_b = 0)
2. Pool price for the position's pair has deviated 5% from oracle price
3. Vault slippage tolerance is configured at 3%

**Transaction Steps:**
1. Operator calls `start_op_with_bag` borrowing the zero-liquidity Momentum position
2. Vault status changes to `VAULT_DURING_OPERATION_STATUS` (status = 1)
3. Operator performs operations (no issues, position has no value)
4. Operator calls `end_op_with_bag` - assets returned successfully
5. Operator calls `update_momentum_position_value` to update position value
6. Function reaches price validation at line 55-58
7. Calculation: `(pool_price.diff(oracle_price) * DECIMAL / oracle_price) = 5% * DECIMAL`
8. Comparison: `5% > 3%` (slippage tolerance)
9. Transaction **aborts** with `ERR_INVALID_POOL_PRICE`

**Expected vs Actual Result:**
- **Expected:** Position value updates to 0, operation completes, vault returns to normal
- **Actual:** Transaction aborts, position value not updated, vault stuck in operation status

**Success Condition (Proving the DoS):**
1. After step 9, vault remains in `VAULT_DURING_OPERATION_STATUS`
2. Any user calling `request_deposit` or `request_withdraw` will abort with `ERR_VAULT_NOT_NORMAL`
3. Operator cannot call `end_op_value_update_with_bag` until the price updates (line 355 will abort with `ERR_USD_VALUE_NOT_UPDATED`)
4. Vault is completely unusable until external market conditions change or admin removes the position

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L40-58)
```text
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);

    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
}
```
