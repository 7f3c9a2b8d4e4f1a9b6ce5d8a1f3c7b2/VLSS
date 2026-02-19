### Title
Vault Operation DoS via Suilend Reserve Compound Interest Failure

### Summary
The `suilend_compound_interest()` function loops through all reserves in a Suilend obligation and calls `compound_interest()` for each one without error handling. If any single reserve's compound interest calculation fails (due to arithmetic overflow, excessive gas, or other issues), the entire `update_suilend_position_value()` transaction aborts. This prevents the operator from updating the Suilend position value, which blocks completion of vault operations and permanently locks the vault in `VAULT_DURING_OPERATION_STATUS`, causing a complete DoS where no deposits, withdrawals, or new operations can be executed.

### Finding Description

The vulnerability exists in the interaction between three components:

**1. Mandatory Compound Interest Loop** [1](#0-0) 

The `suilend_compound_interest()` function retrieves all reserve array indices from an obligation's deposits and borrows, then iterates through each one calling `lending_market.compound_interest()`. This uses the `do_ref!` macro which has no error handling - if ANY reserve fails, the entire transaction aborts.

**2. Compound Interest Calculation Risks** [2](#0-1) 

The `compound_interest()` function calculates `(1 + apr/SECONDS_IN_YEAR) ^ time_elapsed_s` where `time_elapsed_s` can be arbitrarily large. The `pow()` function implementation uses iterative multiplication: [3](#0-2) 

This can fail due to: (a) arithmetic overflow when time_elapsed_s is very large, (b) excessive gas consumption from repeated multiplications, or (c) any other calculation errors in the reserve.

**3. Mandatory Update Enforcement with No Recovery Path** [4](#0-3) 

The `update_suilend_position_value()` function calls `suilend_compound_interest()` at line 36 before calculating position value. If this fails, `finish_update_asset_value()` is never called, so the asset is not marked as updated. [5](#0-4) 

The `check_op_value_update_record()` function enforces that ALL borrowed assets must be updated before an operation can complete. At lines 1215-1218, it asserts each borrowed asset type is present in `asset_types_updated` and has a `true` value. [6](#0-5) 

The `end_op_value_update_with_bag()` function calls `check_op_value_update_record()` at line 354. If this check fails, the vault remains in `VAULT_DURING_OPERATION_STATUS` (set at line 74 in `pre_vault_check`).

**4. No Admin Recovery Mechanism** [7](#0-6) 

The only admin function to change vault status is `set_enabled()`, which explicitly blocks changes when `status() == VAULT_DURING_OPERATION_STATUS` at line 523. There is no emergency mechanism to force-complete an operation or reset vault status.

### Impact Explanation

**Complete Vault DoS:**
- The vault becomes permanently locked in `VAULT_DURING_OPERATION_STATUS`
- No new operations can start (requires `VAULT_NORMAL_STATUS`)
- User deposits and withdrawals cannot be processed
- All vault funds remain frozen

**User Fund Impact:**
- All existing depositors cannot withdraw their funds
- New deposits cannot be accepted
- The vault's total value is effectively frozen

**No Recovery Path:**
- Admin cannot reset vault status (blocked by line 523 check)
- Operator cannot bypass the value update requirement
- The issue persists until the external Suilend reserve is fixed (which the vault has no control over)

**Severity: HIGH**
This represents a complete operational failure of the vault with all user funds frozen and no recovery mechanism available.

### Likelihood Explanation

**Medium-High Likelihood:**

1. **Realistic Trigger Conditions:**
   - Only requires ONE reserve in the Suilend obligation to have compound interest issues
   - Large `time_elapsed_s` values naturally occur if reserves haven't been updated recently
   - Arithmetic overflow in exponential calculations is a common DeFi issue

2. **No Attacker Required:**
   - Can occur through normal operation if a reserve has been inactive for extended periods
   - External Suilend governance could misconfigure reserve parameters
   - Time-dependent calculation failures are inevitable over long periods

3. **External Dependency Risk:**
   - The vault has no control over Suilend's reserve interest rate configurations
   - Suilend reserves are shared across multiple protocols
   - A problematic reserve affects all obligations holding it

4. **Operator Vulnerability:**
   - Operators may unknowingly borrow obligations containing problematic reserves
   - No pre-check mechanism to validate reserve compound interest will succeed
   - Once borrowed, the operation cannot be completed if compounding fails

### Recommendation

**Immediate Mitigation:**

1. **Add Try-Catch Pattern or Skip Failed Reserves:**
Modify `suilend_compound_interest()` to handle individual reserve failures gracefully rather than aborting the entire transaction. Consider logging failures but continuing with remaining reserves.

2. **Add Admin Emergency Function:**
Add an admin-only emergency function to force-complete operations and reset vault status:
```move
public fun emergency_reset_operation_status(_: &AdminCap, vault: &mut Vault<PrincipalCoinType>)
```

3. **Add Gas Limit Checks:**
Before calling `compound_interest()`, validate that `time_elapsed_s` is within reasonable bounds to prevent excessive gas consumption.

4. **Alternative Value Calculation:**
Implement an alternative value calculation method that uses simulated compound interest (like `simulated_compound_interest()` at line 660 in reserve.move) which doesn't modify state and could be called in a separate transaction if the full compound fails.

**Test Cases:**
- Test with obligations containing reserves with very large `time_elapsed_s` values
- Test with maximum number of reserves to check gas limits
- Test recovery from failed operations using emergency admin function

### Proof of Concept

**Initial State:**
1. Vault is operational with a Suilend obligation asset containing multiple reserves
2. One reserve has not been updated for an extended period (large `time_elapsed_s`)
3. Operator starts an operation and borrows the Suilend obligation

**Attack Sequence:**
1. Operator calls `start_op_with_bag()` - vault enters `VAULT_DURING_OPERATION_STATUS`, obligation is borrowed
2. Operator performs operations with the borrowed assets
3. Operator calls `end_op_with_bag()` - assets returned, `enable_op_value_update()` called
4. Operator attempts to call `update_suilend_position_value()`:
   - Calls `suilend_compound_interest()` which loops through reserves
   - When reaching the problematic reserve, `compound_interest()` calculation overflows or runs out of gas
   - Transaction aborts, `finish_update_asset_value()` never called
5. Operator cannot complete operation by calling `end_op_value_update_with_bag()`:
   - `check_op_value_update_record()` fails because Suilend asset not marked as updated
   - Transaction aborts
6. Admin attempts `set_vault_enabled()`:
   - Blocked by check at line 523 (vault is in `DURING_OPERATION` status)
   - Transaction aborts

**Expected Result:** Operator can update position value and complete operation

**Actual Result:** Vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`, all operations frozen, no recovery possible

### Citations

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L91-102)
```text
fun suilend_compound_interest<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
) {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());
    let reserve_array_indices = get_reserve_array_indicies(obligation);

    reserve_array_indices.do_ref!(|reserve_array_index| {
        lending_market.compound_interest(*reserve_array_index, clock);
    });
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L596-657)
```text
    public(package) fun compound_interest<P>(reserve: &mut Reserve<P>, clock: &Clock) {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        let time_elapsed_s = cur_time_s - reserve.interest_last_update_timestamp_s;
        if (time_elapsed_s == 0) {
            return
        };

        // I(t + n) = I(t) * (1 + apr()/SECONDS_IN_YEAR) ^ n
        let utilization_rate = calculate_utilization_rate(reserve);
        let compounded_borrow_rate = pow(
            add(
                decimal::from(1),
                div(
                    calculate_apr(config(reserve), utilization_rate),
                    decimal::from(365 * 24 * 60 * 60)
                )
            ),
            time_elapsed_s
        );

        reserve.cumulative_borrow_rate = mul(
            reserve.cumulative_borrow_rate,
            compounded_borrow_rate
        );

        let net_new_debt = mul(
            reserve.borrowed_amount,
            sub(compounded_borrow_rate, decimal::from(1))
        );

        let spread_fee = mul(net_new_debt, spread_fee(config(reserve)));

        reserve.unclaimed_spread_fees = add(
            reserve.unclaimed_spread_fees,
            spread_fee
        );

        reserve.borrowed_amount = add(
            reserve.borrowed_amount,
            net_new_debt 
        );

        reserve.interest_last_update_timestamp_s = cur_time_s;

        event::emit(InterestUpdateEvent {
            lending_market_id: object::id_to_address(&reserve.lending_market_id),
            coin_type: reserve.coin_type,
            reserve_id: object::uid_to_address(&reserve.id),
            cumulative_borrow_rate: reserve.cumulative_borrow_rate,
            available_amount: reserve.available_amount,
            borrowed_amount: reserve.borrowed_amount,
            unclaimed_spread_fees: reserve.unclaimed_spread_fees,
            ctoken_supply: reserve.ctoken_supply,

            borrow_interest_paid: net_new_debt,
            spread_fee: spread_fee,
            supply_interest_earned: sub(net_new_debt, spread_fee),
            borrow_interest_paid_usd_estimate: market_value(reserve, net_new_debt),
            protocol_fee_usd_estimate: market_value(reserve, spread_fee),
            supply_interest_earned_usd_estimate: market_value(reserve, sub(net_new_debt, spread_fee)),
        });
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L83-96)
```text
    public fun pow(b: Decimal, mut e: u64): Decimal {
        let mut cur_base = b;
        let mut result = from(1);

        while (e > 0) {
            if (e % 2 == 1) {
                result = mul(result, cur_base);
            };
            cur_base = mul(cur_base, cur_base);
            e = e / 2;
        };

        result
    }
```

**File:** volo-vault/sources/volo_vault.move (L515-531)
```text
    emit(WithdrawFeeChanged { vault_id: self.vault_id(), fee: fee })
}

public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
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
