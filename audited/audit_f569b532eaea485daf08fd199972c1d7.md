### Title
Vault Operations with Suilend Positions Experience Permanent DoS During Pyth Oracle Downtime

### Summary
When Pyth oracle price feeds stop updating for more than 60 seconds, vault operations involving Suilend positions cannot complete their mandatory value update step, causing the vault to become stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism. The vault remains inoperable until Pyth resumes providing fresh prices, blocking all deposits, withdrawals, and new operations.

### Finding Description

The vulnerability exists in the interaction between three components:

**1. Pyth Price Staleness Check** [1](#0-0) 

The `get_pyth_price_and_identifier()` function rejects prices older than 60 seconds by returning `None` for the spot price: [2](#0-1) 

**2. No Fallback in Reserve Price Update** [3](#0-2) 

The `update_price()` function aborts when receiving `None` instead of implementing a fallback mechanism: [4](#0-3) 

**3. Mandatory Asset Value Updates in Operation Flow**

Vault operations follow a three-step pattern where ALL borrowed assets must have their values updated: [5](#0-4) 

The `check_op_value_update_record()` enforces this requirement: [6](#0-5) 

**4. Suilend Position Valuation Requires Fresh Prices**

When updating Suilend position values, the adaptor requires reserve prices to be updated in the same transaction (0-second staleness threshold): [7](#0-6) [8](#0-7) 

**5. No Emergency Recovery Mechanism**

The admin cannot disable the vault while it's in `VAULT_DURING_OPERATION_STATUS`: [9](#0-8) 

### Impact Explanation

**Operational DoS:**
- When an operator starts a vault operation involving Suilend positions (step 1), then Pyth stops updating for >60 seconds before step 3 completes, the operation cannot be finished
- The vault becomes stuck in `VAULT_DURING_OPERATION_STATUS` with no way to transition out
- All vault functionality is blocked: deposits cannot be executed, withdrawals cannot be processed, new operations cannot start
- Admin cannot disable or recover the vault due to the status check

**Affected Parties:**
- All vault users are unable to access their funds (cannot deposit/withdraw)
- Vault operators cannot perform rebalancing or strategy adjustments
- Vault administrators have no emergency override capability

**Severity Justification:**
- Complete operational paralysis of the vault
- Affects all users and all vault functions
- No administrative recovery path exists
- Duration depends entirely on external Pyth oracle recovery (could be hours or days)
- While funds are not at risk of theft, they are completely inaccessible

### Likelihood Explanation

**Realistic Occurrence:**
- Pyth oracle downtime >60 seconds is a realistic scenario due to:
  - Network congestion on the source chain
  - Validator node issues
  - Cross-chain bridge delays
  - Price publisher infrastructure problems
  - Pyth has experienced such outages in production deployments

**Attack Complexity:**
- This is not an intentional attack but a dependency failure
- No attacker action required - normal operations during oracle downtime trigger the issue
- Any operator performing routine vault rebalancing with Suilend positions is affected

**Execution Path:**
1. Operator calls `start_op_with_bag()` including a Suilend obligation asset
2. Pyth oracle stops updating (external event, >60 seconds of staleness)
3. Operator attempts to complete operation by calling `refresh_reserve_price()` → fails with `EInvalidPrice`
4. Cannot call `update_suilend_position_value()` due to stale reserve prices
5. Cannot call `end_op_value_update_with_bag()` due to missing asset updates
6. Vault permanently stuck until Pyth recovers

**Detection Constraints:**
- Operator may not realize Pyth is stale until mid-operation
- No warning system or grace period exists
- Once stuck, requires monitoring Pyth recovery externally

### Recommendation

**1. Implement Fallback Oracle Mechanism:**
Add a secondary oracle (e.g., Switchboard) that can provide prices when Pyth is stale. Modify the Suilend reserve integration to accept alternative price sources.

**2. Add Emergency Recovery Function:**
```
public fun emergency_complete_operation<PrincipalCoinType>(
    admin: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, ERR_NOT_DURING_OPERATION);
    // Force complete operation using last known asset values
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**3. Increase Grace Period:**
Modify `PRICE_STALENESS_THRESHOLD_S` to allow a reasonable grace period (e.g., 300 seconds) instead of 0: [7](#0-6) 

**4. Add Circuit Breaker:**
Implement an automatic pause mechanism that detects oracle staleness before operations begin, preventing vault from entering the stuck state.

**5. Test Cases:**
- Test vault operation with simulated Pyth downtime >60s
- Test emergency recovery function execution
- Test fallback oracle activation when primary oracle is stale
- Test that vault can handle prolonged oracle outages gracefully

### Proof of Concept

**Initial State:**
- Vault has a Suilend obligation position with deposits/borrows
- Vault is in `VAULT_NORMAL_STATUS`
- Pyth oracle is providing fresh prices

**Exploit Sequence:**

**Transaction 1:**
```
operation::start_op_with_bag(
    vault,
    operation,
    operator_cap,
    clock,
    defi_asset_ids: [0], // Suilend obligation ID
    defi_asset_types: [SuilendObligationOwnerCap<P>],
    ...
)
```
- Vault transitions to `VAULT_DURING_OPERATION_STATUS`
- Suilend obligation is borrowed and recorded in `asset_types_borrowed`

**External Event:**
- Pyth oracle stops updating for >60 seconds (simulated by advancing clock without new price updates)

**Transaction 2 (Fails):**
```
lending_market::refresh_reserve_price(lending_market, reserve_index, clock, stale_price_info)
```
- `reserve::update_price()` calls `oracles::get_pyth_price_and_identifier()`
- Returns `(None, ema_price, identifier)` due to staleness
- **Aborts with `EInvalidPrice` at line 588**

**Transaction 3 (Cannot Execute):**
```
suilend_adaptor::update_suilend_position_value(vault, lending_market, clock, asset_type)
```
- Cannot execute because reserve price was not updated
- If attempted, `assert_price_is_fresh()` would abort with `EPriceStale`

**Transaction 4 (Cannot Execute):**
```
operation::end_op_value_update_with_bag(vault, operation, operator_cap, clock, tx_bag)
```
- Cannot execute because `check_op_value_update_record()` would abort
- Suilend obligation in `asset_types_borrowed` but not in `asset_types_updated`

**Transaction 5 (Admin Recovery Fails):**
```
vault_manage::set_vault_enabled(admin_cap, vault, false)
```
- **Aborts at status check: vault is `VAULT_DURING_OPERATION_STATUS`**
- No recovery possible

**Result:**
- Vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`
- All deposits/withdrawals blocked
- No new operations can start
- Admin cannot disable vault
- Vault remains stuck until Pyth provides fresh prices AND operator completes the operation

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L43-48)
```text
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-593)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
        reserve.price_last_update_timestamp_s = clock::timestamp_ms(clock) / 1000;
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

**File:** volo-vault/sources/volo_vault.move (L518-530)
```text
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L42-89)
```text
public(package) fun parse_suilend_obligation<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &LendingMarket<ObligationType>,
    clock: &Clock,
): u256 {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());

    let mut total_deposited_value_usd = 0;
    let mut total_borrowed_value_usd = 0;
    let reserves = lending_market.reserves();

    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```
