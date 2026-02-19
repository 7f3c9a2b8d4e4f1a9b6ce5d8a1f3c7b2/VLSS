### Title
Vault Lockup via Zero Pyth Price in Suilend Position Valuation

### Summary
When Pyth oracle returns a zero price for any Suilend reserve asset, the Suilend oracle parser panics during `i64::get_magnitude_if_positive()` call, preventing Suilend position value updates. This blocks vault operations from completing their mandatory value update phase, causing indefinite vault lockup in DURING_OPERATION status with no admin recovery mechanism.

### Finding Description

**Root Cause Location:**

The vulnerability exists in Suilend's oracle price parsing logic: [1](#0-0) [2](#0-1) 

Both calls to `i64::get_magnitude_if_positive()` will panic if the Pyth price value is zero or negative, causing the entire transaction to abort.

**Exploitation Path:**

1. Vault holds Suilend obligation positions as DeFi assets. Before updating these positions, operators must call `lending_market::refresh_reserve_price()` with Pyth price data: [3](#0-2) 

2. The refresh flow calls into Suilend's reserve update: [4](#0-3) 

3. Which triggers the oracle price parsing: [5](#0-4) 

4. During vault operations, the three-step lifecycle requires value updates for all borrowed assets: [6](#0-5) 

5. After returning assets, operators MUST update all Suilend position values: [7](#0-6) 

6. The vault strictly enforces that all borrowed assets have updated values before completing operations: [8](#0-7) 

7. If price refresh panics due to zero Pyth price, the value update cannot complete, and the final operation step cannot be called: [9](#0-8) 

**Why Existing Protections Fail:**

The Suilend oracle code includes confidence and staleness checks, indicating awareness of potential Pyth issues, but has NO zero-price handling before calling the panic-inducing function. The vault has no emergency override to skip value updates or reset status when stuck.

### Impact Explanation

**Concrete Harm:**

When a vault enters DURING_OPERATION status and cannot complete value updates due to zero Pyth price, it becomes permanently locked until the Pyth feed recovers. During this lockup:

1. All user deposit requests are blocked: [10](#0-9) 

2. All user withdrawal requests are blocked: [11](#0-10) 

3. Pending request cancellations are blocked: [12](#0-11) 

**No Admin Recovery:**

The admin cannot manually reset vault status because `set_vault_enabled` explicitly prevents status changes during operations: [13](#0-12) 

**Affected Parties:**
- All vault depositors cannot withdraw funds
- New users cannot deposit
- Vault effectively frozen until external Pyth oracle recovers
- If Pyth feed is permanently broken, vault funds are permanently locked

### Likelihood Explanation

**Realistic Feasibility:**

1. **No Attacker Required:** Pyth oracles can naturally return zero prices during network outages, extreme market conditions, or oracle maintenance. This is a well-known characteristic of oracle systems.

2. **Natural Occurrence:** The Suilend code's inclusion of confidence ratio checks and staleness validation demonstrates awareness that Pyth feeds can have quality issues. Zero prices fall into this category but are not handled.

3. **Reachable Entry Point:** Any vault using Suilend positions (a core DeFi integration) is vulnerable whenever operators perform routine operations.

4. **No Economic Barrier:** The vulnerability triggers through normal operational flow, requiring no special attacker capabilities or capital.

5. **Permanent Lock Risk:** If a Pyth price feed becomes deprecated or permanently stuck, the vault has no recovery mechanism, leading to permanent fund lockup.

### Recommendation

**Immediate Fix:**

The Suilend oracle module should handle zero/negative prices gracefully by returning `None` instead of panicking:

```move
// In oracles.move, line 30:
let price_i64 = price::get_price(&price);
if (!i64::get_is_positive(&price_i64)) {
    return (option::none(), ema_price, price_identifier)
};
let price_mag = i64::get_magnitude_if_positive(&price_i64);
```

**Vault-Level Protection:**

Add emergency admin function to reset vault status with operator multi-sig requirement:

```move
public entry fun emergency_reset_operation_status<T>(
    vault: &mut Vault<T>,
    admin_cap: &AdminCap,
    operator_caps: vector<&OperatorCap>, // require multiple operator approvals
) {
    // Add multi-sig validation
    // Reset to NORMAL status
    // Emit emergency event
}
```

**Testing Requirements:**

Add regression tests for:
1. Zero Pyth price handling in Suilend refresh
2. Vault recovery from stuck DURING_OPERATION state
3. End-to-end operation flow with temporary oracle failures

### Proof of Concept

**Initial State:**
1. Vault has Suilend obligation position containing asset X
2. Asset X uses Pyth price feed ID `0xABC...`
3. Vault is in NORMAL status

**Exploit Sequence:**

1. Operator calls `operation::start_op_with_bag()` borrowing Suilend position
   - Vault status → DURING_OPERATION
   
2. Operator performs strategy operations (legitimate)

3. Operator calls `operation::end_op_with_bag()` returning Suilend position
   - Assets returned, value_update_enabled = true
   
4. **Pyth oracle for asset X returns zero price** (network issue/oracle downtime)

5. Operator attempts: `lending_market::refresh_reserve_price(lending_market, reserve_index, clock, pyth_price_info)`
   - Transaction panics at `i64::get_magnitude_if_positive()`
   - **Transaction fails**

6. Operator cannot call `suilend_adaptor::update_suilend_position_value()`
   - Value update impossible

7. Operator cannot call `operation::end_op_value_update_with_bag()`
   - Fails at `check_op_value_update_record()` with ERR_USD_VALUE_NOT_UPDATED

8. Vault permanently stuck in DURING_OPERATION status

**Expected vs Actual:**
- **Expected:** Temporary oracle issues should degrade gracefully or allow admin recovery
- **Actual:** Vault enters unrecoverable locked state, blocking all user operations until external Pyth feed recovers

**Success Condition:**
Vault remains in DURING_OPERATION status indefinitely. All `request_deposit()`, `request_withdraw()`, and `cancel_*()` calls fail with ERR_VAULT_NOT_NORMAL until Pyth price becomes positive again.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L30-30)
```text
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L56-56)
```text
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L12-19)
```text
// @dev Need to update the price of the reserve before calling this function
//      Update function: lending_market::refresh_reserve_price
//          public fun refresh_reserve_price<P>(
//              lending_market: &mut LendingMarket<P>,
//              reserve_array_index: u64,
//              clock: &Clock,
//              price_info: &PriceInfoObject,
//           )
```

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-211)
```text
    public fun refresh_reserve_price<P>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
        price_info: &PriceInfoObject,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        reserve::update_price<P>(reserve, clock, price_info);
    }
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

**File:** volo-vault/sources/operation.move (L209-297)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();

    defi_assets.destroy_empty();
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

**File:** volo-vault/sources/volo_vault.move (L516-531)
```text
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

**File:** volo-vault/sources/volo_vault.move (L711-716)
```text
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L842-847)
```text
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
```

**File:** volo-vault/sources/volo_vault.move (L900-905)
```text
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
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
