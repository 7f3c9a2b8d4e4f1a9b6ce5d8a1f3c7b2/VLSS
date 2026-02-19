### Title
Unstrict Operation Value Invariant Allows Rounding Errors to Bypass Loss Tolerance

### Summary
The Volo vault operation value check uses a non-strict comparison (`<` instead of `<=`) when validating total USD value changes during operations. This allows operations where `total_usd_value_after == total_usd_value_before` to record zero loss, even when actual value was extracted through rounding errors in price calculations, asset valuations, or external DeFi protocol interactions. Over multiple operations, these undetected micro-losses can accumulate beyond the intended loss_tolerance limit per epoch.

### Finding Description
The vulnerability exists in the `end_op_value_update_with_bag` function, which performs the final value check after vault operations complete: [1](#0-0) 

The check only records loss when `total_usd_value_after < total_usd_value_before` (strictly less than). When values are equal, no loss is recorded (`loss = 0`), and the loss tolerance mechanism is not invoked.

This is analogous to the external AMM vulnerability where `lp_value_after_swap_and_fee >= lp_value_before_swap` allowed equality, enabling rounding error exploitation. In Volo's case, the rounding errors occur in multiple calculation layers:

1. **Asset valuation calculations** use truncating division in `mul_with_oracle_price` and `div_with_oracle_price`: [2](#0-1) 

2. **Share calculations** use `mul_d` and `div_d` with truncating division: [3](#0-2) 

3. **Total USD value** is calculated by summing individual asset values (each potentially containing rounding errors): [4](#0-3) 

An operator can execute operations involving multiple DeFi protocols (Navi, Cetus, Suilend, Momentum), each introducing additional rounding errors. When these cumulative rounding errors cause small value losses that round back to equality in the final calculation, the loss goes undetected.

The loss tolerance check correctly enforces limits when loss IS detected: [5](#0-4) 

However, if operations consistently show zero loss due to rounding masking, the accumulated real losses never trigger this protection.

### Impact Explanation
**Severity: MEDIUM**

An authorized operator can execute multiple operations per epoch that extract small amounts of value through rounding errors in complex DeFi interactions. Since each operation appears to have zero loss (due to rounding causing `total_usd_value_after == total_usd_value_before`), the loss tolerance mechanism fails to accumulate these losses. Over many operations, the actual cumulative loss could exceed the configured `loss_tolerance` (default 0.1% per epoch), violating the protocol's risk management invariant.

While individual rounding losses are small due to high precision (9 decimals for vault values, 18 for oracle prices), the external report demonstrates that "for a token with 8 decimals, the stable swap math would give up to 1,000,000 atomic units of imprecision, representing up to 1% of the original token's value." Volo's multi-protocol operations (Navi borrow/supply, Cetus liquidity, Suilend lending) compound rounding opportunities across different mathematical implementations.

### Likelihood Explanation
**Likelihood: MEDIUM**

- **Access**: Only operators with valid `OperatorCap` can execute operations [6](#0-5) 

- **Feasibility**: Operators routinely execute legitimate operations involving multiple assets and DeFi protocols. The rounding exploitation doesn't require malicious intent—it can occur naturally through complex operations, but a sophisticated operator could deliberately craft operations to maximize rounding errors while keeping measured loss at zero.

- **Repeatability**: Multiple operations can be executed per epoch before tolerance resets [7](#0-6) 

- **Detection Difficulty**: Since each operation shows zero loss in the event emission, the cumulative effect is hidden from monitoring systems [8](#0-7) 

### Recommendation
Change the operation value check to enforce strict inequality or implement a minimum loss detection threshold:

**Option 1: Strict Comparison (matches external report fix)**
```move
// In end_op_value_update_with_bag at line 361-364
if (total_usd_value_after < total_usd_value_before) {
    loss = total_usd_value_before - total_usd_value_after;
    vault.update_tolerance(loss);
} else if (total_usd_value_after == total_usd_value_before) {
    // For operations that should be neutral, equality is suspicious
    // Consider adding a small mandatory positive value increase to account for operator work
    // OR at minimum, emit a warning event for monitoring
};
```

**Option 2: Minimum Loss Detection Threshold**
```move
// Record even micro-losses to catch rounding accumulation
let mut loss = 0;
if (total_usd_value_after <= total_usd_value_before) {
    loss = total_usd_value_before - total_usd_value_after;
    if (loss > 0) {
        vault.update_tolerance(loss);
    };
};
```

**Option 3: Statistical Monitoring**
Add cumulative tracking of "zero-loss" operations and trigger alerts when the frequency is abnormally high, indicating potential rounding exploitation.

### Proof of Concept

1. **Initial State**: Vault with 10,000 SUI @ $2.00 = $20,000 total value, loss_tolerance = 0.1% = $20 limit per epoch

2. **Operation 1**: Operator borrows 1,000 SUI, supplies to Navi, borrows USDC, swaps in Cetus, repays, withdraws. Due to rounding in:
   - Navi's supply/borrow calculations
   - Cetus swap math  
   - Oracle price conversions (balance * price / 1e18)
   - Vault's mul_d/div_d operations
   
   Real loss: ~0.0001 SUI = $0.0002
   Calculated values: both round to $20,000.000000000 (9 decimals)
   Recorded loss: $0 ✓ (operation succeeds)

3. **Operations 2-100**: Repeat similar complex multi-protocol operations
   Each shows zero loss due to rounding
   Cumulative real loss: ~$0.02

4. **Operation 101**: More aggressive operation
   Real loss: ~0.01 SUI = $0.02  
   Calculated values: still round to equality
   Recorded loss: $0 ✓
   
5. **Cumulative Effect**: 
   - Total real loss: $0.02 + $0.02 = $0.04 (example)
   - Recorded loss: $0
   - Loss tolerance never triggered despite real value extraction

6. **Result**: Operator extracted more value than tolerance allows, bypassing the epoch loss limit protection. The vault's `cur_epoch_loss` remains 0, while actual value decreased.

### Citations

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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/operation.move (L368-373)
```text
    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });
```

**File:** volo-vault/sources/utils.move (L22-30)
```text
// mul with decimals
public fun mul_d(v1: u256, v2: u256): u256 {
    v1 * v2 / DECIMALS
}

// div with decimals
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/utils.move (L69-76)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}

// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/volo_vault.move (L608-624)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
}
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
