# Audit Report

## Title
Navi Position Valuation Fails Completely on Single Reserve Oracle Failure, Causing Vault Operation Deadlock

## Summary
The `calculate_navi_position_value()` function uses assert-based oracle price fetching without error handling. When any single Navi reserve's oracle fails, the entire transaction aborts, preventing the Navi asset from being marked as updated. This creates a permanent deadlock where the vault remains stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all user deposits/withdrawals and admin recovery functions until external oracle infrastructure recovers.

## Finding Description

The vulnerability exists in the Navi position valuation flow where oracle failures cascade into complete protocol denial of service.

**Core Issue: Brittle Oracle Price Fetching**

The `calculate_navi_position_value()` function loops through all Navi reserves and fetches oracle prices for each non-zero balance position. [1](#0-0) 

For each reserve with a balance, it calls `vault_oracle::get_asset_price()` which contains two critical assertions that cause immediate transaction abort: [2](#0-1) 

Since Sui Move lacks try-catch error handling, when any assertion fails, the transaction aborts immediately with no recovery path. The critical design flaw is that `finish_update_asset_value()` is only called after successful calculation completion. [3](#0-2) 

**Deadlock Mechanism:**

1. During vault operations, the operator calls `start_op_with_bag()` which sets vault status to `VAULT_DURING_OPERATION_STATUS` and tracks all borrowed assets. [4](#0-3) 

2. After returning assets via `end_op_with_bag()`, the operator must update each borrowed asset's value. [5](#0-4) 

3. When attempting to update the Navi position value, if any reserve's oracle is stale or missing, the transaction aborts before `finish_update_asset_value()` executes, meaning the asset is never marked as updated in `op_value_update_record.asset_types_updated`.

4. To complete the operation, the system validates that ALL borrowed assets have been updated via `check_op_value_update_record()`. [6](#0-5) 

5. This validation occurs in `end_op_value_update_with_bag()` before resetting vault status to normal. [7](#0-6) 

6. Since the oracle failure prevents the asset update, the validation check always fails with `ERR_USD_VALUE_NOT_UPDATED`, permanently blocking status reset.

**Why Recovery Mechanisms Fail:**

The admin's `set_enabled()` function explicitly blocks execution when vault is in operation status, preventing emergency status override. [8](#0-7) 

All critical user operations require normal vault status and are therefore permanently blocked. [9](#0-8) 

There is no alternative admin function to directly reset vault status or clear the operation value update record when the vault is stuck in `VAULT_DURING_OPERATION_STATUS`.

## Impact Explanation

**HIGH Severity - Complete Protocol Denial of Service**

This vulnerability causes catastrophic operational deadlock with protocol-wide impact:

1. **All user deposits blocked** - Users cannot call `request_deposit()` as it requires `assert_normal()`
2. **All user withdrawals blocked** - Users cannot call `request_withdraw()` as it similarly requires normal vault status  
3. **No new operations possible** - Operators cannot start new operations as `pre_vault_check()` requires normal status
4. **Request cancellations blocked** - Even canceling pending requests requires `assert_not_during_operation()`
5. **No admin recovery path** - Admin cannot use `set_enabled()` to reset vault status due to explicit guard against `VAULT_DURING_OPERATION_STATUS`

**Real-World Scenario:** A Navi position holds balances across 5 reserves (SUI, USDC, USDT, WETH, CETUS). The CETUS oracle experiences staleness due to low liquidity or network issues. Despite 99.5% of the position value being priceable, the entire vault becomes permanently unusable until the external CETUS oracle infrastructure recovers. All vault users lose access to their funds during this period.

## Likelihood Explanation

**HIGH Likelihood**

1. **Routine Operational Flow**: `update_navi_position_value()` is called by operators during standard value update phase after every operation - this is not an edge case but core protocol workflow.

2. **Realistic Preconditions**:
   - Oracle failures occur naturally in production DeFi systems (network congestion, validator downtime, sparse updates for low-liquidity assets, Switchboard infrastructure issues)
   - Multi-reserve Navi positions are common for diversified yield strategies
   - Only requires ONE reserve's oracle to fail among potentially many

3. **No Special Privileges Required**: Natural oracle failures require no attacker action. However, a sophisticated attacker could deliberately trigger this by depositing minimal amounts in reserves with unreliable oracles.

4. **No Prevention Possible**: Even with active oracle monitoring, brief staleness windows are unavoidable, and any transient failure causes permanent vault lockup until external recovery.

## Recommendation

Implement graceful degradation for oracle failures in position valuation:

**Option 1: Skip Failed Assets (Recommended)**
```move
// In calculate_navi_position_value, wrap oracle call with optional handling
let price_opt = try_get_asset_price(config, clock, coin_type);
if (option::is_some(&price_opt)) {
    let price = option::destroy_some(price_opt);
    // Calculate and accumulate USD values
} else {
    // Log warning and skip this reserve
    // Consider returning last known value or zero
};
```

**Option 2: Emergency Admin Override**
Add an admin function to force-clear operation value update record when vault is stuck:
```move
public fun emergency_clear_operation_status(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Allow admin to force-reset vault status and clear update records
    // Should be restricted and logged for auditing
    vault.clear_op_value_update_record();
    vault.set_status(VAULT_NORMAL_STATUS);
}
```

**Option 3: Timeout Mechanism**
Implement automatic vault status reset after a timeout period if value updates are not completed within reasonable timeframe.

## Proof of Concept

```move
#[test]
fun test_navi_oracle_failure_causes_vault_deadlock() {
    // Setup: Create vault with Navi position containing multiple reserves
    let mut scenario = test_scenario::begin(ADMIN);
    let mut vault = create_test_vault(&mut scenario);
    let mut navi_storage = create_navi_storage_with_reserves(&mut scenario);
    let mut oracle_config = create_oracle_config(&mut scenario);
    
    // Setup Navi position with balances in SUI and USDC reserves
    deposit_to_navi_reserve(&mut navi_storage, SUI_RESERVE, 1000);
    deposit_to_navi_reserve(&mut navi_storage, USDC_RESERVE, 500);
    
    // Setup oracles - SUI oracle works, USDC oracle is stale
    setup_valid_oracle(&mut oracle_config, SUI_TYPE, 1000000);
    setup_stale_oracle(&mut oracle_config, USDC_TYPE); // Last updated > update_interval
    
    // Step 1: Start operation - vault status becomes DURING_OPERATION
    let (bag, tx, tx_check, principal, coin) = start_op_with_bag(
        &mut vault, &operation, &cap, &clock, 
        vector[NAVI_ID], vector[type_name::get<NaviAccountCap>()],
        0, 0, &mut scenario
    );
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, 0);
    
    // Step 2: Return assets
    end_op_with_bag(&mut vault, &operation, &cap, bag, tx, principal, coin);
    
    // Step 3: Attempt to update Navi position value - THIS ABORTS
    // Because USDC oracle is stale, get_asset_price() aborts at line 135
    update_navi_position_value(
        &mut vault, &oracle_config, &clock, 
        NAVI_ASSET_TYPE, &mut navi_storage
    ); // TRANSACTION ABORTS HERE
    
    // Since transaction aborted, finish_update_asset_value() never called
    // Asset not marked as updated in op_value_update_record
    
    // Step 4: Attempt to complete operation - THIS FAILS
    end_op_value_update_with_bag(
        &mut vault, &operation, &cap, &clock, tx_check
    ); // ABORTS with ERR_USD_VALUE_NOT_UPDATED
    
    // Vault status remains VAULT_DURING_OPERATION_STATUS forever
    
    // Step 5: Verify all recovery paths are blocked
    
    // Admin cannot enable/disable vault
    set_vault_enabled(&admin_cap, &mut vault, false); // ABORTS with ERR_VAULT_DURING_OPERATION
    
    // Users cannot deposit
    request_deposit(&mut vault, coin, &clock, 100, receipt_id, user); // ABORTS with ERR_VAULT_NOT_NORMAL
    
    // Users cannot withdraw  
    request_withdraw(&mut vault, &clock, receipt_id, 100, 0, user); // ABORTS with ERR_VAULT_NOT_NORMAL
    
    // Operators cannot start new operations
    start_op_with_bag(&mut vault, ...); // ABORTS with ERR_VAULT_NOT_NORMAL
    
    // VAULT PERMANENTLY LOCKED - NO RECOVERY POSSIBLE
}
```

**Notes:**

This vulnerability represents a critical architectural flaw where external oracle reliability directly controls core protocol availability. The lack of graceful degradation or emergency recovery mechanisms amplifies a transient external dependency failure into permanent protocol denial of service. The issue affects not just Navi positions but could theoretically impact any adaptor that relies on oracle price fetching in a similar pattern (Cetus, Suilend, Momentum, Receipt adaptors all use the same oracle module). The severity is HIGH because it causes complete loss of protocol functionality with realistic trigger conditions and no recovery path.

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L43-72)
```text
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
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
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

**File:** volo-vault/sources/volo_vault.move (L518-531)
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
}
```

**File:** volo-vault/sources/volo_vault.move (L707-757)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Generate current request id
    let current_deposit_id = self.request_buffer.deposit_id_count;
    self.request_buffer.deposit_id_count = current_deposit_id + 1;

    // Deposit amount
    let amount = coin.value();

    // Generate the new deposit request and add it to the vault storage
    let new_request = deposit_request::new(
        current_deposit_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        amount,
        expected_shares,
        clock.timestamp_ms(),
    );
    self.request_buffer.deposit_requests.add(current_deposit_id, new_request);

    emit(DepositRequested {
        request_id: current_deposit_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        amount: amount,
        expected_shares: expected_shares,
    });

    // Temporary buffer the coins from user
    // Operator will retrieve this coin and execute the deposit
    self.request_buffer.deposit_coin_buffer.add(current_deposit_id, coin);

    vault_receipt.update_after_request_deposit(amount);

    current_deposit_id
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
