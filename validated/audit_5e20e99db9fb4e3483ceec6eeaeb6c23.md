# Audit Report

## Title
Oracle Aggregator Removal During Vault Operations Causes Permanent Vault Freeze

## Summary
The `remove_switchboard_aggregator()` function lacks validation to check if the aggregator being removed is currently required by an in-progress vault operation. When an admin removes an aggregator while a vault is in `VAULT_DURING_OPERATION_STATUS`, subsequent asset value update calls fail with `ERR_AGGREGATOR_NOT_FOUND`, permanently freezing the vault until the aggregator is re-added. All user deposits and withdrawals are blocked during this freeze.

## Finding Description

The vulnerability stems from insufficient coordination checks between oracle management and vault operations. The protocol implements a three-phase vault operation lifecycle where assets are borrowed, used in DeFi strategies, then returned and revalued. A critical vulnerability window exists between phase 2 (asset return) and phase 3 (value update completion).

**Root Cause:**

The `remove_switchboard_aggregator()` function only validates version and aggregator existence before removal. [1](#0-0)  It performs no checks for whether the aggregator is actively required by ongoing vault operations.

This function is callable by admins through the management interface: [2](#0-1) 

**Attack Path:**

1. **Phase 1 - Operation Start**: Operator initiates vault operation, borrowing assets and setting vault status to `VAULT_DURING_OPERATION_STATUS`. [3](#0-2) 

2. **Phase 2 - Asset Return**: After DeFi operations complete, operator returns all borrowed assets and enables value updates. [4](#0-3)  Specifically, line 294 calls `enable_op_value_update()` which opens the vulnerability window.

3. **Vulnerability Window**: Between phase 2 and phase 3, the operator must update each borrowed asset's value in separate transactions. For coin-type assets, the update function calls `get_normalized_asset_price()`: [5](#0-4) 

4. **Oracle Dependency Failure**: The price fetching functions abort if the aggregator is missing: [6](#0-5)  At line 129, it asserts the aggregator exists, or aborts with `ERR_AGGREGATOR_NOT_FOUND`.

5. **Adaptor Failures**: Similar failures occur in all adaptors. Cetus positions require prices for both tokens: [7](#0-6)  Navi positions iterate through all reserves fetching prices: [8](#0-7) 

6. **Phase 3 Cannot Complete**: The final phase requires all borrowed assets to have updated values: [9](#0-8)  At line 354, `check_op_value_update_record()` verifies this: [10](#0-9)  Lines 1216-1217 abort with `ERR_USD_VALUE_NOT_UPDATED` if any borrowed asset isn't updated.

**Why Recovery Fails:**

The admin cannot reset the vault because `set_enabled()` explicitly prevents status changes during operations: [11](#0-10)  Line 523 asserts the vault is not in `VAULT_DURING_OPERATION_STATUS`, blocking any admin intervention.

The only way to change vault status back to normal is through `end_op_value_update_with_bag()` (line 375 in operation.move), but this requires successful completion of all value updates, which is now impossible without the aggregator.

## Impact Explanation

**Critical Availability & Fund Access Impact:**

The vault becomes permanently frozen in `VAULT_DURING_OPERATION_STATUS` with the following consequences:

1. **User Deposit Blocking**: New deposit requests require `assert_normal()` status check. [12](#0-11)  Line 716 blocks all new deposits.

2. **User Withdrawal Blocking**: Withdrawal requests similarly require normal status. [13](#0-12)  Line 905 performs the same check.

3. **Request Cancellation Blocking**: Users cannot cancel pending requests during operations. [14](#0-13)  Line 769 blocks cancellations.

4. **Fund Lockup**: All user principal remains locked in the vault, with no withdrawal mechanism available until the admin re-adds the removed aggregator.

5. **Protocol Reputation Damage**: A vault freeze incident severely damages user trust and protocol credibility.

**Severity Justification**: This is a **High** severity vulnerability. While funds are not stolen or lost, they become completely inaccessible, constituting a critical denial-of-service attack on user fund availability. The vault's core invariant—users can always withdraw their funds—is violated.

## Likelihood Explanation

**Realistic Triggering Conditions:**

This vulnerability has **Medium-High** likelihood due to natural operational collision:

1. **Legitimate Admin Actions**: Oracle maintenance is routine (updating feed addresses, switching providers, removing deprecated feeds). Admins have no visibility into the current vault operation phase when performing these actions.

2. **Continuous Vault Operations**: Active vaults run operations frequently. The probability of an operation being in-progress during maintenance is substantial.

3. **Extended Vulnerability Window**: The window between phase 2 and phase 3 spans multiple transactions (one per borrowed asset), potentially lasting several minutes. This significantly increases collision probability.

4. **No Coordination Mechanism**: The protocol lacks any coordination between admin oracle actions and operator vault operations. No warnings, locks, or status checks exist.

5. **Honest Operator Behavior**: This vulnerability requires only normal, authorized operations from both admin and operator. No malicious intent or coordination is needed—it's a pure timing race condition.

**Execution Practicality:**

- Admin executes: `vault_manage::remove_switchboard_aggregator(admin_cap, oracle_config, asset_type)`
- Operator concurrently executes standard three-phase operation flow
- Timing collision occurs naturally during routine operations
- No special privileges or attack setup required

## Recommendation

Implement operation-aware oracle management with the following protections:

1. **Add Operation Status Check**: Modify `remove_switchboard_aggregator()` to check if any vault is currently in `VAULT_DURING_OPERATION_STATUS` and using the aggregator being removed:

```move
public(package) fun remove_switchboard_aggregator(
    config: &mut OracleConfig, 
    asset_type: String,
    vaults: &vector<&Vault<_>>,  // Pass all vaults to check
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    // NEW: Check no vault is using this aggregator during operations
    vaults.do_ref!(|vault| {
        if (vault.status() == VAULT_DURING_OPERATION_STATUS) {
            assert!(
                !vault.operation_uses_asset_type(asset_type),
                ERR_AGGREGATOR_IN_USE
            );
        };
    });
    
    emit(SwitchboardAggregatorRemoved { /* ... */ });
    config.aggregators.remove(asset_type);
}
```

2. **Alternative: Add Emergency Admin Recovery**: Allow admin to force-reset vault status with appropriate safeguards and governance delay.

3. **Implement Operation Pause**: Add a mechanism for admins to pause new operations before performing oracle maintenance, allowing in-progress operations to complete.

## Proof of Concept

```move
#[test]
fun test_vault_freeze_via_aggregator_removal() {
    // Setup: Create vault with SUI principal and USDC asset
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Phase 1: Start operation borrowing SUI and USDC
    test_scenario::next_tx(&mut scenario, OPERATOR);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let operation = test_scenario::take_shared<Operation>(&scenario);
        let op_cap = test_scenario::take_from_sender<OperatorCap>(&scenario);
        
        // Borrow assets - vault enters VAULT_DURING_OPERATION_STATUS
        let (assets, tx_bag, value_bag, principal, usdc) = 
            operation::start_op_with_bag<SUI, USDC, _>(
                &mut vault, &operation, &op_cap, &clock, 
                vector[0], vector[type_name::get<Balance<USDC>>()],
                1000, 500, &mut ctx
            );
        
        // Simulate DeFi operations...
        
        // Phase 2: Return assets - enables value update
        operation::end_op_with_bag<SUI, USDC, _>(
            &mut vault, &operation, &op_cap,
            assets, tx_bag, principal, usdc
        );
        // Vault now in vulnerable state: DURING_OPERATION with value_update_enabled
    };
    
    // ADMIN REMOVES AGGREGATOR DURING VULNERABILITY WINDOW
    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
        let mut oracle_config = test_scenario::take_shared<OracleConfig>(&scenario);
        
        // Admin removes USDC aggregator (legitimate maintenance)
        vault_manage::remove_switchboard_aggregator(
            &admin_cap, &mut oracle_config, 
            type_name::get<USDC>().into_string()
        );
    };
    
    // Phase 3 FAILS: Cannot update USDC value
    test_scenario::next_tx(&mut scenario, OPERATOR);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let oracle_config = test_scenario::take_shared<OracleConfig>(&scenario);
        
        // Try to update USDC value - ABORTS with ERR_AGGREGATOR_NOT_FOUND
        vault::update_coin_type_asset_value<SUI, USDC>(
            &mut vault, &oracle_config, &clock
        ); // ❌ ABORTS HERE
        
        // Cannot complete end_op_value_update_with_bag()
        // Vault permanently frozen in VAULT_DURING_OPERATION_STATUS
    };
    
    // Verify vault is frozen - user operations fail
    test_scenario::next_tx(&mut scenario, USER);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let receipt = test_scenario::take_from_sender<Receipt>(&scenario);
        
        // Try to request deposit - ABORTS with ERR_VAULT_NOT_NORMAL
        let deposit_coin = coin::mint_for_testing<SUI>(1000, &mut ctx);
        vault::request_deposit(
            &mut vault, deposit_coin, &clock, 
            100, receipt.id().to_address(), USER
        ); // ❌ ABORTS - vault frozen
    };
    
    test_scenario::end(scenario);
}
```

**Notes:**

This vulnerability demonstrates a critical coordination failure between vault operations and oracle management. While both admin and operator are trusted roles performing legitimate operations, the lack of synchronization creates a severe availability impact. The fix requires implementing operation-aware checks in oracle management functions or providing emergency recovery mechanisms for admins.

### Citations

**File:** volo-vault/sources/oracle.move (L126-154)
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

public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** volo-vault/sources/oracle.move (L186-196)
```text
public(package) fun remove_switchboard_aggregator(config: &mut OracleConfig, asset_type: String) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    emit(SwitchboardAggregatorRemoved {
        asset_type,
        aggregator: config.aggregators[asset_type].aggregator,
    });

    config.aggregators.remove(asset_type);
}
```

**File:** volo-vault/sources/manage.move (L110-116)
```text
public fun remove_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    asset_type: String,
) {
    oracle_config.remove_switchboard_aggregator(asset_type);
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

**File:** volo-vault/sources/volo_vault.move (L761-802)
```text
public(package) fun cancel_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): Coin<PrincipalCoinType> {
    self.check_version();
    self.assert_not_during_operation();

    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == PENDING_DEPOSIT_STATUS, ERR_WRONG_RECEIPT_STATUS);

    let deposit_request = &mut self.request_buffer.deposit_requests[request_id];
    assert!(receipt_id == deposit_request.receipt_id(), ERR_RECEIPT_ID_MISMATCH);
    assert!(
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
    assert!(deposit_request.recipient() == recipient, ERR_RECIPIENT_MISMATCH);

    // deposit_request.cancel(clock.timestamp_ms());
    vault_receipt.update_after_cancel_deposit(deposit_request.amount());

    // Retrieve the receipt and coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);

    emit(DepositCancelled {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: recipient,
        vault_id: self.id.to_address(),
        amount: deposit_request.amount(),
    });

    self.delete_deposit_request(request_id);

    coin
}
```

**File:** volo-vault/sources/volo_vault.move (L896-940)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);
    assert!(vault_receipt.shares() >= shares, ERR_EXCEED_RECEIPT_SHARES);

    // Generate request id
    let current_request_id = self.request_buffer.withdraw_id_count;
    self.request_buffer.withdraw_id_count = current_request_id + 1;

    // Record this new request in Vault
    let new_request = withdraw_request::new(
        current_request_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        shares,
        expected_amount,
        clock.timestamp_ms(),
    );
    self.request_buffer.withdraw_requests.add(current_request_id, new_request);

    emit(WithdrawRequested {
        request_id: current_request_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        shares: shares,
        expected_amount: expected_amount,
    });

    vault_receipt.update_after_request_withdraw(shares, recipient);

    current_request_id
}
```

**File:** volo-vault/sources/volo_vault.move (L1130-1154)
```text
public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();
    assert!(
        type_name::get<CoinType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<CoinType>().into_string();
    let now = clock.timestamp_ms();

    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

    finish_update_asset_value(self, asset_type, coin_usd_value, now);
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-74)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18

    // pool price = price_a / price_b (not consider decimals)
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );

    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
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
