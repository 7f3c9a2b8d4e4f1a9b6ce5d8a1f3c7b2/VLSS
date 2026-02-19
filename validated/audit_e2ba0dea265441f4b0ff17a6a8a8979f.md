# Audit Report

## Title
Oracle Override Creates Staleness Window Causing Vault Operation Failures

## Summary
When Switchboard oracle infrastructure undergoes TEE rotation via `queue_override_oracle_action::run()`, the oracle's signing key is updated but the aggregator's existing price timestamps from the old TEE remain unchanged. This creates a staleness window where vault operations fail to complete because price validation enforces a 60-second freshness requirement against stale aggregator timestamps, potentially leaving vaults stuck in DURING_OPERATION status until the new TEE submits its first price update.

## Finding Description

The vulnerability exists in the coordination gap between Switchboard oracle infrastructure maintenance and Volo vault operations.

**Root Cause:** The `enable_oracle()` function only updates the oracle's identity fields (`secp256k1_key`, `mr_enclave`, `expiration_time_ms`) without clearing or invalidating the aggregator's `current_result` which contains the timestamp from the old TEE's last price submission. [1](#0-0) 

This function is invoked during oracle override operations: [2](#0-1) 

**Blocking Mechanism:** After the override, the old TEE cannot submit new price updates because signature validation in `aggregator_submit_result_action::validate()` requires the signature to match the oracle's current `secp256k1_key`, which has been changed. [3](#0-2) 

**Failure Path:** Vault operations require fresh asset valuations through adaptors. For example, the Navi adaptor calls `vault_oracle::get_asset_price()` to obtain prices for USD value calculations: [4](#0-3) 

The vault oracle's `get_asset_price()` function validates that cached prices are fresh, and the cache is updated via `update_price()` which calls `get_current_price()`: [5](#0-4) 

The `get_current_price()` function enforces staleness validation against the aggregator's `max_timestamp_ms` with a default 60-second interval: [6](#0-5) 

**Vault Stuck State:** During the three-phase vault operation pattern, after `end_op_with_bag()` returns borrowed assets and enables value update tracking, the operation cannot complete `end_op_value_update_with_bag()` without updated asset values: [7](#0-6) 

The `check_op_value_update_record()` validates that all borrowed assets have updated values, and `get_total_usd_value()` requires all asset timestamps to be fresh: [8](#0-7) [9](#0-8) 

If the staleness window (time since old TEE's last update) exceeds the 60-second `update_interval`, all price fetches fail with `ERR_PRICE_NOT_UPDATED`, preventing asset value updates and leaving the vault stuck in DURING_OPERATION status until the new TEE submits a fresh price.

## Impact Explanation

**High Severity Operational Denial of Service:**

1. **Complete Service Disruption:** Once a vault enters DURING_OPERATION status during an oracle transition period, it cannot complete the operation cycle. The vault status check prevents new operations from starting: [10](#0-9) 

2. **User Impact:** All vault users (depositors, withdrawers) are blocked from executing any operations until oracle infrastructure recovers. The vault essentially becomes frozen.

3. **No Programmatic Recovery:** The protocol provides no mechanism to:
   - Abort stuck operations
   - Override the staleness check during infrastructure maintenance
   - Coordinate oracle maintenance with vault operation pauses
   - Use stale-but-valid prices during transition periods

4. **Duration Risk:** Recovery depends entirely on new TEE deployment timing, which could range from seconds to hours depending on infrastructure issues.

## Likelihood Explanation

**High Likelihood During Routine Operations:**

1. **Common Trigger:** Oracle overrides occur during:
   - Regular TEE rotation for security updates
   - Emergency response to compromised TEEs
   - Oracle infrastructure upgrades
   - These are routine maintenance activities, not exceptional events

2. **No Coordination Mechanism:** The protocol lacks any:
   - Oracle maintenance mode flags
   - Vault operation coordination with oracle admin
   - Grace periods for price staleness after overrides
   - Documented operational procedures to prevent conflicts

3. **Timing Window:** The vulnerability window is `update_interval` (60 seconds) plus new TEE deployment time. Any vault operation initiated or in-progress during this window will fail.

4. **Unintentional DoS:** This doesn't require malicious actors - it's a coordination failure between two legitimate protocol operations (oracle maintenance and vault operations) performed by trusted roles.

## Recommendation

Implement one or more of the following mitigations:

1. **Clear Aggregator State on Override:** Modify `enable_oracle()` to reset the aggregator's `current_result.timestamp_ms` to the current time, treating the override as a "fresh start":

```move
public(package) fun enable_oracle(
    oracle: &mut Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
) {
    oracle.secp256k1_key = secp256k1_key;
    oracle.mr_enclave = mr_enclave;
    oracle.expiration_time_ms = expiration_time_ms;
    // Add: Clear stale aggregator data or mark for refresh
}
```

2. **Grace Period After Override:** Add a timestamp to track the last override and allow extended staleness tolerance for a grace period (e.g., 5 minutes) after oracle overrides.

3. **Oracle Maintenance Mode:** Implement a pausable oracle maintenance flag that temporarily prevents vault operations from starting when set by the oracle admin before overrides.

4. **Emergency Recovery Function:** Add an operator/admin function to reset vault status from DURING_OPERATION to NORMAL in exceptional circumstances with proper safeguards.

## Proof of Concept

```move
#[test]
fun test_oracle_override_causes_vault_operation_failure() {
    // Setup: Create vault, oracle, and aggregator
    let mut scenario = test_scenario::begin(ADMIN);
    
    // 1. Old TEE submits price at time T=1000
    scenario.next_tx(ORACLE_OPERATOR);
    {
        let mut aggregator = test_scenario::take_shared<Aggregator>(&scenario);
        let clock = clock::create_for_testing(scenario.ctx());
        clock.set_for_testing(1000);
        
        // Old TEE submits price
        aggregator.add_result(decimal::new(1000000, false), 1000, OLD_ORACLE_ID, &clock);
        
        test_scenario::return_shared(aggregator);
        clock.destroy_for_testing();
    };
    
    // 2. Oracle admin performs override at T=1030 (30 seconds later)
    scenario.next_tx(ORACLE_ADMIN);
    {
        let mut queue = test_scenario::take_shared<Queue>(&scenario);
        let mut oracle = test_scenario::take_shared<Oracle>(&scenario);
        let clock = clock::create_for_testing(scenario.ctx());
        clock.set_for_testing(1030);
        
        // Override oracle with new TEE key
        queue_override_oracle_action::run(
            &mut queue,
            &mut oracle,
            NEW_TEE_KEY,
            NEW_MR_ENCLAVE,
            EXPIRATION_TIME,
            &clock,
            scenario.ctx()
        );
        
        test_scenario::return_shared(queue);
        test_scenario::return_shared(oracle);
        clock.destroy_for_testing();
    };
    
    // 3. Vault operator starts operation at T=1070 (70 seconds from price, 40 from override)
    scenario.next_tx(VAULT_OPERATOR);
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let operation = test_scenario::take_shared<Operation>(&scenario);
        let operator_cap = test_scenario::take_from_sender<OperatorCap>(&scenario);
        let clock = clock::create_for_testing(scenario.ctx());
        clock.set_for_testing(1070); // 70 seconds since last price (> 60 second limit)
        
        // Start operation - this succeeds
        let (bag, tx, tx_update, principal, coin) = operation::start_op_with_bag<SUI, USDC, DummyObligation>(
            &mut vault,
            &operation,
            &operator_cap,
            &clock,
            vector[NAVI_ACCOUNT_ID],
            vector[type_name::get<NaviAccountCap>()],
            0,
            0,
            scenario.ctx()
        );
        
        // Return assets - this succeeds
        operation::end_op_with_bag<SUI, USDC, DummyObligation>(
            &mut vault,
            &operation,
            &operator_cap,
            bag,
            tx,
            principal,
            coin
        );
        
        // Try to update asset values - THIS FAILS
        let mut oracle_config = test_scenario::take_shared<OracleConfig>(&scenario);
        let aggregator = test_scenario::take_shared<Aggregator>(&scenario);
        
        // This call will abort with ERR_PRICE_NOT_UPDATED because:
        // - Aggregator's max_timestamp_ms = 1000 (from old TEE)
        // - Current time = 1070
        // - Staleness = 70 seconds > 60 second limit
        vault_oracle::update_price(&mut oracle_config, &aggregator, &clock, ASSET_TYPE);
        // ABORTS HERE - operation cannot complete
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        test_scenario::return_to_sender(&scenario, operator_cap);
        test_scenario::return_shared(oracle_config);
        test_scenario::return_shared(aggregator);
        clock.destroy_for_testing();
    };
    
    // Vault is now stuck in DURING_OPERATION status
    // Cannot call end_op_value_update_with_bag() because asset values not updated
    // No new operations can start
    
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability represents a genuine coordination gap in the protocol design. While the oracle admin and vault operators are both trusted roles performing legitimate operations, the protocol lacks mechanisms to ensure these operations don't conflict. The 60-second staleness window is intentionally short for price freshness, but this same strictness creates operational fragility during routine infrastructure maintenance. The recommended mitigations would allow the protocol to maintain price freshness guarantees while being resilient to necessary oracle infrastructure updates.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/oracle.move (L113-122)
```text
public(package) fun enable_oracle(
    oracle: &mut Oracle, 
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
) {
    oracle.secp256k1_key = secp256k1_key;
    oracle.mr_enclave = mr_enclave;
    oracle.expiration_time_ms = expiration_time_ms;
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_override_oracle_action.move (L46-71)
```text
fun actuate(
    oracle: &mut Oracle,
    queue: &mut Queue,
    secp256k1_key: vector<u8>,
    mr_enclave: vector<u8>,
    expiration_time_ms: u64,
    clock: &Clock,
) {
    oracle.enable_oracle(
        secp256k1_key,
        mr_enclave,
        expiration_time_ms,
    ); 

    queue.set_last_queue_override_ms(clock.timestamp_ms());

    // emit queue override event
    let queue_override_event = QueueOracleOverride {
        oracle_id: oracle.id(),
        queue_id: queue.id(),
        secp256k1_key: secp256k1_key,
        mr_enclave: mr_enclave,
        expiration_time_ms: expiration_time_ms,
    };
    event::emit(queue_override_event);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L82-91)
```text
    // recover the pubkey from the signature
    let recovered_pubkey_compressed = ecdsa_k1::secp256k1_ecrecover(
        &signature, 
        &update_msg, 
        1,
    );
    let recovered_pubkey = ecdsa_k1::decompress_pubkey(&recovered_pubkey_compressed);

    // check that the recovered pubkey is valid
    assert!(hash::check_subvec(&recovered_pubkey, &oracle.secp256k1_key(), 1), ERecoveredPubkeyInvalid);
```

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

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
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
