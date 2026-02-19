# Audit Report

## Title
Front-Running Vulnerability in Position Value Updates Allows Griefing and Value Manipulation

## Summary
The position value update functions across all adaptors (Momentum, Navi, Suilend, Cetus) are publicly callable without access control, allowing any user to front-run the operator's value update during vault operations. This causes the operator's transaction to fail due to duplicate key insertion in the tracking table, and allows attackers to control the timing of when position values are recorded, potentially manipulating loss calculations and share pricing.

## Finding Description

The vulnerability exists in all adaptor value update mechanisms. The `update_momentum_position_value()` function is marked `public`, operates on shared objects (Vault, OracleConfig, Clock, Pool), and can be called by anyone without any capability or role checks. [1](#0-0) 

This same pattern exists across all adaptors: Navi [2](#0-1) , Suilend [3](#0-2) , and Cetus [4](#0-3)  adaptors all expose public functions without access control.

During vault operations, after `end_op_with_bag()` returns borrowed assets and enables value updates [5](#0-4) , the system requires all borrowed asset values to be updated before completing the operation. An `OperationEnded` event is emitted, making this phase observable on-chain. [6](#0-5) 

When any `update_*_position_value()` function is called during this phase, it invokes `finish_update_asset_value()` which attempts to add the asset_type to a tracking table using Move's `table::add()` function. [7](#0-6) 

**Root Cause**: Move's `table::add()` function aborts if a key already exists. When an attacker front-runs the operator's value update call, the attacker's transaction succeeds and marks the asset as updated. The operator's subsequent call attempts to add the same key again, causing the transaction to abort with a duplicate key error.

The operator cannot retry the update because the asset is already marked as updated in `asset_types_updated`. However, the operation can proceed to completion with the attacker's chosen value timestamp, as the validation check only verifies that all assets have been updated, not who updated them. [8](#0-7) 

## Impact Explanation

**Value Manipulation**: The attacker controls the exact moment when the pool state is sampled for position valuation. Within the oracle's `dex_slippage` tolerance, the attacker can choose a moment when pool prices are temporarily favorable or unfavorable. [9](#0-8) 

**Loss Calculation Bypass**: The vault uses the updated position values to calculate `total_usd_value_after` and compare it against `total_usd_value_before` to determine losses. [10](#0-9)  If the attacker inflates the position value by choosing a favorable pool state, they can hide actual losses that should be tracked. Conversely, deflating the value can trigger false loss alerts. This directly affects the loss_tolerance mechanism which gates whether operations can complete.

**Operator Griefing**: The legitimate operator's transaction fails, requiring transaction reconstruction. Since the asset is already marked as updated, the operator cannot simply retry the same transaction.

**Share Pricing Impact**: The manipulated `total_usd_value` affects share-to-USD conversions used in deposits and withdrawals, potentially allowing value extraction from other vault participants.

## Likelihood Explanation

**Attacker Capabilities**: Any user with no special permissions can execute this attack. They only need access to publicly available shared objects (Vault, OracleConfig, Clock, Pool).

**Attack Complexity**: Low. The attacker monitors the blockchain for `OperationEnded` events or observes when the vault enters `VAULT_DURING_OPERATION_STATUS` with `value_update_enabled = true` [11](#0-10) , then submits a front-running transaction with higher gas fees.

**Feasibility Conditions**: 
- The attack window opens immediately after `end_op_with_bag()` completes
- The window closes when `end_op_value_update_with_bag()` is called
- This window is observable on-chain through vault status and events
- No operator authentication protects the value update functions

**Economic Rationality**: The attack cost is minimal (standard transaction gas fees). The attacker can potentially influence vault valuations affecting all shareholders, or simply grief operators for competitive/malicious purposes.

## Recommendation

Implement access control on all position value update functions. The functions should verify that the caller holds an `OperatorCap` before allowing value updates during the operation phase:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,  // Add capability check
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    // Add operator verification
    vault::assert_operator_not_freezed(operation, cap);
    
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

Apply the same pattern to all adaptor update functions (Navi, Suilend, Cetus).

Alternatively, modify `finish_update_asset_value()` to use `table::contains()` check before `table::add()`, or use upsert logic:

```move
if (self.op_value_update_record.asset_types_updated.contains(&asset_type)) {
    // Key already exists, skip or update
} else {
    self.op_value_update_record.asset_types_updated.add(asset_type, true);
}
```

## Proof of Concept

```move
#[test]
fun test_frontrun_momentum_value_update() {
    let mut scenario = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with momentum position
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let momentum_position = create_test_momentum_position();
        vault.add_new_defi_asset(0, momentum_position);
        test_scenario::return_shared(vault);
    };
    
    // Start operation and borrow momentum position
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let operation = scenario.take_shared<Operation>();
        let cap = scenario.take_from_sender<OperatorCap>();
        
        let (defi_assets, tx_bag, principal, coin_asset) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, TestObligation>(
                &mut vault, &operation, &cap
            );
        
        // End operation - this enables value updates
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, TestObligation>(
            &mut vault, &operation, &cap, defi_assets, tx_bag, principal, coin_asset
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        test_scenario::return_to_sender(&scenario, cap);
    };
    
    // ATTACKER front-runs the operator
    scenario.next_tx(ATTACKER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        let mut pool = scenario.take_shared<MomentumPool<SUI_TEST_COIN, USDC_TEST_COIN>>();
        
        // Attacker can call public function without any capability!
        momentum_adaptor::update_momentum_position_value<SUI_TEST_COIN, SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            asset_type,
            &mut pool,
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(pool);
    };
    
    // OPERATOR tries to update - THIS WILL ABORT due to duplicate key
    scenario.next_tx(ADMIN);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        let mut pool = scenario.take_shared<MomentumPool<SUI_TEST_COIN, USDC_TEST_COIN>>();
        
        // This call will abort with duplicate key error at table::add()
        momentum_adaptor::update_momentum_position_value<SUI_TEST_COIN, SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            asset_type,
            &mut pool,
        ); // ABORTS HERE
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(pool);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

## Notes

This vulnerability affects **all four adaptors** (Momentum, Navi, Suilend, Cetus), not just Momentum. Each adaptor exposes a public `update_*_position_value()` function that suffers from the same access control issue and duplicate key problem. The vulnerability allows any user to:

1. **Grief operators** by causing their transactions to fail
2. **Manipulate timing** of position valuations within oracle slippage tolerances  
3. **Bypass loss tracking** by inflating position values at opportune moments
4. **Affect share pricing** for all vault participants

The core issue is the combination of: (1) public visibility without access control, (2) use of `table::add()` without duplicate checking, and (3) the observable attack window created by the `OperationEnded` event and vault status changes.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L54-58)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
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

**File:** volo-vault/sources/operation.move (L276-284)
```text
    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L1189-1195)
```text
    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };
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
