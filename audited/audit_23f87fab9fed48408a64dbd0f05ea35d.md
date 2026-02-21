# Audit Report

## Title
Authorization Bypass in All Adaptor Asset Value Update Functions Allows Unauthorized Share Ratio Manipulation

## Summary
All five adaptor value update functions are exposed as `public fun` without operator capability checks, allowing any external party to trigger asset value recalculations on the shared Vault object. This bypasses the intended operator-only access control model and enables unauthorized manipulation of the share ratio that determines user withdrawal amounts.

## Finding Description

The Volo vault system implements five adaptor modules for external DeFi protocol integrations. Each adaptor provides a value update function declared as `public fun` without any authorization requirements: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The root cause is that the Vault is created as a shared object, making it accessible to anyone: [6](#0-5) 

All these public adaptor functions call `finish_update_asset_value` to modify critical vault state: [7](#0-6) 

The only protection in `finish_update_asset_value` is `assert_enabled()`, which merely checks the vault is not disabled: [8](#0-7) 

This is critically insufficient. The intended authorization model requires `OperatorCap` verification, as evidenced by all legitimate operation functions: [9](#0-8) [10](#0-9) 

The adaptor functions completely bypass this security model by being callable without any capability parameter, allowing anyone to update asset values that drive the vault's share ratio calculation.

## Impact Explanation

**Direct Share Ratio Manipulation**: Updated asset values directly affect the vault's total USD value calculation through the `assets_value` table: [11](#0-10) 

This total USD value determines the share ratio used in all withdrawal calculations: [12](#0-11) 

The share ratio directly controls how much principal users receive when withdrawing: [13](#0-12) 

**Attack Scenarios:**
1. **Front-running Withdrawals**: Attacker monitors pending withdrawals and front-runs them with value updates to manipulate the share ratio, causing victims to receive less than expected
2. **Strategic Value Updates**: Within oracle slippage tolerance, attacker can repeatedly update asset values at favorable moments to gradually shift share ratios
3. **Access Control Violation**: Operators lose exclusive control over value updates, breaking the security model where only trusted operators should trigger value recalculations
4. **Griefing**: Continuous unauthorized update calls can interfere with legitimate vault operations and increase operational costs

All vault depositors are affected as their withdrawal amounts depend on the share ratio that can now be influenced by unauthorized parties.

## Likelihood Explanation

**Reachable Entry Point**: All five adaptor update functions are `public fun` and directly callable from any transaction. Since the Vault is a shared object, any external party can obtain a mutable reference to it.

**Attacker Capabilities Required:**
- Shared Vault object reference (trivially obtained in any transaction)
- OracleConfig reference (shared object)
- Clock reference (standard Sui framework object)
- Relevant pool/market references (shared DEX/lending protocol objects)
- Standard transaction fees only

**Execution Practicality**: An attacker can construct a simple programmable transaction block calling these public functions directly. No custom module deployment or complex setup is required.

**Constraint Evasion**: The only check (`assert_enabled()`) is trivially satisfied for any actively operating vault. Oracle slippage checks exist but don't prevent unauthorized updates—they only ensure pool prices are within tolerance of oracle prices. Within that tolerance window, manipulation is possible.

## Recommendation

Add operator capability checks to all adaptor value update functions. The functions should require an `OperatorCap` parameter and verify it through `assert_operator_not_freezed`:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    operation: &Operation,
    cap: &OperatorCap,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    // ... rest of function
}
```

Apply this pattern to all five adaptor update functions: `update_momentum_position_value`, `update_cetus_position_value`, `update_navi_position_value`, `update_suilend_position_value`, and `update_receipt_value`.

## Proof of Concept

```move
#[test]
public fun test_unauthorized_value_update_attack() {
    let mut scenario = test_scenario::begin(@attacker);
    let attacker = @attacker;
    
    // Setup: vault exists with some assets
    setup_vault_with_navi_position(&mut scenario);
    
    scenario.next_tx(attacker);
    {
        let mut vault = scenario.take_shared<Vault<SUI>>();
        let oracle_config = scenario.take_shared<OracleConfig>();
        let clock = scenario.take_shared<Clock>();
        let mut navi_storage = scenario.take_shared<Storage>();
        
        // ATTACK: Attacker (without any capability) can call update function
        // This should fail but currently succeeds
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &oracle_config,
            &clock,
            string::utf8(b"navi_account_0"),
            &mut navi_storage
        );
        
        // Asset value has been updated by unauthorized party
        let (new_value, _) = vault.get_asset_value(string::utf8(b"navi_account_0"));
        assert!(new_value > 0); // Unauthorized update succeeded
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
        test_scenario::return_shared(clock);
        test_scenario::return_shared(navi_storage);
    };
    
    scenario.end();
}
```

## Notes

This vulnerability represents a fundamental breach of the vault's access control model. While oracle slippage checks provide some constraint on the magnitude of manipulation, they do not prevent unauthorized access. The issue affects all five adaptor modules uniformly, indicating a systemic design flaw in the authorization model for value update operations.

The vulnerability is particularly severe because:
1. It's directly exploitable without any preconditions beyond vault being enabled
2. It affects the core share ratio calculation that determines all withdrawal amounts
3. It violates the clearly intended operator-only access pattern seen throughout the codebase
4. The attack surface is large (five independent entry points across different adaptors)

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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L1005-1023)
```text
    // Get the current share ratio
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

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

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/sources/operation.move (L94-106)
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
```

**File:** volo-vault/sources/operation.move (L209-219)
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
```
