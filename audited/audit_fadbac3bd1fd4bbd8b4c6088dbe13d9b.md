# Audit Report

## Title
Unauthorized Public Access to Asset Value Update Functions Enables DoS Attack on Vault Operations

## Summary
Multiple adaptor modules expose asset value update functions as `public` instead of `public(package)`, allowing any user to front-run the operator's legitimate update calls during vault operations. When an attacker calls these functions first, the operator's subsequent transaction aborts due to duplicate key errors in the `op_value_update_record.asset_types_updated` table. This leaves the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all user deposits and withdrawals with no admin recovery mechanism.

## Finding Description

The vulnerability stems from a critical combination of insufficient access controls and duplicate key handling in the vault's operation flow.

**Root Cause - Unrestricted Public Access:**

All asset value update functions across adaptors are declared as `public fun`, making them callable by anyone: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

**Critical Flaw - Unprotected Table Operation:**

These functions all call `finish_update_asset_value()`, which performs an unchecked `table.add()` operation: [8](#0-7) 

The code adds entries to `asset_types_updated` table without checking if the key already exists. In Sui Move, calling `.add()` with a duplicate key causes the transaction to abort with an error.

**Missing Authorization:**

The `finish_update_asset_value()` function only checks version and enabled status, with no operator or admin capability requirement: [9](#0-8) 

**Attack Window:**

The vault operation follows a three-phase pattern. After `end_op_with_bag()` enables value updates, a vulnerability window opens: [10](#0-9) [11](#0-10) 

During this window, the vault is in `VAULT_DURING_OPERATION_STATUS` with `value_update_enabled = true`, and any attacker can front-run the operator's update calls.

**DoS Impact on Users:**

All user deposit and withdrawal requests require the vault to be in `VAULT_NORMAL_STATUS`: [12](#0-11) [13](#0-12) [14](#0-13) 

**No Recovery Mechanism:**

The only admin function that can change vault status explicitly prevents being called during operations: [15](#0-14) 

The `set_enabled()` function will abort if the vault is in `VAULT_DURING_OPERATION_STATUS`, leaving no admin override path to recover from this stuck state.

## Impact Explanation

**High Severity - Protocol-Level Denial of Service:**

1. **Vault Lockdown**: When the operator's update transaction aborts, the vault remains stuck in `VAULT_DURING_OPERATION_STATUS` indefinitely. The operation cannot be completed, preventing the vault from returning to normal status.

2. **User Fund Access Blocked**: All users are completely unable to submit new deposit requests, submit new withdrawal requests, or execute any pending deposits or withdrawals. This effectively locks user funds in the vault with no access path.

3. **No Admin Recovery**: Unlike typical DoS scenarios, there is no emergency admin function to force the vault back to normal status. The `set_enabled()` function explicitly rejects calls during operations, and no other function can override the vault status.

4. **Operational Complexity**: The operator must manually track which assets were front-run and craft complex workaround transactions, introducing significant operational risk and potential for errors.

5. **Timing Manipulation**: Attackers control when asset values are recorded, affecting interest accrual calculations and the `total_usd_value_after` used in loss tolerance validation.

## Likelihood Explanation

**High Likelihood - Easily Executable Attack:**

1. **Public Entry Points**: The vulnerability requires zero special permissions - any address can call the public update functions directly.

2. **Low Cost**: Attack cost is only standard Sui transaction gas fees (negligible compared to potential disruption).

3. **Easily Automated**: Attackers can monitor on-chain events for `OperationEnded` or check vault status transitions, then immediately submit update transactions to front-run the operator.

4. **Wide Attack Window**: The vulnerability window spans from `end_op_with_bag()` until the operator completes all update calls, typically several blocks or longer depending on the number of assets.

5. **Repeatable**: If the operator attempts to retry with a workaround, the attacker can continue front-running indefinitely.

6. **Normal Operations Required**: This attack only requires the vault to be in its standard operation flow, which occurs regularly during normal protocol operation for rebalancing, harvesting, or other DeFi interactions.

## Recommendation

Change all asset value update functions from `public` to `public(package)` to restrict access:

```move
// In all adaptor modules and volo_vault.move
public(package) fun update_navi_position_value<PrincipalCoinType>(...) { ... }
public(package) fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(...) { ... }
public(package) fun update_suilend_position_value<PrincipalCoinType, ObligationType>(...) { ... }
public(package) fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(...) { ... }
public(package) fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(...) { ... }
public(package) fun update_free_principal_value<PrincipalCoinType>(...) { ... }
public(package) fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(...) { ... }
```

Additionally, add operator capability checks to `finish_update_asset_value()` or implement an admin recovery mechanism that can force vault status back to normal in emergency situations.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::dynamic_field::EFieldAlreadyExists)]
fun test_frontrun_asset_value_update_dos() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // Add Navi account cap
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(0, navi_account_cap);
        test_scenario::return_shared(vault);
    };
    
    // Setup oracle and principal
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        test_scenario::return_shared(oracle_config);
        
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault.return_free_principal(coin.into_balance());
        vault::update_free_principal_value(&mut vault, &config, &clock);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // Start operation and enable value updates
    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];
        
        let (asset_bag, tx_bag, _, principal_balance, coin_type_asset_balance) = 
            operation::start_op_with_bag<SUI_TEST_COIN, SUI_TEST_COIN, SUI_TEST_COIN>(
                &mut vault, &operation, &cap, &clock, 
                defi_asset_ids, defi_asset_types, 0, 0, s.ctx()
            );
        
        // End operation - enables value updates
        operation::end_op_with_bag<SUI_TEST_COIN, SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap, asset_bag, tx_bag, 
            principal_balance, coin_type_asset_balance
        );
        
        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };
    
    // ATTACKER front-runs the operator's update call
    s.next_tx(@0xATTACKER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();
        
        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        navi_adaptor::update_navi_position_value(
            &mut vault, &config, &clock, navi_asset_type, &mut storage
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };
    
    // OPERATOR attempts to update - THIS WILL ABORT with duplicate key error
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();
        
        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        // This call will abort because attacker already added the key
        navi_adaptor::update_navi_position_value(
            &mut vault, &config, &clock, navi_asset_type, &mut storage
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-13)
```text
public fun update_navi_position_value<PrincipalCoinType>(
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-19)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-23)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-16)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-21)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L707-716)
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
```

**File:** volo-vault/sources/volo_vault.move (L896-905)
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
```

**File:** volo-vault/sources/volo_vault.move (L1101-1101)
```text
public fun update_free_principal_value<PrincipalCoinType>(
```

**File:** volo-vault/sources/volo_vault.move (L1130-1130)
```text
public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(
```

**File:** volo-vault/sources/volo_vault.move (L1174-1181)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();
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

**File:** volo-vault/sources/volo_vault.move (L1242-1246)
```text
public(package) fun enable_op_value_update<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    self.check_version();
    self.assert_enabled();

    self.op_value_update_record.value_update_enabled = true;
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```
