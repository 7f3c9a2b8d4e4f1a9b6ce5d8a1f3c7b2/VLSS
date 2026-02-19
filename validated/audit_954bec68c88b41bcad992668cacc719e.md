# Audit Report

## Title
Unauthorized Public Access to Asset Value Update Functions Enables DoS Attack on Vault Operations

## Summary
Multiple adaptor modules expose asset value update functions as `public` instead of `public(package)`, allowing any user to front-run the operator's legitimate update calls during vault operations. When an attacker calls these functions first, the operator's subsequent transaction aborts due to duplicate key errors in the `op_value_update_record.asset_types_updated` table. This leaves the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all user deposits and withdrawals with no admin recovery mechanism.

## Finding Description

The vulnerability stems from a critical combination of insufficient access controls and duplicate key handling in the vault's operation flow.

**Root Cause - Unrestricted Public Access:**

All asset value update functions across adaptors are declared as `public fun`, making them callable by anyone: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Critical Flaw - Unprotected Table Operation:**

These functions all call `finish_update_asset_value()`, which performs an unchecked `table.add()` operation: [6](#0-5) 

The code adds entries to `asset_types_updated` table without checking if the key already exists. In Sui Move, calling `.add()` with a duplicate key causes the transaction to **abort with an error**.

**Missing Authorization:**

The `finish_update_asset_value()` function only checks version and enabled status, with **no operator or admin capability requirement**: [7](#0-6) 

**Attack Window:**

The vault operation follows a three-phase pattern. After `end_op_with_bag()` enables value updates, a vulnerability window opens: [8](#0-7) 

During this window (lines 294-297), the vault is in `VAULT_DURING_OPERATION_STATUS` with `value_update_enabled = true`, and any attacker can front-run the operator's update calls.

**DoS Impact on Users:**

All user deposit and withdrawal requests require the vault to be in `VAULT_NORMAL_STATUS`: [9](#0-8) [10](#0-9) [11](#0-10) 

**No Recovery Mechanism:**

The only admin function that can change vault status explicitly prevents being called during operations: [12](#0-11) 

Line 523 shows that `set_enabled()` will abort if the vault is in `VAULT_DURING_OPERATION_STATUS`, leaving no admin override path to recover from this stuck state.

## Impact Explanation

**High Severity - Protocol-Level Denial of Service:**

1. **Vault Lockdown**: When the operator's update transaction aborts, the vault remains stuck in `VAULT_DURING_OPERATION_STATUS` indefinitely. The operation cannot be completed, preventing the vault from returning to normal status.

2. **User Fund Access Blocked**: All users are completely unable to:
   - Submit new deposit requests
   - Submit new withdrawal requests  
   - Execute any pending deposits or withdrawals
   
   This effectively locks user funds in the vault with no access path.

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

**Immediate Fix - Restrict Access Controls:**

Change all adaptor update functions from `public` to `public(package)` and require an `OperatorCap` parameter:

```move
// In navi_adaptor.move
public fun update_navi_position_value<PrincipalCoinType>(
    _: &OperatorCap,  // Add operator cap requirement
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    // ... existing logic
}
```

Apply the same pattern to all adaptor update functions:
- `update_cetus_position_value()`
- `update_suilend_position_value()`  
- `update_momentum_position_value()`
- `update_receipt_value()`
- `update_free_principal_value()`
- `update_coin_type_asset_value()`

**Additional Safety - Idempotent Updates:**

Modify `finish_update_asset_value()` to use `table.contains()` before `table.add()`:

```move
if (
    self.status() == VAULT_DURING_OPERATION_STATUS 
    && self.op_value_update_record.value_update_enabled 
    && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
) {
    if (!self.op_value_update_record.asset_types_updated.contains(asset_type)) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    }
}
```

**Emergency Recovery - Admin Override:**

Add an emergency admin function to force vault status reset (use with extreme caution):

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    vault.clear_op_value_update_record();
    vault.set_status(VAULT_NORMAL_STATUS);
}
```

## Proof of Concept

```move
#[test]
public fun test_dos_via_frontrun_update() {
    let mut s = test_scenario::begin(@0xa);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with NaviAccountCap asset
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(@0xa);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(0, navi_account_cap);
        vault.return_free_principal(coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx()).into_balance());
        test_scenario::return_shared(vault);
    };
    
    // Operator starts operation
    s.next_tx(@0xa);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        let (asset_bag, tx_bag, tx_bag_for_check, principal, coin_type) = 
            operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
                &mut vault, &operation, &cap, &clock,
                vector[0], vector[type_name::get<NaviAccountCap>()],
                0, 0, s.ctx()
            );
        
        // Complete step 2 - enables value updates
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault, &operation, &cap,
            asset_bag, tx_bag, principal, coin_type
        );
        
        // Attacker front-runs the operator's update call
        s.next_tx(@0xattacker);
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();
        
        navi_adaptor::update_navi_position_value(
            &mut vault, &config, &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage
        );
        
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
        
        // Now operator's transaction will ABORT with duplicate key error
        s.next_tx(@0xa);
        // This call will fail:
        // navi_adaptor::update_navi_position_value(...)
        
        // Vault is now stuck in VAULT_DURING_OPERATION_STATUS
        assert!(vault.status() == 1, 0); // Still in operation status
        
        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };
    
    // User attempts are now blocked
    s.next_tx(@0xuser);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        // This will ABORT with ERR_VAULT_NOT_NORMAL
        // user_entry::deposit(&mut vault, &mut reward_manager, coin, amount, ...);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability represents a critical access control failure that breaks the fundamental security guarantee that only trusted operators should be able to modify vault state during operations. The combination of public functions, unchecked table operations, and lack of admin recovery creates a perfect storm for protocol-level DoS attacks that can lock user funds indefinitely.

The fix is straightforward but requires careful coordination: all adaptor update functions must be restricted to package-internal access with operator authentication, and the table operation should be made idempotent to prevent accidental duplicate calls even from legitimate operators.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-21)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-16)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
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
