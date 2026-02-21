# Audit Report

## Title
Vault Operation DoS via Forced Addition of Unsupported Assets to Navi Account

## Summary
An attacker can permanently DoS vault operations by depositing unsupported coin types into the vault's Navi lending account. The position valuation logic unconditionally attempts to fetch oracle prices for all assets with non-zero balances, causing an abort when unsupported coin types are encountered, which prevents operators from completing operations and locks the vault in `VAULT_DURING_OPERATION_STATUS`.

## Finding Description

The vulnerability exists in the Navi position valuation logic. The `calculate_navi_position_value()` function iterates through all Navi reserves and for each reserve where the account has a non-zero supply or borrow balance, it unconditionally calls `vault_oracle::get_asset_price()` to fetch the price. [1](#0-0) 

The oracle's `get_asset_price()` function aborts with `ERR_AGGREGATOR_NOT_FOUND` if the requested coin type is not in the oracle configuration. [2](#0-1) 

**Attack Vector:**

The Navi protocol provides a public entry function `entry_deposit_on_behalf_of_user()` that allows anyone to deposit assets into any user's Navi account without authorization checks. [3](#0-2)  The underlying implementation deposits directly to the specified user address without requiring any capability. [4](#0-3) 

An attacker can discover the vault's Navi account owner address by:
1. Calling the public `get_defi_asset()` function to obtain a reference to the vault's Navi AccountCap [5](#0-4) 
2. Calling the public `account_owner()` function on the AccountCap to get the owner address [6](#0-5) 

**Operation Lockup Mechanism:**

When DeFi assets are borrowed during vault operations, they are automatically tracked in `asset_types_borrowed` within the `OperationValueUpdateRecord`. [7](#0-6) 

Before completing an operation, the `check_op_value_update_record()` function verifies that ALL borrowed assets have had their values updated. [8](#0-7)  This check is called in `end_op_value_update_with_bag()` before the vault status can be reset to normal. [9](#0-8) 

If the position valuation fails due to an unsupported coin type, the operator cannot mark the Navi asset as updated, preventing successful completion of the operation check.

**Admin Recovery Blocked:**

The admin's `set_vault_enabled()` function explicitly rejects operations when the vault is in `VAULT_DURING_OPERATION_STATUS`. [10](#0-9) 

## Impact Explanation

**Critical Operational Impact:**

1. **Vault Lockup**: The vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`, unable to complete the current operation or start new ones. All vault operations requiring normal status are blocked.

2. **Admin Recovery Limitations**: Standard admin recovery mechanisms cannot be used because `set_vault_enabled()` requires the vault NOT be in operation status, creating an unbreakable deadlock.

3. **Extended Downtime**: Recovery requires:
   - Identifying the attacker's deposited coin type
   - Setting up a new Switchboard oracle aggregator for that coin
   - Coordinating with oracle authorities
   - Calling `add_switchboard_aggregator()` to add the aggregator to the oracle config
   
   This process could take hours to days, during which the vault is completely non-operational.

4. **User Fund Access**: Users cannot execute deposits or withdrawals that depend on vault operations, affecting all vault participants.

## Likelihood Explanation

**High Likelihood - All Preconditions Easily Achievable:**

1. **Permissionless Entry Point**: The attack uses a public entry function with no authorization requirements.

2. **Minimal Attack Requirements**:
   - Read vault's Navi account address (two public function calls)
   - Identify a coin type supported by Navi but not in the vault's oracle config
   - Deposit a minimal amount (even 1 unit suffices)
   - Standard transaction fees only

3. **Low Cost**: The attacker only needs a small amount of any unsupported coin type and gas fees. No special privileges, insider knowledge, or significant capital required.

4. **Detection Difficulty**: The attack appears as a legitimate Navi protocol deposit and is indistinguishable from normal user activity until the vault operation fails.

5. **Persistent DoS**: Once executed, the malicious deposit remains in the Navi account, maintaining the DoS until admin intervention.

## Recommendation

Implement a whitelist-based asset filtering mechanism in `calculate_navi_position_value()`:

1. **Add Asset Whitelist**: Maintain a configurable list of supported coin types in the vault or oracle configuration.

2. **Filter During Valuation**: Skip reserves with coin types not in the whitelist:
```move
// In calculate_navi_position_value()
let coin_type = storage.get_coin_type(i - 1);

if (supply == 0 && borrow == 0) {
    i = i - 1;
    continue
};

// Add: Only value assets that have oracle aggregators
if (!vault_oracle::has_aggregator(config, coin_type)) {
    i = i - 1;
    continue  // Skip unsupported assets
};

let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

3. **Add Emergency Recovery**: Allow admin to force vault status reset with appropriate safeguards:
```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Only in extreme circumstances, log extensively
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

4. **Monitor Navi Account**: Implement off-chain monitoring to detect unexpected deposits to the vault's Navi account.

## Proof of Concept

```move
#[test]
fun test_vault_dos_via_unsupported_navi_deposit() {
    // Setup vault with oracle config for standard coins (SUI, USDC, etc.)
    
    // 1. Attacker discovers vault's Navi account address
    let navi_cap = vault.get_defi_asset<SUI, NaviAccountCap>(navi_asset_type);
    let vault_navi_account = navi_cap.account_owner();
    
    // 2. Attacker deposits unsupported coin (e.g., RANDOM_COIN supported by Navi but not in vault oracle)
    incentive_v3::entry_deposit_on_behalf_of_user<RANDOM_COIN>(
        clock, storage, pool, asset_id, 
        coin::mint_for_testing<RANDOM_COIN>(1, ctx),
        1,
        vault_navi_account,  // Vault's Navi account
        incentive_v2, incentive_v3, ctx
    );
    
    // 3. Operator starts operation
    operation::start_op_with_bag(&vault, &operation, &op_cap, clock);
    
    // 4. Operator borrows and returns Navi asset
    // ... borrow/return logic ...
    
    // 5. Operator tries to update Navi position - FAILS
    // This aborts with ERR_AGGREGATOR_NOT_FOUND when it encounters RANDOM_COIN
    navi_adaptor::update_navi_position_value(&mut vault, &oracle_config, clock, navi_asset_type, &mut storage);
    
    // 6. Operator cannot complete operation - FAILS
    // This aborts with ERR_USD_VALUE_NOT_UPDATED because Navi update failed
    operation::end_op_value_update_with_bag(&mut vault, &operation, &op_cap, clock, tx_bag);
    
    // 7. Admin cannot reset vault status - FAILS
    // This aborts with ERR_VAULT_DURING_OPERATION
    vault_manage::set_vault_enabled(&admin_cap, &mut vault, false);
    
    // VAULT IS PERMANENTLY LOCKED
}
```

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L43-63)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L815-831)
```text
    public entry fun entry_deposit_on_behalf_of_user<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        user: address,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_on_behalf_of_user<CoinType>(clock, storage, pool, asset, user, deposit_coin, amount, ctx);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L555-565)
```text
    public(friend) fun deposit_on_behalf_of_user<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, asset: u8, user: address, deposit_coin: Coin<CoinType>, value: u64, ctx: &mut TxContext) {
        let deposit_balance = utils::split_coin_to_balance(deposit_coin, value, ctx);
        base_deposit(clock, storage, pool, asset, user, deposit_balance);

        emit(DepositOnBehalfOfEvent{
            reserve: asset,
            sender: tx_context::sender(ctx),
            user: user,
            amount: value,
        })
    }
```

**File:** volo-vault/sources/volo_vault.move (L142-146)
```text
public struct OperationValueUpdateRecord has store {
    asset_types_borrowed: vector<String>,
    value_update_enabled: bool,
    asset_types_updated: Table<String, bool>,
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

**File:** volo-vault/sources/volo_vault.move (L1451-1456)
```text
public fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType {
    self.assets.borrow<String, AssetType>(asset_type)
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L34-36)
```text
    public fun account_owner(cap: &AccountCap): address {
        cap.owner
    }
```

**File:** volo-vault/sources/operation.move (L354-376)
```text
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
```
