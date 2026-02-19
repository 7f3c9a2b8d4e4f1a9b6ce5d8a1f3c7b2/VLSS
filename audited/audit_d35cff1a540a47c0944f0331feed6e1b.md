# Audit Report

## Title
Vault Operation DoS via Forced Addition of Unsupported Assets to Navi Account

## Summary
An attacker can permanently DoS vault operations by depositing unsupported coin types into the vault's Navi lending account. The position valuation logic unconditionally attempts to fetch oracle prices for all assets with non-zero balances, causing an abort when unsupported coin types are encountered, which prevents operators from completing operations and locks the vault in `VAULT_DURING_OPERATION_STATUS`.

## Finding Description

The vulnerability exists in the Navi position valuation logic. The `calculate_navi_position_value()` function iterates through all Navi reserves and for each reserve where the account has a non-zero supply or borrow balance, it unconditionally calls `vault_oracle::get_asset_price()` to fetch the price. [1](#0-0) 

The oracle's `get_asset_price()` function aborts with `ERR_AGGREGATOR_NOT_FOUND` if the requested coin type is not in the oracle configuration. [2](#0-1) 

**Attack Vector:**

The Navi protocol provides a public entry function `entry_deposit_on_behalf_of_user()` that allows anyone to deposit assets into any user's Navi account without authorization checks. [3](#0-2) 

An attacker can discover the vault's Navi account owner address by:
1. Calling the public `get_defi_asset()` function to obtain a reference to the vault's Navi AccountCap [4](#0-3) 
2. Calling the public `account_owner()` function on the AccountCap to get the owner address [5](#0-4) 

**Operation Lockup Mechanism:**

When DeFi assets are borrowed during vault operations, they are automatically tracked in `asset_types_borrowed`. [6](#0-5) 

Before completing an operation, the `check_op_value_update_record()` function verifies that ALL borrowed assets have had their values updated. [7](#0-6)  This check is called in `end_op_value_update_with_bag()` before the vault status can be reset to normal. [8](#0-7) 

If the position valuation fails due to an unsupported coin type, the operator cannot mark the Navi asset as updated, preventing successful completion of the operation check.

**Admin Recovery Blocked:**

The admin's `set_vault_enabled()` function explicitly rejects operations when the vault is in `VAULT_DURING_OPERATION_STATUS`. [9](#0-8) 

## Impact Explanation

**Critical Operational Impact:**

1. **Vault Lockup**: The vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`, unable to complete the current operation or start new ones. All vault operations requiring normal status are blocked.

2. **Admin Recovery Limitations**: Standard admin recovery mechanisms cannot be used because `set_vault_enabled()` requires the vault NOT be in operation status, creating a deadlock.

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

4. **Detection Difficulty**: The attack appears as a legitimate Navi protocol deposit and is indistinguishable from normal user activity.

5. **Persistent DoS**: Once executed, the malicious deposit remains in the Navi account, maintaining the DoS until admin intervention.

## Recommendation

Implement defensive handling for unsupported assets in `calculate_navi_position_value()`:

```move
// Add try-catch or check before calling get_asset_price
if (supply == 0 && borrow == 0) {
    i = i - 1;
    continue
};

// Check if price is available before attempting to fetch
if (!vault_oracle::has_price_for_asset(config, coin_type)) {
    // Skip this asset or use a default safe handling
    i = i - 1;
    continue
};

let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

Alternatively, add a function to allow operators to withdraw unexpected deposits from the Navi account before valuation, or implement a whitelist of expected coin types for the vault's Navi position.

## Proof of Concept

```move
#[test]
fun test_dos_via_unsupported_navi_deposit() {
    // Setup: Create vault with Navi account, configure oracle with limited coin types
    let mut scenario = test_scenario::begin(@admin);
    
    // 1. Attacker reads vault's Navi AccountCap using get_defi_asset()
    // 2. Attacker calls account_owner() to get the owner address
    // 3. Attacker identifies COIN_X supported by Navi but not in vault oracle
    // 4. Attacker calls entry_deposit_on_behalf_of_user() with vault's Navi owner address
    test_scenario::next_tx(&mut scenario, @attacker);
    {
        // Deposit unsupported COIN_X to vault's Navi account
        navi::entry_deposit_on_behalf_of_user<COIN_X>(
            clock,
            navi_storage,
            navi_pool,
            asset_id,
            coin_x,
            amount,
            vault_navi_owner_address, // Victim's Navi account
            incentive_v2,
            incentive_v3,
            test_scenario::ctx(&mut scenario)
        );
    };
    
    // 5. Operator attempts normal vault operation
    test_scenario::next_tx(&mut scenario, @operator);
    {
        // Start operation, borrow Navi account
        let (bag, tx, tx_check, _, _) = operation::start_op_with_bag(...);
        // ... perform operation ...
        operation::end_op_with_bag(...); // Returns assets successfully
        
        // 6. Operator tries to update Navi position value
        // This will ABORT because COIN_X is not in oracle config
        navi_adaptor::update_navi_position_value(...); // ABORTS HERE
        
        // 7. Cannot complete: end_op_value_update_with_bag() will fail
        // because check_op_value_update_record() requires Navi asset to be updated
        // Vault is now STUCK in VAULT_DURING_OPERATION_STATUS
    };
    
    // 8. Admin cannot recover using set_vault_enabled()
    test_scenario::next_tx(&mut scenario, @admin);
    {
        // This will ABORT due to status check
        vault_manage::set_vault_enabled(admin_cap, vault, true); // ABORTS
    };
    
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L58-63)
```text
        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/oracle.move (L126-129)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
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

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```
