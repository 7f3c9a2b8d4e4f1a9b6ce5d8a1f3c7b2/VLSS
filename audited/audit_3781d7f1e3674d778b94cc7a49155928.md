### Title
No Recovery Mechanism for AccountCap with Active Positions - Permanent Fund Lock Risk

### Summary
The Volo vault's only mechanism for extracting DeFi assets (`remove_defi_asset_support`) contains an overly restrictive assertion that prevents extraction of NaviAccountCap once it has been used for operations and valued. This creates a permanent fund lock scenario where all Navi lending positions controlled by the AccountCap become irrecoverable if the vault encounters any operational issues, contract bugs, or requires emergency asset migration.

### Finding Description

The AccountCap object controls access to all positions in the Navi lending protocol. [1](#0-0) 

In the Volo vault system, AccountCap is stored as a DeFi asset in the vault's `assets: Bag` field. [2](#0-1) 

During normal operations, the vault uses AccountCap through borrow/return operations and updates its USD value via adaptors. [3](#0-2) 

The value update mechanism records non-zero values in both `assets_value` and `assets_value_updated` tables. [4](#0-3) 

**Root Cause:** The only extraction mechanism for DeFi assets is `remove_defi_asset_support`, which contains a critical restriction: [5](#0-4) 

The assertion at line 1405 prevents extraction of any asset with non-zero value:
```
assert!(asset_value == 0 || asset_value_updated == 0, ERR_ASSET_TYPE_NOT_FOUND);
```

This means once an AccountCap has been used for Navi operations and its value recorded, it can NEVER be extracted from the vault, even in emergency situations.

**Why Protections Fail:**
1. The lending protocol provides NO alternative recovery mechanism in the account module [6](#0-5) 

2. The `delete_account` function in the lending module is disabled (aborts with error 0) [7](#0-6) 

3. There are no admin override functions to reset asset values or extract assets with non-zero value [8](#0-7) 

4. The vault must be in NORMAL status to call `remove_defi_asset_support`, preventing extraction if vault is stuck in DURING_OPERATION status [9](#0-8) 

### Impact Explanation

**Direct Fund Impact:** All Navi lending positions (deposits, collateral, borrows) controlled by the AccountCap become permanently inaccessible. This includes:
- All deposited collateral in Navi protocol
- All borrowed funds that cannot be repaid
- All accrued interest that cannot be claimed
- Potential liquidation of positions if they become unhealthy

**Who Is Affected:**
- All vault depositors whose funds are allocated to Navi positions
- The protocol itself loses control over significant TVL
- Cannot migrate positions to new vaults or recover from bugs

**Severity Justification - HIGH:**
1. **Permanent loss of custody:** No time-limited or reversible - positions are permanently locked
2. **No admin override:** Even AdminCap cannot bypass the restriction
3. **Realistic triggering conditions:** Contract bugs, upgrade issues, or operational errors are not theoretical
4. **Systemic risk:** Single vault issue locks all users' Navi positions

The Navi adaptor integration is a core vault feature, making this a critical operational risk that violates the stated invariant: "All borrowed DeFi assets returned; no leakage of account caps/positions." [10](#0-9) 

### Likelihood Explanation

**Realistic Scenarios:**

1. **Vault State Corruption:** A bug in vault operations leaves vault stuck in DURING_OPERATION status. The `remove_defi_asset_support` requires NORMAL status, preventing extraction even though AccountCap is present in the vault.

2. **Emergency Migration Need:** Vault has been operating normally but requires emergency migration due to discovered critical bug. Cannot extract AccountCap with active positions to transfer to new vault.

3. **Contract Upgrade Issues:** Post-upgrade bug corrupts vault state or breaks operation flow. No emergency extraction path for AccountCap.

**Feasibility:**
- **Preconditions:** Only requires normal usage of Navi integration (standard vault operation)
- **No special privileges needed:** The design flaw affects normal operational flow
- **Practical execution:** Smart contract bugs, state corruption, and upgrade issues are well-documented risks in DeFi

**Probability Assessment:**
While not exploitable by malicious actors, the probability of encountering operational issues during the vault's lifetime is non-trivial. Complex DeFi protocols regularly face:
- Contract upgrade bugs
- State management issues  
- Multi-step operation flow failures
- Integration conflicts

The lack of ANY recovery mechanism for such scenarios represents an unacceptable systemic risk.

### Recommendation

**Immediate Fix:**

1. Add an emergency extraction function with AdminCap authorization that bypasses the value check:

```move
public fun emergency_extract_defi_asset<PrincipalCoinType, AssetType: key + store>(
    _: &AdminCap,
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    // Note: No assert_normal() check - allows extraction even in bad state
    
    let asset_type = vault_utils::parse_key<AssetType>(idx);
    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    
    self.asset_types.remove(index);
    self.assets_value.remove(asset_type);
    self.assets_value_updated.remove(asset_type);
    
    emit(EmergencyDefiAssetExtracted { vault_id: self.vault_id(), asset_type });
    
    self.assets.remove<String, AssetType>(asset_type)
}
```

2. Alternatively, modify `remove_defi_asset_support` to accept AdminCap as optional parameter to bypass checks:

```move
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    admin_override: Option<&AdminCap>,
): AssetType
```

**Additional Recommendations:**

1. Add comprehensive tests for emergency extraction scenarios
2. Document emergency procedures in vault operational guidelines  
3. Consider implementing a circuit breaker pattern for critical vault states
4. Add monitoring/alerts for vault state anomalies

### Proof of Concept

**Setup:**
1. Vault has NaviAccountCap stored as DeFi asset with idx=1
2. Operator performs normal Navi operations: deposit, borrow
3. `update_navi_position_value` is called, setting `assets_value[navi_asset_type] = 1000000` and `assets_value_updated[navi_asset_type] = timestamp`

**Scenario 1 - Vault Stuck in Operation State:**
```
Step 1: start_op_with_bag() borrows AccountCap, vault status = VAULT_DURING_OPERATION_STATUS
Step 2: Operation encounters bug, cannot complete end_op_with_bag()
Step 3: Operator attempts: remove_defi_asset_support<NaviAccountCap>(vault, 1)
Result: FAIL - assert_normal() fails at line 1395 (vault not in NORMAL status)
```

**Scenario 2 - Emergency Migration:**
```
Step 1: Vault operating normally with active Navi positions
Step 2: Critical bug discovered, need to migrate AccountCap to new vault  
Step 3: Operator attempts: remove_defi_asset_support<NaviAccountCap>(vault, 1)
Result: FAIL - assertion at line 1405 fails (asset_value=1000000, asset_value_updated=timestamp, both non-zero)
```

**Expected Behavior:** Emergency extraction should be possible with proper authorization to recover positions

**Actual Behavior:** No recovery mechanism exists - all Navi positions permanently locked

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/account.move (L1-37)
```text
module lending_core::account {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use lending_core::error::{Self};

    friend lending_core::lending;

    struct AccountCap has key, store {
        id: UID,
        owner: address
    }

    public(friend) fun create_account_cap(ctx: &mut TxContext): AccountCap {
        let id = object::new(ctx);
        let owner = object::uid_to_address(&id);
        AccountCap { id, owner}
    }

    public(friend) fun create_child_account_cap(parent_account_cap: &AccountCap, ctx: &mut TxContext): AccountCap {
        let owner = parent_account_cap.owner;
        assert!(object::uid_to_address(&parent_account_cap.id) == owner, error::required_parent_account_cap());

        AccountCap {
            id: object::new(ctx),
            owner: owner
        }
    }

    public(friend) fun delete_account_cap(cap: AccountCap) {
        let AccountCap { id, owner: _} = cap;
        object::delete(id)
    }

    public fun account_owner(cap: &AccountCap): address {
        cap.owner
    }
}
```

**File:** volo-vault/sources/volo_vault.move (L96-130)
```text
public struct Vault<phantom T> has key, store {
    id: UID,
    version: u64,
    // ---- Pool Info ---- //
    status: u8,
    total_shares: u256,
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
    // ---- Fee ---- //
    deposit_withdraw_fee_collected: Balance<T>,
    // ---- Principal Info ---- //
    free_principal: Balance<T>,
    claimable_principal: Balance<T>,
    // ---- Config ---- //
    deposit_fee_rate: u64,
    withdraw_fee_rate: u64,
    // ---- Assets ---- //
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
    // ---- Loss Tolerance ---- //
    cur_epoch: u64,
    cur_epoch_loss_base_usd_value: u256,
    cur_epoch_loss: u256,
    loss_tolerance: u256,
    // ---- Request Buffer ---- //
    request_buffer: RequestBuffer<T>,
    // ---- Reward Info ---- //
    reward_manager: address,
    // ---- Receipt Info ---- //
    receipts: Table<address, VaultReceiptInfo>,
    // ---- Operation Value Update Record ---- //
    op_value_update_record: OperationValueUpdateRecord,
}
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

**File:** volo-vault/sources/volo_vault.move (L1390-1413)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();

    let asset_type = vault_utils::parse_key<AssetType>(idx);

    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    self.asset_types.remove(index);

    let asset_value = self.assets_value[asset_type];
    let asset_value_updated = self.assets_value_updated[asset_type];
    assert!(asset_value == 0 || asset_value_updated == 0, ERR_ASSET_TYPE_NOT_FOUND);

    emit(DefiAssetRemoved {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L479-481)
```text
    public fun delete_account(_cap: AccountCap) {
        abort 0
    }
```

**File:** volo-vault/sources/manage.move (L1-176)
```text
module volo_vault::vault_manage;

use std::ascii::String;
use sui::balance::Balance;
use sui::clock::Clock;
use switchboard::aggregator::Aggregator;
use volo_vault::reward_manager::{Self, RewardManager};
use volo_vault::vault::{Self, Operation, Vault, AdminCap, OperatorCap};
use volo_vault::vault_oracle::OracleConfig;

// ------------------------ Vault Status ------------------------ //

public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}

#[allow(unused_variable)]
public fun upgrade_vault<PrincipalCoinType>(_: &AdminCap, vault: &mut Vault<PrincipalCoinType>) {
    vault.upgrade_vault();
}

public fun upgrade_reward_manager<PrincipalCoinType>(
    _: &AdminCap,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
) {
    reward_manager.upgrade_reward_manager();
}

public fun upgrade_oracle_config(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
) {
    oracle_config.upgrade_oracle_config();
}

// ------------------------ Setters ------------------------ //

public fun set_deposit_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    deposit_fee: u64,
) {
    vault.set_deposit_fee(deposit_fee);
}

public fun set_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    withdraw_fee: u64,
) {
    vault.set_withdraw_fee(withdraw_fee);
}

public fun set_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    loss_tolerance: u256,
) {
    vault.set_loss_tolerance(loss_tolerance);
}

public fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_cancel_request(locking_time);
}

public fun set_locking_time_for_withdraw<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_withdraw(locking_time);
}

// ------------------------ Operator ------------------------ //

public fun create_operator_cap(_: &AdminCap, ctx: &mut TxContext): OperatorCap {
    vault::create_operator_cap(ctx)
}

public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
}

// ------------------------ Oracle ------------------------ //

public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}

public fun remove_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    asset_type: String,
) {
    oracle_config.remove_switchboard_aggregator(asset_type);
}

public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}

public fun set_update_interval(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    update_interval: u64,
) {
    oracle_config.set_update_interval(update_interval);
}

public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}

// ------------------------ Fees ------------------------ //

public fun retrieve_deposit_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
}

public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    _: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
}

// ------------------------ Reward Manager ------------------------ //

public fun create_reward_manager<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &mut TxContext,
) {
    reward_manager::create_reward_manager<PrincipalCoinType>(vault, ctx);
}

// ------------------------ Reset Loss Tolerance ------------------------ //

public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.try_reset_tolerance(true, ctx);
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
