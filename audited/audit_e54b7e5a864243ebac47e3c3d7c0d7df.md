### Title
Vault Permanently Locked in DURING_OPERATION Status When end_op_value_update_with_bag Fails After end_op_with_bag

### Summary
The vault operation flow has a critical failure point where `end_op_with_bag()` successfully enables the op_value_update flag but leaves the vault in DURING_OPERATION status. If the subsequent `end_op_value_update_with_bag()` call fails (due to loss tolerance exceeded, stale prices, or share mismatch), the vault becomes permanently stuck with no recovery mechanism, freezing all user operations indefinitely.

### Finding Description

The vault operation lifecycle consists of three phases:

1. **Phase 1**: `start_op_with_bag()` transitions vault to DURING_OPERATION status [1](#0-0) 

2. **Phase 2**: `end_op_with_bag()` returns borrowed assets and enables the op_value_update flag, but critically **does not reset vault status** [2](#0-1) 

The flag is enabled at line 294: [3](#0-2) 

3. **Phase 3**: `end_op_value_update_with_bag()` validates values and **only then** resets status to NORMAL [4](#0-3) 

**Root Cause**: Phase 3 contains multiple checks that can fail:

- **Loss tolerance check**: If losses exceed the configured tolerance, `update_tolerance()` aborts with ERR_EXCEED_LOSS_LIMIT [5](#0-4) 

- **Value update validation**: `check_op_value_update_record()` requires all borrowed assets have updated values [6](#0-5) 

- **Staleness check**: `get_total_usd_value()` enforces MAX_UPDATE_INTERVAL (set to 0ms), causing strict timing requirements [7](#0-6) 

- **Share invariant check**: Total shares must remain unchanged during operation [8](#0-7) 

**Why Recovery Fails**: The admin's `set_enabled()` function explicitly prevents status changes when vault is in DURING_OPERATION: [9](#0-8) 

The only other function that can change status is `set_status()`, which is `public(package)` and not exposed through any admin function: [10](#0-9) 

No emergency recovery mechanism exists in the management module: [11](#0-10) 

### Impact Explanation

**Operational DoS (High Severity)**:
- All user deposit requests blocked - `request_deposit()` requires `assert_normal()` [12](#0-11) 

- All user withdrawal requests blocked - `request_withdraw()` requires `assert_normal()` [13](#0-12) 

- Vault becomes completely non-functional for all users
- Funds remain in vault but cannot be accessed through normal flows
- Only recovery is contract upgrade or emergency migration, both requiring significant time and coordination
- **Quantified Impact**: 100% of vault operations frozen, affecting all vault depositors

### Likelihood Explanation

**Medium-High Likelihood**:

1. **Realistic Failure Scenario**: Loss tolerance limits are designed to protect against excessive losses, meaning they are expected to trigger during adverse market conditions or strategy failures. This is not an edge case but a normal protection mechanism.

2. **Operator Has No Control**: Once `end_op_with_bag()` is called successfully, the operator cannot prevent the loss tolerance check in Phase 3. If market movements cause losses to exceed tolerance between Phase 2 and Phase 3, the vault locks regardless of operator actions.

3. **Timing Sensitivity**: MAX_UPDATE_INTERVAL is set to 0, making the value update checks extremely strict [14](#0-13) 

4. **No Transaction Atomicity Guarantee**: The three-phase operation requires separate transactions. Network delays, gas issues, or oracle availability can cause Phase 3 to fail even with successful Phase 2.

5. **Economic Rationality**: This is not an attack but a failure mode in legitimate operations during market volatility.

### Recommendation

**Immediate Fix**: Add emergency recovery function that allows admin to reset vault status when operation fails:

```move
// In vault_manage.move
public fun emergency_reset_operation_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Only allow if operation was started but didn't complete properly
    vault.assert_during_operation();
    
    // Clear operation state
    vault.clear_op_value_update_record();
    vault.set_status(VAULT_NORMAL_STATUS);
    
    // Emit event for transparency
    // ...
}
```

**Better Fix**: Make the operation atomic or add automatic rollback:
- Combine end_op_with_bag and end_op_value_update_with_bag into a single transaction
- OR add try-catch logic that reverts status to NORMAL if Phase 3 fails
- OR implement a timeout mechanism that auto-recovers after N epochs

**Test Coverage**: Add regression test for this specific scenario:
```move
#[test, expected_failure]
public fun test_vault_stuck_when_loss_exceeds_tolerance_after_end_op()
```

### Proof of Concept

**Initial State**:
- Vault in NORMAL status with $1M USD total value
- Loss tolerance: 10 bps (0.1%)
- Operator has valid OperatorCap

**Exploitation Steps**:

1. Operator calls `start_op_with_bag()` → Vault status = DURING_OPERATION
2. Operator borrows assets and executes strategy
3. Market moves adversely, causing $2000 loss (0.2%, exceeds 0.1% tolerance)
4. Operator calls `end_op_with_bag()` → **SUCCESS**
   - All assets returned to vault
   - op_value_update flag enabled
   - Vault status still DURING_OPERATION
5. Operator updates all asset values via oracle
6. Operator calls `end_op_value_update_with_bag()` → **ABORTS** at line 635 with ERR_EXCEED_LOSS_LIMIT [15](#0-14) 

**Result**: 
- Vault permanently stuck in DURING_OPERATION
- All user operations (deposit/withdraw requests) permanently blocked
- Admin cannot recover via `set_enabled()` due to line 523 check [16](#0-15) 

**Success Condition**: Vault remains in DURING_OPERATION indefinitely with no recovery path except contract upgrade.

### Citations

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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L366-366)
```text
    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);
```

**File:** volo-vault/sources/operation.move (L375-376)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
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

**File:** volo-vault/sources/volo_vault.move (L533-541)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;

    emit(VaultStatusChanged {
        vault_id: self.vault_id(),
        status: status,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
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
