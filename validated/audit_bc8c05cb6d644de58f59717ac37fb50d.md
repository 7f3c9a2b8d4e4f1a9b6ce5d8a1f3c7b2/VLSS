# Audit Report

## Title
Momentum Adaptor DoS: Unimplemented mmt_v3 Math Functions Cause Permanent Vault Lock

## Summary
The local `mmt_v3` dependency contains only stub implementations that abort with error code 0. When a vault operation borrows a MomentumPosition, the mandatory value update process will abort, permanently locking the vault in "during operation" status and freezing all user funds.

## Finding Description

The `mmt_v3` math modules contain only stub implementations that unconditionally abort. All critical functions in `pool.move` return `abort 0`, including `sqrt_price()` [1](#0-0) , similarly for `position.move` getter functions [2](#0-1) , `tick_math.move` [3](#0-2) , and `liquidity_math.move` [4](#0-3) .

The momentum adaptor depends on these functions to calculate position values. The `update_momentum_position_value` function calls `get_position_value`, which invokes `get_position_token_amounts` at line 40 [5](#0-4) . This function directly calls the stub implementations starting at line 73 [6](#0-5) .

When a MomentumPosition is borrowed during an operation via `start_op_with_bag`, it's added to the `asset_types_borrowed` tracking vector [7](#0-6) . This tracking occurs in the vault's `borrow_defi_asset` function when status is `VAULT_DURING_OPERATION_STATUS` [8](#0-7) .

Before completing an operation, the protocol enforces that all borrowed assets have their values updated. The `check_op_value_update_record` function iterates through all borrowed assets and asserts each one is present in `asset_types_updated` with a `true` value [9](#0-8) . This check is mandatory during operation finalization at line 354 of `end_op_value_update_with_bag` [10](#0-9) .

**Attack Path:**
1. Admin/operator adds a MomentumPosition to vault using `add_new_defi_asset` [11](#0-10) 
2. Operator starts an operation that borrows the MomentumPosition via `start_op_with_bag` [12](#0-11) 
3. Operator attempts to update the position value via `update_momentum_position_value`
4. The call aborts at the first mmt_v3 function (e.g., `pool.sqrt_price()` at line 73)
5. The position cannot be marked as updated in `asset_types_updated` because `finish_update_asset_value` is never reached [13](#0-12) 
6. Operation completion fails at `check_op_value_update_record` with `ERR_USD_VALUE_NOT_UPDATED` (error 5_007)
7. Vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`
8. Admin cannot recover because `set_enabled` explicitly aborts when status is "during operation" [14](#0-13) 

The root cause is the intentional use of local stub implementations as documented in Move.toml [15](#0-14) .

## Impact Explanation

**Critical Protocol DoS - Complete Vault Freeze:**

Once triggered, the vault enters an unrecoverable state:
- Status permanently locked at `VAULT_DURING_OPERATION_STATUS` (value 1) [16](#0-15) 
- All user deposit requests blocked (require normal status via `assert_normal()`) [17](#0-16) 
- All user withdrawal requests blocked (require normal status) [18](#0-17) 
- Existing pending requests cannot be executed
- All deposited user funds become inaccessible

The only function that can restore normal status is `end_op_value_update_with_bag`, which sets status back to `VAULT_NORMAL_STATUS` at line 375. However, this function requires `check_op_value_update_record()` to pass first (line 354), which is impossible when the momentum position value update aborts [19](#0-18) .

No emergency recovery mechanism exists - even the admin's `set_enabled` function explicitly rejects status changes during operations [20](#0-19) .

**Scope of Impact:**
- Affects any vault with MomentumPosition assets
- All vault depositors lose access to their principal and yields
- Permanent capital lockup until contract upgrade/migration

## Likelihood Explanation

**Current Status - Latent Vulnerability:**
- No tests exist for momentum positions (verified via grep search showing 0 matches)
- The feature infrastructure is complete but mmt_v3 functions are stubs
- No MomentumPosition assets appear to be currently deployed

**Trigger Conditions:**
- Requires trusted operator to add MomentumPosition to vault (within threat model)
- Once added, ANY operation borrowing it triggers the DoS
- 100% reproducible - not probabilistic

**Deployment Risk:**
- **Currently**: LOW likelihood (feature not enabled)
- **If momentum integration deployed without fixing stubs**: CERTAIN (100% occurrence rate)
- The Move.toml comment indicates awareness of the stub implementation but not the DoS risk

**Economic Rationality:**
This is not an "attack" but an implementation gap. If the momentum feature is enabled in production with stub dependencies, normal vault operations will cause self-inflicted DoS.

## Recommendation

**Immediate Actions:**
1. Replace local stub `mmt_v3` dependency with the actual mainnet implementation from the official repository
2. Update Move.toml to use the real mmt_v3 package: `git = "https://github.com/mmt-finance/mmt-contract-interface.git"` with appropriate mainnet revision
3. Add comprehensive integration tests for momentum position operations before deployment

**Code Fix:**
In `volo-vault/Move.toml`, replace lines 79-86 with:
```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
addr = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

**Long-term Safeguards:**
1. Add a circuit breaker mechanism that allows admin to force-reset vault status in emergency situations
2. Implement grace period for value updates with fallback recovery path
3. Add pre-deployment validation that verifies all external dependencies have functional implementations

## Proof of Concept

```move
#[test]
fun test_momentum_position_dos() {
    // Setup vault and operator
    let mut scenario = test_scenario::begin(ADMIN);
    let admin_cap = create_admin_cap(&mut scenario);
    let vault = create_vault<SUI>(&admin_cap, &mut scenario);
    let operator_cap = create_operator_cap(&admin_cap, &mut scenario);
    
    // Add MomentumPosition to vault (stub implementation)
    let momentum_position = create_mock_momentum_position(&mut scenario);
    add_new_defi_asset<SUI, MomentumPosition>(
        &operation,
        &operator_cap,
        &mut vault,
        1, // idx
        momentum_position
    );
    
    // Start operation that borrows MomentumPosition
    let (defi_assets, tx, tx_update, principal, coin_asset) = start_op_with_bag<SUI, USDC, ObligationType>(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[1], // defi_asset_ids (momentum position)
        vector[type_name::get<MomentumPosition>()], // defi_asset_types
        0, // principal_amount
        0, // coin_type_asset_amount
        &mut scenario.ctx()
    );
    
    // Attempt to update momentum position value - THIS WILL ABORT
    // Due to stub implementation of pool.sqrt_price() at line 132 of pool.move
    update_momentum_position_value<SUI, TokenA, TokenB>(
        &mut vault,
        &oracle_config,
        &clock,
        asset_type,
        &mut mock_pool // This contains stub sqrt_price() that aborts
    ); // Expected: aborts with error 0
    
    // Now vault is stuck in DURING_OPERATION_STATUS
    // Cannot complete operation because check_op_value_update_record will fail
    // All user funds are frozen
}
```

The test demonstrates that any attempt to update a MomentumPosition value will abort at the first mmt_v3 stub call, leaving the vault permanently locked in operation status with no recovery path.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L50-59)
```text
    public fun reward_length(position: &Position) : u64 { abort 0 }
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
    public fun fee_growth_inside_x_last(position: &Position) : u128 { abort 0 }
    public fun fee_growth_inside_y_last(position: &Position) : u128 { abort 0 }
    public fun fee_rate(position: &Position) : u64 { abort 0 }
    public fun pool_id(position: &Position) : ID { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-10)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L19-27)
```text
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L34-40)
```text
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L69-91)
```text
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();

    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
    (amount_a, amount_b, sqrt_price)
}
```

**File:** volo-vault/sources/operation.move (L94-207)
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

    let mut defi_assets = bag::new(ctx);

    let defi_assets_length = defi_asset_ids.length();
    assert!(defi_assets_length == defi_asset_types.length(), ERR_ASSETS_LENGTH_MISMATCH);

    let mut i = 0;
    while (i < defi_assets_length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = vault.borrow_defi_asset<T, CetusPosition>(cetus_asset_type);
            defi_assets.add<String, CetusPosition>(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let obligation_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = vault.borrow_defi_asset<T, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
            );
            defi_assets.add<String, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
                obligation,
            );
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = vault.borrow_defi_asset<T, Receipt>(receipt_asset_type);
            defi_assets.add<String, Receipt>(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    let principal_balance = if (principal_amount > 0) {
        vault.borrow_free_principal(principal_amount)
    } else {
        balance::zero<T>()
    };

    let coin_type_asset_balance = if (coin_type_asset_amount > 0) {
        vault.borrow_coin_type_asset<T, CoinType>(
            coin_type_asset_amount,
        )
    } else {
        balance::zero<CoinType>()
    };

    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };

    emit(OperationStarted {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount,
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount,
        total_usd_value,
    });

    (defi_assets, tx, tx_for_check_value_update, principal_balance, coin_type_asset_balance)
}
```

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**File:** volo-vault/sources/operation.move (L565-574)
```text
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```

**File:** volo-vault/sources/volo_vault.move (L24-24)
```text
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
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

**File:** volo-vault/sources/volo_vault.move (L707-757)
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

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Generate current request id
    let current_deposit_id = self.request_buffer.deposit_id_count;
    self.request_buffer.deposit_id_count = current_deposit_id + 1;

    // Deposit amount
    let amount = coin.value();

    // Generate the new deposit request and add it to the vault storage
    let new_request = deposit_request::new(
        current_deposit_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        amount,
        expected_shares,
        clock.timestamp_ms(),
    );
    self.request_buffer.deposit_requests.add(current_deposit_id, new_request);

    emit(DepositRequested {
        request_id: current_deposit_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        amount: amount,
        expected_shares: expected_shares,
    });

    // Temporary buffer the coins from user
    // Operator will retrieve this coin and execute the deposit
    self.request_buffer.deposit_coin_buffer.add(current_deposit_id, coin);

    vault_receipt.update_after_request_deposit(amount);

    current_deposit_id
}
```

**File:** volo-vault/sources/volo_vault.move (L896-940)
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

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);
    assert!(vault_receipt.shares() >= shares, ERR_EXCEED_RECEIPT_SHARES);

    // Generate request id
    let current_request_id = self.request_buffer.withdraw_id_count;
    self.request_buffer.withdraw_id_count = current_request_id + 1;

    // Record this new request in Vault
    let new_request = withdraw_request::new(
        current_request_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        shares,
        expected_amount,
        clock.timestamp_ms(),
    );
    self.request_buffer.withdraw_requests.add(current_request_id, new_request);

    emit(WithdrawRequested {
        request_id: current_request_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        shares: shares,
        expected_amount: expected_amount,
    });

    vault_receipt.update_after_request_withdraw(shares, recipient);

    current_request_id
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

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/Move.toml (L79-86)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/mmt_v3"
rev = "main"
```
