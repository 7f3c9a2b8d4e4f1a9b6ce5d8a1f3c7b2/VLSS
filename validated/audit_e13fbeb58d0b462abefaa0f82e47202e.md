# Audit Report

## Title
Momentum Position Accumulated Fees Excluded from Value Calculations Enable Undetected Fund Theft

## Summary
The momentum adaptor's value calculation mechanism completely ignores accumulated trading fees (`owed_coin_x` and `owed_coin_y`) in MMT v3 positions, allowing operators to collect these fees during operations without triggering the vault's loss detection system. This bypasses the loss tolerance security mechanism designed to constrain operator behavior, enabling undetectable theft of vault assets.

## Finding Description

**Root Cause - Incomplete Value Calculation:**

The momentum adaptor calculates position values solely from liquidity-derived amounts, completely excluding accumulated fees. The `get_position_value()` function calls `get_position_token_amounts()`, which derives token amounts exclusively from the liquidity field using `liquidity_math::get_amounts_for_liquidity()`. [1](#0-0) 

The MMT v3 Position struct contains `owed_coin_x` and `owed_coin_y` fields representing accumulated trading fees that are never included in this calculation. [2](#0-1) 

**Exploitation Mechanism:**

MMT v3 provides a public `fee()` function that allows anyone with a mutable position reference to collect accumulated fees without special authorization. [3](#0-2) 

During vault operations, operators borrow momentum positions into a Bag under their control through `start_op_with_bag()`. [4](#0-3) 

While holding the borrowed position, a malicious operator can:
1. Extract the position from the Bag
2. Call `mmt_v3::collect::fee()` to collect accumulated fees as Coins
3. Transfer these coins to their own address
4. Return the position (now with zero fees) via `end_op_with_bag()`

The `return_defi_asset()` function performs no validation of the asset's state when returned - it only checks version, emits an event, and adds the asset back to the vault's bag. [5](#0-4) 

**Why Loss Detection Fails:**

At operation start, `start_op_with_bag()` captures the total USD value by summing all asset values from the vault's `assets_value` table. [6](#0-5) 

The `get_total_usd_value()` function retrieves pre-stored USD values from the `assets_value` table without recalculation. [7](#0-6) 

These stored values are updated via `finish_update_asset_value()`, which stores whatever USD value is provided by adaptors. [8](#0-7) 

Since the momentum adaptor never includes fees in its value calculation, both the "before" and "after" total values exclude fees. When `end_op_value_update_with_bag()` compares these values, it detects no loss even though fees have been stolen. [9](#0-8) 

**Security Control Bypass:**

The vault implements a loss tolerance mechanism that enforces maximum loss limits per epoch to constrain operator behavior. [10](#0-9) 

The vault also maintains an operator freeze mechanism that allows admins to freeze operators who act maliciously. [11](#0-10) 

These mechanisms demonstrate that operators are not fully trusted - they exist specifically to constrain operator behavior and detect unauthorized value extraction. This vulnerability bypasses these security controls entirely because the extracted value (accumulated fees) is never measured in the first place.

## Impact Explanation

**Direct Financial Loss:**
The vault loses accumulated trading fees that belong to vault depositors. In active liquidity pools, these fees continuously accrue from trading activity and can represent significant value, especially for long-lived positions in high-volume pools.

**Security Control Bypass:**
This vulnerability circumvents the core loss detection mechanism. The loss tolerance system enforces maximum acceptable losses per epoch specifically to constrain operator behavior and prevent unauthorized fund extraction. By bypassing this security boundary, the vulnerability undermines a fundamental protocol invariant: that operators cannot extract vault value beyond acceptable limits without detection.

**Systematic Exploitation:**
- The attack can be repeated every operation cycle
- Multiple momentum positions multiply the attack surface  
- Losses accumulate over time completely undetected
- The per-epoch loss tolerance protection is rendered ineffective

**Impact Classification: MEDIUM-HIGH**
While requiring operator role, this explicitly bypasses security mechanisms designed to constrain operators, resulting in undetectable fund theft from depositors.

## Likelihood Explanation

**Attacker Capability:**
Requires OperatorCap. However, the existence of operator freeze mechanism and loss tolerance checks proves operators are not fully trusted - these security boundaries exist precisely to constrain operator behavior.

**Attack Complexity:**
Very low. Uses only standard function calls in normal sequence:
1. `start_op_with_bag()` - borrows position into operator-controlled Bag
2. Extract position from Bag (standard Sui Move bag operation)
3. `mmt_v3::collect::fee()` - public function with no special authorization
4. Transfer collected fee coins to operator address
5. `end_op_with_bag()` - returns position (no validation)
6. `update_momentum_position_value()` - updates value (still excludes fees)
7. `end_op_value_update_with_bag()` - loss check passes incorrectly

**Preconditions:**
- Vault holds momentum position (common for DeFi vaults)
- Position has accumulated fees (occurs naturally in active pools)
- No special timing or state requirements

**Detection Capability:**
Zero. The theft is completely invisible because the fee value is never measured by the vault's accounting system.

**Likelihood Assessment: HIGH (if operator is malicious)**
No technical barriers, guaranteed success, zero detection risk, repeatable with no cost.

## Recommendation

Modify the momentum adaptor's value calculation to include accumulated fees:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
    
    // ADD: Include accumulated fees in value calculation
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    
    let total_amount_a = amount_a + owed_a;
    let total_amount_b = amount_b + owed_b;
    
    // ... rest of price validation and value calculation using total amounts
    
    let value_a = vault_utils::mul_with_oracle_price(total_amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(total_amount_b as u256, normalized_price_b);
    
    value_a + value_b
}
```

Additionally, consider implementing validation in `return_defi_asset()` or adding a mechanism to track and verify that fees are properly accounted for when positions are returned to the vault.

## Proof of Concept

```move
#[test]
fun test_operator_steals_momentum_fees() {
    // Setup: Create vault with momentum position that has accumulated fees
    // 1. Initialize vault with operator
    // 2. Add momentum position to vault with owed_coin_x > 0, owed_coin_y > 0
    // 3. Record initial vault value (excludes fees)
    
    // Attack:
    // 4. Operator calls start_op_with_bag() - borrows position into Bag
    // 5. Extract position from Bag: let mut pos = bag.remove()
    // 6. Call mmt_v3::collect::fee() - returns (Coin<X>, Coin<Y>) with fees
    // 7. Transfer fee coins to operator address
    // 8. Return position to Bag: bag.add(pos)
    // 9. Call end_op_with_bag() - returns position to vault
    // 10. Call update_momentum_position_value() - still excludes fees
    // 11. Call end_op_value_update_with_bag() - loss check passes (no loss detected)
    
    // Verify:
    // - Operator received fee coins
    // - Vault position now has owed_coin_x = 0, owed_coin_y = 0
    // - No loss was recorded (cur_epoch_loss = 0)
    // - Operation completed successfully without triggering ERR_EXCEED_LOSS_LIMIT
    // - Vault total value unchanged (because fees were never included)
}
```

## Notes

This vulnerability represents a fundamental accounting flaw where a valuable component of vault assets (accumulated trading fees) is completely excluded from the vault's accounting system. This creates an exploitable gap where operators can extract value that the vault considers to not exist. The loss tolerance mechanism, designed as a security boundary to constrain operator behavior, is completely bypassed because it can only detect losses in assets that are measured - and accumulated fees are never measured.

### Citations

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L10-24)
```text
    public struct Position has store, key {
        id: UID,
        pool_id: ID,
        fee_rate: u64,
        type_x: TypeName,
        type_y: TypeName,
        tick_lower_index: I32,
        tick_upper_index: I32,
        liquidity: u128,
        fee_growth_inside_x_last: u128,
        fee_growth_inside_y_last: u128,
        owed_coin_x: u64,
        owed_coin_y: u64,
        reward_infos: vector<PositionRewardInfo>,
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/collect.move (L25-33)
```text
    public fun fee<X, Y>(
        pool: &mut Pool<X, Y>, 
        position: &mut Position, 
        clock: &Clock, 
        version: &Version,
        tx_context: &mut TxContext
    ) : (Coin<X>, Coin<Y>) {
        abort 0
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

**File:** volo-vault/sources/operation.move (L353-363)
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
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
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

**File:** volo-vault/sources/volo_vault.move (L1254-1278)
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
```

**File:** volo-vault/sources/volo_vault.move (L1436-1449)
```text
public(package) fun return_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    asset: AssetType,
) {
    self.check_version();

    emit(DefiAssetReturned {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.add<String, AssetType>(asset_type, asset);
}
```
