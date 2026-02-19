# Audit Report

## Title
Momentum Position Accumulated Fees Excluded from Value Calculations Enable Undetected Fund Theft

## Summary
The momentum adaptor calculates position values based solely on liquidity-derived token amounts, completely ignoring the `owed_coin_x` and `owed_coin_y` fields that represent accumulated trading fees in MMT v3 positions. This allows operators to collect accumulated fees during operations without triggering the vault's loss detection mechanism, bypassing security checks designed to prevent unauthorized fund extraction.

## Finding Description

**Root Cause - Incomplete Value Calculation:**

The momentum adaptor's `get_position_value()` function calculates position value by calling `get_position_token_amounts()`, which derives token amounts purely from liquidity using `liquidity_math::get_amounts_for_liquidity()`. [1](#0-0) 

This calculation completely ignores the `owed_coin_x` and `owed_coin_y` fields that exist in the MMT v3 Position struct and represent accumulated trading fees. [2](#0-1) 

**Exploitation Mechanism:**

The MMT v3 protocol provides a public `fee()` function that allows anyone with a mutable position reference to collect accumulated fees. [3](#0-2) 

During operations, operators borrow momentum positions into a Bag they control through `start_op_with_bag()`. [4](#0-3) 

While holding the borrowed position, a malicious operator can:
1. Extract the position from the Bag
2. Call `mmt_v3::collect::fee()` to collect accumulated fees as coins
3. Transfer these coins to their own address
4. Return the position (now with zero fees) via `end_op_with_bag()`

The `return_defi_asset()` function performs no validation of the asset's state when it's returned. [5](#0-4) 

**Why Loss Detection Fails:**

At operation start, `start_op_with_bag()` captures `total_usd_value` which sums all asset values from the vault's `assets_value` table. [6](#0-5) 

The `get_total_usd_value()` function retrieves pre-stored USD values from the `assets_value` table without recalculation. [7](#0-6) 

These stored values are updated via `finish_update_asset_value()` which stores whatever USD value is calculated by adaptors. [8](#0-7) 

Since the momentum adaptor never includes fees in its value calculation, both the "before" and "after" total values exclude fees. When the operator calls `end_op_value_update_with_bag()`, it compares these two values and detects no loss, even though fees worth real USD value have been stolen. [9](#0-8) 

## Impact Explanation

**Direct Financial Loss:**
The vault loses accumulated trading fees that rightfully belong to vault depositors. In active liquidity pools, these fees can represent significant value that accrues continuously from trading activity.

**Security Control Bypass:**
This vulnerability circumvents the core loss detection mechanism. The vault system implements value update checks and loss tolerance limits specifically to constrain operator behavior and prevent unauthorized fund extraction. The operator freeze mechanism exists precisely because operators are not fully trusted. [10](#0-9) 

**Systematic Exploitation:**
- The attack can be repeated on every operation cycle
- Multiple momentum positions multiply the attack surface
- Losses accumulate over time completely undetected
- The per-epoch loss_tolerance protection is ineffective since no loss is recorded

**Impact Classification: MEDIUM**
Requires operator role (semi-trusted) but explicitly bypasses security checks designed to constrain operators, resulting in undetectable fund theft.

## Likelihood Explanation

**Attacker Capability:**
Requires OperatorCap, a semi-trusted role. However, the vault's architecture explicitly does not fully trust operators, implementing value update checks and loss tolerance limits as security boundaries.

**Attack Complexity:**
Very low. The attack uses only standard function calls in their normal sequence:
1. `start_op_with_bag()` - standard operation initialization
2. Extract position from Bag (standard Sui Move operation)
3. `mmt_v3::collect::fee()` - public MMT v3 function
4. `end_op_with_bag()` - standard operation completion  
5. `update_momentum_position_value()` - required value update
6. `end_op_value_update_with_bag()` - value verification (passes incorrectly)

**Preconditions:**
- Vault holds at least one momentum position (common for DeFi vaults)
- Position has accumulated fees (occurs naturally over time in active pools)
- No special timing or external dependencies required

**Detection Capability:**
Zero. The theft is completely invisible to all security checks because the fee value was never measured in the first place.

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
    
    // Add accumulated fees to the amounts
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    let total_amount_a = amount_a + owed_a;
    let total_amount_b = amount_b + owed_b;

    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());

    // ... rest of price validation and USD conversion using total_amount_a and total_amount_b
}
```

This ensures that:
1. All position value (liquidity + fees) is measured before operations
2. Fee collection during operations causes a detectable value decrease
3. Loss tolerance limits apply correctly to fee theft attempts
4. The security invariant "operators cannot extract value without detection" is restored

## Proof of Concept

A complete test would require:
1. Deploy vault with momentum position containing accumulated fees
2. Operator calls `start_op_with_bag()` to borrow the position
3. Operator extracts position from Bag, calls `mmt_v3::collect::fee()`, transfers fee coins
4. Operator returns position via `end_op_with_bag()`
5. Operator calls `update_momentum_position_value()` and `end_op_value_update_with_bag()`
6. Verify: No loss detected, fee coins transferred to operator, vault value unchanged

The vulnerability is demonstrated by the fact that `get_position_value()` returns the same value before and after fee collection, despite real economic value being extracted from the position.

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L34-91)
```text
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);

    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );

    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
}

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

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L178-193)
```text
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
```

**File:** volo-vault/sources/operation.move (L353-373)
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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
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
