# Audit Report

## Title
Type Confusion in Momentum Position Valuation Enables Vault Fund Drainage

## Summary
The `update_momentum_position_value` function accepts generic type parameters without validating they match the position's stored token types, allowing any user to artificially inflate asset valuations and drain vault funds through manipulated share ratios.

## Finding Description

The vulnerability stems from a critical type safety gap between the generic `Pool<X, Y>` struct and the non-generic `Position` struct in the Momentum protocol integration.

The `Position` struct stores its token types as runtime `TypeName` values rather than compile-time generics [1](#0-0) , while the `Pool` uses phantom type parameters enforced at compile time.

The vulnerability manifests in the momentum adaptor's value update function, which is publicly accessible without any operator capability requirements [2](#0-1) . 

When calculating position value, the function derives `TypeName` values from the generic type parameters `<CoinA, CoinB>` and uses them to fetch oracle prices [3](#0-2) , but **never validates** that these types match the position's actual stored `type_x` and `type_y` fields.

The token amount calculation combines the position's liquidity and tick data with the provided pool's sqrt_price [4](#0-3) , then values these amounts using oracle prices for the mismatched generic type parameters [5](#0-4) .

While there is a sanity check that validates pool price matches oracle price [6](#0-5) , this check only ensures consistency between the **provided** pool and oracle for the **generic** types - it does NOT validate these types match the position's stored types.

The inflated value directly updates the vault's asset valuation table [7](#0-6) , which is summed to calculate total USD value [8](#0-7) , which directly impacts the share ratio calculation [9](#0-8) .

The only access controls are `check_version()` and `assert_enabled()` [10](#0-9) , neither of which prevents unauthorized users from calling the function.

## Impact Explanation

**Critical Fund Drainage**: An attacker can execute the following attack:

1. Vault contains a MomentumPosition for USDC/USDT (each ~$1)
2. Attacker publishes a Move module that calls `update_momentum_position_value<PrincipalCoin, WETH, WBTC>` with a WETH/WBTC pool reference
3. The position's liquidity gets valued using WETH ($3,000) and WBTC ($60,000) oracle prices instead of USDC/USDT prices
4. Position value inflates by 1,000x-60,000x depending on price differences
5. The vault's total_usd_value becomes inflated
6. Share ratio = inflated_total_usd_value / total_shares
7. When legitimate users withdraw, they receive shares × inflated_ratio worth of principal
8. Vault funds are drained as withdrawals pay out based on inflated valuations

**Loss Tolerance Bypass**: The inflated values mask actual protocol losses, allowing operators to violate the epoch loss tolerance invariant without triggering safeguards.

**Widespread Impact**: The identical vulnerability exists in the Cetus adaptor [11](#0-10) , affecting all vaults using either DEX integration.

## Likelihood Explanation

**Attack Feasibility**: HIGH

- **No Privileged Access Required**: Any user can call this public function
- **Trivial Execution**: In Sui Move, users can deploy their own modules with entry functions that call public functions from other packages
- **Low Cost**: Gas fees for module deployment (~0.01 SUI) + minimal deposit amount
- **High Reward**: Can extract millions from popular vaults
- **Detection Difficulty**: Inflated values appear in events but may not trigger immediate alerts if vault contains multiple positions

**Attack Steps**:
1. Deploy malicious Move module with entry function
2. Call `momentum_adaptor::update_momentum_position_value` with wrong generic types
3. Provide a pool reference matching those wrong types (to pass price sanity check)
4. Deposit minimal funds to receive shares
5. Wait for legitimate deposits to flow in
6. Withdraw to extract excess principal based on inflated share ratio

## Recommendation

Add type validation to ensure the generic type parameters match the position's stored token types:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // ADD VALIDATION:
    let type_a = type_name::get<CoinA>();
    let type_b = type_name::get<CoinB>();
    assert!(position.type_x() == type_a, ERR_TYPE_MISMATCH);
    assert!(position.type_y() == type_b, ERR_TYPE_MISMATCH);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

Apply the same fix to `update_cetus_position_value` and any other DEX adaptor functions that exhibit this pattern.

## Proof of Concept

```move
#[test_only]
module volo_vault::exploit_test {
    use volo_vault::momentum_adaptor;
    use volo_vault::vault::Vault;
    use mmt_v3::pool::Pool as MomentumPool;
    
    // Test demonstrates calling update_momentum_position_value with mismatched types
    #[test]
    fun test_type_confusion_exploit() {
        // Setup: vault contains USDC/USDT position
        let vault = /* initialize vault with USDC/USDT MomentumPosition */;
        let weth_wbtc_pool = /* get reference to WETH/WBTC pool */;
        let config = /* oracle config */;
        let clock = /* clock */;
        
        // Exploit: call with wrong generic types
        // This should fail with type validation but currently succeeds
        momentum_adaptor::update_momentum_position_value<
            PrincipalCoin,
            WETH,  // Wrong type - should be USDC
            WBTC   // Wrong type - should be USDT
        >(
            &mut vault,
            &config,
            &clock,
            b"MomentumPosition_1".to_ascii_string(),
            &mut weth_wbtc_pool
        );
        
        // Result: position valued using WETH/WBTC prices instead of USDC/USDT
        // This inflates the vault's total_usd_value by orders of magnitude
    }
}
```

### Citations

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L42-50)
```text
    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L53-58)
```text
    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-66)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
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
