# Audit Report

## Title
Asset Type Mismatch in Momentum Position Valuation Allows Vault Accounting Manipulation

## Summary
The `update_momentum_position_value` function is publicly callable without access controls and fails to validate that the provided pool's coin types match the position's actual coin types. An attacker can provide a mismatched pool to calculate incorrect USD values, corrupting the vault's accounting system and enabling share price manipulation for value extraction.

## Finding Description

The vulnerability exists in the momentum adaptor's value update mechanism. The `update_momentum_position_value` function is declared as `public fun`, making it callable by any user without requiring operator capabilities. [1](#0-0) 

The function retrieves a MomentumPosition from the vault and calculates its USD value. [2](#0-1) 

The critical flaw is in `get_position_value`: it extracts coin types from the **pool's generic parameters** (`CoinA` and `CoinB`), not from the position itself. [3](#0-2) 

The MomentumPosition struct stores the actual coin types in `type_x` and `type_y` fields, but there are no public getter functions for these fields. [4](#0-3)  The available getters do not include `type_x` or `type_y`. [5](#0-4) 

Critically, there is **no validation** that the pool's coin types match the position's stored types, and the function never validates that the pool's ID matches the position's `pool_id` field.

The extracted types are used to fetch oracle prices and calculate position value. [6](#0-5) [7](#0-6) 

The slippage check only validates that the pool's internal price is consistent with oracle prices for that specific pool's tokens—it does NOT validate pool-position matching. [8](#0-7) 

The incorrect USD value is stored via `finish_update_asset_value`, which only checks vault version and enabled status. [9](#0-8) 

## Impact Explanation

This vulnerability has **HIGH severity** impact because it directly corrupts the vault's accounting foundation:

1. **Share Price Manipulation**: The vault calculates `total_usd_value` by summing all asset values. [10](#0-9)  Share ratio is calculated as `total_usd_value / total_shares`. [11](#0-10) 

2. **Deposit Impact**: During deposits, user shares are calculated as `new_usd_value_deposited / share_ratio_before`. [12](#0-11) [13](#0-12)  If share ratio is artificially inflated, users receive fewer shares than deserved.

3. **Withdrawal Impact**: During withdrawals, the amount is calculated from shares using the current ratio. [14](#0-13) [15](#0-14)  If share ratio is artificially inflated, users withdraw more principal than deserved.

4. **Value Extraction**: An attacker can systematically:
   - Inflate valuation before their withdrawal to extract excess funds
   - Deflate valuation before their deposit to receive excess shares
   - Repeat the attack to drain vault value over time

5. **All Users Affected**: Since share prices are global, all depositors suffer from incorrect valuations.

## Likelihood Explanation

The likelihood of exploitation is **HIGH**:

1. **No Access Control**: The function is `public fun` with no capability requirements—any wallet can call it via PTB.

2. **Observable Preconditions**: Momentum positions in vaults are observable on-chain through the vault's asset list.

3. **Available Pools**: The attacker only needs access to a different Momentum pool. Public pools are readily available, and the attacker can even create a custom pool if needed.

4. **Bypassing Slippage Check**: The slippage validation only requires that the mismatched pool's price be consistent with oracle prices for its own tokens—a condition easily satisfied by choosing pools with similar token price ratios or tokens with correlated prices.

5. **Simple Execution**: The attack requires a single PTB call with standard parameters—no complex MEV, timing dependencies, or multi-step setups.

6. **Economic Viability**: Attack cost is minimal (gas fees only), capital lockup is zero, and the attack is repeatable to maintain manipulated valuations for profit extraction.

## Recommendation

Add validation to ensure the pool matches the position:

1. Add public getter functions in the Momentum Position module to expose `type_x`, `type_y`, and validate against pool types
2. Add pool ID validation to ensure the provided pool matches `position.pool_id()`
3. Consider restricting `update_momentum_position_value` to operator-only access with `public(package)` visibility

Example fix for the momentum adaptor:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Validate pool ID matches position
    assert!(pool.pool_id() == position.pool_id(), ERR_POOL_MISMATCH);
    
    // Validate pool types match position types (requires new getters in position module)
    assert!(pool.type_x() == position.type_x(), ERR_TYPE_MISMATCH);
    assert!(pool.type_y() == position.type_y(), ERR_TYPE_MISMATCH);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

## Proof of Concept

```move
#[test]
fun test_momentum_position_value_mismatch_attack() {
    // Setup: Create vault with USDC/SUI momentum position worth 1000 USD
    let scenario = test_scenario::begin(ADMIN);
    let vault = create_test_vault_with_momentum_position(&mut scenario, 1000);
    
    // Attack: Call update with USDT/WETH pool (assume prices give 1500 USD)
    let usdt_weth_pool = create_mismatched_pool(&mut scenario);
    momentum_adaptor::update_momentum_position_value(
        &mut vault,
        &oracle_config,
        &clock,
        momentum_position_type,
        &mut usdt_weth_pool
    );
    
    // Verify: Vault now reports inflated value
    let total_value = vault.get_total_usd_value(&clock);
    assert!(total_value == 1500, 0); // Should be 1000, but is 1500
    
    // Impact: Share ratio is now inflated, enabling value extraction
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-27)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L28-29)
```text
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L42-43)
```text
    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-50)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L63-66)
```text
    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L49-60)
```text
    // public getter functions
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
}
```

**File:** volo-vault/sources/volo_vault.move (L820-821)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1006)
```text
    let ratio = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1013-1022)
```text
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1174-1187)
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
```

**File:** volo-vault/sources/volo_vault.move (L1289-1292)
```text
    self.asset_types.do_ref!(|asset_type| {
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```
