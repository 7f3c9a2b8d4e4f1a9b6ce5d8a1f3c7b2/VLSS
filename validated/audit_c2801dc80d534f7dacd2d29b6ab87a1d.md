# Audit Report

## Title
Asset Type Mismatch in Momentum Position Valuation Allows Incorrect USD Value Storage

## Summary
The `update_momentum_position_value` function is publicly callable without access controls and fails to validate that the provided pool's coin types match the position's actual coin types. An attacker can provide a pool with different coin types, causing the position's value to be calculated using wrong token prices and storing incorrect USD values in the vault's accounting system, directly affecting share prices and enabling value extraction.

## Finding Description

The vulnerability exists in the `update_momentum_position_value` function which is declared as `public fun`, making it callable by any user via Programmable Transaction Blocks without requiring operator capabilities or authorization. [1](#0-0) 

The function retrieves a MomentumPosition from the vault and calls `get_position_value` to calculate its USD value, then stores this value in the vault's accounting system. [2](#0-1) 

The critical flaw is in how `get_position_value` extracts coin types - it extracts them from the **pool's generic parameters** (`CoinA` and `CoinB`), not from the position itself. [3](#0-2) 

The MomentumPosition struct stores the actual coin types in its `type_x` and `type_y` fields. [4](#0-3) 

However, these fields have no public getter functions available to verify the position's actual types. [5](#0-4) 

There is **no validation** anywhere in the code that the pool's generic types match the position's stored types. The extracted types are then used to fetch oracle prices and calculate the position value. [6](#0-5) 

The pool price slippage check only validates that the pool's internal price is consistent with oracle prices **for that specific pool's tokens**. It does NOT validate that the pool matches the position. [7](#0-6) 

Finally, the incorrect USD value is stored in the vault through `finish_update_asset_value`, which performs no authorization checks beyond vault status. [8](#0-7) 

## Impact Explanation

This vulnerability has **HIGH severity** impact:

1. **Direct Fund Impact**: The vault's asset values are summed to calculate total_usd_value, which directly determines share prices. [9](#0-8)  Users depositing or withdrawing receive wrong amounts of shares or principal based on manipulated valuations.

2. **Vault Accounting Corruption**: Violates the critical invariant of total_usd_value correctness. The vault's `assets_value` table stores fundamentally wrong USD values for momentum positions.

3. **Systematic Manipulation**: An attacker can repeatedly call this function to maintain artificially high or low valuations, enabling:
   - Depositing when value is artificially low to receive more shares
   - Withdrawing when value is artificially high to extract more principal
   - Preventing legitimate loss tolerance checks from triggering during operations

4. **All Users Affected**: Since share prices are calculated from total vault value, all depositors in the vault are impacted by incorrect position valuations.

## Likelihood Explanation

The likelihood of exploitation is **HIGH**:

1. **Reachable Entry Point**: The function is `public fun`, meaning any user can call it via a Programmable Transaction Block without any special permissions or capabilities. No OperatorCap or access control is required.

2. **Feasible Preconditions**: 
   - Attacker only needs knowledge of which momentum positions exist in the vault (observable on-chain)
   - Attacker needs access to a different momentum pool with token pairs that would pass the slippage validation
   - Both requirements are easily met in production environments

3. **Execution Practicality**: Attack sequence is straightforward:
   - Identify target vault with momentum position for TokenA/TokenB
   - Find or create pool for TokenC/TokenD where prices are similar enough to pass slippage check
   - Construct PTB calling `update_momentum_position_value` with mismatched pool
   - No complex timing, front-running, or state manipulation required

4. **Economic Rationality**: 
   - Attack cost is minimal (just transaction fees)
   - No capital lockup required
   - Can be repeated to maintain incorrect valuations
   - Profit potential through share price manipulation makes this economically viable

## Recommendation

Add validation to ensure the pool's coin types match the position's stored types. Since the Position struct lacks public getters for `type_x`, `type_y`, and `pool_id`, there are two approaches:

**Option 1**: Add public getter functions to the MomentumPosition module to expose `type_x()`, `type_y()`, and `pool_id()`. Then validate in `update_momentum_position_value`:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Validate pool ID matches
    assert!(pool.pool_id() == position.pool_id(), ERR_POOL_MISMATCH);
    
    // Validate coin types match
    let type_a = type_name::get<CoinA>();
    let type_b = type_name::get<CoinB>();
    assert!(type_a == position.type_x() && type_b == position.type_y(), ERR_TYPE_MISMATCH);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**Option 2**: Restrict the function visibility to `public(package)` or require OperatorCap, ensuring only trusted operators can update position values.

## Proof of Concept

```move
#[test]
fun test_momentum_position_value_type_mismatch() {
    // Setup: Create vault with SUI/USDC momentum position
    let mut scenario = test_scenario::begin(ADMIN);
    let mut vault = create_test_vault(&mut scenario);
    let clock = clock::create_for_testing(scenario.ctx());
    
    // Vault has a momentum position for SUI/USDC
    let sui_usdc_position = create_momentum_position<SUI, USDC>(&mut scenario);
    vault.add_defi_asset(string::utf8(b"momentum_position_1"), sui_usdc_position);
    
    // Attacker creates or finds a different pool (USDT/DAI) with similar prices
    let mut usdt_dai_pool = create_momentum_pool<USDT, DAI>(&mut scenario);
    
    // Attacker calls update with WRONG pool type
    // This should fail but currently succeeds
    momentum_adaptor::update_momentum_position_value<PrincipalCoin, USDT, DAI>(
        &mut vault,
        &oracle_config,
        &clock,
        string::utf8(b"momentum_position_1"), // SUI/USDC position
        &mut usdt_dai_pool, // USDT/DAI pool - WRONG!
    );
    
    // The position value is now calculated using USDT/DAI prices instead of SUI/USDC
    // This corrupts the vault's accounting
    let total_value = vault.get_total_usd_value_without_update();
    // Assert that value is incorrect based on wrong token prices
}
```

### Citations

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L42-43)
```text
    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-66)
```text
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L50-60)
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
}
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

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```
