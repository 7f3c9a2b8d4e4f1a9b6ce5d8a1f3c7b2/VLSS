# Audit Report

## Title
Asset Type Mismatch in Momentum Position Valuation Allows Incorrect USD Value Storage

## Summary
The `update_momentum_position_value` function is publicly callable without access controls and fails to validate that the provided pool's coin types match the position's actual coin types. An attacker can provide a pool with different coin types, causing the position's value to be calculated using wrong token prices and storing incorrect USD values in the vault's accounting system, directly affecting share prices and enabling value extraction.

## Finding Description

The vulnerability exists in the `update_momentum_position_value` function which is declared as `public fun`, making it callable by any user via Programmable Transaction Blocks (PTBs) without requiring operator capabilities or any authorization. [1](#0-0) 

The function retrieves a MomentumPosition from the vault and calls `get_position_value` to calculate its USD value. [2](#0-1) 

The critical flaw is in how `get_position_value` extracts coin types - it extracts them from the **pool's generic parameters** (`CoinA` and `CoinB`), not from the position itself. [3](#0-2) 

The MomentumPosition struct stores the actual coin types in its `type_x` and `type_y` fields, but these fields have no public getter functions. [4](#0-3) [5](#0-4) 

More critically, **there is no validation** anywhere in the code that the pool's generic types match the position's stored types, and the function never validates that the pool's ID matches the position's `pool_id` field.

The extracted types are then used to fetch oracle prices and calculate the position value. [6](#0-5) [7](#0-6) 

The pool price slippage check only validates that the pool's internal price is consistent with oracle prices **for that specific pool's tokens**. It does NOT validate that the pool matches the position. [8](#0-7) 

Finally, the incorrect USD value is stored in the vault through `finish_update_asset_value`, which performs no authorization checks beyond vault status. [9](#0-8) 

## Impact Explanation

This vulnerability has **HIGH severity** impact:

1. **Direct Fund Impact**: The vault's asset values are summed to calculate total_usd_value, which directly determines share prices. [10](#0-9) [11](#0-10)  Users depositing or withdrawing receive wrong amounts of shares or principal based on manipulated valuations.

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

Add validation to ensure the pool matches the position:

1. Make `type_x` and `type_y` accessible via public getter functions in the Position struct
2. Add validation in `update_momentum_position_value` or `get_position_value` to verify:
   - Pool's `CoinA` type matches position's `type_x`
   - Pool's `CoinB` type matches position's `type_y`
   - Pool's ID matches position's `pool_id`
3. Consider making `update_momentum_position_value` require operator capability or change to `public(package)` visibility

Alternatively, the pool object ID can be compared with the position's stored pool_id to ensure they match before calculating values.

## Proof of Concept

```move
// Test demonstrating the vulnerability
public fun test_momentum_value_manipulation() {
    // Setup: Vault has position in USDC/USDT pool (low value tokens)
    let vault = create_test_vault();
    let usdc_usdt_position = create_momentum_position(/* USDC/USDT with liquidity */);
    vault.add_defi_asset(string("momentum_pos_1"), usdc_usdt_position);
    
    // Attacker: Call with SUI/WETH pool (high value tokens) instead
    let sui_weth_pool = get_sui_weth_pool(); // Different pool with different tokens
    
    // This call succeeds and stores wrong USD value
    update_momentum_position_value(
        &mut vault,
        config,
        clock,
        string("momentum_pos_1"),
        &mut sui_weth_pool  // WRONG POOL with different coin types!
    );
    
    // Result: Position valued using SUI/WETH prices instead of USDC/USDT prices
    // Share price becomes inflated, attacker withdraws more principal
    let share_ratio = vault.get_share_ratio(clock);
    assert!(share_ratio > expected_correct_ratio, 0); // Inflated!
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L28-31)
```text
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/volo_vault.move (L1268-1269)
```text
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```
