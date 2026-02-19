# Audit Report

## Title
Pool Type Mismatch in MomentumPosition Valuation Allows Complete Asset Value Manipulation

## Summary
The `update_momentum_position_value()` function in the Momentum adaptor fails to validate that the provided `MomentumPool<CoinA, CoinB>` parameter matches the `MomentumPosition`'s actual pool. This missing validation allows anyone to pass an arbitrary pool with different token pairs, causing the vault to calculate and store completely incorrect USD valuations that directly affect share pricing and enable fund theft.

## Finding Description

The vulnerability exists in the momentum adaptor's position valuation logic. Each `MomentumPosition` object stores its associated pool's ID in a `pool_id` field [1](#0-0) , and the `Pool` object provides a corresponding `pool_id()` getter function [2](#0-1) . However, the adaptor functions never validate this relationship.

The `update_momentum_position_value()` function accepts an arbitrary `MomentumPool<CoinA, CoinB>` parameter and retrieves a `MomentumPosition` from the vault [3](#0-2) . It then calls `get_position_value()` which uses the pool's `sqrt_price` and the pool's generic type parameters `<CoinA, CoinB>` to determine token types and fetch oracle prices [4](#0-3) .

The function extracts token amounts using `get_position_token_amounts()` which combines the pool's `sqrt_price` with the position's tick bounds and liquidity [5](#0-4) .

**Why Existing Protections Fail:**

The slippage validation only checks that the pool's price is consistent with oracle prices for CoinA and CoinB [6](#0-5) , but does NOT verify that these are the correct tokens for the position. If an attacker passes `Pool<USDC, USDT>` for a position that actually belongs to `Pool<SUI, USDC>`, the slippage check validates USDC/USDT consistency, not whether these are the right tokens for the position.

The MMT v3 module provides a `verify_pool()` function [7](#0-6)  that could validate the pool-position match, but it is never called in the adaptor code.

**Access Control Issue:**

The function is declared as `public fun`, requiring no capability whatsoever, only that the vault be enabled [8](#0-7) . This means **anyone** can call this function, not just operators.

## Impact Explanation

This vulnerability enables complete manipulation of vault asset valuations with direct fund theft implications:

1. **Direct Asset Value Manipulation**: An attacker can pass any pool with arbitrary token pairs to value a position, causing the vault to record fundamentally incorrect USD values [9](#0-8) .

2. **Share Price Corruption**: The manipulated asset values directly affect the vault's total USD value, which determines share prices for all deposit and withdrawal operations.

3. **Fund Theft Vector**: 
   - Attacker deflates a high-value position (e.g., $100,000 SUI/USDC) by passing a near-worthless pool
   - Vault records position as worth $100 instead of $100,000
   - Attacker or accomplice immediately withdraws at the deflated share price
   - Result: ~$99,900 stolen from other vault users

4. **No Complexity Barriers**: The attack requires only a single function call with any pool reference available on the Sui blockchain.

This violates the critical protocol invariant that `total_usd_value` must accurately reflect actual vault asset values for correct share pricing.

## Likelihood Explanation

**Extremely High Likelihood:**

1. **No Access Control**: The function is `public fun` with no capability requirement - literally anyone on the Sui network can call it.

2. **Trivial Execution**: 
   - Attacker only needs to find any pool with different token pairs
   - Single transaction call to manipulate valuation
   - No complex setup or timing requirements

3. **Zero Cost Attack**: Only requires gas fees to execute, with potential profit equal to the entire manipulated position value.

4. **Difficult Detection**: The attack leaves no obvious on-chain trace distinguishing it from legitimate value updates. Off-chain monitoring would need to track pool IDs for each position and verify all updates.

5. **No Preconditions**: Only requires that the vault be enabled (not disabled), which is the normal operational state.

## Recommendation

Add validation to ensure the pool parameter matches the position's stored pool ID:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Add validation: ensure pool ID matches position's pool ID
    let position_pool_id = position.pool_id();
    pool.verify_pool<CoinA, CoinB>(position_pool_id);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

This leverages the existing `verify_pool()` function provided by the MMT v3 module to ensure the pool parameter is the correct pool for the position being valued.

Additionally, consider restricting this function to require an `OperatorCap` to prevent arbitrary external callers from updating asset values.

## Proof of Concept

```move
#[test]
fun test_pool_mismatch_attack() {
    // Setup: Create vault with a high-value SUI/USDC position worth $100,000
    let mut scenario = test_scenario::begin(@attacker);
    let vault = setup_vault_with_position(&mut scenario, @sui_usdc_pool_id);
    
    // Attack: Call update with a different pool (USDC/USDT) that has low liquidity
    // This pool's price will value the position incorrectly
    let malicious_pool = get_usdc_usdt_pool(&mut scenario);
    
    test_scenario::next_tx(&mut scenario, @attacker);
    {
        let vault_mut = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let config = test_scenario::take_shared<OracleConfig>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let pool = test_scenario::take_shared<MomentumPool<USDC, USDT>>(&scenario);
        
        // This call succeeds despite pool mismatch - no validation!
        momentum_adaptor::update_momentum_position_value(
            &mut vault_mut,
            &config,
            &clock,
            asset_type,
            &mut pool
        );
        
        // Verify vault now has incorrect (deflated) valuation
        let value = vault_mut.get_asset_value(asset_type);
        assert!(value < 1000 * DECIMAL, 0); // Should be $100k but is now < $1k
        
        test_scenario::return_shared(vault_mut);
        test_scenario::return_shared(config);
        test_scenario::return_shared(clock);
        test_scenario::return_shared(pool);
    };
    
    test_scenario::end(scenario);
}
```

**Notes:**
- The vulnerability is more severe than initially described because the function is `public fun` without any capability requirement
- Any user can manipulate any vault's Momentum position valuations
- The MMT v3 module already provides the necessary validation function (`verify_pool()`), but it's simply not being used
- This is a critical vault accounting invariant violation that enables direct fund theft with no execution barriers

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L106-111)
```text
    public fun verify_pool<X, Y>(
        pool: &Pool<X, Y>,
        id: ID,
    ) {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L139-139)
```text
    public fun pool_id<X, Y>(pool: &Pool<X, Y>): ID { abort 0 }
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L34-67)
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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```
