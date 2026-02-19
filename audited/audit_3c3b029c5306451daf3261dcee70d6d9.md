# Audit Report

## Title
Missing Pool-Position Validation in Momentum Adaptor Allows Arbitrary Asset Value Manipulation

## Summary
The `update_momentum_position_value()` function in the Momentum adaptor does not validate that the supplied `MomentumPool` parameter corresponds to the `MomentumPosition`'s actual pool. This allows **any caller** (not just operators) to manipulate vault asset valuations by providing an arbitrary pool with different token pairs, directly corrupting share pricing and enabling fund extraction.

## Finding Description

The vulnerability exists due to missing validation between a position and its associated pool. A `MomentumPosition` stores its pool's ID [1](#0-0) , and the MMT v3 `Pool` module provides a `pool_id()` getter function [2](#0-1)  and a `verify_pool()` validation function [3](#0-2) .

However, the `update_momentum_position_value()` function is declared as `public fun` with no authorization checks [4](#0-3) . It accepts an arbitrary `pool` parameter and retrieves the position from the vault [5](#0-4) , then calls `get_position_value()` which uses the pool's `sqrt_price` and generic type parameters `<CoinA, CoinB>` [6](#0-5) .

The critical flaw is in `get_position_token_amounts()`, which combines the **pool's** `sqrt_price` with the **position's** tick bounds and liquidity [7](#0-6) . When the wrong pool is provided, this produces completely incorrect token amounts. The function then fetches oracle prices for the wrong token types (from the pool's generics, not the position's actual tokens) and calculates an invalid USD value.

The slippage validation [8](#0-7)  only verifies that the **supplied** pool's price is consistent with oracle prices for **that pool's** tokens. It does not verify these are the correct tokens for the position. An attacker can pass any pool (e.g., `Pool<USDT, USDC>` for a `SUI/USDC` position) as long as the pool's price matches its own token oracles.

The calculated value is then stored in the vault's asset tracking [9](#0-8) , where it directly affects `total_usd_value` calculations and share pricing.

## Impact Explanation

This vulnerability breaks the core vault accounting invariant that asset valuations must be accurate. The impact is **CRITICAL**:

1. **Direct Fund Theft**: An attacker can deflate a position's recorded value (e.g., from $100,000 to $100), then immediately execute withdrawals at the artificially low share price, extracting ~$99,900 from other vault users.

2. **Share Price Manipulation**: Conversely, inflating values allows attackers to acquire underpriced shares, diluting existing holders when the valuation is corrected.

3. **Total Loss of Accounting Integrity**: The vault's `total_usd_value` becomes unreliable, affecting all deposit/withdrawal calculations and breaking the fundamental trust model.

4. **No Recovery Mechanism**: Once the incorrect value is stored, it remains until updated again, and the vault continues operating with corrupted data.

## Likelihood Explanation

The likelihood is **CRITICAL** because:

1. **No Authorization Required**: The function is `public fun` with zero capability checks. Any user can call it via Programmable Transaction Block, not just operators as the original claim suggested.

2. **Trivial Execution**: The attacker only needs references to shared objects (vault, oracle config, clock, any pool) - all publicly accessible. No special privileges or complex setup required.

3. **Minimal Barriers**: The only check is `vault.assert_enabled()` [10](#0-9) , which allows calls in both NORMAL and DURING_OPERATION states.

4. **Slippage Check Bypassable**: Attackers can use any legitimate pool with correct oracle prices for its own tokens, completely bypassing the intended protection.

5. **No Detection**: The attack appears as a normal value update event, indistinguishable from legitimate operations without off-chain pool ID tracking.

## Recommendation

Add pool-position validation at the start of `update_momentum_position_value()`:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Add validation: verify the pool matches the position's stored pool_id
    pool::verify_pool(pool, position.pool_id());
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

Additionally, consider restricting this function to package-level visibility or adding OperatorCap requirement to prevent unauthorized value updates.

## Proof of Concept

```move
// Attacker can call this via PTB:
// 1. Reference target vault with MomentumPosition for Pool<SUI, USDC> 
// 2. Reference malicious Pool<TokenX, TokenY> with low prices
// 3. Call update_momentum_position_value(vault, config, clock, "momentum_position_0", malicious_pool)
// 4. Vault's position value is now calculated using wrong tokens
// 5. Execute withdrawal at manipulated share price
// Result: Direct fund extraction from vault
```

**Notes**

The original claim incorrectly states that OperatorCap is required. In reality, the function is completely public with no authorization, making the vulnerability **more severe** than described. Any user can manipulate vault asset values, not just malicious operators. The core technical issue (missing pool-position validation) is valid and exploitable, but the threat model was understated.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L12-12)
```text
        pool_id: ID,
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-26)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L28-29)
```text
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L40-43)
```text
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);

    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L73-90)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L1181-1181)
```text
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```
