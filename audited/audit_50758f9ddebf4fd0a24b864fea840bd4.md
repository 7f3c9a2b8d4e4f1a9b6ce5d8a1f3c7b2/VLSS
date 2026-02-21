# Audit Report

## Title
Cross-Pool Manipulation Vulnerability in Momentum Position Valuation

## Summary
The Momentum adaptor's `get_position_token_amounts()` function fails to validate that the provided pool reference matches the position's stored `pool_id`, allowing attackers to manipulate vault asset valuations by passing an arbitrary pool with different pricing. This directly corrupts the vault's USD accounting system, enabling share price manipulation and potential fund theft.

## Finding Description

The vulnerability exists in the position valuation logic where pool and position data are combined without validation.

The `get_position_token_amounts()` function reads the current `sqrt_price` from the provided pool parameter and combines it with the position's `liquidity` and tick range to calculate token amounts. [1](#0-0) 

However, it never validates that the pool's ID matches the position's `pool_id` field. The MomentumPosition struct explicitly stores which pool it belongs to via a `pool_id` field, [2](#0-1) 

and both Position and Pool have accessible ID fields through public getters. [3](#0-2) [4](#0-3) 

The parent function `update_momentum_position_value()` is publicly accessible without any authorization checks, [5](#0-4) 

and since the Vault is a shared object, [6](#0-5) 

any transaction can call this function. The downstream function `finish_update_asset_value()` only validates vault status, not caller authorization, [7](#0-6) 

and directly updates the vault's `assets_value` table with the calculated USD value.

The oracle slippage check validates that the pool's price is within tolerance of oracle prices, [8](#0-7) 

but this only ensures the malicious pool's price is near oracle values for those coin types—it does not validate that this is the correct pool for the position.

**Contrast with Cetus Implementation:**

The Cetus adaptor correctly validates pool-position association by calling `pool.get_position_amounts(position_id)`, [9](#0-8) 

where the pool itself validates ownership before returning position amounts, preventing cross-pool attacks.

## Impact Explanation

**Direct Financial Impact:**
An attacker can inflate or deflate position valuations by providing a pool with manipulated `sqrt_price` (within oracle slippage tolerance). The liquidity math formula converts position liquidity to token amounts based on the current sqrt_price [10](#0-9) 

—using a different pool's price produces different token amounts, which are then valued at oracle prices to produce incorrect USD totals.

- **Inflated valuations** → existing shares appear more valuable → attackers withdraw more assets than entitled (vault fund theft)
- **Deflated valuations** → existing shares appear less valuable → attackers deposit at discount, acquiring undervalued shares (dilution of existing shareholders)

**Custody Integrity Impact:**
The vault's `assets_value` table becomes corrupted with incorrect position valuations, affecting all operations dependent on accurate USD valuation including share price calculations, deposit/withdrawal amounts, and loss tolerance enforcement.

**Systemic Impact:**
With typical DEX slippage tolerances of 0.5-1%, two pools with the same coin pair can have prices differing by up to 2% (one at +slippage, one at -slippage from oracle). For a vault with $1M in Momentum positions, this enables $20K of value manipulation per attack, directly extractable through subsequent deposit or withdrawal operations.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Access to submit transactions to the shared Vault object (any blockchain user)
- Ability to reference two Momentum pools with same coin types but different prices (publicly available pool objects)
- No special privileges, operator access, or admin capabilities needed

**Attack Complexity:**
Low complexity—the attack requires:
1. Observing a MomentumPosition in the vault (via events or state queries)
2. Identifying or creating Pool B with same `<CoinA, CoinB>` types as the position's Pool A, but different `sqrt_price` (within oracle slippage tolerance)
3. Calling `update_momentum_position_value()` with Pool B reference instead of Pool A
4. The function calculates amounts using Pool B's price, producing incorrect USD valuation that gets written to `assets_value`

**Feasibility Conditions:**
- Vault must be enabled (normal operating condition)
- Position must exist in vault (required for vault functionality)
- Multiple pools with same coin pairs can exist on Momentum with different fee tiers [11](#0-10) 

- Attack cost is minimal (single transaction fee), while potential gain is proportional to vault TVL and price differential

## Recommendation

Add validation to ensure the pool reference matches the position's stored `pool_id`:

```move
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    // Validate pool-position association
    assert!(pool.pool_id() == position.pool_id(), ERR_POOL_POSITION_MISMATCH);
    
    let sqrt_price = pool.sqrt_price();
    // ... rest of implementation
}
```

This mirrors the security model used by the Cetus adaptor, where the pool itself validates position ownership.

## Proof of Concept

```move
#[test]
fun test_cross_pool_manipulation() {
    // Setup: Create vault with position in Pool A (price = 1.0)
    // Create Pool B with same coin types but price = 1.02 (within 2% slippage)
    // Call update_momentum_position_value(vault, config, clock, asset_type, pool_B)
    // Verify: assets_value[asset_type] is ~2% higher than actual value
    // Execute withdrawal with inflated share price to extract excess funds
    
    // This test would demonstrate that:
    // 1. Position liquidity L with Pool A price produces amounts (X1, Y1)
    // 2. Same liquidity L with Pool B price produces amounts (X2, Y2) where X2 > X1 or Y2 > Y1
    // 3. USD value increases without any actual change in position
    // 4. Share price becomes manipulated, enabling fund extraction
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L59-59)
```text
    public fun pool_id(position: &Position) : ID { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L139-139)
```text
    public fun pool_id<X, Y>(pool: &Pool<X, Y>): ID { abort 0 }
```

**File:** volo-vault/sources/volo_vault.move (L456-456)
```text
    transfer::share_object(vault);
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L39-41)
```text
    let position_id = object::id(position);

    let (amount_a, amount_b) = pool.get_position_amounts(position_id);
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/create_pool.move (L17-24)
```text
    public fun new<X, Y>(
        global_config: &mut GlobalConfig,
        fee_rate: u64,
        version: &Version,        
        tx_context: &mut TxContext
    ): Pool<X, Y> {
        abort 0
    }
```
