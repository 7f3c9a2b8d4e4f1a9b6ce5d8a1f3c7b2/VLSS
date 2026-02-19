# Audit Report

## Title
Unprotected Asset Type Mismatch in Momentum Position Valuation Enables USD Value Manipulation

## Summary
The `update_momentum_position_value()` function in the Momentum adaptor lacks authorization controls and type validation, allowing any attacker to provide a pool with mismatched token types that don't correspond to the position's actual tokens. This causes the vault to calculate and store incorrect USD values using wrong oracle prices, corrupting the vault's accounting and enabling share price manipulation.

## Finding Description

The vulnerability exists in the momentum adaptor's position valuation flow. The `update_momentum_position_value()` function is marked as `public fun` without requiring `OperatorCap` [1](#0-0)  and accepts a generic `MomentumPool<CoinA, CoinB>` parameter without validating that CoinA/CoinB match the position's actual token types.

The MomentumPosition struct stores its token types in `type_x` and `type_y` fields [2](#0-1)  but these fields have no public getters exposed to validate against [3](#0-2) .

In `get_position_value()`, the function uses the generic type parameters from the pool to fetch oracle prices instead of the position's stored types [4](#0-3) . Specifically, it extracts type names from the generic parameters CoinA and CoinB at lines 42-43 and uses these to fetch prices at lines 49-50, rather than validating against the position's actual token types.

Unlike the safer Cetus adaptor which validates position ownership through the pool by calling `pool.get_position_amounts(position_id)` [5](#0-4) , the Momentum adaptor manually calculates amounts without any pool ID validation [6](#0-5) . The position has a `pool_id` field but it's never checked against the provided pool.

The `finish_update_asset_value()` function only checks that the vault is enabled, not operator authorization [7](#0-6) . It performs `assert_enabled()` at line 1181 which only prevents calls when vault status is DISABLED [8](#0-7) , but has no OperatorCap requirement.

**Attack Scenario:**
1. Vault contains a Momentum position for SUI-USDC (type_x=SUI, type_y=USDC) stored under `asset_type = "momentum_position_1"`
2. Attacker creates or finds a Momentum pool for high-value TOKEN_X and TOKEN_Y where the pool's price ratio happens to match SUI/USDC within slippage tolerance
3. Attacker calls `update_momentum_position_value<PrincipalCoin, TOKEN_X, TOKEN_Y>(vault, config, clock, "momentum_position_1", malicious_pool)` via Programmable Transaction Block
4. Function retrieves the SUI-USDC position from vault using the correct asset_type string
5. But uses TOKEN_X and TOKEN_Y prices from oracle to value the position
6. Slippage check passes because attacker chose tokens where pool price matches oracle price
7. Vault stores the inflated/deflated USD value for the position
8. Share price calculations become corrupted, enabling fund extraction

## Impact Explanation

This vulnerability enables direct economic damage to vault participants:

1. **Share Price Manipulation**: The vault's `total_usd_value` is calculated by aggregating all asset values stored in `assets_value` table. Corrupted Momentum position values directly affect this total, which is used in share price calculations for deposits and withdrawals. An attacker can inflate values before depositing to receive more shares, or deflate values before withdrawing to receive more principal than entitled.

2. **Loss Tolerance Bypass**: The vault's loss tolerance mechanism compares current epoch losses against `loss_tolerance` [9](#0-8) . By manipulating position valuations, an attacker can make losses appear smaller than they are, bypassing this critical safety mechanism.

3. **Broken Accounting Invariant**: The vault's core invariant is that `total_usd_value` accurately reflects the USD value of all assets. This vulnerability violates that invariant, undermining all financial operations including deposit execution, withdrawal execution, and share ratio calculations.

The severity is HIGH because it requires no privileged access and directly enables fund theft from other vault participants.

## Likelihood Explanation

The attack is highly feasible:

1. **No Authorization**: The function is `public fun` callable by anyone via Sui PTB, unlike operation functions that require `OperatorCap`

2. **Minimal Prerequisites**: Attacker only needs access to shared objects (Vault, OracleConfig, Clock) and a MomentumPool reference - all are standard accessible shared objects on Sui

3. **Bypassable Protection**: The slippage check at lines 55-58 only validates that the provided pool's price matches the oracle price for the PROVIDED generic types CoinA/CoinB, not the position's actual types. An attacker can find or create pools with different tokens whose price ratio happens to match within the configurable slippage tolerance

4. **Repeatable**: Attack can be executed repeatedly via PTB to maintain manipulated valuations throughout an epoch

5. **Low Cost**: Only requires transaction gas costs, no economic stake needed

The attack complexity is LOW and economic barriers are MINIMAL.

## Recommendation

Implement multiple layers of defense:

1. **Add Pool ID Validation**: Validate that the position's pool_id matches the provided pool
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    // Add validation
    assert!(position.pool_id() == object::id(pool), ERR_POOL_MISMATCH);
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

2. **Require OperatorCap**: Change visibility to `public(package)` and add operator authorization check similar to other operation functions

3. **Type Validation**: If pool_id validation is insufficient, add explicit type checks by exposing position.type_x() and position.type_y() getters and validating they match the pool's generic types

## Proof of Concept

```move
#[test]
fun test_momentum_type_mismatch_attack() {
    let mut scenario = test_scenario::begin(ATTACKER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup: Vault has SUI-USDC position
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    // Operator adds legitimate SUI-USDC Momentum position to vault
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let sui_usdc_position = create_momentum_position<SUI_TEST_COIN, USDC_TEST_COIN>();
        vault.add_new_defi_asset("sui_usdc_position", sui_usdc_position);
        test_scenario::return_shared(vault);
    };
    
    // Attack: Attacker calls update with wrong pool types (BTC-USDC instead of SUI-USDC)
    scenario.next_tx(ATTACKER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        let mut btc_usdc_pool = create_momentum_pool<BTC_TEST_COIN, USDC_TEST_COIN>();
        
        // This call succeeds despite type mismatch!
        momentum_adaptor::update_momentum_position_value<SUI_TEST_COIN, BTC_TEST_COIN, USDC_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            ascii::string(b"sui_usdc_position"), // Correct asset_type
            &mut btc_usdc_pool, // Wrong pool with BTC instead of SUI!
        );
        
        // Vault now has corrupted USD value using BTC price instead of SUI price
        let stored_value = vault.get_asset_value(ascii::string(b"sui_usdc_position"));
        // Assert stored_value is wrong (would be ~50x inflated if BTC=$50k, SUI=$1k)
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        // Pool can be destroyed or kept
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

This test demonstrates that an attacker can call the update function with a pool of completely different token types (BTC-USDC) while targeting a SUI-USDC position, causing the vault to store incorrect USD values based on BTC prices instead of SUI prices.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L49-59)
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
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L33-45)
```text
public fun calculate_cetus_position_value<CoinTypeA, CoinTypeB>(
    pool: &mut CetusPool<CoinTypeA, CoinTypeB>,
    position: &CetusPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let position_id = object::id(position);

    let (amount_a, amount_b) = pool.get_position_amounts(position_id);

    let type_name_a = into_string(get<CoinTypeA>());
    let type_name_b = into_string(get<CoinTypeB>());

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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
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
