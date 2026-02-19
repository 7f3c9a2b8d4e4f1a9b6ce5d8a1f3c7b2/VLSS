# Audit Report

## Title
Type Safety Bypass in Momentum Position Valuation Allows Arbitrary Value Manipulation

## Summary
The `update_momentum_position_value` function accepts arbitrary generic type parameters without validating they match the position's actual coin types stored as runtime `TypeName` values. This allows attackers to value Momentum positions using completely wrong coin prices, manipulating the vault's total USD value and share ratio to steal funds from other depositors.

## Finding Description

**Root Cause - Type System Mismatch:**

The Momentum `Position` struct stores coin types as runtime `TypeName` values in its `type_x` and `type_y` fields, not as compile-time generic parameters. [1](#0-0) 

In contrast, the `Pool` struct uses compile-time generic type parameters `<phantom X, phantom Y>`. [2](#0-1) 

The vulnerability exists in `update_momentum_position_value` which is a public function accepting arbitrary generic type parameters `<PrincipalCoinType, CoinA, CoinB>` without any validation. [3](#0-2) 

**Critical Missing Validations:**

The function retrieves the position using only the asset_type string identifier, then immediately calls `get_position_value` with whatever pool and type parameters the caller provided. [4](#0-3) 

Inside `get_position_value`, the coin type names are derived from the GENERIC PARAMETERS (not from the position's stored type_x/type_y fields), and oracle prices are fetched for these potentially wrong types. [5](#0-4) 

The position amounts are calculated using the position's liquidity and tick range with the pool's sqrt_price, but then valued using prices for the wrong coin types. [6](#0-5) 

**Why Existing Protections Fail:**

The slippage check only validates that the provided pool's price matches the oracle price ratio for the types specified in the generic parameters - it does NOT validate that these types match the position's actual coin types. [7](#0-6) 

There is no verification that:
1. The pool's ID matches the position's stored `pool_id` field (despite `pool_id()` getter being available at line 59 of position.move and `verify_pool()` function existing at line 106-111 of pool.move)
2. The generic parameters CoinA/CoinB match the position's type_x/type_y

The `get_defi_asset` function performs no type checking - it simply borrows from the Bag using the string key. [8](#0-7) 

## Impact Explanation

**Direct Fund Theft via Share Ratio Manipulation:**

The manipulated USD value directly updates the vault's `assets_value` table. [9](#0-8) 

The vault's `get_total_usd_value` function sums all asset values from this table. [10](#0-9) 

The share ratio is calculated as `total_usd_value / total_shares`, directly using the manipulated total. [11](#0-10) 

User shares are calculated as `new_usd_value_deposited / share_ratio_before`, meaning an inflated total_usd_value leads to receiving disproportionately more shares. [12](#0-11) 

**Attack Scenario:**
1. Vault holds a Momentum position for SUI/USDC (SUI price = $3)
2. Attacker calls `update_momentum_position_value<PrincipalCoin, WETH, USDC>` where WETH = $3000
3. Provides a legitimate WETH/USDC pool
4. Function values the SUI/USDC position using WETH prices, inflating value 1000x
5. Attacker immediately deposits funds, receiving massive shares due to inflated total_usd_value
6. Later when value is corrected (or through normal operations), attacker withdraws more funds than deposited

**Severity: HIGH** - Direct theft of user funds with no authorization requirements and minimal execution cost.

## Likelihood Explanation

**Attack is Highly Feasible:**

1. **No Access Control:** The function is `public` with no capability checks beyond vault being enabled. [13](#0-12) 

2. **Low Prerequisites:**
   - Attacker only needs to identify a Momentum position in the vault
   - Must use oracle-registered coin types (WETH, WBTC, USDT are standard)
   - Must provide a legitimate pool for those types (publicly available on DEXs)

3. **Simple Execution:**
   - Single Programmable Transaction Block with wrong type arguments
   - No timing constraints or complex state manipulation
   - Slippage check passes because attacker uses a real pool with matching types

4. **Economic Viability:**
   - Cost: Only transaction fees (minimal)
   - Reward: Proportional to vault TVL
   - Risk: Low detection until value correction

**Probability: HIGH** - Attack is straightforward with readily available components and no significant barriers.

## Recommendation

**Immediate Fix - Add Type Validation:**

1. Add validation that the provided pool's type parameters match the position's stored coin types:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // CRITICAL: Validate coin types match
    let pool_type_x = pool.type_x();
    let pool_type_y = pool.type_y();
    assert!(type_name::get<CoinA>() == pool_type_x, ERR_TYPE_MISMATCH);
    assert!(type_name::get<CoinB>() == pool_type_y, ERR_TYPE_MISMATCH);
    
    // CRITICAL: Validate pool ID matches
    let position_pool_id = position.pool_id();
    pool.verify_pool<CoinA, CoinB>(position_pool_id);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

2. Consider restricting the function to `public(package)` visibility and requiring operator capabilities for value updates.

## Proof of Concept

```move
#[test]
fun test_momentum_type_safety_bypass() {
    // Setup: Vault with SUI/USDC Momentum position valued at $1000
    let vault = create_test_vault();
    let sui_usdc_position = create_momentum_position(/* SUI/USDC */);
    vault.add_defi_asset(sui_usdc_position, "momentum_pos_1");
    
    // Attack: Call with WETH/USDC types (WETH=$3000, SUI=$3 = 1000x inflation)
    let weth_usdc_pool = get_legitimate_pool<WETH, USDC>();
    
    // This should fail but currently succeeds
    update_momentum_position_value<PrincipalCoin, WETH, USDC>(
        &mut vault,
        &oracle_config,
        &clock,
        string::utf8(b"momentum_pos_1"),
        &mut weth_usdc_pool
    );
    
    // Result: Position now valued at $1,000,000 instead of $1,000
    let total_value = vault.get_total_usd_value(&clock);
    assert!(total_value == 1_000_000_000_000_000_000_000, 0); // 1000x inflated
    
    // Attacker deposits $1000, gets shares worth $1,000,000
    // Withdraws later stealing $999,000 from other depositors
}
```

**Notes:**
- This vulnerability affects all Momentum positions in any Volo vault
- The same pattern exists in the Cetus adaptor and should be checked
- The fix requires both type validation and pool ID verification
- Consider implementing a whitelist of valid pool-position pairs for additional security

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L14-15)
```text
        type_x: TypeName,
        type_y: TypeName,
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L16-16)
```text
    public struct Pool<phantom X, phantom Y> has key {
```

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

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1180-1181)
```text
    self.check_version();
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1183-1184)
```text
    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;
```

**File:** volo-vault/sources/volo_vault.move (L1289-1291)
```text
    self.asset_types.do_ref!(|asset_type| {
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/volo_vault.move (L1451-1456)
```text
public fun get_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &Vault<PrincipalCoinType>,
    asset_type: String,
): &AssetType {
    self.assets.borrow<String, AssetType>(asset_type)
}
```
