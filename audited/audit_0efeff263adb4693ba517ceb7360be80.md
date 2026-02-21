# Audit Report

## Title
Momentum Adaptor Type Parameter Manipulation Allows Arbitrary Asset Valuation Corruption

## Summary
The `update_momentum_position_value` function accepts generic type parameters `CoinA` and `CoinB` that are not validated against the actual MomentumPosition's stored coin types. An attacker can call this public function with arbitrary type parameters to value positions using incorrect oracle prices, corrupting the vault's `total_usd_value` and enabling theft through share price manipulation.

## Finding Description

The vulnerability exists in the momentum adaptor's value update mechanism. The function is declared as public with generic type parameters that determine which oracle prices are used for valuation: [1](#0-0) 

These type parameters are used to derive type name strings for oracle price lookups: [2](#0-1) 

The calculated USD value is then stored in the vault's asset value table via `finish_update_asset_value`: [3](#0-2) 

**Root Cause:** The MomentumPosition struct stores the correct coin types in `type_x` and `type_y` fields: [4](#0-3) 

However, these fields have NO public getter functions: [5](#0-4) 

The adaptor performs NO validation that the caller-provided type parameters match the position's actual stored types.

**Why Existing Protections Fail:**

The slippage check only compares the pool price against the oracle relative price of the **provided** types, not the position's actual types: [6](#0-5) 

Additionally, the Vault is a shared object accessible to anyone: [7](#0-6) 

The function has public visibility with no capability requirements, and `get_defi_asset` is also public: [8](#0-7) 

## Impact Explanation

The vault's share price is calculated as `total_usd_value / total_shares`: [9](#0-8) 

Where `total_usd_value` is computed by summing all asset values from the `assets_value` table: [10](#0-9) 

**Direct Fund Impact:** An attacker can manipulate this calculation by providing incorrect coin types when valuing MomentumPositions:

1. Vault holds a MomentumPosition with 1000 SUI + 3000 USDC (actual value ~$6,000 at SUI=$3, USDC=$1)
2. Attacker calls `update_momentum_position_value<_, COIN_C, USDC>` where COIN_C has price $30 (maintaining similar price ratio to pass slippage check)
3. Position gets valued as if it contains COIN_C instead of SUI (e.g., $30,000+ instead of $6,000)
4. Vault's `total_usd_value` becomes grossly inflated
5. Share price increases proportionally
6. Attacker or existing holders can withdraw at inflated prices, extracting the difference from other vault participants

This enables:
- **Withdrawal exploitation**: Withdraw when vault is overvalued, receive excess principal
- **Deposit exploitation**: Deposit when vault is undervalued, receive excess shares, then correct and withdraw
- **Value extraction**: Direct theft from existing vault participants

## Likelihood Explanation

**Reachable Entry Point:** The function is public with no capability requirements, and the vault is a shared object.

**Feasible Preconditions:**
1. Attacker needs no special capabilities or permissions
2. Vault must have at least one MomentumPosition asset (normal operational condition)
3. Attacker must identify coin pairs with similar price ratios to the position's actual coins but different absolute prices
   - Example: If position uses coins with ratio 3:1, find different coins also with ratio ~3:1
   - With the variety of tokens on Sui, this is highly feasible

**Execution Practicality:**
1. Query vault to identify stored MomentumPosition assets
2. Identify suitable coin pairs meeting the slippage criteria
3. Call `update_momentum_position_value` with chosen type parameters and a pool reference
4. Exploit the mispriced shares through withdrawal before correction

**Economic Rationality:** Attack requires only transaction fees. The attacker can immediately profit by exploiting the mispriced shares, with potential gains in multiples of the actual position value.

## Recommendation

Add validation to ensure the provided type parameters match the position's stored coin types:

1. Add public getter functions to the MomentumPosition struct for `type_x` and `type_y`
2. In `update_momentum_position_value`, validate that `type_name::get<CoinA>()` matches `position.type_x()` and `type_name::get<CoinB>()` matches `position.type_y()`
3. Alternatively, restrict the function to `package` visibility and only call it from trusted operator flows with proper validation

## Proof of Concept

```move
// Test demonstrating the vulnerability
// 1. Setup vault with MomentumPosition for SUI/USDC
// 2. Call update_momentum_position_value with WETH/USDC types
// 3. Observe inflated total_usd_value
// 4. Calculate excess withdrawal amount available
// This would require a full test setup with oracle config and position creation
```

**Notes**

This is a critical vulnerability that breaks the fundamental accounting invariant of the vault system. The lack of type parameter validation, combined with the public accessibility and shared object model, creates a direct path to fund theft. The vulnerability is exploitable by any external actor without requiring special privileges, making it a high-severity issue requiring immediate remediation.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L51-58)
```text
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/volo_vault.move (L456-456)
```text
    transfer::share_object(vault);
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
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
