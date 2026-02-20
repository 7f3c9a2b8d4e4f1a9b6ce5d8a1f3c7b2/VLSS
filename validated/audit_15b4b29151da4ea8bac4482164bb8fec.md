# Audit Report

## Title
Type Confusion in Momentum Position Valuation Enables Vault Fund Drainage

## Summary
The `update_momentum_position_value` function is publicly accessible without capability checks and accepts generic type parameters that determine which oracle prices to use for position valuation. However, it never validates these types match the position's actual token types stored as runtime `TypeName` fields. This allows any user to artificially inflate asset valuations by pricing a low-value position (USDC/USDT) using high-value token prices (WETH/WBTC), directly inflating the vault's share ratio and enabling theft of principal from other depositors through excess withdrawals.

## Finding Description

The vulnerability stems from a critical type safety gap between compile-time generics and runtime type storage in the Momentum adaptor integration.

The Momentum `Position` struct stores its token types as runtime `TypeName` values [1](#0-0) , while the pool uses compile-time phantom type parameters. This creates a fundamental mismatch.

The `update_momentum_position_value` function is declared as public with no operator capability requirement [2](#0-1) . Since the Vault is a shared object [3](#0-2) , any address can call this function.

The function retrieves a position from the vault by string key without type validation [4](#0-3) , then calculates its value using the **caller-provided** generic type parameters to fetch oracle prices [5](#0-4)  and value the token amounts [6](#0-5) .

The `finish_update_asset_value` function only verifies the vault is enabled [7](#0-6)  with no capability or type validation, then stores the manipulated value [8](#0-7) .

While a price sanity check exists [9](#0-8) , it only validates the pool price matches the oracle price **for the provided generic types**, never verifying these types match the position's stored `type_x` and `type_y` fields.

The inflated asset value directly affects vault accounting: it's summed into `total_usd_value` [10](#0-9) , which determines the share ratio [11](#0-10) , which directly controls withdrawal payouts [12](#0-11) .

**Attack Execution:**
1. Attacker deposits principal legitimately to acquire shares
2. Vault contains a Momentum position for USDC/USDT pair (each worth ~$1)
3. Attacker calls `update_momentum_position_value<PrincipalCoin, WETH, WBTC>` providing a WETH/WBTC pool
4. Function calculates position's token amounts but values them using WETH ($3,000) and WBTC ($60,000) oracle prices
5. Position value inflates from $20,000 to potentially $30,000,000+ (1,000x-1,500x multiplier)
6. Total vault value becomes inflated proportionally
7. Share ratio = inflated_total_value / total_shares becomes inflated
8. Attacker requests withdrawal using inflated share ratio
9. Withdrawal amount calculation multiplies shares by inflated ratio
10. Attacker extracts excess principal limited only by available `free_principal` balance
11. Other depositors lose funds proportional to the theft

The identical vulnerability exists in the Cetus adaptor [13](#0-12) .

## Impact Explanation

**Critical Fund Theft**: This vulnerability enables systematic theft of vault principal through share ratio manipulation. An attacker can inflate position values by thousands of times by substituting high-value token prices (WETH at $3,000, WBTC at $60,000) for the position's actual low-value tokens (USDC/USDT at ~$1 each).

The inflated share ratio directly translates to excess principal extraction during withdrawals. Since withdrawal amounts are calculated as `shares × share_ratio` and paid from `free_principal`, the attacker receives far more principal than their rightful share. This theft comes directly from other depositors' funds.

The attack can be repeated to drain vaults systematically. As operators return deployed capital to `free_principal` for normal operations, attackers can immediately exploit the inflated ratio to extract it. Over time, this enables draining the entire vault.

**Loss Tolerance Bypass**: The inflated asset values mask actual investment losses, allowing the vault to violate its epoch loss tolerance invariant [14](#0-13)  without detection.

**Widespread Impact**: All vaults using Momentum or Cetus positions are vulnerable. Given these are major DeFi protocols on Sui, popular vaults could hold millions in TVL.

## Likelihood Explanation

**Highly Exploitable**:

- **No Privileges Required**: The update function is public and the vault is a shared object. Any address can call it.

- **Simple Execution**: Attacker needs only to:
  1. Deposit minimal principal to acquire shares
  2. Call the public update function with mismatched type parameters
  3. Request withdrawal to extract excess principal
  
- **Low Cost**: Only gas fees plus minimal deposit amount required

- **High Reward**: Can extract all available `free_principal`, potentially millions in large vaults

- **No Race Conditions**: Unlike typical MEV, this doesn't require front-running. The attacker controls timing completely.

**Realistic Preconditions**: Requires only an enabled vault with Momentum/Cetus positions, which represents the standard operational state for these vault types.

**Detection Challenges**: While `AssetValueUpdated` events emit the inflated values, they may not trigger immediate alerts in vaults with multiple positions or during market volatility. The attacker can execute the full attack in a single transaction block.

## Recommendation

Add compile-time type validation by storing and checking phantom type parameters. Specifically:

1. **Immediate Fix**: Restrict `update_momentum_position_value` to require operator capability:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    _: &OperatorCap,  // Add capability check
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
)
```

2. **Proper Fix**: Store positions with phantom type parameters and validate at runtime:
```move
// Store position type information
public struct MomentumPositionWrapper<phantom CoinA, phantom CoinB> has key, store {
    id: UID,
    position: MomentumPosition,
}

// Validate types match
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let wrapper = vault.get_defi_asset<PrincipalCoinType, MomentumPositionWrapper<CoinA, CoinB>>(asset_type);
    // Type mismatch would fail at compile time
    let position = &wrapper.position;
    // ... continue with validation
}
```

Apply the same fixes to the Cetus adaptor.

## Proof of Concept

```move
#[test]
fun test_type_confusion_exploit() {
    // Setup vault with USDC/USDT position worth $20,000
    let vault = create_test_vault();
    add_momentum_position<USDC, USDT>(vault, 10000, 10000); // Worth $20k
    
    // Attacker deposits $1,000 to get shares
    let attacker_shares = deposit(vault, 1000);
    assert!(get_share_ratio(vault) == 1.0); // $1 per share
    
    // Attacker calls update with wrong types (WETH/WBTC instead of USDC/USDT)
    let weth_wbtc_pool = get_pool<WETH, WBTC>();
    update_momentum_position_value<PrincipalCoin, WETH, WBTC>(
        vault,
        config,
        clock,
        "MomentumPosition",
        weth_wbtc_pool
    );
    
    // Position value now inflated (valued using WETH=$3k, WBTC=$60k instead of USDC=$1)
    let total_value = get_total_usd_value(vault);
    assert!(total_value > 30_000_000); // Inflated from $21k to $30M+
    
    // Share ratio becomes inflated
    let ratio = get_share_ratio(vault);
    assert!(ratio > 1000.0); // Was $1, now $1000+
    
    // Attacker withdraws, extracting excess principal
    let withdrawal = execute_withdraw(vault, attacker_shares);
    assert!(withdrawal > 20_000); // Stole $20k from other depositors
}
```

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L14-15)
```text
        type_x: TypeName,
        type_y: TypeName,
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L28-28)
```text
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L63-64)
```text
    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/volo_vault.move (L456-456)
```text
    transfer::share_object(vault);
```

**File:** volo-vault/sources/volo_vault.move (L626-640)
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

**File:** volo-vault/sources/volo_vault.move (L1180-1181)
```text
    self.check_version();
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1309-1309)
```text
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
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
