### Title
Type Confusion in Momentum Position Valuation Enables Vault Fund Drainage

### Summary
The `update_momentum_position_value` function accepts generic type parameters `<CoinA, CoinB>` and a `MomentumPool<CoinA, CoinB>` reference but retrieves a non-generic `MomentumPosition` that stores its token types as `TypeName` fields. The function never validates that the pool's generic types match the position's stored types, allowing any user to call it with mismatched types to artificially inflate asset valuations. This inflates the vault's share ratio, enabling attackers to drain vault funds through excess withdrawals.

### Finding Description

The root cause lies in the type safety gap between the generic `Pool<X, Y>` and non-generic `Position` structs. [1](#0-0) 

The `Position` struct stores token types as runtime `TypeName` values rather than compile-time generics, while `Pool<phantom X, phantom Y>` enforces types at compile time. [2](#0-1) 

The vulnerability manifests in the momentum adaptor's value update function, which is publicly accessible and requires no operator capabilities. [3](#0-2) 

When calculating position value, the function uses the generic type parameters to fetch oracle prices without validating they match the position's actual token types. [4](#0-3) 

The token amount calculation mixes the position's liquidity and tick data with the provided pool's sqrt_price, then values these amounts using oracle prices for the generic type parameters. [5](#0-4) 

Critically, the vault is a shared object accessible to any user. [6](#0-5) 

The price sanity check only validates that the pool's price matches the oracle price for the provided generic types - it does NOT validate these types match the position's stored types. [7](#0-6) 

The inflated value is then used to update the vault's total USD value, which directly impacts the share ratio calculation. [8](#0-7) 

When users withdraw, the share ratio determines their payout amount. [9](#0-8) 

### Impact Explanation

**Direct Fund Theft**: An attacker can drain all vault funds through the following mechanism:

1. Vault holds a MomentumPosition for USDC/USDT (each worth ~$1)
2. Attacker calls `update_momentum_position_value<PrincipalCoin, WETH, WBTC>` with a WETH/WBTC pool (worth $3,000/$60,000 respectively)
3. The position's USD value is calculated using WETH/WBTC oracle prices instead of USDC/USDT prices
4. Position value is inflated by 1,000x-60,000x depending on token price differences
5. Vault's `total_usd_value` is inflated
6. Share ratio becomes: `inflated_total_usd_value / total_shares`
7. When users withdraw, they receive: `shares × inflated_ratio` worth of principal
8. Legitimate withdrawals drain vault principal that should belong to other depositors

**Loss Tolerance Bypass**: The inflated values mask actual losses, allowing violation of the epoch loss tolerance invariant. [10](#0-9) 

**Scope**: All vaults using Momentum positions are vulnerable. The same pattern exists in Cetus adaptor. [11](#0-10) 

### Likelihood Explanation

**Attacker Capabilities**: Any untrusted user can exploit this vulnerability without requiring operator or admin capabilities. In Sui Move, users can publish their own modules containing entry functions that call public functions from other packages.

**Attack Complexity**: Low. The attacker needs to:
1. Publish a malicious Move module with an entry function
2. Call `momentum_adaptor::update_momentum_position_value` with wrong generic types and a pool for those wrong types
3. Deposit minimal funds to receive shares
4. Wait for legitimate users to deposit
5. Withdraw to receive excess principal based on inflated share ratio

**Execution Practicality**: Fully executable under Sui Move semantics. The vault is a shared object accessible via `&mut Vault` references in any transaction. The adaptor functions are public and have no capability checks beyond vault status (enabled/normal).

**Economic Rationality**: 
- Cost: Gas fees for module publishing (~0.01 SUI) + minimal deposit
- Reward: Can extract entire vault principal over time
- Net profit: Potentially millions of dollars for popular vaults

**Detection Difficulty**: The inflated values would appear in `AssetValueUpdated` events but may not trigger immediate alerts if the vault contains multiple positions. [12](#0-11) 

### Recommendation

**Immediate Fix**: Add type validation to all position value update functions. The position should store a validation hash or the pool ID it was created from, and the update function should verify the provided pool matches.

```move
// In momentum.adaptor.move, add validation:
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // CRITICAL: Validate pool types match position types
    let pool_type_x = pool.type_x();
    let pool_type_y = pool.type_y();
    assert!(pool_type_x == position.type_x(), ERR_POOL_TYPE_MISMATCH);
    assert!(pool_type_y == position.type_y(), ERR_POOL_TYPE_MISMATCH);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**Access Control**: Add operator capability requirement to all adaptor value update functions to prevent untrusted users from manipulating valuations.

**Structural Fix**: Consider making Position generic `Position<X, Y>` to leverage compile-time type safety, though this requires significant refactoring.

**Test Cases**: Add regression tests that attempt to call update functions with mismatched pool types and verify they fail with appropriate errors.

### Proof of Concept

**Initial State**:
- Vault contains MomentumPosition for USDC/USDT pair with 10,000 units of liquidity
- Position's actual USD value: ~$20,000
- Vault total_shares: 20,000
- Share ratio: $1 per share

**Attack Steps**:
1. Attacker publishes malicious module:
```move
module attacker::exploit {
    entry fun exploit_vault(
        vault: &mut Vault<SUI>,
        config: &OracleConfig,
        clock: &Clock,
        usdc_usdt_position_asset_type: String,
        weth_wbtc_pool: &mut MomentumPool<WETH, WBTC>,
    ) {
        momentum_adaptor::update_momentum_position_value<SUI, WETH, WBTC>(
            vault,
            config, 
            clock,
            usdc_usdt_position_asset_type,
            weth_wbtc_pool  // Wrong pool!
        );
    }
}
```

2. Attacker calls exploit_vault, passing:
   - The vault's USDC/USDT position asset_type
   - A WETH/WBTC pool reference
   - Generic types <SUI, WETH, WBTC>

3. Function calculates value using WETH ($3,000) and WBTC ($60,000) prices instead of USDC/USDT ($1 each)

**Expected vs Actual Result**:
- Expected: Position value remains ~$20,000, share ratio $1/share
- Actual: Position value inflated to ~$600,000, share ratio becomes $30/share

4. Attacker deposits 1000 SUI, receives 33 shares (at $30/share)
5. Attacker immediately withdraws 33 shares, receives 990 SUI back (33 × $30 / $1)
6. Profit: 990 - 1000 = net loss initially, but vault is now undercollateralized
7. As legitimate users deposit, attacker's inflated shares entitle them to excess withdrawals
8. Vault is drained as attackers extract value exceeding their deposits

**Success Condition**: The vault's `total_usd_value` is inflated without corresponding increase in actual assets, enabling attackers to withdraw more principal than they deposited.

### Notes

This vulnerability also affects the Cetus adaptor with identical type confusion between `CetusPosition` (non-generic) and `CetusPool<CoinA, CoinB>` (generic). The same fix should be applied to all position value update functions across all adaptors.

The mmt_v3 modules appear to be stub implementations (all functions abort), but the vulnerability exists in the integration layer where these stubs are called, making it exploitable once real implementations are deployed.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L16-19)
```text
    public struct Pool<phantom X, phantom Y> has key {
        id: UID,
        type_x: TypeName,
        type_y: TypeName,
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L34-66)
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

**File:** volo-vault/sources/volo_vault.move (L456-456)
```text
    transfer::share_object(vault);
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

**File:** volo-vault/sources/volo_vault.move (L994-1022)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Get the current share ratio
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
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

**File:** volo-vault/sources/volo_vault.move (L1197-1202)
```text
    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
```

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
}
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
