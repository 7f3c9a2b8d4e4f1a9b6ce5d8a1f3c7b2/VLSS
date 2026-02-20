# Audit Report

## Title
Momentum Position Value Calculation Excludes All Uncollected Trading Fees

## Summary
The Momentum adaptor systematically excludes uncollected trading fees from position valuations, causing the vault's share price to be artificially depressed. This enables value extraction through share dilution during deposits and reduced payouts during withdrawals, breaking the fundamental accounting invariant that `total_usd_value` must reflect all vault-owned claimable assets.

## Finding Description

The vulnerability exists in the Momentum adaptor's incomplete position valuation logic. The `get_position_value()` function calculates position value by calling `get_position_token_amounts()` [1](#0-0) , which retrieves only the liquidity component through `liquidity_math::get_amounts_for_liquidity()` [2](#0-1) .

However, the Momentum `Position` struct tracks uncollected trading fees in separate fields that are never accessed during valuation [3](#0-2) . These fields include `owed_coin_x` and `owed_coin_y` (fees ready for collection) and `fee_growth_inside_x_last` and `fee_growth_inside_y_last` (tracking newly accrued fees).

The Momentum protocol provides public getter functions for these fee fields [4](#0-3)  and a separate fee collection mechanism [5](#0-4) , but the Volo adaptor never invokes these getters during valuation.

This incomplete valuation directly impacts the vault's share price calculation. The `get_share_ratio()` function divides `total_usd_value` by `total_shares` [6](#0-5) , where `total_usd_value` is calculated by summing all asset values from the `assets_value` table [7](#0-6) . Since Momentum position values exclude fees, the total value is systematically underestimated.

During deposits, the undervalued share ratio is used to calculate shares to mint: `user_shares = new_usd_value_deposited / share_ratio_before` [8](#0-7) . A lower share ratio results in minting MORE shares for the same deposit amount, diluting existing shareholders.

During withdrawals, the same undervalued ratio calculates payout amounts: `usd_value_to_withdraw = shares_to_withdraw * ratio` [9](#0-8) , resulting in withdrawing users receiving LESS value than their shares represent.

## Impact Explanation

This vulnerability breaks the fundamental accounting invariant that the vault's `total_usd_value` must reflect the actual total value of all vault-owned assets. The impact is direct fund loss through:

1. **Share dilution**: When new users deposit while uncollected fees exist, they receive proportionally more shares than deserved. If a vault has $100,000 in liquidity and $5,000 in uncollected fees, the share price is calculated based on only $100,000, causing a 5% dilution of existing shareholders.

2. **Withdrawal underpayment**: When users withdraw, they receive amounts based on the undervalued share ratio, effectively leaving a portion of their entitled value in the vault for others to claim.

3. **Compounding effect**: The discrepancy grows over time as trading activity in Momentum pools generates more fees. High-volume pools accumulate fees faster, making the undervaluation more severe.

4. **Exploitability**: Sophisticated actors can monitor on-chain fee accumulation and time deposits to maximize gains immediately before any fee collection operations, extracting maximum value from existing shareholders.

The vault stores these `MomentumPosition` objects in its asset bag [10](#0-9) , meaning the uncollected fees legally belong to the vault and represent real, claimable value that should be accounted for in valuations.

## Likelihood Explanation

This vulnerability triggers automatically during normal vault operations with high likelihood:

1. **No special preconditions**: Fees naturally accrue from trading activity in Momentum pools. Any position in an active pool will accumulate fees over time.

2. **Frequent occurrence**: The undervaluation persists continuously between any potential fee collection operations. The `update_momentum_position_value()` function is called during regular vault operations [11](#0-10) , and each call uses the incomplete calculation.

3. **No privilege required**: Any user can deposit or withdraw through the standard vault interfaces, triggering the incorrect share calculations.

4. **Economic incentive**: The attack cost is minimal (only gas fees), while gains are proportional to the accumulated uncollected fees as a percentage of vault value. Even a 1-2% fee accumulation represents significant value in large vaults.

5. **Detection difficulty**: The undervaluation appears as normal share price behavior rather than an obvious exploit, making it hard to detect until substantial value has been extracted.

## Recommendation

Modify the `get_position_value()` function in the Momentum adaptor to include uncollected fees:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
    
    // Add uncollected fees to the amounts
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    amount_a = amount_a + owed_a;
    amount_b = amount_b + owed_b;
    
    // Rest of the existing logic...
}
```

This ensures that the position's full claimable value is included in the vault's `total_usd_value` calculation, maintaining the correct share price.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a vault with a Momentum position in an active trading pool
2. Allowing trading activity to generate uncollected fees in the position
3. Observing that `get_position_value()` returns only the liquidity value, excluding `owed_coin_x` and `owed_coin_y`
4. Showing that deposits receive more shares than they should due to the artificially low share ratio
5. Showing that withdrawals receive less value than they should based on the same undervalued ratio

The core issue is evident from the code: `get_position_token_amounts()` [12](#0-11)  only calculates liquidity amounts and never accesses the `owed_coin_x()` or `owed_coin_y()` getters that would return the uncollected fees [13](#0-12) , despite these fees being real, claimable vault assets.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L40-40)
```text
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L18-22)
```text
        liquidity: u128,
        fee_growth_inside_x_last: u128,
        fee_growth_inside_y_last: u128,
        owed_coin_x: u64,
        owed_coin_y: u64,
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L54-57)
```text
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
    public fun fee_growth_inside_x_last(position: &Position) : u128 { abort 0 }
    public fun fee_growth_inside_y_last(position: &Position) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/collect.move (L25-33)
```text
    public fun fee<X, Y>(
        pool: &mut Pool<X, Y>, 
        position: &mut Position, 
        clock: &Clock, 
        version: &Version,
        tx_context: &mut TxContext
    ) : (Coin<X>, Coin<Y>) {
        abort 0
    }
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1013-1013)
```text
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```
