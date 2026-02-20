# Audit Report

## Title
Momentum Position Valuation Excludes Uncollected Trading Fees Leading to Systematic Undervaluation

## Summary
The Momentum adaptor systematically excludes uncollected trading fees (`owed_coin_x` and `owed_coin_y`) from position valuations, causing all Momentum positions to be undervalued. This directly impacts vault share price calculations, resulting in unfair distribution during deposits (users receive excess shares diluting existing holders) and withdrawals (users receive insufficient principal).

## Finding Description

The Momentum Position struct contains fields for tracking uncollected trading fees that accrue automatically from pool swap activity [1](#0-0) , with public getter functions available to retrieve these amounts [2](#0-1) . These fees represent real claimable value that can be collected via the Momentum protocol's fee collection function [3](#0-2) .

However, the vault's `get_position_token_amounts()` function only retrieves the position's liquidity amount and converts it to token amounts, completely ignoring the `owed_coin_x` and `owed_coin_y` fields [4](#0-3) .

This incomplete valuation propagates through the system:

1. The undervalued token amounts are used directly in USD value calculation [5](#0-4) 

2. The undervalued USD amount is stored in the vault's `assets_value` table [6](#0-5) 

3. The vault's total USD value calculation sums all these undervalued amounts [7](#0-6) 

4. The share ratio (share price) is calculated as `total_usd_value / total_shares`, producing an artificially low ratio [8](#0-7) 

This breaks the fundamental vault accounting invariant: share price must accurately reflect ALL vault assets, including accrued but uncollected value.

## Impact Explanation

**Direct Fund Misallocation:**

The undervalued share ratio directly impacts fund distribution:

- **Deposits**: Users receive shares calculated as `new_usd_value / share_ratio` [9](#0-8) . Since share_ratio is artificially low, depositors receive more shares than they should, directly diluting existing holders.

- **Withdrawals**: Users receive principal calculated as `shares * ratio` [10](#0-9) . Since ratio is artificially low, withdrawers receive less principal than their shares are actually worth.

**Quantifiable Impact**: If a Momentum position has $1,000 in liquidity value and $100 in uncollected fees, the vault values it at only $1,000 (9% undervaluation). This causes:
- Share ratio to be 9% too low
- New depositors to receive 9% more shares than fair value
- Withdrawers to receive 9% less principal than their shares represent

**Cumulative Effect**: Trading fees accumulate automatically on active positions with every pool swap. High-volume positions can accumulate significant fees, causing substantial misvaluation that grows over time.

**Affected Parties**:
- New depositors gain unfair advantage (excess shares)
- Withdrawers suffer direct losses (insufficient principal)
- Existing holders are systematically diluted
- Protocol TVL reporting is incorrect

## Likelihood Explanation

**Certainty: 100% - This is a systematic accounting bug, not an exploit scenario.**

**Automatic Trigger**: Trading fees accumulate automatically on Momentum liquidity positions whenever swaps occur in the underlying pool. The Momentum protocol is designed to reward liquidity providers with these fees, which are tracked in the position's `owed_coin_x` and `owed_coin_y` fields and can be collected at any time [11](#0-10) .

**No Attack Required**: Every call to `update_momentum_position_value()` produces an undervalued result whenever the position has any uncollected fees. This is the normal operational state for active positions - fees accumulate continuously.

**Preconditions**: Only requires the vault to hold a Momentum position with trading activity in its pool - standard operational conditions. No attacker action or special setup needed.

## Recommendation

Modify `get_position_token_amounts()` to include uncollected fees in the valuation:

```move
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
    
    // ADD: Include uncollected fees in valuation
    let total_amount_a = amount_a + position.owed_coin_x();
    let total_amount_b = amount_b + position.owed_coin_y();
    
    (total_amount_a, total_amount_b, sqrt_price)
}
```

Alternatively, consider periodically collecting fees from Momentum positions during operations and adding them to the vault's principal or separate fee tracking.

## Proof of Concept

While a complete on-chain test would require Momentum pool setup with trading activity to generate fees, the logic flow can be demonstrated:

1. Vault holds Momentum position with liquidity value of 1000 USDC
2. Pool trading activity generates 100 USDC in uncollected fees (tracked in `owed_coin_x`)
3. Operator calls `update_momentum_position_value()` 
4. `get_position_token_amounts()` returns only liquidity amount (1000), ignoring 100 in fees
5. Position valued at $1000 instead of $1100 (9% undervaluation)
6. User deposits $1100
7. Share ratio calculated with undervalued total (missing $100)
8. User receives ~9% more shares than fair value
9. Existing holders diluted by 9%
10. Later withdrawer with same shares receives 9% less principal

The vulnerability is deterministic - it occurs on every valuation when fees exist, which is the standard state for active liquidity positions.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L21-22)
```text
        owed_coin_x: u64,
        owed_coin_y: u64,
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L54-55)
```text
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
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

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1011-1023)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L338-359)
```markdown
9. Collect fee

```move
/// Collects the fee for a given position in the specified pool.
///
/// # Parameters
/// - `pool`: A mutable reference to the pool from which the fee will be collected.
/// - `position`: A mutable reference to the position for which the fee will be collected.
/// - `clock`: A reference to the clock object to track time.
/// - `version`: A reference to the version object to ensure compatibility.
/// - `tx_context`: A mutable reference to the transaction context.
///
/// # Returns
/// A tuple containing the coins of type X and Y representing the collected fee.
public fun fee<X, Y>(
    pool: &mut Pool<X, Y>, 
    position: &mut Position, 
    clock: &Clock, 
    version: &Version,
    tx_context: &mut TxContext
    ) : (Coin<X>, Coin<Y>) {}
```
```
