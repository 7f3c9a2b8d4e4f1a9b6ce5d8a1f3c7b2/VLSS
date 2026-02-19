### Title
Momentum Position Valuation Excludes Accumulated Fees and Rewards Leading to Systematic Vault Undervaluation

### Summary
The `get_position_token_amounts()` function in the Momentum adaptor calculates position value based solely on active liquidity, completely ignoring accumulated but unclaimed trading fees (`owed_coin_x`, `owed_coin_y`) and rewards (`coins_owed_reward`) that belong to the position. This causes the vault's `total_usd_value` to be systematically understated, leading to incorrect share pricing that disadvantages existing shareholders and enables value extraction through strategic deposit/withdrawal timing.

### Finding Description
The vulnerability exists in the `get_position_token_amounts()` function which is responsible for calculating token amounts held in a Momentum concentrated liquidity position: [1](#0-0) 

This function only retrieves amounts based on active liquidity using `liquidity_math::get_amounts_for_liquidity()`. It never accesses the fee and reward fields that exist on the Position struct: [2](#0-1) 

The Position struct contains three critical fields for accumulated but unclaimed value:
- `owed_coin_x: u64` - accumulated fees in token X
- `owed_coin_y: u64` - accumulated fees in token Y  
- `reward_infos: vector<PositionRewardInfo>` with `coins_owed_reward: u64` - accumulated rewards

Public getter functions exist for these fields: [3](#0-2) 

However, the Momentum adaptor never calls these getters. The calculated amounts flow into position valuation: [4](#0-3) 

This undervalued amount is then stored as the vault's asset value: [5](#0-4) 

The vault's `total_usd_value` is used throughout the protocol for share pricing during deposits and withdrawals, directly impacting all share calculations.

### Impact Explanation
**Direct Fund Impact - Share Mispricing:**

When accumulated fees are excluded from valuation, the vault's `total_usd_value` is understated. This causes:

1. **New Depositor Advantage**: When users deposit, shares are calculated as `deposit_amount * total_shares / total_usd_value`. With understated `total_usd_value`, new depositors receive more shares than they should, diluting existing shareholders.

2. **Existing Shareholder Loss**: Existing shareholders own a claim on accumulated fees that aren't reflected in the vault's reported value. Their shares are worth more than the vault's accounting indicates.

3. **Strategic Exploitation**: Sophisticated actors can:
   - Monitor Momentum pools to identify when significant fees have accumulated
   - Deposit when fees are highest (vault most undervalued) to maximize share allocation
   - Withdraw after fees are collected or before next fee accumulation

**Magnitude**: In active Momentum pools, trading fees can represent 1-5% of position value over time. For a vault with $1M in Momentum positions, this could mean $10,000-$50,000 in unaccounted value - a material discrepancy affecting all share pricing.

**Affected Parties**: All vault shareholders suffer dilution with each new deposit while fees remain unclaimed.

**Severity Justification**: HIGH - This violates the critical invariant "total_usd_value correctness" and causes measurable fund impact through systematic share mispricing.

### Likelihood Explanation
**Reachable Entry Point**: The `update_momentum_position_value()` function is called by vault operators as part of normal operations before processing deposits and withdrawals.

**Feasible Preconditions**: 
- Vault holds Momentum positions (expected use case)
- Trading activity occurs in the Momentum pool (natural market behavior)
- Time passes, allowing fees to accumulate (passive occurrence)

**Execution Practicality**: This is not an active attack but a systematic accounting error. Fees accumulate automatically whenever trades occur in the underlying Momentum pool. No special actions are required - the vulnerability manifests during normal protocol operation.

**Economic Rationality**: 
- **Zero attack cost**: Fees accumulate naturally
- **Low detection risk**: Undervaluation appears as normal price variance
- **Exploitable pattern**: Depositors who monitor pool fee accrual can time deposits for maximum advantage
- **Continuous opportunity**: Occurs with every valuation update while fees remain unclaimed

**Probability**: CERTAIN - This happens with every position valuation update. The only variable is the magnitude of accumulated fees, which grows over time and with trading volume.

### Recommendation
**Code-Level Mitigation:**

Modify `get_position_token_amounts()` to include accumulated fees and rewards:

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
    
    // ADD: Include accumulated fees
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    
    amount_a = amount_a + owed_a;
    amount_b = amount_b + owed_b;
    
    // ADD: Include accumulated rewards if tracking reward value is desired
    // Note: Rewards may be in different token types and require separate valuation
    
    (amount_a, amount_b, sqrt_price)
}
```

**Invariant Checks:**
- Add assertion that total position value >= liquidity-based value (fees are additive)
- Log fee amounts separately for monitoring and validation
- Consider periodic fee collection to minimize accumulation

**Test Cases:**
1. Create position, generate trading fees, verify valuation includes fees
2. Test with multiple reward tokens active
3. Verify correct behavior when fees are zero
4. Test maximum fee accumulation scenarios

### Proof of Concept

**Initial State:**
- Vault holds a Momentum position with 1000 USDC + 1000 USDT in liquidity (worth $2000)
- Trading activity generates 50 USDC + 50 USDT in accumulated fees (worth $100)
- Position struct has: `liquidity = X`, `owed_coin_x = 50`, `owed_coin_y = 50`

**Execution Steps:**

1. Operator calls `update_momentum_position_value()` to update vault valuation
2. Function calls `get_position_value()` → `get_position_token_amounts()`
3. `get_position_token_amounts()` calculates amounts from liquidity only: returns (1000, 1000)
4. `get_position_value()` calculates: 1000 USDC ($1000) + 1000 USDT ($1000) = $2000 total
5. Vault's `total_usd_value` is set to $2000 (should be $2100)

**Impact Demonstration:**

6. User deposits $1000 when vault should be worth $2100 (100 existing shares)
7. Expected shares (correct): 1000 * 100 / 2100 = 47.62 shares
8. Actual shares (incorrect): 1000 * 100 / 2000 = 50 shares
9. User receives 2.38 extra shares (worth $50), diluting existing shareholders by $50

**Expected vs Actual Result:**
- **Expected**: Position valued at $2100 including $100 in fees
- **Actual**: Position valued at $2000, excluding $100 in fees
- **Success Condition for Exploit**: New depositor receives >47.62 shares for $1000 deposit

**Verification**: Check `owed_coin_x` and `owed_coin_y` on the Position object - these values exist but are never read by the valuation logic.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L54-55)
```text
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
```
