# Audit Report

## Title
Concentrated Liquidity Position Valuation Excludes Unclaimed Fees Leading to Share Dilution

## Summary
The Cetus and Momentum adaptors systematically underreport vault position values by excluding unclaimed trading fees, causing an artificially deflated share ratio that results in excess share minting during deposits. This directly dilutes existing shareholders' ownership through normal vault operations without requiring any attack.

## Finding Description

Concentrated Liquidity Market Maker (CLMM) positions accumulate trading fees in dedicated storage fields separate from principal liquidity. The Momentum Position struct explicitly defines `owed_coin_x` and `owed_coin_y` fields with public getter functions to track these unclaimed fees. [1](#0-0) [2](#0-1) 

However, the Momentum adaptor's `get_position_token_amounts` function calculates position value solely from principal liquidity using `liquidity_math::get_amounts_for_liquidity()`, completely ignoring the `owed_coin_x()` and `owed_coin_y()` getters. [3](#0-2)  The function returns only the principal amounts for USD conversion. [4](#0-3) 

The Cetus adaptor exhibits identical behavior - it retrieves position amounts via `pool.get_position_amounts(position_id)` which returns only principal liquidity. [5](#0-4)  The valuation sums only these principal amounts after USD conversion, with no fee retrieval. [6](#0-5) 

This underreported value flows directly into the vault's accounting system. The `finish_update_asset_value` function stores the calculated USD value in the `assets_value` table. [7](#0-6) 

When calculating total vault value, `get_total_usd_value` iterates through all asset types and sums their values from this table. [8](#0-7)  The share ratio is then computed as `total_usd_value / total_shares`. [9](#0-8) 

During deposit execution, the vault captures the share ratio before adding new principal, then mints shares using `vault_utils::div_d(new_usd_value_deposited, share_ratio_before)`. [10](#0-9) [11](#0-10)  These shares are permanently added to `total_shares`. [12](#0-11) 

Because the share ratio denominator (total_usd_value) excludes unclaimed fees worth $X while the vault actually controls those fees, the ratio is artificially low by factor (total_value - X) / total_value. Depositors receive shares = deposit_amount / deflated_ratio, granting them ownership claims exceeding their contribution by the reciprocal of this factor.

## Impact Explanation

This vulnerability breaks the fundamental accounting invariant that share ratio must reflect true vault value per share. The impact is direct economic harm through share dilution:

**Quantified Mechanics:** When a vault holds positions with $100,000 principal + $5,000 unclaimed fees but reports only $100,000, the share ratio drops from correct $1.05/share to incorrect $1.00/share. A $10,000 deposit should receive 9,523 shares but actually receives 10,000 shares - a 477 share excess representing $500 transferred from existing holders.

**Compounding Effect:** This dilution occurs on every deposit while positions have unclaimed fees. Since CLMM positions earn fees continuously during normal DEX operations, and fee collection is a separate manual operation from routine valuation updates, time gaps are operationally normal. The dilution compounds across deposits, progressively transferring ownership.

**Severity Multipliers:** Out-of-range positions accumulate fees in both tokens while principal liquidity concentrates in one token. The zero-principal-liquidity token may have substantial fees completely invisible to valuation, creating worst-case scenarios.

The unclaimed fees represent earned yield that should accrue to existing shareholders but instead benefit new depositors through excess share grants.

## Likelihood Explanation

This vulnerability triggers automatically during normal protocol operations with high probability:

**Automatic Occurrence:** Concentrated liquidity positions earn trading fees on every swap passing through their price ranges. These fees accumulate in the `owed_coin_x` and `owed_coin_y` fields without any special conditions. Vaults update position values regularly as part of standard accounting cycles, capturing the undervaluation each time until fees are manually collected.

**No Preconditions Required:** Any user can deposit through the standard request-and-execute flow. When operators execute deposits using `execute_deposit`, they use the current share ratio which reflects underreported vault value. No special timing, permissions, or coordination needed - the vulnerability is structural.

**Expected Frequency:** Active DEX positions on Cetus and Momentum earn fees continuously as market prices fluctuate through their ranges. Positions frequently move in and out of range as market conditions change. The operational gap between routine valuation updates and manual fee collection is normal protocol behavior.

**No Attack Needed:** While individual depositors may be unaware, the vulnerability systematically benefits them at existing holders' expense. The dilution accumulates across all deposits during periods when positions have unclaimed fees, making aggregate impact material even if individual instances seem small.

## Recommendation

Both Cetus and Momentum adaptors must include unclaimed fees in position valuation:

**For Momentum adaptor:**
```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
    
    // Add unclaimed fees
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    let total_amount_a = amount_a + owed_a;
    let total_amount_b = amount_b + owed_b;
    
    // ... rest of valuation logic using total_amount_a and total_amount_b
}
```

**For Cetus adaptor:**
Apply equivalent logic retrieving fees via position getter functions (structure depends on Cetus external API).

**Alternative:** If technical constraints prevent fee inclusion in valuation, implement automatic fee collection before each valuation update to ensure fees are converted to principal before measurement.

## Proof of Concept

The vulnerability is demonstrated through the code execution path verified above. A test would show:

1. Create vault with Momentum/Cetus position containing principal liquidity
2. Simulate DEX swaps to accumulate fees in `owed_coin_x` and `owed_coin_y` 
3. Update position value via adaptor (fees excluded, underreported value stored)
4. Execute deposit using underreported share ratio
5. Verify excess shares minted: `actual_shares > expected_shares_at_correct_ratio`
6. Calculate dilution: excess shares represent value transfer from existing holders

The core issue is architecturally proven: adaptors provably ignore fee fields that provably exist in Position structs, creating a measurable accounting error that flows through the share minting formula.

---

## Notes

This vulnerability affects **both Momentum and Cetus adaptors** through identical root causes. While Cetus Position struct details cannot be verified from in-scope code (external dependency), the Momentum evidence is definitive, and both protocols use the same CLMM (UniswapV3) architecture where fees accumulate separately from principal liquidity. The mathematical certainty of share dilution given underreported valuations makes this a **HIGH severity** finding regardless of whether developers were aware of the fee tracking fields.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L63-66)
```text
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L41-41)
```text
    let (amount_a, amount_b) = pool.get_position_amounts(position_id);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L71-74)
```text
    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
```

**File:** volo-vault/sources/volo_vault.move (L821-821)
```text
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L853-853)
```text
    self.total_shares = self.total_shares + user_shares;
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
