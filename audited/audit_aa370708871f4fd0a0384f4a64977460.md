# Audit Report

## Title
Concentrated Liquidity Position Valuation Excludes Unclaimed Fees Leading to Share Dilution

## Summary
The Cetus and Momentum adaptor valuation functions systematically underreport vault USD value by excluding unclaimed trading fees that accumulate in concentrated liquidity positions. This artificially low valuation causes the share ratio calculation to undervalue existing shares, resulting in new depositors receiving excess shares that dilute existing shareholders. The vulnerability occurs automatically during normal vault operations.

## Finding Description

Concentrated liquidity positions in both Cetus and Momentum protocols accumulate trading fees separately from principal liquidity. The Position struct explicitly defines `owed_coin_x: u64` and `owed_coin_y: u64` fields to track these unclaimed fees, with dedicated getter functions to access them. [1](#0-0) [2](#0-1) 

The protocol provides a separate `fee<X, Y>()` function specifically for collecting these unclaimed fees, which returns them as separate coins, confirming they represent real economic value distinct from principal liquidity. [3](#0-2) 

However, the Cetus adaptor's `calculate_cetus_position_value()` function only retrieves principal liquidity amounts via `pool.get_position_amounts(position_id)` and converts only these amounts to USD value, completely ignoring the unclaimed fees. [4](#0-3) [5](#0-4) 

The Momentum adaptor exhibits identical behavior, calculating position value only from principal liquidity via `get_amounts_for_liquidity()` and ignoring unclaimed fees. [6](#0-5) [7](#0-6) 

This underreported position value is stored in the vault's `assets_value` table, which directly flows into `get_total_usd_value()` that sums all asset values. [8](#0-7) [9](#0-8) 

The share ratio is then calculated as `total_usd_value / total_shares`, producing an artificially low ratio when positions have unclaimed fees. [10](#0-9) 

During deposit execution, new shares are minted using this underreported ratio via `vault_utils::div_d(new_usd_value_deposited, share_ratio_before)`, giving depositors more shares than their contribution warrants. [11](#0-10) 

These excess shares are permanently added to `total_shares`, granting new depositors ownership claims over vault value (including the excluded unclaimed fees) that exceed their actual contributions. [12](#0-11) 

Critically, vault operations borrow and return positions without collecting fees, meaning the unclaimed fees remain in the positions while being systematically excluded from valuations. [13](#0-12) [14](#0-13) 

## Impact Explanation

This vulnerability causes direct economic harm through share dilution. When unclaimed fees worth $X are excluded from a vault holding $Y in principal, the share ratio becomes `Y / total_shares` instead of `(Y + X) / total_shares`. A new depositor contributing $Z receives `Z * total_shares / Y` shares instead of the correct `Z * total_shares / (Y + X)` shares.

**Quantified Example:**
- Vault has $100,000 principal + $5,000 unclaimed fees = $105,000 actual value
- 100,000 existing shares outstanding
- Correct ratio: $105,000 / 100,000 = $1.05 per share
- Underreported ratio: $100,000 / 100,000 = $1.00 per share
- New $10,000 deposit should receive: 10,000 / 1.05 = 9,523 shares
- Actually receives: 10,000 / 1.00 = 10,000 shares
- Excess: 477 shares × $1.05 = $500 transferred from existing holders

This dilution compounds with each deposit. The unclaimed fees represent earned yield that should accrue to existing shareholders but instead subsidizes new entrants. Out-of-range positions create worst-case scenarios where one token may have zero principal but substantial accumulated fees that are completely invisible to valuation.

## Likelihood Explanation

This vulnerability triggers automatically during normal protocol operations:

**Continuous Fee Accumulation**: Concentrated liquidity positions earn trading fees on every swap occurring through their price ranges. These fees accumulate in `owed_coin_x` and `owed_coin_y` fields without any special actions required.

**Standard Operation Flow**: 
1. Users request deposits through normal public interfaces
2. Operators execute deposits using the current share ratio
3. The share ratio reflects underreported vault value due to excluded fees
4. No special timing, permissions, or attack coordination needed

**Operational Inevitability**: Fee collection is a separate manual operation distinct from position valuation updates. Time gaps between valuations and fee collection are operationally normal, creating persistent windows where substantial unclaimed fees exist but are excluded from vault value.

**High Frequency**: Active DEX positions earn fees continuously, and the vault regularly updates position values as part of its standard accounting cycle, capturing the undervaluation each time deposits occur.

## Recommendation

Modify the position valuation functions to include unclaimed fees:

**For Cetus Adaptor (`cetus_adaptor.move`):**
```move
public fun calculate_cetus_position_value<CoinTypeA, CoinTypeB>(
    pool: &mut CetusPool<CoinTypeA, CoinTypeB>,
    position: &CetusPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let position_id = object::id(position);
    let (amount_a, amount_b) = pool.get_position_amounts(position_id);
    
    // ADD: Retrieve unclaimed fees
    let fee_a = position.owed_coin_x();
    let fee_b = position.owed_coin_y();
    
    // Include fees in total amounts
    let total_amount_a = amount_a + fee_a;
    let total_amount_b = amount_b + fee_b;
    
    // ... rest of valuation logic using total_amount_a and total_amount_b
}
```

**For Momentum Adaptor (`momentum.adaptor.move`):**
Apply the same pattern - retrieve `owed_coin_x()` and `owed_coin_y()` from the position and add them to the principal amounts before USD valuation.

## Proof of Concept

```move
#[test]
fun test_unclaimed_fees_excluded_from_valuation() {
    // Setup vault with Momentum position having principal + unclaimed fees
    let mut scenario = test_scenario::begin(OWNER);
    
    // Create position with 1000 SUI principal + 100 SUI unclaimed fees
    // Position value should be 1100 SUI but valuation will only see 1000
    
    // Initial state: 10,000 shares, $10,000 value, ratio = $1.00
    
    // Update position value (excludes fees)
    // Reported: $10,000 (correct: $11,000)
    
    // New user deposits $1,000
    // Should receive: 1000/1.10 = 909 shares
    // Actually receives: 1000/1.00 = 1000 shares
    // Excess: 91 shares worth $100
    
    // Assert: New user received 1000 shares instead of 909
    // Assert: Existing shareholders diluted by ~$100
}
```

## Notes

This vulnerability affects both Cetus and Momentum concentrated liquidity position adaptors, as both follow identical patterns of excluding unclaimed fees from valuation. The issue is definitively confirmed for Momentum positions through direct code evidence of the Position struct fields and fee collection mechanisms. While Cetus positions are external dependencies, standard concentrated liquidity AMM architecture (based on Uniswap v3) universally implements this separation of fees from principal, and the identical adaptor patterns strongly indicate Cetus follows the same structure.

The severity is heightened because:
1. Fee accumulation is continuous and automatic
2. The valuation understatement persists until manual fee collection
3. Share dilution is permanent and compounds with each deposit
4. No user action or attack is required - it occurs during normal operations

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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L29-29)
```text
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L63-66)
```text
    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L83-89)
```text
    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L853-853)
```text
    self.total_shares = self.total_shares + user_shares;
```

**File:** volo-vault/sources/volo_vault.move (L1268-1269)
```text
        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L259-265)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };
```
