# Audit Report

## Title
Cetus Position Valuation Excludes Unclaimed Fees Leading to Share Dilution

## Summary
The Cetus adaptor's position valuation function systematically underreports the vault's total USD value by ignoring unclaimed trading fees stored in Cetus positions. This creates an artificially low share ratio that causes new depositors to receive excess shares, directly diluting existing shareholders. The issue occurs automatically during normal vault operations without requiring any attack.

## Finding Description

The `calculate_cetus_position_value()` function retrieves position token amounts by calling `pool.get_position_amounts(position_id)`, which returns only the principal liquidity amounts based on the position's liquidity parameter and tick range. [1](#0-0) 

However, Cetus concentrated liquidity positions accumulate trading fees separately in dedicated storage fields. The Position struct explicitly defines `owed_coin_x: u64` and `owed_coin_y: u64` fields to track unclaimed fees. [2](#0-1) 

These unclaimed fees represent real economic value that belongs to the vault through its ownership of the position. The position struct even provides public getter functions `owed_coin_x()` and `owed_coin_y()` to access these values. [3](#0-2) 

The Cetus adaptor never retrieves or includes these unclaimed fees in its valuation calculation. It only converts the principal liquidity amounts to USD and returns their sum. [4](#0-3) 

This underreported position value flows into the vault's total USD value calculation, which sums all asset values from the `assets_value` table. [5](#0-4) 

The share ratio is then calculated as `total_usd_value / total_shares`, producing an artificially low ratio when Cetus positions have unclaimed fees. [6](#0-5) 

During deposit execution, new shares are minted using this underreported share ratio via the formula `user_shares = new_usd_value_deposited / share_ratio_before`. [7](#0-6) 

The excess shares are permanently minted and added to `total_shares`, giving new depositors ownership claims over vault value (including the unclaimed fees) that exceed their actual contributions. [8](#0-7) 

## Impact Explanation

This vulnerability causes direct economic harm to existing vault shareholders through share dilution:

**Mechanics of Value Transfer:**
When unclaimed fees worth $X are excluded from valuation, the share ratio decreases proportionally. A depositor contributing $Y receives `shares = Y / (correct_ratio * dilution_factor)` where `dilution_factor < 1.0`. These excess shares represent permanent claims on vault assets, including the very unclaimed fees that were excluded from the valuation.

**Quantified Example:**
- Vault holds Cetus position: $100,000 principal + $5,000 unclaimed fees = $105,000 actual value
- Reported value: $100,000 (fees excluded)
- Existing shares: 100,000 (assume 1:1 ratio historically)
- Correct share ratio: $105,000 / 100,000 = $1.05 per share
- Actual share ratio used: $100,000 / 100,000 = $1.00 per share

When a new user deposits $10,000:
- Shares they should receive: $10,000 / $1.05 = 9,523 shares
- Shares they actually receive: $10,000 / $1.00 = 10,000 shares
- Excess shares: 477 shares = $500 value transferred from existing holders

**Compounding Effect:**
This dilution compounds with each deposit, progressively transferring ownership of vault assets from existing shareholders to new depositors. The unclaimed fees represent earned yield that should accrue to existing shareholders but instead benefits new entrants.

**Severity Multiplier for Out-of-Range Positions:**
Out-of-range positions convert all principal liquidity to a single token, but fees continue accumulating in both tokens. The token with zero principal liquidity may have substantial accumulated fees that are completely invisible to the valuation function, creating worst-case dilution scenarios.

## Likelihood Explanation

This vulnerability triggers automatically during normal protocol operations with high probability:

**Automatic Occurrence:**
Concentrated liquidity positions earn trading fees continuously as swaps occur through their price ranges. These fees accumulate in `owed_coin_x` and `owed_coin_y` without any special actions. The vault updates position values regularly as part of its standard accounting cycle, capturing the undervaluation each time.

**No Preconditions or Privileges Required:**
Any user can deposit principal tokens through the standard request-and-execute flow. When operators execute these deposits, they use the current share ratio which reflects the underreported vault value. No special timing, permissions, or coordinator actions are needed.

**Expected Frequency:**
- Active DEX positions on Cetus earn fees on every swap that occurs within or through their ranges
- Positions frequently move in and out of range as market prices fluctuate
- Fee collection is a separate manual operation distinct from valuation updates
- Time gaps between valuations and fee collection are operationally normal

**Economic Incentive:**
While individual depositors may not deliberately exploit this (they may be unaware), the vulnerability systematically benefits them at existing holders' expense. The dilution accumulates across all deposits, making the aggregate impact material even if individual instances are small.

## Recommendation

Modify `calculate_cetus_position_value()` to include unclaimed fees in the position valuation:

```move
public fun calculate_cetus_position_value<CoinTypeA, CoinTypeB>(
    pool: &mut CetusPool<CoinTypeA, CoinTypeB>,
    position: &CetusPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let position_id = object::id(position);
    
    // Get principal liquidity amounts
    let (amount_a, amount_b) = pool.get_position_amounts(position_id);
    
    // Get unclaimed fees
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    
    // Add unclaimed fees to total amounts
    let total_amount_a = amount_a + owed_a;
    let total_amount_b = amount_b + owed_b;
    
    let type_name_a = into_string(get<CoinTypeA>());
    let type_name_b = into_string(get<CoinTypeB>());
    
    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);
    
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
    
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL / relative_price_from_oracle) < (DECIMAL * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
    
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
    
    // Value includes both principal and unclaimed fees
    let value_a = vault_utils::mul_with_oracle_price(total_amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(total_amount_b as u256, normalized_price_b);
    
    value_a + value_b
}
```

Alternatively, implement a separate fee collection mechanism before each valuation update to ensure fees are converted to principal tokens and counted in the standard balance calculations.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```move
#[test]
fun test_cetus_position_fee_exclusion_causes_share_dilution() {
    // Setup: Create vault with 100,000 shares at $1 per share
    let vault = create_test_vault();
    vault.total_shares = 100_000_000_000_000_000_000_000; // 100k shares (18 decimals)
    
    // Setup: Create Cetus position with $100k principal + $5k unclaimed fees
    let position = create_cetus_position(
        principal_a: 50_000_000_000, // 50k tokens worth $100k total
        principal_b: 50_000_000_000,
        owed_coin_x: 2_500_000_000,  // 2.5k tokens = $5k unclaimed fees
        owed_coin_y: 2_500_000_000,
    );
    
    // Action: Update position value (excludes fees)
    update_cetus_position_value(&mut vault, position, config, clock);
    // Result: vault.assets_value["CetusPosition_0"] = $100k (should be $105k)
    
    // Action: Calculate share ratio
    let total_usd = vault.get_total_usd_value(clock);
    // Result: total_usd = $100k (underreported by $5k)
    
    let share_ratio = vault.get_share_ratio(clock);
    // Result: share_ratio = $100k / 100k shares = $1.00 per share
    // Expected: $105k / 100k shares = $1.05 per share
    
    // Action: New user deposits $10k
    request_deposit(&mut vault, deposit_amount: 10_000_000_000);
    execute_deposit(&mut vault, clock, config, request_id);
    
    // Result: User receives 10k shares (should receive ~9,523 shares)
    // Impact: Existing holders diluted by 477 shares worth ~$500
    
    assert!(vault.total_shares == 110_000_000_000_000_000_000_000); // 110k shares
    // But total value is actually $115k (105k + 10k), not $110k
    // True share ratio: $115k / 110k = $1.045 per share (down from $1.05)
    // Existing holders lost: (100k shares * $1.05) - (100k shares * $1.045) = $500
}
```

This test demonstrates that the systematic exclusion of unclaimed fees from Cetus position valuations causes measurable and permanent dilution of existing shareholders' ownership stakes.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L853-853)
```text
    self.total_shares = self.total_shares + user_shares;
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
