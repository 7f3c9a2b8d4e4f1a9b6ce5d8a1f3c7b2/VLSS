# Audit Report

## Title
Pool Mismatch Vulnerability in Momentum Position Valuation Allows Vault Accounting Manipulation

## Summary
The `update_momentum_position_value` function accepts an arbitrary pool parameter without validating it matches the position's `pool_id`, allowing anyone to calculate position values using a mismatched pool's price. This corrupts the vault's USD valuation records and enables attackers to manipulate share ratios for fund extraction.

## Finding Description

The vulnerability exists in the `update_momentum_position_value` function where a position's value is calculated without verifying pool ownership. [1](#0-0) 

The function is publicly accessible with no capability checks, allowing any caller to provide an arbitrary pool reference. It retrieves a `MomentumPosition` from the vault and calls `get_position_value` with the caller-provided pool parameter.

**Root Cause:** The critical flaw occurs in `get_position_token_amounts`, which uses the provided pool's `sqrt_price` with the position's tick ranges and liquidity to calculate token amounts. [2](#0-1) 

The function extracts `sqrt_price` from the provided pool and combines it with the position's `tick_lower_index`, `tick_upper_index`, and `liquidity` values to calculate token amounts. This creates a mismatch where Pool B's price is used to value Pool A's position parameters.

**Missing Validation:** Momentum positions contain a `pool_id` field that identifies which pool they belong to. [3](#0-2) 

The position provides a getter for this pool_id. [4](#0-3) 

Similarly, pools expose their ID. [5](#0-4) 

However, **no validation exists** that `pool.pool_id() == position.pool_id()`. An attacker can provide Pool B while the position actually exists in Pool A, causing incorrect valuation.

**Why Existing Protections Fail:**

1. **No Authorization Required:** The function is declared as `public fun` with no capability parameter requirements.

2. **Slippage Check Insufficient:** The slippage validation only ensures the pool price is within tolerance of the oracle price, not that it's the correct pool. [6](#0-5) 

This check validates price deviation but not pool identity. An attacker can create or reference an alternative pool with the same token types but different price (within slippage bounds).

3. **Value Recording Is Blind:** The `finish_update_asset_value` function records whatever value is provided without validating its correctness. [7](#0-6) 

The function directly updates `assets_value[asset_type]` with no verification that the value was calculated correctly.

## Impact Explanation

**Direct Fund Impact:**

The corrupted position value directly affects the vault's total USD value calculation. [8](#0-7) 

This function sums all asset values from `assets_value`, which includes the manipulated position value. The total value determines the share ratio used for all deposits and withdrawals. [9](#0-8) 

The share ratio calculation uses `total_usd_value / total_shares`. This ratio is fundamental to the vault's accounting:
- **Withdrawals:** `withdrawal_amount = shares_burned × share_ratio`
- **Deposits:** `shares_minted = deposit_amount ÷ share_ratio`

**Concrete Harm:**

1. **Inflated Valuation Attack:** Attacker provides a pool with higher price (within slippage tolerance) → position value inflated → total vault value inflated → share ratio inflated → attacker withdraws more funds than entitled

2. **Deflated Valuation Attack:** Attacker deflates position value → existing shareholders' share value decreases → attacker can acquire shares at artificially low prices

3. **Manipulation Window:** Value updates persist until the next correct update, providing a window for exploitation during deposit/withdrawal operations

**Affected Parties:**
- Existing vault shareholders lose funds through manipulated share values
- New depositors receive incorrect share amounts
- Vault protocol loses integrity of its core accounting mechanism

The severity is **High** because it allows unauthorized accounting manipulation leading to fund misdirection, though the impact is bounded by the slippage tolerance (typically 1-5%).

## Likelihood Explanation

**Attacker Capabilities Required:**
- Access to create or reference a Momentum pool with same token types (permissionless in typical AMM protocols)
- Ability to call public functions (any Sui user)
- Knowledge of vault's position asset_type string (publicly observable on-chain)

**Attack Complexity:** Low
1. Query vault to identify Momentum position details and asset_type string
2. Create or identify alternative pool with same CoinA/CoinB types but manipulated price within slippage tolerance
3. Call `update_momentum_position_value` with mismatched pool reference
4. Exploit manipulated share ratio through deposit or withdrawal transactions

**Feasibility Conditions:**
- Vault must hold at least one Momentum position (normal operation)
- Attacker can create pools with prices within slippage tolerance of oracle price
- No special permissions or capabilities required
- Attack is economically viable if position represents significant portion of vault value

**Detection Constraints:**
- Value manipulation may appear legitimate as pool price passes slippage checks
- No on-chain events differentiate correct vs incorrect pool usage
- Impact only visible through off-chain comparison of expected vs recorded values

**Probability:** High - the attack is straightforward, low-cost, and directly exploitable by any external user through a public interface.

## Recommendation

Add validation to ensure the provided pool matches the position's pool_id:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Add this validation
    assert!(pool.pool_id() == position.pool_id(), ERR_POOL_MISMATCH);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

This ensures that only the correct pool can be used to value each position, preventing the accounting manipulation attack.

## Proof of Concept

```move
#[test]
fun test_pool_mismatch_vulnerability() {
    // Setup: Create vault with Momentum position in Pool A
    let vault = create_test_vault();
    let pool_a = create_momentum_pool_sui_usdc(sqrt_price_100);
    let position = create_position_in_pool_a();
    vault.add_defi_asset(asset_type, position);
    
    // Attack: Create Pool B with different price (within slippage)
    let pool_b = create_momentum_pool_sui_usdc(sqrt_price_105); // 5% higher
    
    // Exploit: Call update with mismatched pool
    update_momentum_position_value(
        &mut vault,
        &config,
        &clock,
        asset_type,
        &mut pool_b  // Wrong pool!
    );
    
    // Result: Position valued using Pool B's price with Pool A's parameters
    let (corrupted_value, _) = vault.get_asset_value(asset_type);
    assert!(corrupted_value > correct_value); // Inflated accounting
    
    // Impact: Share ratio is now inflated, enabling fund extraction
    let manipulated_ratio = vault.get_share_ratio(&clock);
    assert!(manipulated_ratio > correct_ratio);
}
```

The PoC demonstrates that an attacker can provide an arbitrary pool reference to corrupt the vault's accounting without any authorization checks or pool identity validation.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L59-59)
```text
    public fun pool_id(position: &Position) : ID { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L139-139)
```text
    public fun pool_id<X, Y>(pool: &Pool<X, Y>): ID { abort 0 }
```

**File:** volo-vault/sources/volo_vault.move (L1175-1203)
```text
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
}
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
