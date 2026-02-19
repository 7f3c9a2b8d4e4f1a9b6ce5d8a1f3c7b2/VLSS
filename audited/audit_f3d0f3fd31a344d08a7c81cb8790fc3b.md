### Title
Momentum Positions with Unclaimed Fees/Rewards Can Be Removed Despite Having Value, Causing Loss to Vault Shareholders

### Summary
The vault's Momentum position value calculation only accounts for active liquidity and ignores unclaimed trading fees (`owed_coin_x`, `owed_coin_y`) and liquidity mining rewards (`coins_owed_reward`). This allows positions with zero liquidity but non-zero claimable fees/rewards to be incorrectly valued at $0 and subsequently removed via `remove_defi_asset_support()`, transferring those unclaimed funds out of the vault and causing direct loss to shareholders.

### Finding Description

The `Position` struct in MMT v3 tracks multiple types of value: [1](#0-0) 

However, the momentum adaptor's value calculation only considers active liquidity: [2](#0-1) 

The `get_position_token_amounts()` function only accesses `tick_lower_index()`, `tick_upper_index()`, and `liquidity()`, completely ignoring the position's unclaimed fees (`owed_coin_x`, `owed_coin_y`) and rewards (`coins_owed_reward` in `reward_infos`).

When an operator attempts to remove a position, the vault checks: [3](#0-2) 

The check on line 1405 allows removal if `asset_value == 0`, which will be true for positions with zero liquidity even if they have substantial unclaimed fees/rewards. The position is then removed from the vault's assets and transferred to the operator.

Critically, the `is_empty()` function exists in the Position interface but is **never called** anywhere in the vault codebase. The vault has no mechanism to collect fees/rewards before removal, as the `mmt_v3::collect` module is never imported or used. [4](#0-3) 

### Impact Explanation

**Direct Fund Loss**: When a position with zero liquidity but non-zero claimable fees/rewards is removed, the vault loses those funds permanently. In concentrated liquidity AMM v3 protocols, positions continue to hold claimable fees even after all liquidity is withdrawn - these fees represent value that belongs to vault shareholders.

**Quantified Damage**: The loss equals the total USD value of:
- Unclaimed trading fees in both tokens (`owed_coin_x * price_x + owed_coin_y * price_y`)
- Unclaimed liquidity mining rewards (sum of all `coins_owed_reward` across reward types)

For actively traded pools, positions can accumulate substantial fees even with modest liquidity. A position that provided $100k liquidity in a 0.3% fee pool generating $10M daily volume could accumulate $300+ per day in fees.

**Who Is Affected**: All vault shareholders lose proportional value, as their share price should include the position's total value (liquidity + unclaimed fees/rewards), but only the liquidity portion is counted.

**Severity**: High - This is direct, measurable loss of user funds with no recovery mechanism once the position is removed.

### Likelihood Explanation

**Reachable Entry Point**: The `operation::remove_defi_asset_support()` function is callable by any non-frozen operator: [5](#0-4) 

**Preconditions Are Natural**:
1. Positions accumulate fees whenever swaps occur in their price range
2. Operators may legitimately remove all liquidity for rebalancing or strategy changes
3. A position with `liquidity = 0` appears "empty" to operators checking the adaptor's value calculation
4. No malicious intent is required - operators would reasonably believe such positions are safe to remove

**Execution Practicality**: 
1. Position has active liquidity, accumulates fees over time
2. Operator removes all liquidity via normal operations
3. Position now has `liquidity = 0` but `owed_coin_x/y > 0`
4. Adaptor calculates `asset_value = 0` (only looks at liquidity)
5. Operator calls `remove_defi_asset_support()` to clean up "empty" position
6. Check passes: `asset_value == 0`
7. Position removed, operator receives it with unclaimed fees
8. Vault loses the fee value that belonged to shareholders

**Economic Rationality**: No attack cost - this occurs during normal vault operations. Operators routinely remove positions they believe are empty, especially during rebalancing or strategy changes.

**Probability**: Medium to High - Likely to occur eventually as operators manage positions through normal lifecycle. The vulnerability doesn't require specific market conditions, just normal position management where liquidity is fully withdrawn.

### Recommendation

**1. Include All Value Components in Position Valuation**

Modify `momentum_adaptor::get_position_value()` to query and include unclaimed fees and rewards:

```move
// Pseudo-code - actual implementation would need to:
// 1. Call position.owed_coin_x() and position.owed_coin_y()
// 2. Iterate through position.reward_infos and sum coins_owed_reward
// 3. Convert all amounts to USD using oracle prices
// 4. Add to the liquidity-based value
```

**2. Enforce Pre-Collection Before Removal**

Modify `remove_defi_asset_support()` to require positions have no claimable value:

```move
// In volo_vault.move, before line 1405:
// Verify position is truly empty by checking is_empty() or manually verifying:
// - liquidity == 0
// - owed_coin_x == 0  
// - owed_coin_y == 0
// - all reward_infos have coins_owed_reward == 0
```

**3. Implement Fee/Reward Collection Flow**

Create operator functions to collect fees/rewards from positions before removal:
- Import and use `mmt_v3::collect::fee()` and `mmt_v3::collect::reward()`
- Add collected amounts to vault's coin balances
- Update vault USD value to reflect collected amounts

**4. Add Test Cases**

Test that:
- Positions with `liquidity = 0` but `owed_coin_x > 0` cannot be removed
- Position value correctly includes unclaimed fees and rewards
- Fee/reward collection properly updates vault balances

### Proof of Concept

**Initial State**:
- Vault holds MomentumPosition in SUI/USDC pool
- Position has 10,000 SUI liquidity providing liquidity
- Pool generates trading volume, position accumulates 5 SUI + 100 USDC in fees
- SUI = $2, USDC = $1

**Step 1**: Operator removes all liquidity
- Calls MMT's `remove_liquidity()` with `liquidity = 10000`
- Position now has `liquidity = 0`, `owed_coin_x = 5 SUI`, `owed_coin_y = 100 USDC`
- Position's true value = $0 (liquidity) + $10 (fees) + $100 (fees) = $110

**Step 2**: Adaptor calculates value
- `get_position_token_amounts()` called
- Uses `position.liquidity()` = 0
- Calculates `amount_a = 0`, `amount_b = 0`
- Returns `usd_value = 0`
- Vault's `asset_value[position_asset_type] = 0`

**Step 3**: Operator removes position
- Calls `operation::remove_defi_asset_support()`
- Check passes: `asset_value == 0`
- Position removed from vault's assets Bag
- Operator receives Position object with $110 in claimable fees

**Expected Result**: Removal should fail because position has $110 in value

**Actual Result**: Removal succeeds, vault loses $110 that belonged to shareholders, operator receives position with claimable fees

**Success Condition**: Vault's total USD value decreases by $110, shareholders' share price decreases proportionally, while position with claimable value is transferred out of vault custody.

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

**File:** volo-vault/sources/volo_vault.move (L1390-1413)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();

    let asset_type = vault_utils::parse_key<AssetType>(idx);

    let (contains, index) = self.asset_types.index_of(&asset_type);
    assert!(contains, ERR_ASSET_TYPE_NOT_FOUND);
    self.asset_types.remove(index);

    let asset_value = self.assets_value[asset_type];
    let asset_value_updated = self.assets_value_updated[asset_type];
    assert!(asset_value == 0 || asset_value_updated == 0, ERR_ASSET_TYPE_NOT_FOUND);

    emit(DefiAssetRemoved {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/collect.move (L25-43)
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
    
    public fun reward<X, Y, R>(
        pool: &mut Pool<X, Y>,  
        position: &mut Position, 
        clock: &Clock, 
        version: &Version,        
        ctx: &mut TxContext
    ) : Coin<R> {
        abort 0
    }
```

**File:** volo-vault/sources/operation.move (L576-584)
```text
public fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    vault::assert_operator_not_freezed(operation, cap);
    vault.remove_defi_asset_support(idx)
}
```
