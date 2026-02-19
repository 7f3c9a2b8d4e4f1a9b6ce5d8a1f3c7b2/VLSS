### Title
Pool Type Mismatch in MomentumPosition Valuation Allows Complete Asset Value Manipulation

### Summary
The `get_position_value()` and `update_momentum_position_value()` functions in momentum.adaptor.move do not validate that the `MomentumPool<CoinA, CoinB>` parameter matches the `MomentumPosition`'s actual pool. This allows operators to pass an arbitrary pool with different token pairs, causing the vault to calculate and store completely incorrect USD valuations that affect all share pricing and user funds.

### Finding Description

**Root Cause:**
The vulnerability exists in the momentum adaptor's position valuation logic. A `MomentumPosition` object stores its associated pool's ID in a `pool_id` field [1](#0-0) , and the `Pool` object has a corresponding `pool_id()` getter function [2](#0-1) . However, the adaptor functions never validate this relationship.

**Vulnerable Code Path:**
The `update_momentum_position_value()` function accepts a `MomentumPool<CoinA, CoinB>` parameter and retrieves a `MomentumPosition` from the vault [3](#0-2) . It then calls `get_position_value()` which uses the pool's `sqrt_price` and the pool's generic type parameters `<CoinA, CoinB>` to determine token types and fetch oracle prices [4](#0-3) .

The function extracts token amounts using `get_position_token_amounts()` which combines the pool's `sqrt_price` with the position's tick bounds and liquidity [5](#0-4) .

**Why Existing Protections Fail:**
The slippage validation (lines 55-58) only checks that the pool's price is consistent with oracle prices for CoinA and CoinB, but does NOT verify that these are the correct tokens for the position. If an attacker passes `Pool<USDC, USDT>` for a position that actually belongs to `Pool<SUI, USDC>`, the slippage check validates USDC/USDT consistency, not whether these are the right tokens for the position.

The MMT v3 module provides a `verify_pool()` function [6](#0-5)  that could be used for validation, but it is never called in the adaptor code.

### Impact Explanation

**Direct Fund Impact:**
- An operator can completely manipulate the vault's recorded USD value for any MomentumPosition asset
- This directly affects the vault's `total_usd_value` calculation which determines share prices
- Users withdrawing at an artificially inflated valuation extract more value than they should
- Conversely, deflated valuations allow others to acquire underpriced shares

**Concrete Attack Scenario:**
1. Vault holds a MomentumPosition for a high-value SUI/USDC pool worth $100,000
2. Malicious operator calls `update_momentum_position_value` with a near-worthless Pool<TokenX, TokenY> that has very low liquidity
3. The calculation uses TokenX/TokenY prices instead of SUI/USDC prices
4. Vault records position as worth $100 instead of $100,000
5. Operator or accomplice immediately withdraws at the deflated share price, stealing ~$99,900 from other users

**Who Is Affected:**
All vault users are affected as share pricing depends on accurate total vault valuation. This violates the critical invariant that "total_usd_value correctness" must be maintained.

**Severity Justification:**
CRITICAL - Direct fund theft vector, no complexity barriers, affects core invariant, 100% success rate.

### Likelihood Explanation

**Entry Point:**
The `update_momentum_position_value()` function is marked `public fun` [7](#0-6) , making it callable during the vault operation value update phase.

**Attacker Capabilities:**
- Requires OperatorCap, which is a standard operational requirement, not a privileged admin role
- Operators are expected to manage vault operations and update asset values between operation phases
- No additional permissions needed beyond normal operator duties

**Execution Practicality:**
1. Operator initiates standard operation with `start_op_with_bag()` and `end_op_with_bag()`
2. Between phases, operator calls `update_momentum_position_value()` with any Pool reference they choose
3. The vault's internal validation only checks that the vault is enabled and the asset type exists [8](#0-7) 
4. No cross-validation occurs to ensure pool-position matching

**Detection Constraints:**
- Attack leaves no obvious on-chain trace distinguishing it from legitimate value updates
- Off-chain monitoring would need to track which pool ID each position belongs to and verify all updates

**Economic Rationality:**
- Attack cost: Only gas fees for the transaction
- Potential profit: Entire position value can be manipulated
- Risk: Low if done carefully to avoid detection before withdrawal

### Recommendation

**Code-Level Mitigation:**
Add pool ID validation in `get_position_value()`:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    // ADD THIS VALIDATION
    let position_pool_id = position.pool_id();
    let actual_pool_id = pool.pool_id();
    assert!(position_pool_id == actual_pool_id, ERR_POOL_MISMATCH);
    
    // Rest of existing code...
}
```

Alternatively, use the MMT v3 module's `verify_pool()` function:
```move
pool::verify_pool(pool, position.pool_id());
```

**Invariant Checks:**
Add assertion: "The pool used for position valuation must match the position's stored pool_id"

**Test Cases:**
1. Test calling `update_momentum_position_value()` with mismatched pool - should fail
2. Test with correct pool - should succeed
3. Test that manipulation attempt reverts before vault value update
4. Fuzz test with various pool/position combinations

### Proof of Concept

**Initial State:**
- Vault contains MomentumPosition "pos_sui_usdc" for Pool<SUI, USDC> with ID `0xABC`
- Position represents 10 SUI worth $20 and 20 USDC worth $20, total $40
- Attacker has OperatorCap

**Transaction Steps:**
1. Attacker obtains reference to different Pool<TokenX, TokenY> with ID `0xDEF`
2. Attacker calls: `update_momentum_position_value<USDT, TokenX, TokenY>(vault, config, clock, "pos_sui_usdc", wrong_pool)`
3. Function executes:
   - Gets pos_sui_usdc (which is for SUI/USDC pool)
   - Uses wrong_pool's sqrt_price for TokenX/TokenY
   - Fetches oracle prices for TokenX and TokenY (not SUI and USDC)
   - Calculates amounts using wrong price
   - Vault stores incorrect USD value for "pos_sui_usdc"

**Expected vs Actual Result:**
- Expected: Transaction fails with ERR_POOL_MISMATCH
- Actual: Transaction succeeds, vault records wrong USD value (e.g., $0.01 instead of $40)

**Success Condition:**
After the transaction, querying the vault's asset value for "pos_sui_usdc" returns an incorrect amount, demonstrating that pool mismatch bypassed all validation and corrupted vault state.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L106-111)
```text
    public fun verify_pool<X, Y>(
        pool: &Pool<X, Y>,
        id: ID,
    ) {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L139-139)
```text
    public fun pool_id<X, Y>(pool: &Pool<X, Y>): ID { abort 0 }
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

**File:** volo-vault/sources/volo_vault.move (L1174-1195)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
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
```
