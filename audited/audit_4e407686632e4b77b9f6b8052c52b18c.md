### Title
Momentum Position Accumulated Fees Excluded from Value Calculations Enable Undetected Fund Theft

### Summary
The momentum adaptor calculates position value based solely on liquidity-derived token amounts, completely ignoring the `owed_coin_x` and `owed_coin_y` fields that represent accumulated trading fees. This allows operators to collect these fees during operations without triggering loss detection, bypassing the vault's value update security checks designed to prevent fund theft.

### Finding Description

**Root Cause:**

The momentum adaptor's `get_position_value()` function only calculates value from the position's liquidity field, ignoring accumulated fees: [1](#0-0) 

The function calls `get_position_token_amounts()` which uses `liquidity_math::get_amounts_for_liquidity()`: [2](#0-1) 

This calculation is based purely on liquidity and does NOT include fees stored in the Position struct: [3](#0-2) 

The MMT v3 protocol provides a `fee()` function to collect these accumulated fees: [4](#0-3) 

**Exploitation Path:**

1. During `start_op_with_bag()`, the operator borrows a momentum position that has accumulated trading fees (owed_coin_x, owed_coin_y > 0): [5](#0-4) 

2. While holding the position, the operator calls `mmt_v3::collect::fee()` to extract the accumulated fees and transfers them to their own address.

3. The operator returns the position via `end_op_with_bag()`: [6](#0-5) 

4. The operator calls `update_momentum_position_value()` which recalculates value using only liquidity (fees now zero): [7](#0-6) 

5. The value update check in `end_op_value_update_with_bag()` compares total vault value before and after: [8](#0-7) 

**Why Protections Fail:**

The value calculation before the operation excludes fees (because the adaptor doesn't measure them), and after the operation also excludes fees (now zero). The total measured value appears unchanged, so no loss is detected. However, the vault has actually lost the USD value of those collected fees.

The Position struct documentation confirms these fields exist and represent real value: [9](#0-8) 

### Impact Explanation

**Direct Fund Impact:**

The vault loses the accumulated trading fees from momentum positions, which represent real economic value that should belong to vault shareholders. These fees accumulate over time as the position earns trading fees from the DEX pool.

**Quantified Damage:**

- For an active momentum position in a high-volume pool, fees can accumulate to significant amounts
- The theft is repeatable on every operation cycle
- Multiple momentum positions multiply the attack surface
- The loss bypasses the per-epoch loss_tolerance protection since it's not detected as a loss

**Affected Parties:**

- Vault depositors lose their proportional share of the accumulated fees
- The vault's reported value becomes increasingly inaccurate over time
- Trust in the operator oversight mechanism is undermined

**Severity Justification:**

This is a Medium severity issue because:
1. It requires operator role (semi-trusted position with security checks)
2. However, operators are explicitly constrained by value update checks - this is a bypass of those security controls
3. The loss accumulates over time and is undetectable by design
4. The operator freeze mechanism exists specifically because operators are not fully trusted [10](#0-9) 

### Likelihood Explanation

**Attacker Capabilities:**

Requires OperatorCap, which is a semi-trusted role. However, the vault system explicitly implements security checks (value updates, loss tolerance) because operators are not fully trusted. This vulnerability bypasses those checks.

**Attack Complexity:**

Very low - the attack is a simple sequence of standard function calls:
1. `start_op_with_bag()` - normal operation start
2. `mmt_v3::collect::fee()` - standard MMT v3 function
3. `end_op_with_bag()` - normal operation end
4. `update_momentum_position_value()` - required value update
5. `end_op_value_update_with_bag()` - passes without detecting loss

**Feasibility Conditions:**

- Vault must have at least one momentum position (common in DeFi vaults)
- Position must have accumulated fees (happens naturally over time in active pools)
- No external dependencies or timing requirements

**Detection Constraints:**

The theft is completely undetectable by the system's security checks. The value update mechanism is specifically designed to catch losses but fails here due to incomplete accounting.

**Probability Reasoning:**

High probability if an operator becomes malicious, since:
- No technical barriers beyond standard operation flow
- Zero cost to execute
- Guaranteed profit with no risk of detection
- Can be repeated on every operation cycle

### Recommendation

**Code-Level Mitigation:**

Modify `momentum_adaptor::get_position_value()` to include accumulated fees in the value calculation:

```move
public fun get_position_value<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let (amount_a, amount_b, sqrt_price) = get_position_token_amounts(pool, position);
    
    // Add accumulated fees to token amounts
    let total_amount_a = amount_a + position.owed_coin_x();
    let total_amount_b = amount_b + position.owed_coin_y();
    
    // ... existing price validation ...
    
    let value_a = vault_utils::mul_with_oracle_price(total_amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(total_amount_b as u256, normalized_price_b);
    
    value_a + value_b
}
```

**Invariant Checks:**

Add assertions that accumulated fees should not decrease during operations without corresponding coin deposits to the vault.

**Test Cases:**

1. Test that position value includes `owed_coin_x` and `owed_coin_y`
2. Test that collecting fees during an operation triggers loss detection
3. Test value calculation before and after fee collection shows the expected difference
4. Regression test with positions that have accumulated fees

### Proof of Concept

**Initial State:**
- Vault has a momentum position with liquidity L
- Position has accumulated fees: owed_coin_x = 100 token_x, owed_coin_y = 50 token_y
- Token prices: token_x = $2, token_y = $3
- Total position value should be: value(L) + $200 (fees for token_x) + $150 (fees for token_y)

**Transaction Sequence:**

1. Operator calls `start_op_with_bag()` with momentum position
   - Position borrowed from vault
   - Initial value recorded: value(L) + $350
   - BUT adaptor only records: value(L) ← **Missing $350 in fees**

2. Operator calls `mmt_v3::collect::fee()` on the position
   - Returns: (Coin<X> with 100 units, Coin<Y> with 50 units)
   - Operator transfers these to their own address
   - Position now has: owed_coin_x = 0, owed_coin_y = 0

3. Operator calls `end_op_with_bag()` - position returned to vault

4. Operator calls `update_momentum_position_value()`
   - Calculates value: value(L) ← **Fees already zero, not counted**

5. Operator calls `end_op_value_update_with_bag()`
   - Compares: value(L) before vs value(L) after
   - No loss detected! ✓ Check passes

**Expected Result:** 
Loss of $350 should be detected and operation should fail

**Actual Result:** 
No loss detected, operator successfully steals $350 in accumulated fees

**Success Condition:** 
Operator's address receives Coin<X> and Coin<Y> representing the fees, while vault shows no loss in the value update check.

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

**File:** volo-vault/sources/operation.move (L218-219)
```text
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();
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

**File:** volo-vault/sources/operation.move (L353-364)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L39-57)
```markdown
1. Position

```move
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
```
