### Title
Unclaimed MMT Position Fees Not Included in Vault Valuation Causing Share Price Manipulation

### Summary
The Momentum adaptor calculates position value based solely on liquidity without including unclaimed trading fees (`owed_coin_x` and `owed_coin_y`). This causes the vault's `total_usd_value` to be understated, resulting in an incorrect share ratio that allows depositors to mint excess shares (diluting existing holders) and causes withdrawers to receive less principal than entitled.

### Finding Description

The vulnerability exists in the position value calculation flow: [1](#0-0) 

The `get_position_token_amounts` function only uses `position.liquidity()` to calculate token amounts via `liquidity_math::get_amounts_for_liquidity()`, completely ignoring the `owed_coin_x` and `owed_coin_y` fields that track unclaimed trading fees. [2](#0-1) 

These fee fields exist in the Position struct but are never read during value calculations. The position value calculation then uses only the liquidity-based amounts: [3](#0-2) 

This incomplete value propagates through the vault's total value calculation: [4](#0-3) 

Which directly affects the share ratio calculation: [5](#0-4) 

Finally, this incorrect share ratio is used during deposit execution to determine how many shares to mint: [6](#0-5) 

**Root Cause:** The momentum adaptor's value calculation does not account for all value components of a Position object, specifically excluding unclaimed fees.

**Why Protections Fail:** There is no mechanism to collect fees before position operations, and no validation that position value includes all claimable assets. The MMT fee collection function exists but is never called: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
When a MomentumPosition has unclaimed fees (e.g., 100 USDC in `owed_coin_x`), the vault's `total_usd_value` is understated by that amount. This creates two distinct impacts:

1. **Share Dilution on Deposits:** If the vault has $10,000 actual value but only reports $9,900 (missing 100 USDC in fees), and a user deposits $1,000:
   - Correct share ratio: 10,000 / 1,000 shares = 10.0
   - Calculated share ratio: 9,900 / 1,000 shares = 9.9
   - User should receive: 1,000 / 10.0 = 100 shares
   - User actually receives: 1,000 / 9.9 ≈ 101 shares
   - **Existing holders lose 1% of their ownership**

2. **Withdrawal Shortfall:** When the same user withdraws their 101 shares:
   - True value per share: 10.0
   - Calculated value per share: 9.9
   - User entitled to: 101 × 10.0 = $1,010
   - User receives: 101 × 9.9 = $999.90
   - **User loses $10.10**

**Who is Affected:** All vault depositors and withdrawers. Depositors gain at the expense of existing holders; withdrawers lose value. The magnitude scales with the proportion of unclaimed fees to total vault value.

**Severity Justification:** This violates CRITICAL INVARIANT #3 "total_usd_value correctness" and creates measurable fund redistribution on every deposit/withdrawal when unclaimed fees exist.

### Likelihood Explanation

**Attacker Capabilities:** Any user can exploit this by timing deposits when MomentumPositions have accumulated unclaimed fees. No special privileges required.

**Attack Complexity:** Minimal - user simply monitors on-chain position state and calls normal deposit functions when fees have accumulated but haven't been collected.

**Feasibility Conditions:**
- Vault must have at least one MomentumPosition (intended use case)
- Position must have non-zero `owed_coin_x` or `owed_coin_y` (inevitable in active AMM pools as trading occurs)
- No operator intervention to collect fees (realistic given no automated collection mechanism)

**Detection/Operational Constraints:** The issue occurs passively during normal operations. Unclaimed fees accumulate naturally as users trade in the MMT pool. No unusual transactions required.

**Probability:** HIGH - This occurs continuously whenever positions have unclaimed fees, affecting all subsequent deposits/withdrawals until fees are collected.

### Recommendation

**Code-Level Mitigation:**

1. Modify `get_position_token_amounts` to include unclaimed fees:

```move
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    // ... existing liquidity calculation ...
    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(...);
    
    // Add unclaimed fees
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    
    (amount_a + owed_a, amount_b + owed_b, sqrt_price)
}
```

2. Alternatively, implement automatic fee collection before value updates via `mmt_v3::collect::fee()`.

**Invariant Checks:** Add assertion in position value updates that all claimable position value is accounted for.

**Test Cases:**
- Test deposit/withdrawal with position having unclaimed fees
- Verify share ratio includes full position value
- Test fee collection before position removal
- Regression test for correct total_usd_value calculation

### Proof of Concept

**Initial State:**
- Vault has 1,000 shares outstanding
- Vault holds MomentumPosition with $9,900 liquidity value
- Position has 100 USDC unclaimed fees (owed_coin_x = 100e6)
- True vault value: $10,000
- Calculated vault value: $9,900 (fees not counted)

**Transaction Steps:**
1. Attacker calls `update_momentum_position_value()` to update position value (returns $9,900, excluding fees)
2. Attacker calls `user_entry::deposit()` with 1,000 USDC
3. `execute_deposit()` calculates share_ratio = 9,900 / 1,000 = 9.9
4. Attacker receives shares = 1,000 / 9.9 ≈ 101.01 shares

**Expected vs Actual Result:**
- Expected: Attacker receives 100 shares (at true ratio of 10.0)
- Actual: Attacker receives 101.01 shares
- **Impact:** Attacker gained 1.01% extra ownership, diluting existing holders by $10

**Success Condition:** Attacker's share balance exceeds the fair share amount by the percentage of unclaimed fees to total vault value.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L841-872)
```text
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

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
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
