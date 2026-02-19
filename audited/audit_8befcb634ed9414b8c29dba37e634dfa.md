### Title
Cetus Position Valuation Excludes Unclaimed Fees Leading to Share Dilution

### Summary
The `calculate_cetus_position_value()` function in the Cetus adaptor only accounts for principal liquidity amounts and completely ignores unclaimed fees stored in the position's `owed_coin_x` and `owed_coin_y` fields. This causes the vault's total USD value to be underreported, leading to an artificially low share ratio that allows new depositors to receive more shares than they should, diluting existing shareholders. The issue is particularly severe for out-of-range positions where all principal liquidity is in one token but significant fees may have accumulated in the other token.

### Finding Description

The Cetus position value calculation retrieves only the principal liquidity amounts without considering accumulated fees: [1](#0-0) 

The function calls `pool.get_position_amounts(position_id)` which returns the token amounts based solely on the position's liquidity within its tick range. However, Cetus positions accumulate trading fees separately in dedicated fields: [2](#0-1) 

These unclaimed fees (`owed_coin_x` and `owed_coin_y`) represent real economic value owned by the position holder but must be collected through a separate function call: [3](#0-2) 

The vault's total USD value calculation depends on accurate asset valuations: [4](#0-3) 

This total USD value directly determines the share ratio used for all deposits and withdrawals: [5](#0-4) 

When new deposits are executed, shares are calculated using this underreported share ratio: [6](#0-5) 

### Impact Explanation

**Direct Fund Impact - Share Dilution:**
When Cetus position values exclude unclaimed fees, the vault's `total_usd_value` is underreported. This causes:

1. **Share Ratio Manipulation**: The share ratio (`total_usd_value / total_shares`) is artificially lowered.

2. **Excessive Share Issuance**: New depositors receive more shares than they should because `user_shares = deposit_value / share_ratio`. A lower share ratio means more shares for the same deposit.

3. **Value Transfer**: This dilutes existing shareholders, as the unclaimed fees rightfully belong to the vault (through the position) but aren't reflected in the valuation, allowing new depositors to claim a disproportionate share of these fees.

**Severity for Out-of-Range Positions:**
Out-of-range positions are particularly problematic because:
- All principal liquidity converts to a single token (e.g., all USDC when price is below range)
- Trading fees continue to accumulate in both tokens as swaps occur through the range
- The "missing" token may have substantial accumulated fees that represent real value
- These fees are completely invisible to the valuation function

**Quantified Impact:**
If a Cetus position has $100,000 in principal liquidity plus $5,000 in unclaimed fees, but only $100,000 is counted, the vault is undervalued by 5%. New depositors receive ~5% more shares than they should, directly diluting existing holders by that amount.

### Likelihood Explanation

**High Probability:**

1. **Automatic Occurrence**: This happens naturally without any attack:
   - Concentrated liquidity positions frequently go out of range as market prices move
   - Trading fees accumulate continuously whenever swaps occur
   - The vault regularly updates position values through normal operations

2. **No Special Preconditions**: 
   - Any depositor can trigger this by depositing when Cetus positions have unclaimed fees
   - No special permissions or timing required
   - Works against any vault holding Cetus positions

3. **Realistic Frequency**:
   - Active DEX positions earn fees constantly
   - Positions can remain out-of-range for extended periods
   - Fee collection is a separate manual operation, so gaps between value updates and fee collection are expected

4. **Economic Feasibility**:
   - No attack cost beyond normal deposit amounts
   - Direct financial benefit to depositors (more shares)
   - Loss borne by existing shareholders who may not notice gradual dilution

### Recommendation

**Immediate Fix:**
Modify `calculate_cetus_position_value()` to include unclaimed fees in the valuation:

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
    
    // Add unclaimed fees
    let total_amount_a = amount_a + position.owed_coin_x();
    let total_amount_b = amount_b + position.owed_coin_y();
    
    let type_name_a = into_string(get<CoinTypeA>());
    let type_name_b = into_string(get<CoinTypeB>());
    
    // ... rest of price calculation using total_amount_a and total_amount_b
}
```

**Additional Recommendations:**

1. **Apply Same Fix to Momentum Adaptor**: The Momentum adaptor likely has the same issue since it uses the same underlying position structure.

2. **Add Assertion**: Verify that `owed_coin_x()` and `owed_coin_y()` are accessible and add them to the calculation.

3. **Test Coverage**: Add test cases that:
   - Create positions with accumulated fees
   - Verify valuations include fees
   - Test out-of-range positions specifically
   - Verify share calculations are correct with fee-inclusive valuations

4. **Documentation**: Document that position valuations must include all claimable value, not just active liquidity.

### Proof of Concept

**Initial State:**
1. Vault has 1,000,000 shares with `total_usd_value = $1,000,000` (share_ratio = $1.00)
2. Vault holds a Cetus SUI-USDC position that is out of range:
   - Principal liquidity: 0 SUI, 50,000 USDC = $50,000
   - Unclaimed fees: 1,000 SUI ($2,000 at $2/SUI), 500 USDC = $2,500
   - True position value: $52,500
   - Calculated position value: $50,000 (fees ignored)

**Attack Sequence:**
1. Attacker calls `update_cetus_position_value()` which calculates only $50,000
2. Vault's `total_usd_value = $950,000 (other assets) + $50,000 (Cetus) = $1,000,000` (should be $1,002,500)
3. Share ratio = $1,000,000 / 1,000,000 = $1.00 (should be $1.0025)
4. Attacker deposits $100,000
5. Receives 100,000 shares (should receive 99,750 shares)
6. Attacker gains 250 extra shares worth $250

**Expected vs Actual:**
- **Expected**: Attacker receives 99,750 shares for $100,000 deposit when true vault value is $1,002,500
- **Actual**: Attacker receives 100,000 shares because fees aren't counted
- **Result**: 250 shares of dilution distributed across existing holders, representing a 0.25% value transfer from existing holders to the new depositor

**Success Condition:**
After the deposit, the attacker holds a larger percentage of the vault than they should, having effectively acquired a portion of the unclaimed fees without paying for them.

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L33-75)
```text
public fun calculate_cetus_position_value<CoinTypeA, CoinTypeB>(
    pool: &mut CetusPool<CoinTypeA, CoinTypeB>,
    position: &CetusPosition,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let position_id = object::id(position);

    let (amount_a, amount_b) = pool.get_position_amounts(position_id);

    let type_name_a = into_string(get<CoinTypeA>());
    let type_name_b = into_string(get<CoinTypeB>());

    let decimals_a = config.coin_decimals(type_name_a);
    let decimals_b = config.coin_decimals(type_name_b);

    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18

    // pool price = price_a / price_b (not consider decimals)
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
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

**File:** volo-vault/sources/volo_vault.move (L806-872)
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
