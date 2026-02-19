### Title
Momentum Position Valuation Excludes Uncollected Trading Fees Leading to Systematic Undervaluation and Value Extraction

### Summary
The `get_position_token_amounts()` function in the Momentum adaptor only calculates token amounts based on principal liquidity and completely excludes uncollected trading fees stored in `owed_coin_x` and `owed_coin_y` fields. This systematic undervaluation corrupts the vault's share pricing mechanism, causing new depositors to receive excess shares at the expense of existing shareholders and withdrawing users to receive less value than entitled.

### Finding Description

The vulnerability exists in the `get_position_token_amounts()` function which is responsible for calculating the token amounts held in a Momentum position: [1](#0-0) 

The function retrieves only the position's principal liquidity and passes it to `liquidity_math::get_amounts_for_liquidity()`, which calculates token amounts based solely on this liquidity value.

However, the MMT v3 `Position` struct explicitly maintains separate fields for uncollected trading fees: [2](#0-1) 

Public getter functions exist for these uncollected fee fields: [3](#0-2) 

The protocol also provides a fee collection mechanism via `mmt_v3::collect::fee()`: [4](#0-3) 

Despite these available mechanisms, the Momentum adaptor never accesses `owed_coin_x` or `owed_coin_y`, and the vault codebase contains zero usages of the `mmt_v3::collect` module (confirmed via grep search across all vault source files).

The undervalued position USD value flows through the valuation chain: [5](#0-4) 

This incorrect value is stored in the vault's asset value table and directly impacts total vault valuation: [6](#0-5) 

The corrupted total USD value then affects share ratio calculation: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact - Value Extraction:**

When Momentum positions accumulate trading fees but these fees are excluded from valuation, the vault's `total_usd_value` is artificially deflated, which directly corrupts the `share_ratio = total_usd_value / total_shares` calculation.

During deposit execution, users receive shares based on the undervalued share ratio: [8](#0-7) 

Since `share_ratio_before` is artificially low due to missing fee value, the calculation `user_shares = new_usd_value_deposited / share_ratio_before` results in excess shares being issued to new depositors. This excess comes directly from diluting existing shareholders' proportional ownership of the vault's actual assets (including the uncounted fees).

Similarly, withdrawing users receive assets based on their shares multiplied by the undervalued share ratio, receiving less than their entitled value.

**Concrete Example:**
- Vault has $1M in assets including a Momentum position worth $100K in liquidity + $10K in uncollected fees
- Adaptor only counts $100K, so `total_usd_value = $990K` (missing $10K)
- Actual value is $1M, but share ratio calculated on $990K basis
- New $100K deposit receives shares as if vault is worth $990K instead of $1M
- Depositor gains ~1% extra value ($1K) stolen from existing shareholders
- Impact scales with fee accumulation over time

**Security Integrity Impact:**

The undervaluation also affects loss tolerance enforcement: [9](#0-8) 

When uncollected fees are eventually collected (if ever), the vault value suddenly increases without actual yield generation, potentially masking real losses that should have triggered `ERR_EXCEED_LOSS_LIMIT`.

### Likelihood Explanation

**Automatic and Guaranteed Occurrence:**

The vulnerability triggers automatically during normal vault operations. Position value updates are required during the operation lifecycle phase 3: [5](#0-4) 

Every time the operator completes an operation involving Momentum positions, the undervaluation occurs without any attacker intervention.

**No Special Capabilities Required:**

- Standard users depositing/withdrawing are automatically affected
- No special permissions needed beyond normal vault access
- No timing manipulation or front-running required
- Works against all users indiscriminately

**Continuous Accumulation:**

Momentum (MMT v3) positions accumulate trading fees continuously from swap activity in the underlying liquidity pools. The longer positions remain active, the more significant the undervaluation becomes.

**Economic Impact Certainty:**

The value extraction is guaranteed and measurable. There are no probabilistic elements - if uncollected fees exist (`owed_coin_x > 0` or `owed_coin_y > 0`), they are systematically excluded from valuation on every update.

### Recommendation

**Immediate Fix:**

Modify `get_position_token_amounts()` to include uncollected fees:

```move
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
    
    // Add uncollected fees to amounts
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    amount_a = amount_a + owed_a;
    amount_b = amount_b + owed_b;
    
    (amount_a, amount_b, sqrt_price)
}
```

**Invariant Checks:**

Add assertions to ensure position valuations account for all value sources:
- Before returning position value, verify that `owed_coin_x` and `owed_coin_y` have been accounted for
- Add event emissions tracking uncollected fee amounts during valuation for monitoring

**Regression Prevention:**

- Unit test verifying positions with uncollected fees are valued correctly
- Integration test showing share ratio accurately reflects positions with accumulated fees
- Test case confirming deposit/withdrawal fairness with fee-accumulating positions

### Proof of Concept

**Initial State:**
1. Vault contains a Momentum position with:
   - Liquidity value: 100,000 USDC equivalent
   - Uncollected fees: 5,000 USDC equivalent in `owed_coin_x` and `owed_coin_y`
   - Total actual value: 105,000 USDC
2. Vault total value (other assets + this position): 1,000,000 USDC actual
3. Total shares outstanding: 1,000,000 shares
4. Correct share ratio should be: 1.0 USDC per share

**Attack Sequence:**

1. Operator calls operation lifecycle including `update_momentum_position_value()`
2. `get_position_token_amounts()` calculates value using only liquidity (100K)
3. Missing 5K in fees causes `total_usd_value = 995K` instead of 1M
4. Calculated share ratio: 0.995 USDC per share (should be 1.0)
5. User deposits 10,000 USDC
6. User receives: 10,000 / 0.995 ≈ 10,050 shares (should receive 10,000 shares)
7. User gains 50 extra shares worth $50, diluting existing shareholders

**Expected Result:**
Position should be valued at 105,000 USDC (liquidity + fees), share ratio = 1.0, user receives exactly 10,000 shares for 10,000 USDC deposit.

**Actual Result:**
Position valued at 100,000 USDC (fees excluded), share ratio = 0.995, user receives 10,050 shares, effectively stealing $50 from existing shareholders.

**Success Condition:**
After deposit, new user owns more proportional vault value than their contribution, verified by: `(user_shares / new_total_shares) * actual_total_value > user_deposit_amount`

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

**File:** volo-vault/sources/volo_vault.move (L820-872)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1297-1310)
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

```

**File:** volo-vault/sources/operation.move (L353-377)
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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
