# Audit Report

## Title
Momentum Position Unclaimed Fees Not Included in Vault Valuation

## Summary
The vault's momentum position valuation mechanism excludes unclaimed trading fees stored in MMT v3 Position objects, causing systematic undervaluation of vault assets. This leads to incorrect share price calculations and dilution of existing shareholders during deposit operations.

## Finding Description

The MMT v3 Position struct maintains unclaimed trading fees in dedicated fields `owed_coin_x` and `owed_coin_y`. [1](#0-0) 

These fees must be claimed separately through the `fee()` function in the collect module. [2](#0-1) 

**Root Cause:** The momentum adaptor's `get_position_token_amounts()` function calculates position value exclusively from `position.liquidity()`, completely ignoring the `owed_coin_x` and `owed_coin_y` fields. [3](#0-2) 

This understated value is then stored in the vault's `assets_value` table through `finish_update_asset_value()`. [4](#0-3) 

The vault's `get_total_usd_value()` aggregates all asset values from this table. [5](#0-4) 

The share ratio calculation divides this understated total by total shares. [6](#0-5) 

Finally, `execute_deposit()` mints shares using this deflated share ratio, resulting in excessive share issuance. [7](#0-6) 

## Impact Explanation

**Direct Financial Impact:**
- When momentum positions accumulate unclaimed fees, the vault's `total_usd_value` understates actual recoverable value
- Share price formula `share_ratio = total_usd_value / total_shares` produces artificially low prices
- New depositors receive `user_shares = new_usd_value / share_ratio_before`, getting more shares than economically justified
- Existing shareholders suffer proportional dilution of their ownership stake
- If operators remove positions without claiming fees (via `remove_defi_asset_support`), accumulated fees may be permanently lost

**Custody Integrity:**
- Share accounting becomes progressively incorrect as fees accumulate across multiple positions
- Withdrawal calculations use wrong share prices, causing systematic value leakage
- The protocol provides no automated mechanism to claim fees or alert operators

**Severity Assessment:** Medium - Impact accumulates gradually as trading fees accrue. While not an immediate critical loss, extended periods without fee collection cause material valuation errors affecting all vault participants.

## Likelihood Explanation

**Reachability:** The vulnerability manifests during routine vault operations when `update_momentum_position_value()` is called to refresh position valuations. [8](#0-7) 

**Preconditions:**
- No malicious action required - occurs during normal protocol operation
- Trading fees naturally accumulate on any active liquidity position over time
- Operators may reasonably focus on liquidity management without separately tracking fee claims
- The codebase contains no calls to `mmt_v3::collect::fee()` to claim accumulated fees

**Execution Path:**
1. Vault holds one or more momentum positions earning trading fees
2. Operators perform routine operations (add/remove liquidity, rebalancing) without calling fee collection
3. Position value updates calculate amounts solely from liquidity, excluding owed fees
4. Vault's total USD value becomes understated
5. All subsequent deposit/withdraw operations use incorrect share prices
6. Dilution compounds over time

**Probability:** High - This occurs automatically unless operators maintain perfect discipline to claim fees before every valuation update or liquidity operation, which is unrealistic given the lack of protocol enforcement or guidance.

## Recommendation

Modify the momentum adaptor's valuation logic to include unclaimed fees:

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
    
    // ADD: Include unclaimed fees in position valuation
    let owed_a = position.owed_coin_x();
    let owed_b = position.owed_coin_y();
    
    (amount_a + owed_a, amount_b + owed_b, sqrt_price)
}
```

Additionally, implement a mechanism to automatically claim fees during liquidity operations or provide clear operator guidance on fee collection requirements.

## Proof of Concept

A valid test demonstrating this vulnerability would:

1. Create a vault with a momentum position in an active trading pool
2. Allow time for trading fees to accumulate (owed_coin_x, owed_coin_y > 0)
3. Call `update_momentum_position_value()` to refresh valuation
4. Observe that `get_total_usd_value()` excludes the accumulated fees
5. Execute a deposit and verify that shares minted exceed expected amount
6. Calculate the dilution percentage for existing shareholders

The test would confirm that the position's `owed_coin_x()` and `owed_coin_y()` values are non-zero but excluded from the vault's total USD value calculation, proving systematic undervaluation and resulting share dilution.

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

**File:** volo-vault/sources/volo_vault.move (L811-872)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
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
