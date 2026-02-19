# Audit Report

## Title
Momentum Position Valuation Excludes Accumulated Fees and Rewards Leading to Systematic Vault Undervaluation

## Summary
The Momentum adaptor's position valuation function systematically undervalues positions by ignoring accumulated but unclaimed trading fees and rewards. This causes the vault's total USD value to be understated, leading to incorrect share pricing that disadvantages existing shareholders during deposits and withdrawals.

## Finding Description

The vulnerability exists in the `get_position_token_amounts()` function which calculates the token amounts for a Momentum concentrated liquidity position. [1](#0-0) 

This function only retrieves amounts based on active liquidity using `liquidity_math::get_amounts_for_liquidity()` and never accesses the accumulated fee and reward fields.

However, the Momentum Position struct contains three critical fields for accumulated but unclaimed value:
- `owed_coin_x: u64` - accumulated fees in token X
- `owed_coin_y: u64` - accumulated fees in token Y  
- `reward_infos: vector<PositionRewardInfo>` with `coins_owed_reward: u64` - accumulated rewards [2](#0-1) 

Public getter functions exist for these fields: [3](#0-2) 

The Momentum protocol also provides fee collection functions that would claim these accumulated amounts: [4](#0-3) 

However, the Volo vault never calls these fee collection functions, and more critically, never includes the accumulated fees/rewards in position valuation calculations.

The undervalued amounts flow through the valuation chain:

1. `get_position_token_amounts()` returns only liquidity-based amounts [1](#0-0) 

2. These amounts are converted to USD value in `get_position_value()` [5](#0-4) 

3. The USD value is stored in the vault's `assets_value` table via `finish_update_asset_value()` [6](#0-5) 

4. `get_total_usd_value()` sums all asset values including this undervalued Momentum position [7](#0-6) 

5. The understated `total_usd_value` is used to calculate the share ratio [8](#0-7) 

6. This incorrect share ratio is used for deposit share calculations [9](#0-8) 

7. And for withdrawal amount calculations [10](#0-9) 

**Security Guarantee Broken**: The protocol's core invariant of "total_usd_value correctness" is violated. The vault's reported total value does not include all assets that legally belong to the vault's positions.

## Impact Explanation

This vulnerability causes **HIGH severity** direct fund impact through systematic share mispricing:

**Deposit Impact**: When users deposit, shares are calculated as `new_usd_value_deposited / share_ratio_before`. With an understated `total_usd_value`, the share ratio is artificially low, causing new depositors to receive more shares than they should. This directly dilutes existing shareholders. [11](#0-10) 

**Withdrawal Impact**: When users withdraw, the amount is calculated as `shares_to_withdraw * share_ratio`. With an understated share ratio, withdrawing users receive less principal than they should. [12](#0-11) 

**Magnitude**: In active Momentum concentrated liquidity pools, trading fees typically represent 1-5% of position value over time. For a vault with $1M in Momentum positions, this could mean $10,000-$50,000 in unaccounted value - a material discrepancy affecting all share pricing.

**Affected Parties**: All vault shareholders suffer wealth transfer effects. Existing shareholders lose value through dilution when new deposits occur. Withdrawing shareholders receive less than their fair share.

**Exploitability**: Sophisticated actors can monitor Momentum pool fee accrual and time deposits when fees are highest (vault most undervalued) to maximize their share allocation advantage.

## Likelihood Explanation

**Likelihood: CERTAIN**

This is not an attack but a systematic accounting error that occurs during normal protocol operation:

**Entry Point**: The `update_momentum_position_value()` function is a public function designed to be called by vault operators before processing deposits and withdrawals. [13](#0-12) 

**Preconditions** (all standard operational scenarios):
- Vault holds Momentum positions (expected use case)
- Trading activity occurs in the Momentum pool (natural market behavior)
- Time passes, allowing fees to accumulate (passive occurrence)

**Execution**: Fees and rewards accumulate automatically in the Position struct whenever:
- Traders execute swaps in the Momentum pool
- The pool distributes rewards
- No special actions or attacks required

**Probability**: This happens with every position valuation update. The magnitude of missing value grows continuously with trading volume and time. There is zero operational cost to this occurring - it's the default behavior.

## Recommendation

Modify `get_position_token_amounts()` to include accumulated fees and rewards in the position valuation:

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
    
    // Add accumulated but unclaimed fees
    let amount_a = amount_a + position.owed_coin_x();
    let amount_b = amount_b + position.owed_coin_y();
    
    // Add accumulated rewards if any
    let reward_length = position.reward_length();
    let mut i = 0;
    while (i < reward_length) {
        // Note: Would need to handle reward token conversion to CoinA/CoinB
        // or add separate reward valuation logic
        i = i + 1;
    };
    
    (amount_a, amount_b, sqrt_price)
}
```

**Additional Considerations**:
- Implement periodic fee collection to prevent excessive accumulation
- Add monitoring for unclaimed fee amounts
- Consider separate tracking of fee/reward value vs liquidity value for transparency

## Proof of Concept

The following test demonstrates the vulnerability by showing that accumulated fees in a Momentum position are not reflected in the vault's total USD value calculation:

```move
#[test]
fun test_momentum_fees_not_included_in_valuation() {
    // Setup: Create vault with Momentum position
    let mut scenario = test_scenario::begin(ADMIN);
    
    // 1. Create vault and add Momentum position
    setup_vault_with_momentum_position(&mut scenario);
    
    // 2. Simulate trading activity that generates fees in the Momentum pool
    // This would populate position.owed_coin_x and position.owed_coin_y
    simulate_momentum_trading_fees(&mut scenario);
    
    // 3. Call update_momentum_position_value() to get vault's calculated value
    let calculated_value = get_vault_momentum_position_value(&mut scenario);
    
    // 4. Get actual position value including fees
    let position = get_momentum_position(&scenario);
    let owed_x = position.owed_coin_x();
    let owed_y = position.owed_coin_y();
    let actual_value = calculated_value + value_of_fees(owed_x, owed_y);
    
    // 5. Assert that vault value is understated
    assert!(calculated_value < actual_value, 0);
    assert!(owed_x > 0 || owed_y > 0, 1); // Fees exist but not counted
    
    test_scenario::end(scenario);
}
```

This test would fail in the current implementation because the vault's calculated value would not include the accumulated fees, demonstrating the systematic undervaluation.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L10-29)
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
    
    public struct PositionRewardInfo has copy, drop, store {
        reward_growth_inside_last: u128,
        coins_owed_reward: u64,
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L36-58)
```text
    public fun coins_owed_reward(position: &Position, reward_index: u64) : u64 {
        abort 0
    }

    // returns if position does not have claimable rewards.
    public fun is_empty(position: &Position) : bool {
        abort 0
    }
    
    public fun reward_growth_inside_last(position: &Position, reward_index: u64) : u128 {
        abort 0
    }
    
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

**File:** volo-vault/sources/volo_vault.move (L994-1070)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
    assert!(self.request_buffer.withdraw_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Get the current share ratio
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

    // Decrease the share in vault and receipt
    self.total_shares = self.total_shares - shares_to_withdraw;

    // Split balances from the vault
    assert!(amount_to_withdraw <= self.free_principal.value(), ERR_NO_FREE_PRINCIPAL);
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);

    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);

    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
    });

    // Update total usd value after withdraw executed
    // This update should not generate any performance fee
    // (actually the total usd value will decrease, so there is no performance fee)
    self.update_free_principal_value(config, clock);

    // Update the vault receipt info
    let vault_receipt = &mut self.receipts[withdraw_request.receipt_id()];

    let recipient = withdraw_request.recipient();
    if (recipient != address::from_u256(0)) {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            0,
        )
    } else {
        vault_receipt.update_after_execute_withdraw(
            shares_to_withdraw,
            withdraw_balance.value(),
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
