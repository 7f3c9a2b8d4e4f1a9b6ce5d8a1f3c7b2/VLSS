# Audit Report

## Title
Complete Momentum Adaptor Failure Due to Stub Implementation Causing Vault DoS

## Summary
The mmt_v3 local dependency contains only stub implementations where all functions call `abort 0`. When a vault contains a MomentumPosition, any value update operation aborts, blocking all deposits and withdrawals since the vault requires all asset values to be updated within MAX_UPDATE_INTERVAL (set to 0) before calculating total USD value.

## Finding Description
The mmt_v3 local dependency was intended to "remove some test functions with errors" [1](#0-0)  but instead consists entirely of stub implementations.

All critical position functions are stubs that immediately abort: [2](#0-1) 

All critical pool functions are stubs that immediately abort: [3](#0-2) 

The momentum_adaptor's `get_position_token_amounts` function depends on these stub functions: [4](#0-3) 

MomentumPosition is explicitly supported in vault operations for borrowing: [5](#0-4) 

And for returning: [6](#0-5) 

Operators can add MomentumPosition as a generic DeFi asset: [7](#0-6) 

The vault enforces that all asset values must be updated within MAX_UPDATE_INTERVAL (defined as 0): [8](#0-7) 

The `get_total_usd_value` function checks staleness and aborts if any asset is not updated: [9](#0-8) 

Deposits require calling `get_total_usd_value` twice: [10](#0-9) 

Withdrawals require calling `get_share_ratio`: [11](#0-10) 

Which internally calls `get_total_usd_value`: [12](#0-11) 

## Impact Explanation
**Severity: CRITICAL - Vault Denial of Service**

When a MomentumPosition exists in a vault:
1. Any deposit or withdrawal operation requires `get_total_usd_value()` which mandates all asset values be fresh (MAX_UPDATE_INTERVAL = 0)
2. To update the MomentumPosition value, `update_momentum_position_value` must be called
3. This function calls mmt_v3 stub functions (`position.tick_lower_index()`, `position.tick_upper_index()`, `position.liquidity()`, `pool.sqrt_price()`) which all `abort 0`
4. The transaction aborts, preventing the value update
5. Without the value update, `get_total_usd_value` aborts due to staleness check
6. All deposits and withdrawals become impossible

This creates a complete vault DoS affecting all users. While the admin could remove the position to restore functionality, any period with a MomentumPosition renders the vault completely non-functional despite the protocol explicitly supporting this asset type.

## Likelihood Explanation
**Likelihood: HIGH**

- **Precondition**: Admin/operator adds a MomentumPosition using the generic `add_new_defi_asset` function - a legitimate operation on an explicitly supported asset type
- **Trigger**: Any user deposit or withdrawal, or any operation requiring total USD value calculation
- **Complexity**: Zero - normal protocol usage automatically triggers the bug
- **Detection**: Immediately evident once a MomentumPosition is added and value update is attempted
- **Cost**: No cost to trigger - happens through standard operations

The vulnerability is guaranteed to manifest if MomentumPosition support is used, as the production code is deployed with complete stub implementations that abort.

## Recommendation
Replace the stub mmt_v3 local dependency with the actual upstream implementation. The current approach of using local dependencies to "remove test functions with errors" should be revised to properly fork and fix the test functions rather than replacing all implementations with stubs.

Either:
1. Use the actual mmt_v3 package from the official repository and fix/remove only the problematic test functions
2. Implement the required functions in the local dependency instead of stub implementations
3. Remove MomentumPosition support entirely until proper integration can be achieved

## Proof of Concept
```move
// Test demonstrating the DoS
#[test]
fun test_momentum_position_causes_vault_dos() {
    // Setup vault with normal operations working
    let vault = setup_test_vault();
    let clock = clock::create_for_testing(ctx);
    
    // Admin adds MomentumPosition (legitimate operation)
    operation::add_new_defi_asset<SUI, MomentumPosition>(
        &operation,
        &operator_cap,
        &mut vault,
        0,
        momentum_position
    );
    
    // User attempts deposit - requires value update
    // Operator calls momentum_adaptor::update_momentum_position_value
    // This will abort because all mmt_v3 functions call abort 0
    
    // Expected: transaction aborts with error
    // Result: All deposits/withdrawals blocked, vault DoS
}
```

### Citations

**File:** volo-vault/Move.toml (L79-79)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L36-59)
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
    public fun pool_id(position: &Position) : ID { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L98-192)
```text
    public fun initialize<X, Y>(
        pool: &mut Pool<X, Y>,
        sqrt_price: u128,
        clock: &Clock
    ) {
        abort 0
    }

    public fun verify_pool<X, Y>(
        pool: &Pool<X, Y>,
        id: ID,
    ) {
        abort 0
    }

    #[allow(lint(share_owned))]
    public fun transfer<X, Y>(self: Pool<X, Y>) {
        abort 0
    }

    public fun borrow_observations<X, Y>(pool: &Pool<X, Y>): &vector<Observation> { abort 0 }
    public fun borrow_tick_bitmap<X, Y>(pool: &Pool<X, Y>): &Table<I32, u256> { abort 0 }
    public fun borrow_ticks<X, Y>(pool: &Pool<X, Y>): &Table<I32, TickInfo> { abort 0 }

    public fun get_reserves<X, Y>(
        pool: &Pool<X, Y>
    ): (u64, u64) {
        abort 0
    }
    
    // pool getters
    public fun type_x<X, Y>(pool: &Pool<X, Y>): TypeName { abort 0 }
    public fun type_y<X, Y>(pool: &Pool<X, Y>): TypeName { abort 0 }
    public fun liquidity<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
    public fun tick_index_current<X, Y>(pool: &Pool<X, Y>) : I32 { abort 0 }
    public fun tick_spacing<X, Y>(pool: &Pool<X, Y>) : u32 { abort 0 }
    public fun max_liquidity_per_tick<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
    public fun observation_cardinality<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun observation_cardinality_next<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun observation_index<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun pool_id<X, Y>(pool: &Pool<X, Y>): ID { abort 0 }
    public fun swap_fee_rate<X, Y>(self: &Pool<X, Y>) : u64 { abort 0 }
    public fun flash_loan_fee_rate<X, Y>(self: &Pool<X, Y>) : u64 { abort 0 }
    public fun protocol_fee_share<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun protocol_flash_loan_fee_share<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun protocol_fee_x<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun protocol_fee_y<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun reserves<X, Y>(pool: &Pool<X, Y>): (u64, u64) { abort 0 }
    public fun reward_coin_type<X, Y>(pool: &Pool<X, Y>, index: u64): TypeName { abort 0 }
    public fun fee_growth_global_x<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
    public fun fee_growth_global_y<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }

    // oracle public functions
    public fun observe<X, Y>(
        pool: &Pool<X, Y>,
        seconds_ago: vector<u64>,
        clock: &Clock
    ): (vector<i64::I64>, vector<u256>) {
        abort 0
    }

    // rewards getters
    public fun total_reward<X, Y>(pool: &Pool<X, Y>, reward_id: u64) : u64 { abort 0 }
    public fun total_reward_allocated<X, Y>(pool: &Pool<X, Y>, reward_id: u64) : u64 { abort 0 }
    public fun reward_ended_at<X, Y>(pool: &Pool<X, Y>, reward_index: u64): u64 { abort 0 }
    public fun reward_growth_global<X, Y>(pool: &Pool<X, Y>, timestamp: u64): u128 { abort 0 }
    public fun reward_last_update_at<X, Y>(pool: &Pool<X, Y>, reward_index: u64): u64 { abort 0 }
    public fun reward_per_seconds<X, Y>(pool: &Pool<X, Y>, timestamp: u64): u128 { abort 0 }
    public fun reward_length<X, Y>(pool: &Pool<X, Y>): u64 {abort 0}
    public fun reward_info_at<X, Y>(pool: &Pool<X, Y>, index: u64): &PoolRewardInfo {
        abort 0
    }

    // returns friendly ticks by adjusting tick spacing of the pool.
    public fun get_friendly_ticks<X, Y>(
        pool: &Pool<X, Y>, 
        lower_sqrt_price: u128, 
        upper_sqrt_price: u128
    ): (I32, I32) {
        abort 0
    }



    fun find_reward_info_index<X, Y, R>(
        pool: &Pool<X, Y>
    ): u64 {
        abort 0
    }

    fun safe_withdraw<X>(balance: &mut Balance<X>, amount: u64) : Balance<X> {
        abort 0
    }
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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
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

**File:** volo-vault/sources/volo_vault.move (L994-1077)
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
        )
    };

    self.delete_withdraw_request(request_id);

    (withdraw_balance, recipient)
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

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```
