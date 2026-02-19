# Audit Report

## Title
Reward Loss via Zero Address Allocation in incentive_v2 During Liquidations

## Summary
The `entry_liquidation()` function updates rewards for address @0x0 to refresh global indices, but inadvertently treats @0x0 as a real user. Since anyone can deposit to @0x0 via `entry_deposit_on_behalf_of_user`, and @0x0 cannot withdraw or claim rewards, this creates a permanent reward sink that reduces rewards available to legitimate users.

## Finding Description

The vulnerability exists in the Navi protocol's incentive system integration. During liquidations, the protocol calls `incentive_v2::update_reward_all()` with @0x0 for both collateral and debt assets: [1](#0-0) 

The reward update mechanism retrieves the user's balance from storage without any special handling for @0x0: [2](#0-1) 

It then calculates rewards based on that balance: [3](#0-2) [4](#0-3) 

And stores the rewards in @0x0's account: [5](#0-4) 

The attack is possible because anyone can deposit to @0x0 using the public entry function: [6](#0-5) 

This function has no address validation and calls the base deposit: [7](#0-6) [8](#0-7) 

The storage layer treats @0x0 like any other address with no special handling: [9](#0-8) 

However, withdrawals and reward claims are impossible for @0x0 because all methods require either being the transaction sender: [10](#0-9) [11](#0-10) 

Or having an AccountCap: [12](#0-11) [13](#0-12) 

Neither of which can be satisfied for @0x0 since no one can sign transactions or create capabilities for the zero address.

## Impact Explanation

**Direct Fund Impact:**
- Protocol incentive rewards are permanently burned when allocated to @0x0
- If @0x0 holds X% of total supply, it receives X% of all distributed rewards during each liquidation
- These rewards come from the fixed reward pool and proportionally reduce legitimate users' share
- The impact scales linearly with @0x0's deposited balance (attacker-controlled)

**Affected Parties:**
- All users participating in the affected incentive pools
- The protocol's reward distribution efficiency

**Severity:**
This is a Medium severity issue as it requires an attacker to sacrifice deposited capital (making it a griefing attack), but it causes permanent and irreversible reward loss to the protocol with each liquidation event.

## Likelihood Explanation

**Reachability:** The attack uses publicly accessible entry functions with no special permissions required.

**Preconditions:** Only requires capital to deposit to @0x0 - no complex protocol state requirements.

**Execution:** Single transaction to execute the deposit; subsequent liquidations automatically trigger the reward allocation.

**Economic Viability:** This is a griefing attack where the attacker sacrifices deposited funds that cannot be recovered from @0x0. However, the cost scales linearly with desired impact, making it economically viable for an attacker seeking to reduce protocol efficiency.

**Probability:** HIGH - The attack is straightforward to execute with no barriers beyond capital requirements.

## Recommendation

Add address validation to prevent deposits to @0x0:

```move
public entry fun entry_deposit_on_behalf_of_user<CoinType>(
    clock: &Clock,
    storage: &mut Storage,
    pool: &mut Pool<CoinType>,
    asset: u8,
    deposit_coin: Coin<CoinType>,
    amount: u64,
    user: address,
    incentive_v2: &mut IncentiveV2,
    incentive_v3: &mut Incentive,
    ctx: &mut TxContext
) {
    // Add validation
    assert!(user != @0x0, ERROR_INVALID_USER_ADDRESS);
    
    incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
    update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

    lending::deposit_on_behalf_of_user<CoinType>(clock, storage, pool, asset, user, deposit_coin, amount, ctx);
}
```

Additionally, consider modifying the liquidation flow to avoid updating rewards for @0x0, or use a dedicated mechanism for global index updates that doesn't allocate per-user rewards.

## Proof of Concept

```move
#[test]
fun test_zero_address_reward_loss() {
    let scenario = test_scenario::begin(OWNER);
    let _clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    clock::set_for_testing(&mut _clock, 1700006400000);
    
    // Initialize protocol and incentive pools
    {
        base::initial_protocol(&mut scenario, &_clock);
        initial_incentive_v2_v3(&mut scenario);
    };
    
    // Create incentive pool with rewards
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let usdt_funds = test_scenario::take_shared<IncentiveFundsPool<USDT_TEST>>(&scenario);
        create_incentive_pool_for_testing(
            &mut scenario, &usdt_funds, 0, 1700006400000, 
            1700006400000 + 1000 * 60 * 60, 0, 100_000000, 1, 0, 
            1000000000000000000000000000
        );
        test_scenario::return_shared(usdt_funds);
    };
    
    // Attacker deposits to @0x0
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        clock::increment_for_testing(&mut _clock, 1000 * 10);
        let pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
        let coin = coin::mint_for_testing<SUI_TEST>(10000_000000000, test_scenario::ctx(&mut scenario));
        
        // Deposit to @0x0 - THIS SHOULD FAIL BUT DOESN'T
        entry_deposit_on_behalf_of_user_for_testing(&mut scenario, &_clock, &mut pool, coin, 0, 10000_000000000, @0x0);
        
        test_scenario::return_shared(pool);
    };
    
    // Verify @0x0 has balance
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let storage = test_scenario::take_shared<Storage>(&scenario);
        let (user_supply, user_borrow) = storage::get_user_balance(&mut storage, 0, @0x0);
        assert!(user_supply == 10000_000000000, 0); // @0x0 has balance!
        test_scenario::return_shared(storage);
    };
    
    // Simulate liquidation triggering reward update for @0x0
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        clock::increment_for_testing(&mut _clock, 1000 * 30); // 30 seconds later
        let incentive = test_scenario::take_shared<Incentive>(&scenario);
        let storage = test_scenario::take_shared<Storage>(&scenario);
        
        // This is what happens during liquidation
        incentive_v2::update_reward_all(&_clock, &mut incentive, &mut storage, 0, @0x0);
        
        // Verify @0x0 accumulated rewards
        let pool_objs = incentive_v2::get_active_pools(&incentive, 0, 1, clock::timestamp_ms(&_clock));
        let (_, total_rewards) = incentive_v2::calculate_one_from_pool(&incentive, *vector::borrow(&pool_objs, 0), clock::timestamp_ms(&_clock), &mut storage, 0, @0x0);
        
        assert!(total_rewards > 0, 0); // @0x0 accumulated rewards!
        // But @0x0 can NEVER claim these rewards
        
        test_scenario::return_shared(incentive);
        test_scenario::return_shared(storage);
    };
    
    clock::destroy_for_testing(_clock);
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L815-831)
```text
    public entry fun entry_deposit_on_behalf_of_user<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        user: address,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_on_behalf_of_user<CoinType>(clock, storage, pool, asset, user, deposit_coin, amount, ctx);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L844-850)
```text
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        let _balance = lending::withdraw_coin<CoinType>(clock, oracle, storage, pool, asset, amount, ctx);
        let _coin = coin::from_balance(_balance, ctx);
        transfer::public_transfer(_coin, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L853-865)
```text
    public fun withdraw_with_account_cap<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap
    ): Balance<CoinType> {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L1077-1078)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L272-281)
```text
    public entry fun claim_reward<T>(clock: &Clock, incentive: &mut Incentive, funds_pool: &mut IncentiveFundsPool<T>, storage: &mut Storage, asset_id: u8, option: u8, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let reward_balance = base_claim_reward(clock, incentive, funds_pool, storage, asset_id, option, sender);

        if (balance::value(&reward_balance) > 0) {
            transfer::public_transfer(coin::from_balance(reward_balance, ctx), sender)
        } else {
            balance::destroy_zero(reward_balance)
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L288-291)
```text
    public fun claim_reward_with_account_cap<T>(clock: &Clock, incentive: &mut Incentive, funds_pool: &mut IncentiveFundsPool<T>, storage: &mut Storage, asset_id: u8, option: u8, account_cap: &AccountCap): Balance<T> {
        let sender = account::account_owner(account_cap);
        base_claim_reward(clock, incentive, funds_pool, storage, asset_id, option, sender)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L385-385)
```text
        let (user_supply_balance, user_borrow_balance) = storage::get_user_balance(storage, asset_id, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L398-399)
```text
            let user_effective_amount = calculate_user_effective_amount(option, user_supply_balance, user_borrow_balance, pool.factor);
            let (index_reward, total_rewards_of_user) = calculate_one(pool, now, total_supply_balance, user, user_effective_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L409-412)
```text
            if (table::contains(&pool.total_rewards_of_users, user)) {
                table::remove(&mut pool.total_rewards_of_users, user);
            };
            table::add(&mut pool.total_rewards_of_users, user, total_rewards_of_user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L452-453)
```text
        let reward_increase = (index_reward - index_rewards_paid) * user_balance;
        total_rewards_of_user = total_rewards_of_user + reward_increase;
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L176-198)
```text
    fun base_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        user: address,
        deposit_balance: Balance<CoinType>,
    ) {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let deposit_amount = balance::value(&deposit_balance);
        pool::deposit_balance(pool, deposit_balance, user);

        let normal_deposit_amount = pool::normal_amount(pool, deposit_amount);
        logic::execute_deposit<CoinType>(clock, storage, asset, user, (normal_deposit_amount as u256));

        emit(DepositEvent {
            reserve: asset,
            sender: user,
            amount: deposit_amount,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L555-565)
```text
    public(friend) fun deposit_on_behalf_of_user<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, asset: u8, user: address, deposit_coin: Coin<CoinType>, value: u64, ctx: &mut TxContext) {
        let deposit_balance = utils::split_coin_to_balance(deposit_coin, value, ctx);
        base_deposit(clock, storage, pool, asset, user, deposit_balance);

        emit(DepositOnBehalfOfEvent{
            reserve: asset,
            sender: tx_context::sender(ctx),
            user: user,
            amount: value,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L414-427)
```text
    public fun get_user_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        let supply_balance = 0;
        let borrow_balance = 0;

        if (table::contains(&reserve.supply_balance.user_state, user)) {
            supply_balance = *table::borrow(&reserve.supply_balance.user_state, user)
        };
        if (table::contains(&reserve.borrow_balance.user_state, user)) {
            borrow_balance = *table::borrow(&reserve.borrow_balance.user_state, user)
        };

        (supply_balance, borrow_balance)
    }
```
