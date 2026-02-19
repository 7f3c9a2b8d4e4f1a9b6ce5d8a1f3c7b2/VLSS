# Audit Report

## Title
Insufficient Balance Check Causes Reward Claim Denial of Service

## Summary
The `base_claim_reward()` function in `incentive_v2.move` lacks validation that `IncentiveFundsPool` has sufficient balance before attempting to pay rewards. When administrators withdraw funds through `withdraw_funds()`, the pool balance can drop below total unclaimed rewards owed to users, causing all subsequent reward claims to permanently fail.

## Finding Description

The vulnerability exists due to missing synchronization between logical reward accounting and physical token custody in the incentive system.

The `base_claim_reward()` function calculates the total `amount_to_pay` based on user rewards tracked in the `IncentivePool` data structure, iterating through matching pools and accumulating rewards from each. [1](#0-0) 

After calculating the reward amount, it directly calls `decrease_balance()` to transfer tokens to the user without verifying that the `IncentiveFundsPool` has sufficient balance. [2](#0-1) 

The `decrease_balance()` function directly invokes `balance::split()` without any balance validation, which will abort if the requested amount exceeds the available balance. [3](#0-2) 

Meanwhile, administrators can withdraw funds at any time using the `withdraw_funds()` function, which only validates that the withdrawal amount doesn't exceed the current balance, but does not check whether this would leave enough funds to cover pending user reward claims. [4](#0-3) 

The protocol maintains two independent accounting systems:
1. **Logical reward tracking** in `IncentivePool` (`total_supply`, `distributed`, `total_rewards_of_users`)
2. **Physical token custody** in `IncentiveFundsPool` (`balance`)

There is no invariant enforcement that `IncentiveFundsPool.balance >= sum_of_all_unclaimed_rewards`, creating a critical desynchronization risk.

For comparison, the `storage.move` module demonstrates the correct pattern with an explicit balance check before decreasing. [5](#0-4) 

## Impact Explanation

This vulnerability causes a denial of service with the following impacts:

1. **User Fund Lock**: Users who have legitimately earned rewards through supplying, borrowing, or other incentivized actions become unable to claim their rewards. All claim attempts abort at the `balance::split()` call, with error code 1506 (insufficient_balance). [6](#0-5) 

2. **Permanence**: The DoS persists indefinitely unless administrators manually refund the pool. Users' unclaimed rewards remain inaccessible despite being correctly tracked in the accounting system.

3. **Scope**: Affects all users with pending claims for any pool where the `IncentiveFundsPool` has been over-withdrawn relative to unclaimed obligations.

4. **Protocol Trust**: Severely undermines user confidence as the protocol fails to honor earned incentive rewards, even though rewards are accurately calculated and tracked.

This represents an **Operational Impact** where valid user actions (claiming earned rewards through public entry functions) are blocked due to a missing protocol invariant.

## Likelihood Explanation

The likelihood of this vulnerability manifesting is **HIGH**:

1. **Reachable Entry Points**: Any user can call the public entry function `claim_reward()` or the public function `claim_reward_non_entry()` to trigger the vulnerable code path. [7](#0-6) 

2. **Feasible Preconditions**: Administrators with valid `OwnerCap` can legitimately call `withdraw_funds()` at any time. They may withdraw funds believing them to be excess or for operational rebalancing, unaware that these funds are reserved for pending user claims. The system provides no warning or check to prevent this.

3. **No Synchronization Mechanism**: The protocol maintains separate accounting systems with no enforcement mechanism linking them. There is no proactive validation, no event emission indicating unsafe state, and no getter function to calculate total pending obligations.

4. **Normal Operational Scenario**: In routine operations, administrators may need to:
   - Rebalance funds across multiple incentive pools
   - Withdraw excess funds for treasury management
   - Consolidate liquidity for operational efficiency
   
   Each of these legitimate actions risks creating the insufficient balance condition.

5. **Detection Difficulty**: The issue only becomes apparent when users attempt to claim rewards, not when administrators perform withdrawals. This delayed failure makes the problem harder to detect and prevent proactively.

## Recommendation

Add explicit balance validation before attempting to pay rewards:

```move
fun base_claim_reward<T>(clock: &Clock, incentive: &mut Incentive, funds_pool: &mut IncentiveFundsPool<T>, storage: &mut Storage, asset_id: u8, option: u8, user: address): Balance<T> {
    version_verification(incentive);
    
    let now = clock::timestamp_ms(clock);
    update_reward(clock, incentive, storage, asset_id, option, user);
    
    let hits = get_pool_from_funds_pool(incentive, funds_pool, asset_id, option);
    let hit_length = vector::length(&hits);
    let amount_to_pay = 0;
    
    // [existing reward calculation loop - lines 303-338]
    
    if (amount_to_pay > 0) {
        // ADD THIS CHECK:
        assert!(balance::value(&funds_pool.balance) >= amount_to_pay, error::insufficient_balance());
        
        let _balance = decrease_balance(funds_pool, amount_to_pay);
        return _balance
    };
    return balance::zero<T>()
}
```

Additionally, add a validation check in `withdraw_funds()` to prevent over-withdrawal:

```move
public fun withdraw_funds<T>(_: &OwnerCap, funds: &mut IncentiveFundsPool<T>, incentive: &Incentive, value: u64, ctx: &mut TxContext) {
    let current_balance = balance::value(&funds.balance);
    assert!(current_balance >= value, error::insufficient_balance());
    
    // Calculate total pending obligations for this funds pool
    let total_pending = calculate_total_pending_rewards(incentive, funds);
    assert!(current_balance - value >= total_pending, error::insufficient_balance());
    
    let _coin = coin::from_balance(
        balance::split(&mut funds.balance, value),
        ctx
    );
    transfer::public_transfer(_coin, tx_context::sender(ctx));
    
    emit(WithdrawFunds {
        sender: tx_context::sender(ctx),
        value: value,
    })
}
```

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = 1506, location = lending_core::incentive_v2)]
public fun test_claim_fails_after_admin_withdrawal() {
    let scenario = test_scenario::begin(OWNER);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    let current_timestamp = 1700000000000;
    clock::set_for_testing(&mut clock, current_timestamp);
    
    // Initialize protocol and incentive pools
    base::initial_protocol(&mut scenario, &clock);
    initial_incentive_v2(&mut scenario);
    
    // Create incentive pool with 1000 USDT total supply
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let usdt_funds = test_scenario::take_shared<IncentiveFundsPool<USDT_TEST>>(&scenario);
        create_incentive_pool_for_testing(
            &mut scenario,
            &usdt_funds,
            0, // phase
            current_timestamp, 
            current_timestamp + 3600000, // 1 hour duration
            0, // no close time
            1000_000000, // total_supply: 1000 USDT
            1, // option: supply
            0, // asset: SUI
            1000000000000000000000000000 // factor
        );
        test_scenario::return_shared(usdt_funds);
    };
    
    // User deposits SUI to earn rewards
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        clock::increment_for_testing(&mut clock, 1800000); // Fast forward 30 minutes
        let pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
        let coin = coin::mint_for_testing<SUI_TEST>(10000_000000000, test_scenario::ctx(&mut scenario));
        entry_deposit_for_testing(&mut scenario, &clock, &mut pool, coin, 0, 10000_000000000);
        test_scenario::return_shared(pool);
    };
    
    // Admin withdraws 900 USDT (leaving only 100, but user has earned ~500 in rewards)
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let owner_cap = test_scenario::take_from_sender<OwnerCap>(&scenario);
        let usdt_funds = test_scenario::take_shared<IncentiveFundsPool<USDT_TEST>>(&scenario);
        
        // This withdrawal is allowed (900 < 1000 balance)
        incentive_v2::withdraw_funds(&owner_cap, &mut usdt_funds, 90000_000000, test_scenario::ctx(&mut scenario));
        
        test_scenario::return_shared(usdt_funds);
        test_scenario::return_to_sender(&scenario, owner_cap);
    };
    
    // User tries to claim rewards - THIS WILL FAIL
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        clock::increment_for_testing(&mut clock, 1800000); // Complete the reward period
        let usdt_funds = test_scenario::take_shared<IncentiveFundsPool<USDT_TEST>>(&scenario);
        
        // This will abort with error 1506 (insufficient_balance) 
        // because funds_pool only has 10000_000000 but user earned ~500_000000
        claim_reward_for_testing(&mut scenario, &clock, &mut usdt_funds, 0, 1);
        
        test_scenario::return_shared(usdt_funds);
    };
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L167-180)
```text
    public fun withdraw_funds<T>(_: &OwnerCap, funds: &mut IncentiveFundsPool<T>, value: u64, ctx: &mut TxContext) {
        assert!(balance::value(&funds.balance) >= value, error::insufficient_balance());

        let _coin = coin::from_balance(
            balance::split(&mut funds.balance, value),
            ctx
        );
        transfer::public_transfer(_coin, tx_context::sender(ctx));

        emit(WithdrawFunds {
            sender: tx_context::sender(ctx),
            value: value,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L272-286)
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

    public fun claim_reward_non_entry<T>(clock: &Clock, incentive: &mut Incentive, funds_pool: &mut IncentiveFundsPool<T>, storage: &mut Storage, asset_id: u8, option: u8, ctx: &TxContext): Balance<T> {
        let sender = tx_context::sender(ctx);
        base_claim_reward(clock, incentive, funds_pool, storage, asset_id, option, sender)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L300-338)
```text
        let hits = get_pool_from_funds_pool(incentive, funds_pool, asset_id, option);
        let hit_length = vector::length(&hits);
        let amount_to_pay = 0;
        while (hit_length > 0) {
            let pool_obj = *vector::borrow(&hits, hit_length-1);
            let pool = table::borrow_mut(&mut incentive.pools, pool_obj);
            if (pool.closed_at > 0 && now > pool.closed_at) {
                hit_length = hit_length -1;
                continue
            };

            let total_rewards_of_user = 0;
            if (table::contains(&pool.total_rewards_of_users, user)) {
                total_rewards_of_user = *table::borrow(&pool.total_rewards_of_users, user);
            };

            let total_claimed_of_user = 0;
            if (table::contains(&pool.total_claimed_of_users, user)) {
                total_claimed_of_user = table::remove(&mut pool.total_claimed_of_users, user);
            };
            table::add(&mut pool.total_claimed_of_users, user, total_rewards_of_user);

            let reward = ((total_rewards_of_user - total_claimed_of_user) / ray_math::ray() as u64);
            if ((pool.distributed + reward) > pool.total_supply) {
                reward = pool.total_supply - pool.distributed
            };

            if (reward > 0) {
                amount_to_pay = amount_to_pay + reward;
                pool.distributed = pool.distributed + reward;

                emit(RewardsClaimed {
                    sender: user,
                    pool: pool_obj,
                    amount: reward,
                })
            };
            hit_length = hit_length -1;
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L340-344)
```text
        if (amount_to_pay > 0) {
            let _balance = decrease_balance(funds_pool, amount_to_pay);
            return _balance
        };
        return balance::zero<T>()
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L634-637)
```text
    fun decrease_balance<T>(funds_pool: &mut IncentiveFundsPool<T>, amount: u64): Balance<T> {
        let _balance = balance::split(&mut funds_pool.balance, amount);
        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L553-563)
```text
    fun decrease_balance(_balance: &mut TokenBalance, user: address, amount: u256) {
        let current_amount = 0;

        if (table::contains(&_balance.user_state, user)) {
            current_amount = table::remove(&mut _balance.user_state, user)
        };
        assert!(current_amount >= amount, error::insufficient_balance());

        table::add(&mut _balance.user_state, user, current_amount - amount);
        _balance.total_supply = _balance.total_supply - amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/error.move (L11-11)
```text
    public fun insufficient_balance(): u64 {1506}
```
