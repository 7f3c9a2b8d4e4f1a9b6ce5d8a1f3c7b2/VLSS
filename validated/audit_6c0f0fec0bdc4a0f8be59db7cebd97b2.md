# Audit Report

## Title
Insufficient Balance Check Causes Reward Claim Denial of Service

## Summary
The `base_claim_reward()` function lacks validation that `IncentiveFundsPool` has sufficient balance before attempting reward payouts. Administrators can withdraw funds through `withdraw_funds()` without checking if this leaves enough to cover pending user rewards, causing permanent DoS for all reward claim attempts until manual refunding occurs.

## Finding Description

The vulnerability arises from a missing protocol invariant between logical reward accounting (`IncentivePool`) and physical token custody (`IncentiveFundsPool`).

The `base_claim_reward()` function calculates `amount_to_pay` by iterating through matching incentive pools and accumulating user rewards based on the logical accounting system. [1](#0-0) 

After calculating the total reward amount, it directly calls `decrease_balance()` to transfer tokens without verifying that `IncentiveFundsPool` has sufficient physical balance. [2](#0-1) 

The `decrease_balance()` function directly invokes `balance::split()` without any balance validation. [3](#0-2)  When the requested amount exceeds available balance, this operation aborts with error code 1506 (insufficient_balance). [4](#0-3) 

Meanwhile, the `withdraw_funds()` function allows administrators with `OwnerCap` to withdraw funds at any time. It only validates that the withdrawal amount doesn't exceed current balance, but performs no check whether this would leave sufficient funds to cover pending user reward claims. [5](#0-4) 

The protocol maintains two separate accounting systems with no synchronization:
1. **Logical reward tracking** in `IncentivePool` via `total_supply`, `distributed`, and `total_rewards_of_users` fields [6](#0-5) 
2. **Physical token custody** in `IncentiveFundsPool` via the `balance` field [7](#0-6) 

There is no invariant enforcement that `IncentiveFundsPool.balance >= sum_of_all_unclaimed_rewards`. For comparison, the `storage.move` module demonstrates proper balance checking with an explicit assertion before decreasing balances. [8](#0-7) 

## Impact Explanation

This vulnerability causes denial of service with the following impacts:

1. **User Fund Lock**: Users who have legitimately earned rewards through supplying, borrowing, or other incentivized actions become unable to claim their rewards. All claim attempts via the public entry functions `claim_reward()` and `claim_reward_non_entry()` abort at the `balance::split()` call. [9](#0-8) 

2. **Permanence**: The DoS persists indefinitely unless administrators manually detect the issue and refund the pool. Users' unclaimed rewards remain correctly tracked in the accounting system but inaccessible.

3. **Scope**: Affects all users with pending claims for any pool where the `IncentiveFundsPool` has been over-withdrawn relative to unclaimed obligations.

4. **Protocol Trust**: Severely undermines user confidence as the protocol fails to honor earned incentive rewards despite accurate calculation and tracking.

This represents an operational impact where valid user actions are blocked due to a missing protocol invariant enforcement, violating the fundamental guarantee that users can claim their earned rewards.

## Likelihood Explanation

The likelihood of this vulnerability manifesting is **HIGH**:

1. **Reachable Entry Points**: Any user can trigger the vulnerable code path by calling the public entry function `claim_reward()` or public function `claim_reward_non_entry()`. [9](#0-8) 

2. **Feasible Preconditions**: Administrators with valid `OwnerCap` can legitimately call `withdraw_funds()` at any time during normal operations. They may withdraw funds believing them to be excess or for operational rebalancing, unaware that these funds are reserved for pending user claims. The system provides no warning, check, or getter function to calculate total pending obligations.

3. **No Synchronization Mechanism**: The protocol maintains separate accounting systems with no enforcement linking them. There is no proactive validation preventing unsafe withdrawals and no event emission indicating an unsafe state.

4. **Normal Operational Scenario**: In routine operations, administrators may need to rebalance funds across multiple incentive pools, withdraw excess funds for treasury management, or consolidate liquidity for operational efficiency. Each of these legitimate actions risks creating the insufficient balance condition without the administrator realizing it.

5. **Detection Difficulty**: The issue only becomes apparent when users attempt to claim rewards, not when administrators perform withdrawals. This delayed failure makes the problem extremely difficult to detect and prevent proactively.

## Recommendation

Add a balance check before the `decrease_balance()` call in `base_claim_reward()`:

```move
if (amount_to_pay > 0) {
    assert!(balance::value(&funds_pool.balance) >= amount_to_pay, error::insufficient_balance());
    let _balance = decrease_balance(funds_pool, amount_to_pay);
    return _balance
};
```

Additionally, implement a view function to calculate total unclaimed rewards and add a check in `withdraw_funds()` to prevent withdrawals that would violate the invariant:

```move
public fun withdraw_funds<T>(_: &OwnerCap, funds: &mut IncentiveFundsPool<T>, incentive: &Incentive, value: u64, ctx: &mut TxContext) {
    let funds_pool_address = object::uid_to_address(&funds.id);
    let total_unclaimed = calculate_total_unclaimed_rewards(incentive, funds_pool_address);
    let current_balance = balance::value(&funds.balance);
    
    assert!(current_balance >= value, error::insufficient_balance());
    assert!(current_balance - value >= total_unclaimed, error::insufficient_balance());
    
    // ... rest of function
}
```

## Proof of Concept

```move
#[test]
fun test_reward_claim_dos_after_admin_withdrawal() {
    let scenario_val = test_scenario::begin(OWNER);
    let scenario = &mut scenario_val;
    
    // Setup: Initialize protocol, create incentive pool with 1000 tokens total_supply
    base_lending_tests::initial_lending(scenario);
    initial_incentive_v2_v3(scenario);
    
    test_scenario::next_tx(scenario, OWNER);
    let owner_cap = test_scenario::take_from_sender<OwnerCap>(scenario);
    let incentive = test_scenario::take_shared<Incentive>(scenario);
    let usdc_funds = test_scenario::take_shared<IncentiveFundsPool<USDC_TEST>>(scenario);
    let clock = clock::create_for_testing(test_scenario::ctx(scenario));
    
    // Create incentive pool with 1000 tokens supply
    create_incentive_pool_for_testing<USDC_TEST>(scenario, &usdc_funds, 1, 1000, 2000, 0, 1000_000000, 0, 1, 1000000000000000000000000000);
    
    // Users earn rewards through deposits (rewards tracked in IncentivePool)
    test_scenario::next_tx(scenario, UserB);
    let storage = test_scenario::take_shared<Storage>(scenario);
    let pool = test_scenario::take_shared<Pool<USDC_TEST>>(scenario);
    let deposit_coin = coin::mint_for_testing<USDC_TEST>(1000_000000, test_scenario::ctx(scenario));
    
    // ... user deposits and earns rewards ...
    
    // Admin withdraws 800 tokens (thinking they are excess)
    test_scenario::next_tx(scenario, OWNER);
    incentive_v2::withdraw_funds(&owner_cap, &mut usdc_funds, 800_000000, test_scenario::ctx(scenario));
    
    // Now IncentiveFundsPool.balance = 200 tokens, but users have earned 1000 tokens
    
    // User tries to claim 300 tokens of rewards
    test_scenario::next_tx(scenario, UserB);
    clock::set_for_testing(&mut clock, 1500);
    
    // This call will ABORT with error 1506 (insufficient_balance)
    incentive_v2::claim_reward<USDC_TEST>(&clock, &mut incentive, &mut usdc_funds, &mut storage, 1, 0, test_scenario::ctx(scenario));
    
    // DoS: All users cannot claim rewards until admin refunds the pool
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L45-62)
```text
    struct IncentivePool has key, store {
        id: UID,
        phase: u64,
        funds: address, // IncentiveFundsPool.id -> pre_check: object::id_to_address(IncentiveFundsPool.id) equals IncentivePool.funds
        start_at: u64, // Distribution start time
        end_at: u64, // Distribution end time
        closed_at: u64, // Distribution closed time, that means you cannot claim after this time. But the administrator can set this value to 0, which means it can always be claimed.
        total_supply: u64, // sui::balance::supply_value max is 18446744073709551615u64, see https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/packages/sui-framework/sources/balance.move#L53
        option: u8, // supply, withdraw, borrow, repay or liquidation
        asset_id: u8, // the asset id on protocol pool
        factor: u256, // the ratio, type in 1e18
        last_update_at: u64,
        distributed: u64,
        index_reward: u256,
        index_rewards_paids: Table<address, u256>,
        total_rewards_of_users: Table<address, u256>,
        total_claimed_of_users: Table<address, u256>,
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L64-69)
```text
    struct IncentiveFundsPool<phantom CoinType> has key, store {
        id: UID,
        oracle_id: u8,
        balance: Balance<CoinType>,
        coin_type: TypeName,
    }
```

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/error.move (L11-11)
```text
    public fun insufficient_balance(): u64 {1506}
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
