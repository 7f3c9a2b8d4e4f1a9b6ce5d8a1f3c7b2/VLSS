### Title
Premature Freezing of Active Incentive Pools Due to Phase-Based Logic Causing Reward Loss

### Summary
The `freeze_incentive_pool()` function incorrectly uses the `phase` field to determine which pools to freeze, rather than checking whether pools have actually ended their distribution period. This causes legitimate active pools with low phase numbers to be frozen prematurely, preventing users from earning and claiming rewards they are entitled to for the remaining distribution duration.

### Finding Description

The `freeze_incentive_pool()` function moves pools from active (`pool_objs`) to inactive (`inactive_objs`) status based solely on comparing their `phase` field against a `deadline` parameter: [1](#0-0) 

The function freezes all pools where `pool_info.phase < deadline`, regardless of whether these pools are currently distributing rewards.

However, the `IncentivePool` struct shows that `phase` is completely independent from the timing fields that determine active distribution: [2](#0-1) 

The actual active status of a pool is determined by `start_at` and `end_at` timestamps, as evidenced by the `get_active_pools()` function which checks timing, not phase: [3](#0-2) 

Once a pool is frozen and moved to `inactive_objs`, it is excluded from all reward operations. The `get_pool_from_funds_pool()` function only iterates through `pool_objs`: [4](#0-3) 

Similarly, `update_reward()` relies on `get_pool_from_asset_and_option()` which also only processes active pools in `pool_objs`: [5](#0-4) 

The test suite demonstrates this exact scenario - a pool with `phase=0` that should distribute for 1 hour gets frozen after only ~20 minutes when `freeze_incentive_pool` is called with `deadline=1`: [6](#0-5) 

### Impact Explanation

**Direct Fund Impact:**
Users suffer direct financial loss by losing access to rewards they should legitimately earn. When a pool with `phase=N` is frozen while `current_time < end_at`, all users who deposited/borrowed to earn from that pool lose rewards for the entire remaining duration (`end_at - current_time`).

**Quantified Loss:**
For example, if a pool has:
- `total_supply = 100,000 USDT`
- `duration = 30 days`
- Frozen after 10 days with 20 days remaining
- Users lose 66% (20/30) of expected rewards = 66,666 USDT in lost rewards

**Who is Affected:**
All protocol users who have deposits/borrows in pools matching the frozen phase, regardless of their actual reward entitlement period.

**Severity Justification:**
HIGH severity because:
1. Direct, measurable financial loss to users
2. No mechanism to recover lost rewards or unfreeze pools
3. Affects all users of frozen pools simultaneously
4. Pool funds become permanently inaccessible for distribution

### Likelihood Explanation

**Attacker Capabilities:**
This requires the `OwnerCap` holder to call `freeze_incentive_pool()`, which is a normal administrative operation for cleaning up old campaign phases.

**Attack Complexity:**
No attack complexity - this is a logic bug in the freeze implementation. The vulnerability manifests during legitimate admin operations:
1. Protocol creates multiple incentive pools across different phases
2. Pools within the same phase have different end dates (common for staggered campaigns)
3. Admin calls `freeze_incentive_pool(deadline=N)` to clean up phase N-1
4. All phase N-1 pools are frozen, including those still actively distributing

**Feasibility Conditions:**
Highly likely to occur because:
- Phase-based organization is the intended design pattern
- Multiple pools in same phase with different durations is standard practice
- Freezing old phases is routine maintenance
- No validation prevents freezing active pools

**Detection/Operational Constraints:**
The bug is not easily detectable because:
- No error is raised when freezing active pools
- Test suite demonstrates this behavior without failing
- Users only discover lost rewards when attempting to claim

**Probability Reasoning:**
MEDIUM-HIGH probability. While it requires admin action, the admin is performing a legitimate, expected operation. The bug is in the implementation, not in admin behavior.

### Recommendation

**Code-Level Mitigation:**
Modify `freeze_incentive_pool()` to check timing-based active status before freezing:

```move
public fun freeze_incentive_pool(_: &OwnerCap, incentive_v2: &mut Incentive, deadline: u64, current_time: u64) {
    let new_active_pools = vector::empty<address>();
    let new_inactive_pools = vector::empty<address>();

    let pool_length = vector::length(&incentive_v2.pool_objs);
    while (pool_length > 0) {
        let pool_obj = *vector::borrow(&incentive_v2.pool_objs, pool_length-1);
        let pool_info = table::borrow(&incentive_v2.pools, pool_obj);
        
        // Only freeze if phase is below deadline AND pool has actually ended
        if (pool_info.phase < deadline && pool_info.end_at < current_time) {
            vector::push_back(&mut new_inactive_pools, pool_obj);
        } else {
            vector::push_back(&mut new_active_pools, pool_obj);
        };

        pool_length = pool_length - 1;
    };

    incentive_v2.pool_objs = new_active_pools;
    vector::append(&mut incentive_v2.inactive_objs, new_inactive_pools);
}
```

**Invariant Checks:**
Add assertion: `assert!(pool_info.end_at < current_time, ERROR_POOL_STILL_ACTIVE)` before freezing each pool.

**Test Cases:**
Add test that verifies pools with low phase but future `end_at` remain active after freeze operation.

### Proof of Concept

**Initial State:**
- Current timestamp: T
- Pool A created: `phase=0`, `start_at=T`, `end_at=T+1hour`, `total_supply=100,000 USDT`
- Pool B created: `phase=1`, `start_at=T`, `end_at=T+2hours`, `total_supply=100,000 USDT`
- User deposits 1,000,000 USDC to earn rewards from both pools

**Transaction Steps:**
1. At T+20min: User has accumulated ~33,333 USDT in potential rewards from Pool A (20min/60min * 100,000)
2. Admin calls `freeze_incentive_pool(incentive, deadline=1)` at T+20min
3. Pool A is frozen and moved to `inactive_objs` despite having 40 minutes of distribution remaining

**Expected vs Actual Result:**
- **Expected:** Pool A remains active until T+1hour, user earns full 100,000 USDT rewards
- **Actual:** Pool A frozen at T+20min, user loses remaining 66,666 USDT rewards for the 40 minutes they should have earned

**Success Condition:**
Verify that:
1. `get_pool_objects()` no longer includes Pool A after freeze
2. `claim_reward()` for Pool A's asset/option returns 0 balance for the user
3. User's total claimable rewards reduced by 66,666 USDT despite Pool A's `end_at` not being reached

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L251-270)
```text
    public fun freeze_incentive_pool(_: &OwnerCap, incentive_v2: &mut Incentive, deadline: u64) {
        let new_active_pools = vector::empty<address>();
        let new_inactive_pools = vector::empty<address>();

        let pool_length = vector::length(&incentive_v2.pool_objs);
        while (pool_length > 0) {
            let pool_obj = *vector::borrow(&incentive_v2.pool_objs, pool_length-1);
            let pool_info = table::borrow(&incentive_v2.pools, pool_obj);
            if (pool_info.phase < deadline) {
                vector::push_back(&mut new_inactive_pools, pool_obj);
            } else {
                vector::push_back(&mut new_active_pools, pool_obj);
            };

            pool_length = pool_length - 1;
        };

        incentive_v2.pool_objs = new_active_pools;
        vector::append(&mut incentive_v2.inactive_objs, new_inactive_pools);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L347-370)
```text
    public fun get_pool_from_funds_pool<T>(incentive: &Incentive, funds_pool: &IncentiveFundsPool<T>, asset_id: u8, option: u8): vector<address> {
        let funds_pool_obj = object::uid_to_address(&funds_pool.id);
        let ret = vector::empty<address>();

        let pool_objs = incentive.pool_objs;
        let pool_length = vector::length(&pool_objs);

        while (pool_length > 0) {
            let obj = *vector::borrow(&pool_objs, pool_length-1);
            let info = table::borrow(&incentive.pools, obj);

            if (
                (info.asset_id == asset_id) &&
                (info.option == option) &&
                (info.funds == funds_pool_obj)
            ) {
                vector::push_back(&mut ret, obj)
            };

            pool_length = pool_length - 1;
        };

        ret
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L379-416)
```text
    fun update_reward(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, asset_id: u8, option: u8, user: address) {
        version_verification(incentive);

        let now = clock::timestamp_ms(clock);
        let (_, _, pool_objs) = get_pool_from_asset_and_option(incentive, asset_id, option);
        let pool_length = vector::length(&pool_objs);
        let (user_supply_balance, user_borrow_balance) = storage::get_user_balance(storage, asset_id, user);
        let (total_supply_balance, total_borrow_balance) = storage::get_total_supply(storage, asset_id);
        if (option == constants::option_type_borrow()) {
            total_supply_balance = total_borrow_balance
        };

        
        while(pool_length > 0) {
            let pool = table::borrow_mut(
                &mut incentive.pools,
                *vector::borrow(&pool_objs, pool_length-1)
            );

            let user_effective_amount = calculate_user_effective_amount(option, user_supply_balance, user_borrow_balance, pool.factor);
            let (index_reward, total_rewards_of_user) = calculate_one(pool, now, total_supply_balance, user, user_effective_amount);

            pool.index_reward = index_reward;
            pool.last_update_at = now;
            
            if (table::contains(&pool.index_rewards_paids, user)) {
                table::remove(&mut pool.index_rewards_paids, user);
            };
            table::add(&mut pool.index_rewards_paids, user, index_reward);

            if (table::contains(&pool.total_rewards_of_users, user)) {
                table::remove(&mut pool.total_rewards_of_users, user);
            };
            table::add(&mut pool.total_rewards_of_users, user, total_rewards_of_user);

            pool_length = pool_length - 1;
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L517-537)
```text
    public fun get_active_pools(incentive: &Incentive, asset_id: u8, option: u8, now: u64): vector<address> {
        let pool_objs = incentive.pool_objs;
        let pool_length = vector::length(&pool_objs);

        let pools = vector::empty<address>();
        while (pool_length > 0) {
            let obj = *vector::borrow(&pool_objs, pool_length-1);
            let info = table::borrow(&incentive.pools, obj);

            if (
                (info.asset_id == asset_id) &&
                (info.option == option) &&
                (info.start_at <= now) &&
                (info.end_at >= now)
            ) {
                vector::push_back(&mut pools, obj);
            };
            pool_length = pool_length - 1;
        };
        pools
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/incentive_v2_tests.move (L1311-1458)
```text
                incentive_v2::create_incentive_pool<USDT_TEST>(
                    &owner_cap,
                    &mut incentive,
                    &usdt_funds,
                    0, // phase
                    current_timestamp, // start_at
                    current_timestamp + 1000 * 60 * 60, // end_at
                    0, // closed_at
                    100_000000, // total_supply
                    1, // option
                    1, // asset_id
                    1000000000000000000000000000, // factor
                    test_scenario::ctx(&mut scenario)
                );
            };

            {
                incentive_v2::create_incentive_pool<USDT_TEST>(
                    &owner_cap,
                    &mut incentive,
                    &usdt_funds,
                    0, // phase
                    current_timestamp, // start_at
                    current_timestamp + 1000 * 60 * 60, // end_at
                    0, // closed_at
                    100_000000, // total_supply
                    3, // option
                    1, // asset_id
                    1000000000000000000000000000, // factor
                    test_scenario::ctx(&mut scenario)
                );
            };

            {
                incentive_v2::create_incentive_pool<USDT_TEST>(
                    &owner_cap,
                    &mut incentive,
                    &usdt_funds,
                    1, // phase
                    current_timestamp, // start_at
                    current_timestamp + 1000 * 60 * 60 * 2, // end_at
                    0, // closed_at
                    100_000000, // total_supply
                    3, // option
                    1, // asset_id
                    1000000000000000000000000000, // factor
                    test_scenario::ctx(&mut scenario)
                );
            };

            {
                incentive_v2::create_incentive_pool<USDT_TEST>(
                    &owner_cap,
                    &mut incentive,
                    &usdt_funds,
                    1, // phase
                    current_timestamp, // start_at
                    current_timestamp + 1000 * 60 * 60 * 2, // end_at
                    0, // closed_at
                    100_000000, // total_supply
                    1, // option
                    1, // asset_id
                    1000000000000000000000000000, // factor
                    test_scenario::ctx(&mut scenario)
                );
            };

            test_scenario::return_shared(usdt_funds);
            test_scenario::return_shared(incentive);
            test_scenario::return_to_sender(&scenario, owner_cap);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let incentive = test_scenario::take_shared<Incentive>(&scenario);

            let active_pools = incentive_v2::get_pool_objects(&incentive);
            let inactive_pools = incentive_v2::get_inactive_pool_objects(&incentive);

            assert!(vector::length(&active_pools) == 4, 0);
            assert!(vector::length(&inactive_pools) == 0, 0);

            _target_pool = *vector::borrow(&active_pools, 0);

            let (_,_,_,_,_,_,_,_,_,_,last_update_at,_,_) = incentive_v2::get_pool_info(&incentive, _target_pool);
            _target_pool_update_time = last_update_at;
            test_scenario::return_shared(incentive);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            clock::increment_for_testing(&mut _clock, 1000 * 10); // 10 seconds after the reward starts
            let pool = test_scenario::take_shared<Pool<USDC_TEST>>(&scenario);

            let coin = coin::mint_for_testing<USDC_TEST>(100_000000000, test_scenario::ctx(&mut scenario));

            entry_deposit_for_testing(&mut scenario, &_clock, &mut pool, coin, 1, 100_000000000);
            let (total_supply, _, _) = pool::get_pool_info(&pool);
            assert!(total_supply == 100_000000000, 0);

            test_scenario::return_shared(pool);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            clock::increment_for_testing(&mut _clock, 1000 * 60 * 20); // 50 seconds after the reward starts
            let usdt_funds = test_scenario::take_shared<IncentiveFundsPool<USDT_TEST>>(&scenario);
            let storage = test_scenario::take_shared<Storage>(&scenario);
            let incentive = test_scenario::take_shared<Incentive>(&scenario);
            let price_oracle = test_scenario::take_shared<PriceOracle>(&scenario);
            
            let _balance = incentive_v2::claim_reward_non_entry(&_clock, &mut incentive, &mut usdt_funds, &mut storage, 1, 1, test_scenario::ctx(&mut scenario));
            assert!(balance::value(&_balance) > 0, 0);

            transfer::public_transfer(coin::from_balance(_balance, test_scenario::ctx(&mut scenario)), OWNER);
            test_scenario::return_shared(storage);
            test_scenario::return_shared(incentive);
            test_scenario::return_shared(price_oracle);
            test_scenario::return_shared(usdt_funds);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            clock::increment_for_testing(&mut _clock, 1000 * 1); // 50 seconds after the reward starts
            let owner_cap = test_scenario::take_from_sender<OwnerCap>(&scenario);
            let incentive = test_scenario::take_shared<Incentive>(&scenario);

            incentive_v2::freeze_incentive_pool(&owner_cap, &mut incentive, 1);
            test_scenario::return_shared(incentive);
            test_scenario::return_to_sender(&scenario, owner_cap);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            clock::increment_for_testing(&mut _clock, 1000 * 60 * 20); // 50 seconds after the reward starts
            let usdt_funds = test_scenario::take_shared<IncentiveFundsPool<USDT_TEST>>(&scenario);
            let storage = test_scenario::take_shared<Storage>(&scenario);
            let incentive = test_scenario::take_shared<Incentive>(&scenario);
            let price_oracle = test_scenario::take_shared<PriceOracle>(&scenario);
            
            let _balance = incentive_v2::claim_reward_non_entry(&_clock, &mut incentive, &mut usdt_funds, &mut storage, 1, 1, test_scenario::ctx(&mut scenario));
            assert!(balance::value(&_balance) > 0, 0);

            let active_pools = incentive_v2::get_pool_objects(&incentive);
            let inactive_pools = incentive_v2::get_inactive_pool_objects(&incentive);
            
            assert!(vector::length(&active_pools) == 2, 0);
            assert!(vector::length(&inactive_pools) == 2, 0);
```
