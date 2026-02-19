### Title
Reward Calculation Mismatch Between Global Index and User Balance Causes Systematic Reward Underpayment

### Summary
The incentive_v3 system calculates the global reward index using gross total balances (total_supply/total_borrow) but calculates individual user rewards using net effective balances (user_effective_supply/user_effective_borrow). This denominator mismatch causes all users with effective positions to systematically receive fewer rewards than intended, with the shortfall remaining undistributed in the reward fund.

### Finding Description

The vulnerability exists in the reward calculation logic within the incentive_v3 module:

**Root Cause - Global Index Calculation:** [1](#0-0) 

The `calculate_global_index()` function uses `total_supply` for supply rewards and `total_borrow` for borrow rewards as the denominator. These represent the **gross totals** of all users' positions.

**Root Cause - User Reward Calculation:** [2](#0-1) 

The `calculate_user_reward()` function uses `user_effective_supply` for supply rewards and `user_effective_borrow` for borrow rewards. These represent **net positions** (supply - borrow or borrow - supply).

**The Mismatch:** [3](#0-2) 

The `get_effective_balance()` function calculates effective balances as net positions, where a user with equal supply and borrow has zero effective balance. However, their gross positions still contribute to the total_supply and total_borrow used in the global index denominator.

**Execution Path:** [4](#0-3) 

The flow in `update_reward_state_by_rule_and_balance()` calls both functions, creating the inconsistency where the global index growth rate is diluted by users with offsetting positions, but only users with net effective positions receive rewards.

### Impact Explanation

**Direct Fund Impact:**
Users systematically receive fewer rewards than the configured emission rate intends to distribute. The shortfall remains in the reward fund permanently.

**Quantified Example from Test Code:** [5](#0-4) 

In this test scenario:
- Alice: 100 SUI supply + 100 SUI borrow = 0 effective supply
- Bob: 900 SUI supply + 0 SUI borrow = 900 effective supply
- Total supply: 1000 SUI
- Sum of effective supplies: 900 SUI

Bob should receive 100% of the 100 SUI/day reward (36,500 SUI over 10 years), but the test confirms he receives only ~90% (32,850 SUI). The missing 10% (3,650 SUI) is never distributed.

**Who is Affected:**
All users participating in incentivized supply/borrow positions are affected proportionally to the ratio of (sum of effective balances) / (gross total balances). The more users have offsetting positions, the greater the dilution.

**Severity Justification:**
HIGH - This is a systematic protocol-level accounting error that causes measurable financial loss to all reward participants on every reward accrual. The impact scales with the total value of rewards distributed.

### Likelihood Explanation

**Reachable Entry Point:** [6](#0-5) 

The vulnerability triggers automatically during normal protocol operations (deposits, withdrawals, borrows, repays) through the `update_reward_state_by_asset()` call chain. No special actions required.

**Feasible Preconditions:**
The vulnerability is always active whenever:
1. Reward rules are enabled
2. Any user has offsetting supply/borrow positions in the same asset

This is a common and legitimate use case (e.g., users leveraging positions or maintaining liquidity).

**Execution Practicality:**
The issue occurs passively through the protocol's normal reward accounting logic. Every user interaction that updates rewards perpetuates the miscalculation.

**Economic Rationality:**
No exploit cost exists - the underpayment happens automatically as part of the protocol's core mechanics. Users cannot avoid it or benefit from it differentially.

**Probability:**
CERTAIN - The vulnerability is active continuously in any pool with enabled rewards where users have offsetting positions. The test suite itself confirms this behavior as the implemented logic.

### Recommendation

**Fix the Denominator Mismatch:**

The protocol must choose one consistent approach:

**Option 1 (Recommended):** Use sum of effective balances in global index calculation:
- Track `total_effective_supply` and `total_effective_borrow` separately
- Update these values on every user balance change
- Modify `calculate_global_index()` to use these effective totals as the denominator

**Option 2:** Use gross balances for user rewards (not recommended):
- This would reward users for offsetting positions, creating an economic exploit

**Code Changes Required:** [1](#0-0) 

Replace the denominator in `calculate_global_index()` from `total_supply`/`total_borrow` to `total_effective_supply`/`total_effective_borrow`.

**Test Case to Add:**
Create a test that verifies: When user A has offsetting positions (zero effective balance) and user B has a net position, user B receives 100% of rewards, not a diluted portion.

### Proof of Concept

**Initial State:**
- Reward rule configured: 100 SUI per day for supply rewards
- Total time period: 10 years (3,650 days)
- Expected total distribution: 365,000 SUI

**Transaction Sequence:** [7](#0-6) 

1. Alice borrows 100 SUI
2. Bob deposits 900 SUI  
3. Alice deposits 100 SUI (now has offsetting positions)

**Result State:**
- Alice: 100 supply, 100 borrow → effective_supply = 0
- Bob: 900 supply, 0 borrow → effective_supply = 900
- Total supply: 1,000 SUI (used in index calculation)
- Sum of effective supplies: 900 SUI (used in user rewards)

**Expected vs Actual:** [8](#0-7) 

- Expected: Bob receives 365,000 SUI (100% of rewards, as only qualified user)
- Actual: Bob receives ~328,500 SUI (90% of rewards)
- Shortfall: ~36,500 SUI (10%) remains in reward fund

**Success Condition:**
The test explicitly validates this incorrect behavior with `lib::close_to((bob_sui_amount as u256), 365000000000000 / 10 * 9, 10)`, confirming Bob receives 90% instead of 100% of the intended rewards.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L483-508)
```text
    public fun get_effective_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256, u256, u256) {
        // get the total supply and borrow
        let (total_supply, total_borrow) = storage::get_total_supply(storage, asset);
        let (user_supply, user_borrow) = storage::get_user_balance(storage, asset, user);
        let (supply_index, borrow_index) = storage::get_index(storage, asset);

        // calculate the total supply and borrow
        let total_supply = ray_math::ray_mul(total_supply, supply_index);
        let total_borrow = ray_math::ray_mul(total_borrow, borrow_index);
        let user_supply = ray_math::ray_mul(user_supply, supply_index);
        let user_borrow = ray_math::ray_mul(user_borrow, borrow_index);

        // calculate the user effective supply
        let user_effective_supply: u256 = 0;
        if (user_supply > user_borrow) {
            user_effective_supply = user_supply - user_borrow;
        };

        // calculate the user effective borrow
        let user_effective_borrow: u256 = 0;
        if (user_borrow > user_supply) {
            user_effective_borrow = user_borrow - user_supply;
        };

        (user_effective_supply, user_effective_borrow, total_supply, total_borrow)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L549-571)
```text
    fun update_reward_state_by_rule_and_balance(clock: &Clock, rule: &mut Rule, user: address, user_effective_supply: u256, user_effective_borrow: u256, total_supply: u256, total_borrow: u256) {
        let new_global_index = calculate_global_index(clock, rule, total_supply, total_borrow);
        let new_user_total_reward = calculate_user_reward(rule, new_global_index, user, user_effective_supply, user_effective_borrow);
        // update the user index to the new global index
        if (table::contains(&rule.user_index, user)) {
            let user_index = table::borrow_mut(&mut rule.user_index, user);
            *user_index = new_global_index;
        } else {
            table::add(&mut rule.user_index, user, new_global_index);
        };

        // update the user rewards to plus the new reward
        if (table::contains(&rule.user_total_rewards, user)) {
            let user_total_reward = table::borrow_mut(&mut rule.user_total_rewards, user);
            *user_total_reward = new_user_total_reward;
        } else {
            table::add(&mut rule.user_total_rewards, user, new_user_total_reward);
        };

        // update the last update time and global index
        rule.last_update_at = clock::timestamp_ms(clock);
        rule.global_index = new_global_index;    
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L573-590)
```text
    fun calculate_global_index(clock: &Clock, rule: &Rule, total_supply: u256, total_borrow: u256): u256 {
        let total_balance = if (rule.option == constants::option_type_supply()) {
            total_supply
        } else if (rule.option == constants::option_type_borrow()) {
            total_borrow
        } else {
            abort 0
        };
        
        let now = clock::timestamp_ms(clock);
        let duration = now - rule.last_update_at;
        let index_increased = if (duration == 0 || total_balance == 0) {
            0
        } else {
            (rule.rate * (duration as u256)) / total_balance
        };
        rule.global_index + index_increased
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L592-603)
```text
    fun calculate_user_reward(rule: &Rule, global_index: u256, user: address, user_effective_supply: u256, user_effective_borrow: u256): u256 {
        let user_balance = if (rule.option == constants::option_type_supply()) {
            user_effective_supply
        } else if (rule.option == constants::option_type_borrow()) {
            user_effective_borrow
        } else {
            abort 0
        };
        let user_index_diff = global_index - get_user_index_by_rule(rule, user);
        let user_reward = get_user_total_rewards_by_rule(rule, user);
        user_reward + ray_math::ray_mul(user_balance, user_index_diff)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L789-813)
```text
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_coin<CoinType>(clock, storage, pool, asset, deposit_coin, amount, ctx);
    }

    public fun deposit_with_account_cap<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        account_cap: &AccountCap
    ) {
        let owner = account::account_owner(account_cap);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, owner);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, owner);

        lending::deposit_with_account_cap<CoinType>(clock, storage, pool, asset, deposit_coin, account_cap);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/incentive_v3_tests/incentive_v3.test.move (L1204-1334)
```text
        // 100 SUI per day for supply
        // 50 SUI per day for borrow
        // user B deposit 900 SUI
        // user A borrow 100 SUI
        incentive_v3_util::init_base_deposit_borrow_for_testing<SUI_TEST_V2>(
            scenario_mut, 
            0, 
            alice, 
            100_000000000, 
            bob, 
            900_000000000, 
            &clock);

        // user A deposit 100 SUI
        incentive_v3_util::user_deposit<SUI_TEST_V2>(scenario_mut, alice, 0, 100_000000000, &clock);

        // update index
        test_scenario::next_tx(scenario_mut, alice);
        {
            let incentive = test_scenario::take_shared<Incentive_V3>(scenario_mut);
            let storage = test_scenario::take_shared<Storage>(scenario_mut);

            // update index for 1 second
            clock::set_for_testing(&mut clock, 1000);
            incentive_v3::update_index_for_testing<SUI_TEST_V2>(&clock, &mut incentive, &mut storage);

            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
            lib::printf(b"1s index1:");
            // 100 * 10^9 / 86400000 * 1000 * (10^27) / 1000 / 10^9 = 1.1574074074×10²¹
            lib::print(&idx); // 1157407407407407407407
            assert!(idx == 1157407407407407407407, 0);
            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 3);
            lib::printf(b"1s index3:");
            // 50 * 10^9 / 86400000 * 1000 * (10^27) / 100 / 10^9 = 5.787037037×10²¹
            lib::print(&idx);  // 5787037037037037037037
            assert!(idx == 5787037037037037037037, 0);

            // update index for 1 minute
            clock::set_for_testing(&mut clock, 60 * 1000);
            incentive_v3::update_index_for_testing<SUI_TEST_V2>(&clock, &mut incentive, &mut storage);

            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
            lib::printf(b"1m index1:");
            // 100 * 10^9 / 86400000 * 1000 * 60 * (10^27) / 1000 / 10^9 = 6.9444444444×10²²
            lib::print(&idx); // 69444444444444444444444
            assert!(idx == 69444444444444444444444, 0);
            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 3);
            lib::printf(b"1m index3:"); // 347222222222222222222222
            // 50 * 10^9 / 86400000 * 1000 * 60 * (10^27) / 100 / 10^9 = 3.4722222222×10²³
            assert!(idx == 347222222222222222222222, 0);
            lib::print(&idx); // 347222222222222222222222

            // update index for 1 hour
            clock::set_for_testing(&mut clock, 60 * 60 * 1000);
            incentive_v3::update_index_for_testing<SUI_TEST_V2>(&clock, &mut incentive, &mut storage);

            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
            lib::printf(b"1h index1:");
            // 100 * 10^9 / 86400000 * 1000 * 60 * 60 * (10^27) / 1000 / 10^9 = 4.1666666667×10²⁴
            lib::print(&idx); // 4166666666666666666666666
            assert!(idx == 4166666666666666666666666, 0);
            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 3);
            lib::printf(b"1h index3:"); // 20833333333333333333333333
            // 50 * 10^9 / 86400000 * 1000 * 60 * 60 * (10^27) / 100 / 10^9 = 2.08333333333×10²⁵
            assert!(idx == 20833333333333333333333333, 0);
            lib::print(&idx);

            // update index for 1 day
            clock::set_for_testing(&mut clock, 60 * 60 * 24 * 1000);
            incentive_v3::update_index_for_testing<SUI_TEST_V2>(&clock, &mut incentive, &mut storage); 

            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
            lib::printf(b"1d index1:");
            // 100 * 10^9 / 86400000 * 1000 * 60 * 60 * 24 * (10^27) / 1000 / 10^9 = 1×10²⁶
            lib::print(&idx); // 99999999999999999999999999
            assert!(idx == 99999999999999999999999999, 0);
            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 3);
            lib::printf(b"1d index3:"); // 499999999999999999999999999
            // 50 * 10^9 / 86400000 * 1000 * 60 * 60 * 24 * (10^27) / 100 / 10^9 = 5×10²⁶
            assert!(idx == 499999999999999999999999999, 0);
            lib::print(&idx);

            // update index for 1 year
            clock::set_for_testing(&mut clock, 60 * 60 * 24 * 365 * 1000);
            incentive_v3::update_index_for_testing<SUI_TEST_V2>(&clock, &mut incentive, &mut storage);

            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
            lib::printf(b"1y index1:");
            // 100 * 10^9 / 86400000 * 1000 * 60 * 60 * 24 * 365 * (10^27) / 1000 / 10^9 = 3.65×10²⁸
            lib::print(&idx); // 36499999999999999999999999998
            assert!(idx == 36499999999999999999999999998, 0);
            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 3);
            lib::printf(b"1y index3:"); // 182499999999999999999999999999
            // 50 * 10^9 / 86400000 * 1000 * 60 * 60 * 24 * 365 * (10^27) / 100 / 10^9 = 1.825×10²⁹
            assert!(idx == 182499999999999999999999999999, 0);
            lib::print(&idx);

            // update index for 10 year
            clock::set_for_testing(&mut clock, 60 * 60 * 24 * 365 * 10 * 1000);
            incentive_v3::update_index_for_testing<SUI_TEST_V2>(&clock, &mut incentive, &mut storage);

            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 1);
            lib::printf(b"10y index1:");
            // 100 * 10^9 / 86400000 * 1000 * 60 * 60 * 24 * 3650 * (10^27) / 1000 / 10^9 = 3.65×10²⁹
            lib::print(&idx); // 364999999999999999999999999997
            assert!(idx == 364999999999999999999999999997, 0);
            let (_, _, _, _, idx) = incentive_v3::get_rule_params_for_testing<SUI_TEST_V2, SUI_TEST_V2>(&incentive, 3);
            lib::printf(b"10y index3:"); // 1824999999999999999999999999999
            // 50 * 10^9 / 86400000 * 1000 * 60 * 60 * 24 * 3650 * (10^27) / 100 / 10^9 = 1.825×10³⁰
            assert!(idx == 1824999999999999999999999999999, 0);
            lib::print(&idx);

            test_scenario::return_shared(incentive);
            test_scenario::return_shared(storage);
        };

        // alice claim reward
        incentive_v3_util::user_claim_reward<SUI_TEST_V2, SUI_TEST_V2>(scenario_mut, alice, 3, &clock);
        let alice_sui_amount = incentive_v3_util::get_coin_amount<SUI_TEST_V2>(scenario_mut, alice);
        lib::printf(b"alice_sui_amount:");
        lib::print(&alice_sui_amount);
        // 50 * 3650*1e9 = 182,500,000,000,000
        assert!(alice_sui_amount == 0, 0);

        // bob claim reward 
        incentive_v3_util::user_claim_reward<SUI_TEST_V2, SUI_TEST_V2>(scenario_mut, bob, 1, &clock);
        let bob_sui_amount = incentive_v3_util::get_coin_amount<SUI_TEST_V2>(scenario_mut, bob);
        lib::printf(b"bob_sui_amount:");
        lib::print(&bob_sui_amount);
        // 100 * 3650 * 1e9 = 365,000,000,000,000
        lib::close_to((bob_sui_amount as u256), 365000000000000 / 10 * 9, 10);
```
