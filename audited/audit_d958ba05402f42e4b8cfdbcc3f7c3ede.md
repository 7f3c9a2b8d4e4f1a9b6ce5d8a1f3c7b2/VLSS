### Title
Stale Storage Indices Cause Incorrect Incentive Reward Calculations

### Summary
The `update_reward_state_by_rule` function calls `get_effective_balance` to calculate user and total balances for reward distribution, but reads stale storage indices that have not been updated to reflect accrued interest since the last operation. This causes systematic errors in reward calculations, as the incentive system operates on outdated balance data while the actual lending operation updates storage state afterward.

### Finding Description

The vulnerability exists in the execution order of incentive updates versus storage state updates across all lending entry points in `incentive_v3.move`. [1](#0-0) 

The entry functions (deposit, withdraw, borrow, repay) call `update_reward_state_by_asset` before executing the actual lending operation. This function internally calls `get_effective_balance`: [2](#0-1) 

The `get_effective_balance` function retrieves storage indices and applies them to scaled balances to calculate actual balances: [3](#0-2) 

However, these indices have **not yet been updated** at this point. The storage state update only occurs when the subsequent lending operation calls `logic::execute_deposit` (or withdraw/borrow/repay), which then calls `update_state_of_all`: [4](#0-3) 

**Root Cause:** The indices (`current_supply_index` and `current_borrow_index`) compound over time to represent accrued interest. When `get_effective_balance` reads these indices before `update_state_of_all` is called, it retrieves stale values that do not include interest accrued since the last operation on any asset in the protocol.

**Why Protections Fail:** There is no pre-update of storage state in the incentive calculation path. The `update_state_of_all` function is never called from `incentive_v3.move`.

### Impact Explanation

**Concrete Harm:**
1. **Incorrect Global Index Growth:** The reward global index increase is calculated as `(rule.rate * duration) / total_balance`. When `total_balance` is computed using stale (lower) indices, it underestimates the true total balance, causing the denominator to be too small and the global index to grow faster than intended. [5](#0-4) 

2. **Systematic Reward Miscalculation:** User rewards are calculated as `user_balance * (global_index - user_index)`. With both balances and indices calculated from stale data, the compound effect causes rewards to be distributed incorrectly. [6](#0-5) 

3. **Magnitude:** The error magnitude depends on:
   - Time since last operation (longer = more interest accrued = larger discrepancy)
   - Interest rates (higher rates = faster index growth = larger errors)
   - Pool utilization (affects rate calculations)

**Who Is Affected:**
- All users participating in the incentive program receive incorrect reward amounts
- The reward fund may be depleted at an incorrect rate
- Different users experience different levels of error depending on their interaction timing

**Severity Justification:** This is a HIGH severity issue because it affects the core functionality of the incentive system on every operation, causing systematic misallocation of protocol rewards to all users.

### Likelihood Explanation

**Attack Complexity:** This is not an exploitable attack but a systematic protocol error that occurs on every operation.

**Reachable Entry Point:** All public lending entry functions are affected:
- `entry_deposit`, `deposit_with_account_cap`
- `entry_withdraw`, `withdraw_with_account_cap`
- `entry_borrow`, `borrow_with_account_cap`
- `entry_repay`, `repay_with_account_cap`
- `entry_liquidation`, `liquidation`

**Execution Practicality:** The error occurs automatically on every transaction without requiring any special conditions or attacker actions.

**Probability:** 100% - affects every single incentive reward calculation in the protocol.

### Recommendation

**Code-Level Mitigation:**
Call `logic::update_state_of_all` before calculating incentive rewards. Modify all entry functions to follow this order:

1. Update storage state first: `logic::update_state_of_all(clock, storage)`
2. Then calculate incentive rewards: `update_reward_state_by_asset<CoinType>(...)`
3. Finally execute the lending operation: `lending::deposit_coin<CoinType>(...)`

Since `logic::update_state_of_all` is already called within the lending operations, you need to either:
- Make `update_state_of_all` public and call it explicitly in incentive_v3 entry functions, OR
- Refactor the lending operations to accept a flag indicating whether to skip the update (since it was already done)

**Invariant Checks:**
Add an assertion in `get_effective_balance` to verify that indices have been updated recently (within the current transaction or block), though this may be difficult to implement in Move.

**Test Cases:**
1. Deploy a scenario where no operations occur for an extended period (e.g., 1 day)
2. Execute a deposit operation
3. Verify that the reward calculation uses indices reflecting the full 1-day interest accrual
4. Compare calculated rewards with and without the fix to demonstrate the discrepancy

### Proof of Concept

**Initial State:**
- USDC pool active with 10% annual borrow rate
- User has 10,000 USDC supplied
- Last operation was 24 hours ago
- Borrow index should have increased by ~0.027% (10% / 365 days)

**Transaction Steps:**
1. User calls `entry_deposit` to deposit more USDC
2. `update_reward_state_by_asset` is called
3. `get_effective_balance` reads current indices from storage
4. Indices are stale - they reflect state from 24 hours ago
5. Reward calculation uses these stale indices
6. Then `lending::deposit_coin` calls `update_state_of_all`
7. NOW indices are updated to current values

**Expected vs Actual:**
- **Expected:** Reward calculation should use indices that include 24 hours of accrued interest
- **Actual:** Reward calculation uses 24-hour-old indices, missing one day of interest compounding

**Success Condition:**
Compare the `total_supply` and `total_borrow` values used in `calculate_global_index` before and after the fix. The difference represents the systematic error in reward distribution.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L516-534)
```text
    public fun update_reward_state_by_asset<T>(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, user: address) {
        version_verification(incentive);
        let coin_type = type_name::into_string(type_name::get<T>());
        if (!vec_map::contains(&incentive.pools, &coin_type)) {
            return
        };
        let pool = vec_map::get_mut(&mut incentive.pools, &coin_type);
        let (user_effective_supply, user_effective_borrow, total_supply, total_borrow) = get_effective_balance(storage, pool.asset, user);

        // update rewards
        let rule_keys = vec_map::keys(&pool.rules);
        while (vector::length(&rule_keys) > 0) {
            let key = vector::pop_back(&mut rule_keys);
            let rule = vec_map::get_mut(&mut pool.rules, &key);

            // update the user reward
            update_reward_state_by_rule_and_balance(clock, rule, user, user_effective_supply, user_effective_borrow, total_supply, total_borrow);
        }
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L780-796)
```text
    public entry fun entry_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        deposit_coin: Coin<CoinType>,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        lending::deposit_coin<CoinType>(clock, storage, pool, asset, deposit_coin, amount, ctx);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L37-62)
```text
    public(friend) fun execute_deposit<CoinType>(
        clock: &Clock,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256
    ) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_deposit<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_supply_balance(storage, asset, user, amount);

        if (!is_collateral(storage, asset, user)) {
            storage::update_user_collaterals(storage, asset, user)
        };

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
```
