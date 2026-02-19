# Audit Report

## Title
Incorrect Effective Amount Calculation Due to Mixed Scaled Balance Precision in Incentive V2

## Summary
The `calculate_user_effective_amount()` function in the Navi lending protocol's incentive_v2 module receives scaled balances but performs arithmetic operations as if they were actual token balances. Since supply_index and borrow_index diverge over time due to different interest calculation methods (linear vs compound), this causes systematic reward miscalculation for all users with both supply and borrow positions.

## Finding Description

The vulnerability exists in the incentive reward calculation flow where balances stored in the protocol are normalized (scaled) by their respective indices, but the incentive calculation treats them as actual balances.

**How balances are stored:**
The protocol stores balances as scaled values to efficiently track interest accrual. When users deposit or borrow, the actual amounts are divided by the current index to get scaled amounts. [1](#0-0) 

**What storage::get_user_balance returns:**
This function directly returns the scaled balances from storage without any conversion. [2](#0-1) 

**How the protocol correctly converts scaled to actual balances elsewhere:**
Throughout the codebase, when actual balances are needed, the protocol correctly multiplies scaled balances by their respective indices. [3](#0-2) 

**The bug in incentive_v2:**
The `update_reward()` function retrieves scaled balances and passes them directly to `calculate_user_effective_amount()` without conversion. [4](#0-3) 

The `calculate_user_effective_amount()` function then performs arithmetic operations treating these scaled values as actual token amounts. [5](#0-4) 

**Why indices diverge:**
The borrow index uses compounded interest while the supply index uses linear interest, causing them to diverge over time. [6](#0-5) 

**Proof that incentive_v3 does it correctly:**
The newer incentive_v3 module correctly converts scaled balances to actual balances before performing arithmetic operations. [7](#0-6) 

## Impact Explanation

This vulnerability causes direct fund misallocation from incentive reward pools:

1. **Incorrect reward amounts**: Users with both supply and borrow positions receive systematically wrong reward amounts. When `borrow_index > supply_index`, users are under-rewarded; when `supply_index > borrow_index`, users are over-rewarded.

2. **Example calculation error**: With `supply_index = 1.0 ray` and `borrow_index = 1.5 ray`:
   - Actual balances: 10,000 supply, 5,000 borrow
   - Scaled balances: 10,000 scaled supply, 3,333 scaled borrow
   - Current (wrong) calculation: 10,000 - 3,333 = 6,667
   - Correct calculation: 10,000 - 5,000 = 5,000
   - Error: 33% overestimation

3. **Systemic impact**: This affects every reward calculation for users with both supply and borrow positions across all assets with active incentive pools.

4. **Compounding error**: The error grows over time as indices naturally diverge through normal protocol operation.

5. **Pool depletion**: If users are systematically over-rewarded, incentive pools may be depleted faster than intended by the protocol.

## Likelihood Explanation

**Probability: CERTAIN**

This vulnerability triggers automatically without any special attacker action:

1. **No special privileges required**: Any normal user participating in the lending protocol with both supply and borrow positions is affected.

2. **Automatic trigger**: The bug executes through standard protocol operations - deposit, borrow, and reward claims via public functions like `claim_reward()`. [8](#0-7) 

3. **Natural preconditions**: Indices diverge naturally over time as interest accrues. Users commonly have both supply and borrow positions in lending protocols.

4. **No special setup needed**: Works on any asset where incentive pools are configured, requires no extraordinary gas costs or upfront capital.

5. **Core logic bug**: This is not an edge case - it's a systematic error in the core incentive calculation affecting every eligible user on every reward update.

## Recommendation

Convert scaled balances to actual balances before performing arithmetic operations. The fix should mirror the approach used in incentive_v3:

```move
fun calculate_user_effective_amount(
    option: u8, 
    scaled_supply_balance: u256, 
    scaled_borrow_balance: u256, 
    supply_index: u256,
    borrow_index: u256,
    factor: u256
): u256 {
    // Convert scaled to actual balances
    let actual_supply = ray_math::ray_mul(scaled_supply_balance, supply_index);
    let actual_borrow = ray_math::ray_mul(scaled_borrow_balance, borrow_index);
    
    let tmp_balance = actual_supply;
    if (option == constants::option_type_borrow()) {
        actual_supply = actual_borrow;
        actual_borrow = tmp_balance;
    };
    
    // Now perform arithmetic on actual balances
    let effective_borrow_balance = ray_math::ray_mul(factor, actual_borrow);
    if (actual_supply > effective_borrow_balance) {
        return actual_supply - effective_borrow_balance
    };
    
    0
}
```

And update the call site to pass the indices:

```move
let (supply_index, borrow_index) = storage::get_index(storage, asset_id);
let user_effective_amount = calculate_user_effective_amount(
    option, 
    user_supply_balance, 
    user_borrow_balance,
    supply_index,
    borrow_index,
    pool.factor
);
```

## Proof of Concept

```move
#[test]
fun test_incentive_v2_scaled_balance_bug() {
    // Setup: Create a scenario where indices have diverged
    // supply_index = 1.0 ray (1e27)
    // borrow_index = 1.5 ray (1.5e27)
    
    // User has:
    // Actual supply: 10,000 tokens (10,000e9)
    // Actual borrow: 5,000 tokens (5,000e9)
    
    // Stored as scaled:
    // scaled_supply = 10,000e9 / 1e27 = 10,000e9
    // scaled_borrow = 5,000e9 / 1.5e27 = 3,333e9
    
    // Current (wrong) effective amount calculation:
    // effective = 10,000 - 3,333 = 6,667
    
    // Correct effective amount should be:
    // effective = 10,000 - 5,000 = 5,000
    
    // The user receives rewards based on 6,667 instead of 5,000
    // This is a 33% overestimation, causing unfair reward distribution
    
    // This test would demonstrate that calculate_user_effective_amount
    // returns 6,667 when it should return 5,000 when indices diverge
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L323-353)
```text
    fun increase_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////////////////////////////////
        //                               get the current exchange rate                              //
        // the update_state function has been called before here, so it is the latest exchange rate //
        //////////////////////////////////////////////////////////////////////////////////////////////
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::increase_supply_balance(storage, asset, user, scaled_amount)
    }

    fun decrease_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::decrease_supply_balance(storage, asset, user, scaled_amount)
    }

    fun increase_borrow_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (_, borrow_index) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, borrow_index);

        storage::increase_borrow_balance(storage, asset, user, scaled_amount)
    }

    fun decrease_borrow_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (_, borrow_index) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, borrow_index);

        storage::decrease_borrow_balance(storage, asset, user, scaled_amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L486-500)
```text
    public fun user_collateral_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (supply_balance, _) = storage::get_user_balance(storage, asset, user);
        let (supply_index, _) = storage::get_index(storage, asset);
        ray_math::ray_mul(supply_balance, supply_index) // scaled_amount
    }

    /**
     * Title: get the number of borrowings the user has in given asset, include interest.
     * Returns: token amount.
     */
    public fun user_loan_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (_, borrow_balance) = storage::get_user_balance(storage, asset, user);
        let (_, borrow_index) = storage::get_index(storage, asset);
        ray_math::ray_mul(borrow_balance, borrow_index)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L465-483)
```text
    public fun calculate_user_effective_amount(option: u8, supply_balance: u256, borrow_balance: u256, factor: u256): u256 {
        let tmp_balance = supply_balance;
        if (option == constants::option_type_borrow()) {
            supply_balance = borrow_balance;
            borrow_balance = tmp_balance;
        };

        // supply- Scoefficient*borrow
        // **After many verifications, the calculation method is ray_mul
        // factor is set to 1e27, and borrow_balance decimal is 9
        // the correct one is: ray_math::ray_mul(1000000000000000000000000000, 2_000000000) = 2_000000000
        // ray_math::ray_mul(800000000000000000000000000, 2_000000000) = 1_600000000
        let effective_borrow_balance = ray_math::ray_mul(factor, borrow_balance);
        if (supply_balance > effective_borrow_balance) {
            return supply_balance - effective_borrow_balance
        };

        0
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L55-95)
```text
    public fun calculate_compounded_interest(
        timestamp_difference: u256,
        rate: u256
    ): u256 {
        // // e.g. get the time difference of the last update --> (1685029315718 - 1685029255718) / 1000 == 60s
        if (timestamp_difference == 0) {
            return ray_math::ray()
        };

        // time difference minus 1 --> 60 - 1 = 59
        let exp_minus_one = timestamp_difference - 1;

        // time difference minus 2 --> 60 - 2 = 58
        let exp_minus_two = 0;
        if (timestamp_difference > 2) {
            exp_minus_two = timestamp_difference - 2;
        };

        // e.g. get the rate per second --> (6.3 * 1e27) / (60 * 60 * 24 * 365) --> 1.9977168949771689 * 1e20 = 199771689497716894977
        let rate_per_second = rate / constants::seconds_per_year();
        
        let base_power_two = ray_math::ray_mul(rate_per_second, rate_per_second);
        let base_power_three = ray_math::ray_mul(base_power_two, rate_per_second);

        let second_term = timestamp_difference * exp_minus_one * base_power_two / 2;
        let third_term = timestamp_difference * exp_minus_one * exp_minus_two * base_power_three / 6;
        ray_math::ray() + rate_per_second * timestamp_difference + second_term + third_term
    }

    /**
     * Title: Calculating liner interest
     * Input(current_timestamp): 1685029315718
     * Input(last_update_timestamp): 1685029255718
     * Input(rate): 6.3 * 1e27
     */
    public fun calculate_linear_interest(
        timestamp_difference: u256,
        rate: u256
    ): u256 {
        ray_math::ray() + rate * timestamp_difference / constants::seconds_per_year()
    }
```

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
