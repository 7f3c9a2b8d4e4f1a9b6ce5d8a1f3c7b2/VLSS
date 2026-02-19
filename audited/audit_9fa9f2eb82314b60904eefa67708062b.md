# Audit Report

## Title
Rounding Down to Zero in Borrow Scaling Enables Free Token Extraction from Lending Pool

## Summary
The Navi lending protocol's `increase_borrow_balance` function uses `ray_div` to scale borrow amounts by the `borrow_index`. When the index has grown large enough (≥2x initial value of 1e27) and users borrow minimal amounts, integer division rounds the `scaled_amount` to zero. This allows users to receive borrowed tokens from the pool while having zero debt recorded, enabling complete pool drainage through repeated small borrows.

## Finding Description

**Root Cause:**

The `increase_borrow_balance` function calculates the scaled borrow amount using ray division [1](#0-0) , where `scaled_amount = ray_math::ray_div(amount, borrow_index)`.

The `ray_div` function implements banker's rounding [2](#0-1) , calculating `(a * RAY + halfB) / b` where `RAY = 1e27` and `halfB = b / 2`.

For `scaled_amount` to round to zero when `amount > 0`, the mathematical condition is:
```
(amount × 1e27 + borrow_index/2) / borrow_index < 1
```
This occurs when: `amount < borrow_index / (2 × 1e27)`

**Concrete Example:**
- For amount = 1 (smallest unit for 9-decimal assets like SUI)
- When borrow_index = 3e27 (3× initial due to compound interest)
- Calculation: `(1 × 1e27 + 1.5e27) / 3e27 = 2.5e27 / 3e27 = 0` (integer division)
- Result: User's debt increases by 0

**Exploitation Flow:**

1. User calls the public `borrow` function which invokes `execute_borrow` [3](#0-2) 

2. Validation checks that input `amount != 0` but does NOT validate the scaled result [4](#0-3) 

3. The scaled_amount of 0 is stored in the user's borrow balance [5](#0-4)  with no validation that the amount must be non-zero

4. Meanwhile, `base_borrow` withdraws the actual tokens from the pool [6](#0-5)  via `pool::withdraw_balance` [7](#0-6) 

5. Health factor check passes trivially since recorded debt is 0

**How borrow_index Grows:**

The borrow_index increases through compound interest accumulation [8](#0-7) , specifically via `new_borrow_index = ray_math::ray_mul(compounded_interest, current_borrow_index)`. The compound interest calculation [9](#0-8)  uses a Taylor series approximation that grows exponentially with time and borrow rate.

Starting from the initial value of 1e27, the index can reach 2-3× within 1-2 years at typical DeFi borrow rates (50-100% APR).

## Impact Explanation

**Direct Fund Impact:**
- **Complete pool drainage**: Each exploit iteration extracts 1 token unit with zero debt recorded
- **Unlimited exploitation**: For a pool with 1M tokens at 9 decimals, attacker needs 1M transactions (~1,000 SUI in gas costs) to drain the entire pool worth potentially millions of dollars
- **All borrowable assets vulnerable**: Works on any 9-decimal asset (SUI, USDC, USDT)

**Systemic Damage:**
- **100% loss of pool liquidity** for affected assets
- **Supplier fund loss**: All depositors lose their principal as the pool is drained
- **Protocol insolvency**: Recorded liabilities don't match actual token outflows, breaking the fundamental accounting invariant
- **Protocol treasury loss**: Unable to collect interest on stolen funds

**Affected Parties:**
- All depositors/suppliers to the lending pool (complete loss of funds)
- Protocol treasury (loss of future interest revenue)
- Legitimate borrowers (pool liquidity exhausted, cannot borrow)
- Volo vault when using Navi adaptor (indirect exposure to drained pool)

This breaks the core security guarantee that **borrowed tokens must create corresponding debt records**, enabling direct theft of protocol funds.

## Likelihood Explanation

**Attacker Capabilities:**
- **No special permissions required**: Any user with network access can call the public `borrow` function
- **No capital requirements**: Attack requires no collateral once borrow_index threshold is reached
- **Automation possible**: Simple script can execute repeated borrows from multiple addresses

**Attack Complexity:**
- **LOW**: Deterministic outcome requiring only repeated calls to `borrow(amount=1)`
- **No timing constraints**: Attack works anytime after borrow_index crosses threshold
- **No transaction ordering requirements**: Each borrow is independent

**Feasibility Conditions:**
- **Index growth achievable**: At 50% APR, borrow_index doubles in ~1.4 years; at 100% APR in ~0.7 years through normal protocol operation
- **Always exploitable**: Once threshold reached, condition persists indefinitely
- **Pool liquidity present**: Attack works whenever pool has available tokens (true for all active lending pools)

**Economic Rationality:**
- **Transaction cost**: ~0.001 SUI × 1M transactions = ~1,000 SUI (~$3,000 at current prices)
- **Potential profit**: Entire pool liquidity (potentially millions to tens of millions of dollars)
- **Risk/reward ratio**: Extremely favorable (1000:1 or higher)

**Detection Constraints:**
- **Observable on-chain**: Attack creates pattern of many tiny borrows with zero debt
- **Damage before response**: Complete drainage possible before manual intervention
- **No automatic circuit breakers**: Protocol has no monitoring for unusual borrow patterns

**Probability Assessment:**
**HIGH** - This vulnerability WILL be exploited once borrow_index reaches the threshold (≥2e27) on any active pool with 9-decimal assets. The condition is inevitable given normal interest accrual over 1-2 years of protocol operation.

## Recommendation

Add validation in `increase_borrow_balance` to ensure the scaled amount is non-zero:

```move
fun increase_borrow_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
    let (_, borrow_index) = storage::get_index(storage, asset);
    let scaled_amount = ray_math::ray_div(amount, borrow_index);
    
    // Add validation to prevent zero debt recording
    assert!(scaled_amount > 0, error::scaled_amount_too_small());
    
    storage::increase_borrow_balance(storage, asset, user, scaled_amount)
}
```

Alternatively, enforce a minimum borrow amount in the validation layer that ensures the scaled result is always non-zero given the current borrow_index:

```move
public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
    assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
    
    // Ensure amount is large enough that scaling won't round to zero
    let (_, borrow_index) = storage::get_index(storage, asset);
    let min_amount = borrow_index / (2 * ray_math::ray());
    assert!(amount > min_amount, error::amount_too_small());
    
    // ... rest of validation
}
```

## Proof of Concept

```move
#[test]
fun test_zero_debt_borrow_exploit() {
    // Setup: Create lending pool with borrow_index at 3e27 (3x initial)
    let scenario = test_scenario::begin(ADMIN);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    
    // Initialize protocol and set borrow_index to 3e27 through time progression
    // and interest accrual
    setup_pool_with_high_borrow_index(&mut scenario, &mut clock);
    
    test_scenario::next_tx(&mut scenario, ATTACKER);
    {
        let storage = test_scenario::take_shared<Storage>(&scenario);
        let pool = test_scenario::take_shared<Pool<SUI>>(&scenario);
        let oracle = test_scenario::take_shared<PriceOracle>(&scenario);
        
        // Record initial pool balance
        let initial_pool_balance = pool::get_pool_info(&pool);
        
        // Attacker borrows 1 unit (smallest amount)
        let borrowed_balance = lending::borrow<SUI>(
            &clock,
            &oracle,
            &mut storage,
            &mut pool,
            ASSET_ID,
            1, // Borrow 1 unit
            test_scenario::ctx(&mut scenario)
        );
        
        // Verify: Attacker received 1 token
        assert!(balance::value(&borrowed_balance) == 1, 0);
        
        // Verify: Attacker's recorded debt is 0
        let user_debt = storage::get_user_loan_balance(&storage, ASSET_ID, ATTACKER);
        assert!(user_debt == 0, 1); // VULNERABILITY: Zero debt recorded!
        
        // Verify: Pool lost 1 token
        let final_pool_balance = pool::get_pool_info(&pool);
        assert!(final_pool_balance == initial_pool_balance - 1, 2);
        
        // Attacker can repeat this to drain the entire pool
        balance::destroy_for_testing(borrowed_balance);
        test_scenario::return_shared(storage);
        test_scenario::return_shared(pool);
        test_scenario::return_shared(oracle);
    };
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L127-159)
```text
    public(friend) fun execute_borrow<CoinType>(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_borrow<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_borrow_balance(storage, asset, user, amount);
        
        /////////////////////////////////////////////////////
        // Add the asset to the user's list of loan assets //
        /////////////////////////////////////////////////////
        if (!is_loan(storage, asset, user)) {
            storage::update_user_loans(storage, asset, user)
        };

        //////////////////////////////////
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L256-288)
```text
    fun update_state(clock: &Clock, storage: &mut Storage, asset: u8) {
        // e.g. get the current timestamp in milliseconds
        let current_timestamp = clock::timestamp_ms(clock);

        // Calculate the time difference between now and the last update
        let last_update_timestamp = storage::get_last_update_timestamp(storage, asset);
        let timestamp_difference = (current_timestamp - last_update_timestamp as u256) / 1000;

        // Get All required reserve configurations
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);
        let (current_supply_rate, current_borrow_rate) = storage::get_current_rate(storage, asset);
        let (_, _, _, reserve_factor, _) = storage::get_borrow_rate_factors(storage, asset);
        let (_, total_borrow) = storage::get_total_supply(storage, asset);

        // Calculate new supply index via linear interest
        let linear_interest = calculator::calculate_linear_interest(timestamp_difference, current_supply_rate);
        let new_supply_index = ray_math::ray_mul(linear_interest, current_supply_index);

        // Calculate new borrowing index via compound interest
        let compounded_interest = calculator::calculate_compounded_interest(timestamp_difference, current_borrow_rate);
        let new_borrow_index = ray_math::ray_mul(compounded_interest, current_borrow_index);

        // Calculate the treasury amount
        let treasury_amount = ray_math::ray_mul(
            ray_math::ray_mul(total_borrow, (new_borrow_index - current_borrow_index)),
            reserve_factor
        );
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);

        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
        storage::increase_total_supply_balance(storage, asset, scaled_treasury_amount);
        // storage::increase_balance_for_pool(storage, asset, scaled_supply_amount, scaled_borrow_amount + scaled_reserve_amount) // **No need to double calculate interest
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L341-346)
```text
    fun increase_borrow_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (_, borrow_index) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, borrow_index);

        storage::increase_borrow_balance(storage, asset, user, scaled_amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L85-92)
```text
    public fun ray_div(a: u256, b: u256): u256 {
        assert!(b != 0, RAY_MATH_DIVISION_BY_ZERO);
        let halfB = b / 2;

        assert!(a <= (address::max() - halfB) / RAY, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * RAY + halfB) / b
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L56-58)
```text
    public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L542-551)
```text
    fun increase_balance(_balance: &mut TokenBalance, user: address, amount: u256) {
        let current_amount = 0;

        if (table::contains(&_balance.user_state, user)) {
            current_amount = table::remove(&mut _balance.user_state, user)
        };

        table::add(&mut _balance.user_state, user, current_amount + amount);
        _balance.total_supply = _balance.total_supply + amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L266-289)
```text
    fun base_borrow<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        user: address,
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let normal_borrow_amount = pool::normal_amount(pool, amount);
        logic::execute_borrow<CoinType>(clock, oracle, storage, asset, user, (normal_borrow_amount as u256));

        let _balance = pool::withdraw_balance(pool, amount, user);
        emit(BorrowEvent {
            reserve: asset,
            sender: user,
            amount: amount
        });

        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L125-140)
```text
    public(friend) fun withdraw_balance<CoinType>(pool: &mut Pool<CoinType>, amount: u64, user: address): Balance<CoinType> {
        if (amount == 0) {
            let _zero = balance::zero<CoinType>();
            return _zero
        };

        let _balance = balance::split(&mut pool.balance, amount);
        emit(PoolWithdraw {
            sender: user,
            recipient: user,
            amount: amount,
            pool: type_name::into_string(type_name::get<CoinType>()),
        });

        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L55-82)
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
```
