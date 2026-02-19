### Title
Inconsistent Boundary Condition in Borrow Validation Prevents Valid Borrows at Full Available Liquidity

### Summary
The `validate_borrow` function in the lending protocol uses a strict less-than operator (`<`) instead of less-than-or-equal (`<=`) when checking available liquidity, creating an off-by-one boundary condition bug. This prevents users from borrowing exactly the full available liquidity even when the borrow cap ceiling allows it and they have sufficient collateral, while the equivalent `validate_withdraw` operation uses the correct boundary check and would allow such operations.

### Finding Description

In the lending protocol's validation module, there is a critical inconsistency in boundary condition checks between borrow and withdraw operations that matches the external report's vulnerability class. [1](#0-0) 

The `validate_withdraw` function correctly uses greater-than-or-equal (`>=`) to check if available liquidity is sufficient, allowing withdrawals when the exact available amount is requested. [2](#0-1) 

However, `validate_borrow` uses a strict less-than operator (`<`) at line 67, which prevents borrowing when `scale_borrow_balance + amount == scale_supply_balance`, even though this would represent valid 100% utilization.

**Root Cause:**
The assertion at line 67 uses `scale_borrow_balance + amount < scale_supply_balance` instead of `<=`, creating an artificial restriction that blocks borrowing the final unit of available liquidity.

**Why Current Protections Fail:**
The borrow cap ceiling check at line 73 would normally restrict utilization (default 90%), but the protocol allows setting borrow_cap_ceiling up to 100%: [3](#0-2) [4](#0-3) 

The validation allows borrow_cap_ceiling to equal `ray_math::ray()` (100%). When set to 100%, the strict inequality at line 67 becomes the sole blocker, failing legitimate borrows at the boundary.

**Exploit Path:**
1. Admin sets borrow_cap_ceiling to 100% (allowed by percentage_ray_validation)
2. Pool has scale_supply_balance = X, scale_borrow_balance = 0
3. User with sufficient collateral attempts to borrow exactly X
4. Line 67 check: `0 + X < X` evaluates to FALSE
5. Transaction aborts with `error::insufficient_balance()` code 1506
6. Line 73 borrow cap check is never reached (would have passed: `X/X = 1.0 <= 1.0`) [5](#0-4) 

The execute_borrow function calls validate_borrow, making this vulnerability reachable through the public lending API.

### Impact Explanation

**Severity: Medium**

The vulnerability causes:

1. **Capital Inefficiency**: Users cannot borrow full available liquidity even when protocol configuration permits 100% utilization and they have adequate collateral
2. **Inconsistent Protocol Behavior**: Identical liquidity amounts can be withdrawn but not borrowed, violating user expectations
3. **Denial of Valid Operations**: Legitimate borrow requests that satisfy all intended constraints (collateral, borrow cap) are incorrectly rejected

The impact is reduced by the default 90% borrow cap, but becomes exploitable when administrators adjust the cap to maximize capital efficiency by setting it to 100%.

### Likelihood Explanation

**Likelihood: Medium**

The vulnerability is reachable through standard protocol flows:

1. **Preconditions are Feasible**: 
   - Administrator setting borrow_cap to 100% is a valid configuration choice for optimizing capital efficiency
   - Users attempting to borrow maximum available amounts is common behavior
   - No special permissions or compromised keys required

2. **Realistic Trigger Path**:
   - Tests confirm borrow operations fail when exceeding available liquidity, but no test validates the exact boundary case [6](#0-5) 

The test only validates borrowing 101 when 100 is available (failure expected), but doesn't test borrowing exactly 100 when 100 is available (should succeed with 100% cap).

3. **Not Blocked by Existing Checks**: The borrow cap validation would permit the operation, but the strict inequality prevents reaching that check.

### Recommendation

Change the boundary condition check in `validate_borrow` from strict less-than to less-than-or-equal to be consistent with `validate_withdraw`:

**Current (Line 67):**
```move
assert!(scale_borrow_balance + amount < scale_supply_balance, error::insufficient_balance());
```

**Recommended:**
```move
assert!(scale_borrow_balance + amount <= scale_supply_balance, error::insufficient_balance());
```

This change:
- Aligns borrow validation with withdraw validation logic
- Allows borrowing up to full available liquidity when borrow cap permits
- Maintains safety through the existing borrow_cap_ceiling check at line 73
- Fixes the off-by-one boundary condition bug

### Proof of Concept

**Setup:**
1. Initialize lending protocol with SUI_TEST asset
2. Set borrow_cap_ceiling to 100% (1e27) using set_borrow_cap
3. User A deposits 1000 SUI (scale_supply_balance = 1000)
4. No existing borrows (scale_borrow_balance = 0)
5. User B has sufficient collateral to borrow 1000 SUI

**Execution:**
1. User B calls borrow_coin for exactly 1000 SUI
2. execute_borrow calls validate_borrow
3. Line 67 evaluates: `0 + 1000 < 1000` → FALSE
4. Transaction aborts with error code 1506 (insufficient_balance)
5. User B cannot borrow despite having collateral and borrow cap allowing 100% utilization

**Expected Behavior with Fix:**
1. Line 67 evaluates: `0 + 1000 <= 1000` → TRUE (passes)
2. Line 73 evaluates: `1000/1000 = 1.0 <= 1.0` → TRUE (passes)
3. Borrow succeeds with 100% pool utilization

**Comparison with Withdraw:**
If User A attempts to withdraw 1000 (leaving supply exactly equal to any borrows):
- validate_withdraw line 45: `1000 >= 0 + 1000` → TRUE (succeeds)

This demonstrates the inconsistent boundary handling between equivalent operations.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L35-46)
```text
    public fun validate_withdraw<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_supply_balance >= scale_borrow_balance + amount, error::insufficient_balance())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L56-74)
```text
    public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        // e.g. get the total lending and total collateral for this pool
        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_borrow_balance + amount < scale_supply_balance, error::insufficient_balance());

        // get current borrowing ratio current_borrow_ratio
        let current_borrow_ratio = ray_math::ray_div(scale_borrow_balance + amount, scale_supply_balance);
        // e.g. borrow_ratio
        let borrow_ratio = storage::get_borrow_cap_ceiling_ratio(storage, asset);
        assert!(borrow_ratio >= current_borrow_ratio, error::exceeded_maximum_borrow_cap())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L256-262)
```text
    public fun set_borrow_cap(_: &OwnerCap, storage: &mut Storage, asset: u8, borrow_cap_ceiling: u256) {
        version_verification(storage);
        percentage_ray_validation(borrow_cap_ceiling);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.borrow_cap_ceiling = borrow_cap_ceiling;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L693-695)
```text
    fun percentage_ray_validation(value: u256) {
        assert!(value <= ray_math::ray(), error::invalid_value());
    }
```

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

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/supplementary_tests/sup_lending_tests.move (L1659-1699)
```text
    #[test] 
    #[expected_failure]
    // Should borrow failed for excess max borrow amount 
    public fun test_borrow_excess() {
        let scenario = test_scenario::begin(OWNER);
        let _clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        {
            base::initial_protocol(&mut scenario, &_clock);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
            let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
            let coin = coin::mint_for_testing<SUI_TEST>(100_000000000, test_scenario::ctx(&mut scenario));

            base_lending_tests::base_deposit_for_testing(&mut scenario, &clock, &mut pool, coin, 0, 100_000000000);

            let (total_supply, _, _) = pool::get_pool_info(&pool);
            assert!(total_supply == 100_000000000, 0);

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(pool);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
            let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));

            base_lending_tests::base_borrow_for_testing(&mut scenario, &clock, &mut pool, 0, 101_000000000);
            let (total_supply, _, _) = pool::get_pool_info(&pool);
            assert!(total_supply == 90_000000000, 0);

            clock::destroy_for_testing(clock);
            test_scenario::return_shared(pool);
        };

        clock::destroy_for_testing(_clock);
        test_scenario::end(scenario);
    }
```
