### Title
Inconsistent Supply Cap Validation Scaling Leads to Misconfiguration Risk

### Summary
The `validate_deposit` function in the lending protocol's validation module contains an unnecessary multiplication by RAY (1e27) when comparing estimated supply against the supply cap ceiling. This creates configuration complexity and inconsistency with other validation functions, making it highly likely that administrators will misconfigure supply caps, leading to either complete denial-of-service of deposit operations or ineffective cap enforcement.

### Finding Description

The vulnerability exists in the lending core protocol's validation logic, specifically in the `validate_deposit` function. [1](#0-0) 

**Root Cause Analysis:**

The function performs the following steps:
1. Retrieves scaled `supply_balance` from storage (line 20)
2. Retrieves `current_supply_index` (line 21)
3. Correctly unscales to actual balance: `scale_supply_balance = ray_mul(supply_balance, current_supply_index)` (line 23)
4. **BUG**: Multiplies the sum by RAY: `estimate_supply = (scale_supply_balance + amount) * ray_math::ray()` (line 29)
5. Compares against `supply_cap_ceiling` (line 32)

This forces `supply_cap_ceiling` to be configured in units of `(actual_tokens * 1e27)` rather than actual token amounts. Evidence from test configurations confirms this: [2](#0-1) 

The supply cap is set to `20000000000000000000000000000000000000000000` (2e43), which represents 20 million tokens multiplied by RAY (1e27).

**Inconsistency with Other Validations:**

The `validate_withdraw` function correctly compares unscaled values directly without RAY multiplication: [3](#0-2) 

Similarly, `validate_borrow` uses unscaled comparisons: [4](#0-3) 

This inconsistency makes the deposit cap scaling requirement particularly error-prone.

**Exploit Path:**

1. Administrator initializes a reserve using `storage::init_reserve` [5](#0-4) 
2. If admin sets `supply_cap_ceiling` as actual token amounts (e.g., 20000000 * 1e9 = 2e16 for 20M tokens), all deposits will fail
3. When user calls deposit via `execute_deposit` [6](#0-5) , validation is called after `update_state_of_all` (line 47-49)
4. The validation multiplies estimate by 1e27, resulting in comparison: `2e16 >= deposit_amount * 1e27`
5. Even a 1-token deposit (1e9) becomes 1e9 * 1e27 = 1e36, which exceeds 2e16
6. Error 1604 (`exceeded_maximum_deposit_cap`) is triggered, blocking all deposits

Alternatively, if admin sets the cap too high due to confusion about scaling requirements, the cap becomes ineffective.

### Impact Explanation

**High Severity - Dual Impact Scenarios:**

1. **Denial of Service**: If `supply_cap_ceiling` is misconfigured (set as unscaled token amount), ALL deposit operations for that reserve will permanently fail. This completely breaks the lending pool's deposit functionality for that asset, preventing users from supplying collateral and the protocol from earning fees. Test evidence shows this would trigger error 1604: [7](#0-6) 

2. **Ineffective Cap Enforcement**: If admin sets the cap too high (confused about RAY scaling or using incorrect scale factor), deposits could far exceed intended safety limits, exposing the protocol to concentration risk and potential insolvency during market downturns.

The impact is magnified because this affects core lending operations and the error is non-obvious - administrators may not realize why deposits are failing or that caps are ineffective.

### Likelihood Explanation

**High Likelihood:**

1. **Configuration Complexity**: The requirement to multiply supply caps by 1e27 is non-intuitive and undocumented in the function itself. [8](#0-7) 

2. **Inconsistency**: Other validation functions (`validate_withdraw`, `validate_borrow`) use direct unscaled comparisons, creating expectation mismatch.

3. **No Input Validation**: The `set_supply_cap` function accepts any u256 value without scale validation: [9](#0-8) 

4. **Real-world Pattern**: The external report indicates this exact vulnerability class has occurred in production lending protocols, demonstrating practical exploitability.

### Recommendation

**Code-Level Mitigation:**

Remove the unnecessary RAY multiplication from `validate_deposit`:

```move
// In validation.move, line 29, change from:
let estimate_supply = (scale_supply_balance + amount) * ray_math::ray();

// To:
let estimate_supply = scale_supply_balance + amount;
```

Update all existing `supply_cap_ceiling` configurations to store actual token amounts (unscaled) rather than RAY-scaled values. Add validation in `init_reserve` and `set_supply_cap` to ensure caps are within reasonable ranges for actual token amounts.

Additionally, add inline documentation clarifying the expected scale for supply caps and consider adding a helper function that converts user-friendly token amounts to the internal storage format.

### Proof of Concept

**Scenario 1: Misconfigured Cap Causes DoS**

1. Admin initializes SUI reserve intending 20M token cap
2. Admin sets `supply_cap_ceiling = 20000000 * 1e9 = 2e16` (thinking it's actual tokens)
3. User attempts to deposit 1 SUI (1e9 base units)
4. Validation calculates: `estimate_supply = (0 + 1e9) * 1e27 = 1e36`
5. Check fails: `2e16 >= 1e36` is false
6. Transaction aborts with error 1604
7. ALL subsequent deposits fail, rendering the lending pool unusable

**Scenario 2: Test Demonstrates Required Scaling**

The test at line 263 shows a deposit of `30000000_000000000` (3e16) is expected to fail against a cap set in test setup. [10](#0-9) 

Examining the test setup reveals the cap must be set as `20000000000000000000000000000000000000000000` (2e43), which is 2e16 * 1e27, confirming the RAY scaling requirement. [11](#0-10) 

This proves the validation logic requires RAY-scaled caps, creating the misconfiguration vulnerability.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L15-33)
```text
    public fun validate_deposit<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        // e.g. Pool total collateral of 100ETH
        let (supply_balance, _) = storage::get_total_supply(storage, asset);
        let (current_supply_index, _) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);

        // e.g. The pool has a maximum collateral capacity of 10000 ETH
        let supply_cap_ceiling = storage::get_supply_cap_ceiling(storage, asset);

        // e.g. estimate_supply
        let estimate_supply = (scale_supply_balance + amount) * ray_math::ray();

        // e.g. supply_cap_ceiling >= estimate_supply?
        assert!(supply_cap_ceiling >= estimate_supply, error::exceeded_maximum_deposit_cap());
    }
```

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

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/base_tests.move (L160-181)
```text
        storage::init_reserve<SUI_TEST>(
            &storage_admin_cap,
            &pool_admin_cap,
            clock,
            &mut storage,
            0, // oracle id
            false, // is_isolated
            20000000000000000000000000000000000000000000, // supply_cap_ceiling: 20000000
            900000000000000000000000000, // borrow_cap_ceiling: 90%
            0, // base_rate: 0%
            550000000000000000000000000, // optimal_utilization: 80%
            116360000000000000000000000, // multiplier: 5%
            3000000000000000000000000000, // jump_rate_multiplier: 109%
            200000000000000000000000000, // reserve_factor: 7%
            550000000000000000000000000, // ltv: 55%
            100000000000000000000000000, // treasury_factor: 10%
            350000000000000000000000000, // liquidation_ratio: 35%
            100000000000000000000000000, // liquidation_bonus: 10%
            700000000000000000000000000, // liquidation_threshold: 70%
            &metadata, // metadata
            test_scenario::ctx(scenario)
        );
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L154-237)
```text
    public entry fun init_reserve<CoinType>(
        _: &StorageAdminCap,
        pool_admin_cap: &PoolAdminCap,
        clock: &Clock,
        storage: &mut Storage,
        oracle_id: u8,
        is_isolated: bool,
        supply_cap_ceiling: u256,
        borrow_cap_ceiling: u256,
        base_rate: u256,
        optimal_utilization: u256,
        multiplier: u256,
        jump_rate_multiplier: u256,
        reserve_factor: u256,
        ltv: u256,
        treasury_factor: u256,
        liquidation_ratio: u256,
        liquidation_bonus: u256,
        liquidation_threshold: u256,
        coin_metadata: &CoinMetadata<CoinType>,
        ctx: &mut TxContext
    ) {
        version_verification(storage);

        let current_idx = storage.reserves_count;
        assert!(current_idx < constants::max_number_of_reserves(), error::no_more_reserves_allowed());
        reserve_validation<CoinType>(storage);

        percentage_ray_validation(borrow_cap_ceiling);
        percentage_ray_validation(optimal_utilization);
        percentage_ray_validation(reserve_factor);
        percentage_ray_validation(treasury_factor);
        percentage_ray_validation(liquidation_ratio);
        percentage_ray_validation(liquidation_bonus);

        percentage_ray_validation(ltv);
        percentage_ray_validation(liquidation_threshold);
        
        let reserve_data = ReserveData {
            id: storage.reserves_count,
            oracle_id: oracle_id,
            coin_type: type_name::into_string(type_name::get<CoinType>()),
            is_isolated: is_isolated,
            supply_cap_ceiling: supply_cap_ceiling,
            borrow_cap_ceiling: borrow_cap_ceiling,
            current_supply_rate: 0,
            current_borrow_rate: 0,
            current_supply_index: ray_math::ray(),
            current_borrow_index: ray_math::ray(),
            ltv: ltv,
            treasury_factor: treasury_factor,
            treasury_balance: 0,
            supply_balance: TokenBalance {
                user_state: table::new<address, u256>(ctx),
                total_supply: 0,
            },
            borrow_balance: TokenBalance {
                user_state: table::new<address, u256>(ctx),
                total_supply: 0,
            },
            last_update_timestamp: clock::timestamp_ms(clock),
            borrow_rate_factors: BorrowRateFactors {
                base_rate: base_rate,
                multiplier: multiplier,
                jump_rate_multiplier: jump_rate_multiplier,
                reserve_factor: reserve_factor,
                optimal_utilization: optimal_utilization,
            },
            liquidation_factors: LiquidationFactors {
                ratio: liquidation_ratio,
                bonus: liquidation_bonus,
                threshold: liquidation_threshold,
            },
            reserve_field_a: 0,
            reserve_field_b: 0,
            reserve_field_c: 0
        };

        table::add(&mut storage.reserves, current_idx, reserve_data);
        storage.reserves_count = current_idx + 1;

        let decimals = coin::get_decimals(coin_metadata);
        pool::create_pool<CoinType>(pool_admin_cap, decimals, ctx);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L249-254)
```text
    public fun set_supply_cap(_: &OwnerCap, storage: &mut Storage, asset: u8, supply_cap_ceiling: u256) {
        version_verification(storage);

        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.supply_cap_ceiling = supply_cap_ceiling;
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

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/validation_test.move (L250-270)
```text
    #[test]
    #[expected_failure(abort_code = 1604, location = lending_core::validation)]
    public fun test_validate_deposit_over_cap() {
        let scenario = test_scenario::begin(OWNER);
        let _clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        {
            base::initial_protocol(&mut scenario, &_clock);
        };

        test_scenario::next_tx(&mut scenario, OWNER);
        {
            let stg = test_scenario::take_shared<Storage>(&scenario);

            validation::validate_deposit<SUI_TEST>(&mut stg, 0, 30000000_000000000);

            test_scenario::return_shared(stg);
        };

        clock::destroy_for_testing(_clock);
        test_scenario::end(scenario);
    }
```
