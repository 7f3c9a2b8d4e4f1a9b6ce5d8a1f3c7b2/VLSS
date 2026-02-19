### Title
Pyth Oracle Negative Price Panic Causes DoS of Navi Lending Operations

### Summary
The Pyth oracle adaptor calls `i64::get_magnitude_if_positive()` which panics if Pyth reports a negative or zero price. This causes oracle price update transactions to abort, preventing fresh price updates and causing all Navi lending operations requiring health checks (withdrawals and liquidations) to fail when stored prices become stale. [1](#0-0) 

### Finding Description

**Root Cause**: The Pyth adaptor's `get_price_unsafe_native()` and `get_price_native()` functions call `i64::get_magnitude_if_positive(&i64_price)` without any validation or error handling for negative prices. [2](#0-1) 

**Execution Path**:
1. When `oracle_pro::update_single_price()` is called to update oracle prices, it invokes `get_price_from_adaptor()` at line 83 to fetch the primary oracle price: [3](#0-2) 

2. For Pyth providers, `get_price_from_adaptor()` calls `adaptor_pyth::get_price_unsafe_to_target_decimal()`: [4](#0-3) 

3. This internally calls `get_price_unsafe_native()` which panics on negative prices: [5](#0-4) 

4. **Critical Flaw**: The panic occurs at line 83 of `oracle_pro.move` BEFORE the secondary oracle fallback logic (lines 86-95) can be reached, meaning even if a valid secondary oracle exists, it cannot prevent the DoS: [6](#0-5) 

5. When oracle updates fail, prices in `PriceOracle` become stale. The `get_token_price()` function returns `valid=false` for stale prices: [7](#0-6) 

6. Navi lending operations use `calculator::calculate_value()` which asserts on invalid prices, causing all operations to abort: [8](#0-7) 

### Impact Explanation

**Operational DoS of Critical Lending Functions**:

When Pyth reports negative prices (possible during oracle errors, malfunctions, or inverse pair configurations), the following critical operations become permanently blocked until an admin manually disables the Pyth provider:

1. **User Withdrawals Blocked**: All withdrawal operations require health factor validation which depends on fresh oracle prices: [9](#0-8) 

The health check at line 91 calls `is_health()` which requires valid oracle prices: [10](#0-9) 

2. **Liquidations Blocked**: The `user_health_factor()` calculation depends on `user_collateral_value()` and `user_loan_value()`, both of which call `calculator::calculate_value()` requiring valid oracle prices: [11](#0-10) [12](#0-11) 

3. **Health Limiter Verification Fails**: Vault operations using the Navi health limiter also fail as they depend on the same `user_health_factor()` calculation: [13](#0-12) 

**Affected Users**: All users with positions in Navi lending protocol integrated with the Volo vault system lose the ability to withdraw funds or be liquidated when unhealthy, creating systemic risk.

### Likelihood Explanation

**High Likelihood - Natural Occurrence Scenario**:

1. **Pyth Can Report Negative Prices**: The Pyth oracle uses signed `i64` types to represent prices and CAN return negative values in:
   - Oracle error/malfunction states
   - Network data corruption
   - Inverse price pair configurations
   - Special market conditions or edge cases

2. **No Validation Before Panic**: The code directly calls `i64::get_magnitude_if_positive()` without any prior validation, meaning ANY negative price from Pyth will trigger the panic.

3. **Public Entry Point**: The `update_single_price()` function is public and callable by anyone, so any legitimate price update attempt during a Pyth negative price state will trigger the DoS: [14](#0-13) 

4. **No Automatic Recovery**: The DoS persists until:
   - Pyth stops reporting negative prices, OR
   - An admin manually disables the Pyth oracle provider

   During this window (which could be hours or days), all affected operations are blocked.

5. **No Attacker Required**: This is a natural fault condition, not requiring malicious intent. The vulnerability manifests whenever Pyth's infrastructure experiences issues that cause negative price reporting.

### Recommendation

**Immediate Fix**: Add validation to handle negative/zero prices gracefully instead of panicking:

```move
public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
    let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);
    
    let i64_price = price::get_price(&pyth_price_info_unsafe);
    let i64_expo = price::get_expo(&pyth_price_info_unsafe);
    let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000;
    
    // Add validation before extracting magnitude
    if (!i64::is_positive(&i64_price)) {
        // Return zero price to signal error - will be caught by downstream validation
        return (0, 0, timestamp)
    };
    
    let price = i64::get_magnitude_if_positive(&i64_price);
    let expo = i64::get_magnitude_if_negative(&i64_expo);
    
    (price, expo, timestamp)
}
```

Apply the same fix to `get_price_native()` at line 20.

**Additional Safeguards**:
1. Add explicit minimum price validation in `oracle_pro::update_single_price()` before calling adaptors
2. Ensure the strategy validation layer rejects zero prices returned from failed extractions
3. Add test cases for negative price scenarios to prevent regression
4. Consider wrapping adaptor calls in error handling to allow secondary oracle fallback even when primary adaptor fails

### Proof of Concept

**Initial State**:
- Navi lending protocol with active user positions
- Oracle system configured with Pyth as primary provider
- User has collateral and wants to withdraw

**Attack Sequence**:
1. Pyth oracle enters error state and reports negative price for an asset (e.g., `i64_price = -100`)
2. Automated or manual call to `oracle_pro::update_single_price()` to update oracle prices
3. Function calls `get_price_from_adaptor()` → `adaptor_pyth::get_price_unsafe_to_target_decimal()` → `get_price_unsafe_native()`
4. At line 33: `i64::get_magnitude_if_positive(&i64_price)` receives negative value and **PANICS**
5. Transaction aborts, price in `PriceOracle` is NOT updated
6. Time passes, stored price becomes stale (older than `update_interval`)
7. User attempts withdrawal via `lending::withdraw()`
8. At line 91 of `logic.move`: calls `is_health()` which needs `user_health_factor()`
9. Health factor calculation calls `calculator::calculate_value()` → `oracle::get_token_price()`
10. `get_token_price()` returns `valid=false` for stale price
11. `calculate_value()` asserts at line 99: `assert!(is_valid, error::invalid_price())`
12. **Withdrawal transaction aborts - User funds locked**

**Expected Result**: User can withdraw funds if healthy, or oracle gracefully handles negative price with fallback
**Actual Result**: All withdrawals fail with assertion error, DoS of lending protocol operations

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L14-24)
```text
    public fun get_price_native(clock: &Clock, pyth_state: &State, pyth_price_info: &PriceInfoObject): (u64, u64, u64){
        let pyth_price_info = pyth::get_price(pyth_state, pyth_price_info, clock);

        let i64_price = price::get_price(&pyth_price_info);
        let i64_expo = price::get_expo(&pyth_price_info);
        let timestamp = price::get_timestamp(&pyth_price_info) * 1000; // timestamp from pyth in seconds, should be multiplied by 1000
        let price = i64::get_magnitude_if_positive(&i64_price);
        let expo = i64::get_magnitude_if_negative(&i64_expo);

        (price, expo, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L26-37)
```text
    // get_price_unsafe_native: return the price(uncheck timestamp)/decimal(expo)/timestamp from pyth oracle
    public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
        let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);

        let i64_price = price::get_price(&pyth_price_info_unsafe);
        let i64_expo = price::get_expo(&pyth_price_info_unsafe);
        let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000; // timestamp from pyth in seconds, should be multiplied by 1000
        let price = i64::get_magnitude_if_positive(&i64_price);
        let expo = i64::get_magnitude_if_negative(&i64_expo);

        (price, expo, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L47-53)
```text
    // get_price_unsafe_to_target_decimal: return the target decimal price(uncheck timestamp) and timestamp
    public fun get_price_unsafe_to_target_decimal(pyth_price_info: &PriceInfoObject, target_decimal: u8): (u256, u64) {
        let (price, decimal, timestamp) = get_price_unsafe_native(pyth_price_info);
        let decimal_price = utils::to_target_decimal_value_safe((price as u256), decimal, (target_decimal as u64));

        (decimal_price, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-56)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
        config::version_verification(oracle_config);
        assert!(!config::is_paused(oracle_config), error::paused());
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L73-84)
```text
        // Core Logic
        let primary_oracle_provider = config::get_primary_oracle_provider(price_feed);
        if (provider::is_empty(primary_oracle_provider)) {
            return
        };
        let primary_oracle_provider_config = config::get_primary_oracle_provider_config(price_feed);
        if (!provider::is_oracle_provider_config_enable(primary_oracle_provider_config)) {
            // the administrator should shut it down before reaching here. No event or error is required at this time, it was confirmed by the administrator
            return
        };
        let (primary_price, primary_updated_time) = get_price_from_adaptor(primary_oracle_provider_config, decimal, supra_oracle_holder, pyth_price_info);
        let is_primary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, primary_updated_time, max_timestamp_diff);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L86-95)
```text
        // retrieve secondary price and status
        let is_secondary_price_fresh = false;
        let is_secondary_oracle_available = config::is_secondary_oracle_available(price_feed);
        let secondary_price = 0;
        let secondary_updated_time = 0;
        if (is_secondary_oracle_available) {
            let secondary_source_config = config::get_secondary_source_config(price_feed);
            (secondary_price, secondary_updated_time) = get_price_from_adaptor(secondary_source_config, decimal, supra_oracle_holder, pyth_price_info);
            is_secondary_price_fresh = strategy::is_oracle_price_fresh(current_timestamp, secondary_updated_time, max_timestamp_diff);
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L175-180)
```text
        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-92)
```text
    public(friend) fun execute_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256 // e.g. 100USDT -> 100000000000
    ): u64 {
        assert!(user_collateral_balance(storage, asset, user) > 0, error::user_have_no_collateral());

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_withdraw<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L379-391)
```text
    public fun user_health_factor(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // 
        let health_collateral_value = user_health_collateral_value(clock, oracle, storage, user); // 202500000000000
        let dynamic_liquidation_threshold = dynamic_liquidation_threshold(clock, storage, oracle, user); // 650000000000000000000000000
        let health_loan_value = user_health_loan_value(clock, oracle, storage, user); // 49500000000
        if (health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(health_collateral_value, health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-480)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }

    /**
     * Title: get the number of collaterals the user has in given asset.
     * Returns: USD amount.
     */
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-32)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);

    emit(NaviHealthFactorVerified {
        account,
        health_factor,
        safe_check_hf: min_health_factor,
    });

```
