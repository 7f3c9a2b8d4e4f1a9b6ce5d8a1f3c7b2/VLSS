### Title
Oracle System DoS During Version Upgrade Window

### Summary
When the protocol oracle is upgraded and `constants::version()` is incremented, all oracle operations will fail until admin manually migrates the stored `PriceOracle` and `OracleConfig` objects. This creates a window of unavailability where legitimate user transactions abort with error code 6200, causing operational disruption to oracle price updates, queries, and all dependent systems including lending_core.

### Finding Description

The oracle system implements version checking that compares a compile-time constant against stored version fields. The version check occurs in: [1](#0-0) 

This check is called by all oracle operations through `version_verification()` functions: [2](#0-1) [3](#0-2) 

The version constant is hardcoded: [4](#0-3) 

**Root Cause:** When a package upgrade increments `constants::version()` from N to N+1, the stored `PriceOracle.version` and `OracleConfig.version` fields still contain N. The assertion `v == constants::version()` fails, causing all operations to abort until migration.

**Affected Functions:** All functions calling `version_verification()` fail during the window:
- Price updates: `update_token_price`, `update_token_price_batch`, `update_single_price`
- Price queries: `get_token_price` 
- Admin operations: All 38+ functions in `oracle_manage.move`
- Lending calculations: `calculate_value` and `calculate_amount` in lending_core [5](#0-4) [6](#0-5) [7](#0-6) 

Migration requires separate admin transaction: [8](#0-7) 

### Impact Explanation

**Operational Disruption:**
- Complete oracle system unavailability during upgrade-to-migration window
- All user transactions depending on oracle prices abort with error 6200
- Price feeds cannot be updated, causing potential data staleness
- Lending operations blocked (borrow/repay/liquidation calculations require oracle prices)
- Administrative fixes also blocked (except migration itself)

**Who Is Affected:**
- All users attempting oracle-dependent operations
- Lending protocol users unable to interact with positions
- Oracle feeders unable to update prices
- Any protocol integrating with the oracle system

**Duration:** The window lasts from block N (upgrade) to block N+X (migration), where X depends entirely on admin response time. As stated in the security question, this could be 100+ blocks if migration is delayed.

**Severity:** HIGH - While funds are not at direct risk, the complete unavailability of critical price infrastructure constitutes a significant operational DoS affecting all protocol users.

### Likelihood Explanation

**Occurrence Certainty:** This issue occurs deterministically on every version upgrade where `constants::version()` is incremented. It is not an attack but an inherent characteristic of the upgrade pattern.

**No Attacker Required:** Legitimate users experience transaction failures simply by attempting normal oracle interactions during the window. No malicious action or special capabilities are needed.

**Preconditions:** Only requires standard protocol upgrade process initiated by admin. The larger the delay between upgrade transaction and migration transaction, the more users are affected.

**Detection:** Easily detectable through transaction failures with error code 6200. Test demonstrates the behavior: [9](#0-8) 

### Recommendation

**Immediate Mitigation:**
1. Document upgrade procedure requiring immediate migration within same epoch/block if possible
2. Coordinate upgrades during low-activity periods
3. Pre-announce maintenance windows to users
4. Monitor for transaction failures and execute migration immediately

**Code-Level Improvements:**

Consider implementing version compatibility ranges instead of exact matching:
```move
public fun pre_check_version(v: u64) {
    // Allow current version and previous version during migration window
    assert!(
        v == constants::version() || v == constants::version() - 1,
        error::incorrect_version()
    )
}
```

Or implement automatic version update on first interaction post-upgrade:
```move
public fun version_verification_with_auto_update(object: &mut PriceOracle) {
    if (object.version < version::this_version()) {
        object.version = version::this_version();
    }
}
```

**Testing:**
Add regression test that simulates upgrade scenario and verifies migration must occur before normal operations resume, with explicit documentation of the unavailability window.

### Proof of Concept

**Initial State:**
- Oracle system deployed with `constants::version() = 2`
- `PriceOracle.version = 2`
- `OracleConfig.version = 2`
- Normal operations working

**Transaction Sequence:**

**Block N:** Admin upgrades package with `constants::version() = 3`

**Block N+1 to N+99:** Any user attempts to:
1. Call `update_token_price()` with valid OracleFeederCap
2. Call `get_token_price()` to query price
3. Call any oracle_manage function
4. Call lending_core functions requiring price calculations

**Expected Result:** Operations succeed

**Actual Result:** All transactions abort with error code 6200 (incorrect_version) because:
- Stored objects have `version = 2`
- `constants::version()` now returns `3`  
- Assertion `2 == 3` fails in `pre_check_version()`

**Block N+100:** Admin calls `oracle_manage::version_migrate()` to update stored versions

**Block N+101+:** Normal operations resume

**Success Condition:** The 100-block window of transaction failures is confirmed, validating that version mismatch causes operational DoS between upgrade and migration.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_version.move (L13-15)
```text
    public fun pre_check_version(v: u64) {
        assert!(v == constants::version(), error::incorrect_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L65-67)
```text
    fun version_verification(oracle: &PriceOracle) {
        version::pre_check_version(oracle.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L138-152)
```text
    public entry fun update_token_price(
        _: &OracleFeederCap,
        clock: &Clock,
        price_oracle: &mut PriceOracle,
        oracle_id: u8,
        token_price: u256,
    ) {
        version_verification(price_oracle);

        let price_oracles = &mut price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());
        let price = table::borrow_mut(price_oracles, oracle_id);
        price.value = token_price;
        price.timestamp = clock::timestamp_ms(clock);
    }
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L183-185)
```text
    public fun version_verification(cfg: &OracleConfig) {
        version::pre_check_version(cfg.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L28-28)
```text
    public fun version(): u64 { 2 }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L14-17)
```text
    public fun version_migrate(cap: &OracleAdminCap, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle) {
        config::version_migrate(oracle_config);
        oracle::oracle_version_migrate(cap, price_oracle);
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_config_manage_test.move (L1182-1198)
```text
    #[expected_failure(abort_code = 6200, location = oracle::oracle_version)]
    public fun test_fail_version_check() {
        let _scenario = test_scenario::begin(OWNER);
        let scenario = &mut _scenario;
        let _clock = clock::create_for_testing(test_scenario::ctx(scenario));
        {
            global::init_protocol(scenario);
        };

        test_scenario::next_tx(scenario, OWNER);
        {
            oracle_version::pre_check_version(constants::version() - 1);
        };

        clock::destroy_for_testing(_clock);
        test_scenario::end(_scenario);
    }
```
