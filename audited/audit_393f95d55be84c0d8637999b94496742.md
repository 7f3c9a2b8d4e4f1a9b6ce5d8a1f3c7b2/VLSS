### Title
Oracle System Complete Denial of Service During Version Migration Window

### Summary
During package upgrade from version 1 to version 2, all oracle operations abort with incorrect_version error until the migration transaction completes. The strict version equality check in `pre_check_version()` creates a guaranteed DoS window where no price reads, updates, or configurations are possible, affecting all dependent protocols.

### Finding Description

The oracle version verification system enforces a strict equality check between the stored version and the current package version. [1](#0-0) 

When a package upgrade occurs from version 1 to version 2, the hardcoded version constant immediately changes to 2, [2](#0-1)  but the shared objects `PriceOracle` and `OracleConfig` retain their stored version field value of 1 until migration executes.

Every critical oracle operation invokes version verification before execution. For `PriceOracle`, this check is performed via: [3](#0-2) 

This verification is called by all essential operations:
- Price reading: [4](#0-3) 
- Price updates by feeders: [5](#0-4) 
- Internal price updates: [6](#0-5) 
- Token registration: [7](#0-6) 
- Configuration updates: [8](#0-7) 

Similarly, `OracleConfig` operations perform the same check: [9](#0-8) 

The migration function that updates the version field exists but must be called separately: [10](#0-9) 

The entry point migration is explicitly disabled: [11](#0-10) 

**Root Cause:** The `pre_check_version()` function performs a strict equality assertion rather than checking for a version range or migration state, creating a binary state where operations either fully work or completely fail.

**Why Protections Fail:** There is no graceful degradation, no read-only mode during migration, and no bypass mechanism. The migration must complete successfully in a single transaction, or the oracle remains permanently unavailable.

### Impact Explanation

**Complete Oracle Unavailability:**
- All price reads fail, blocking any protocol or user that depends on oracle prices
- Price feeders cannot update prices, causing price data to become stale
- Administrators cannot register new tokens or update configurations
- The entire oracle system is frozen until migration completes

**Dependent Protocol Disruption:**
The Volo Vault system depends on oracle prices for operations. [12](#0-11)  If the migration transaction fails, gets delayed, or must be retried due to gas issues or other transaction failures, the oracle outage extends indefinitely.

**Severity Justification - HIGH:**
- **Blast Radius:** Affects entire oracle system and all dependent protocols
- **Duration:** Could last from seconds to indefinitely if migration fails
- **Recovery:** Requires successful migration transaction by admin
- **Cascading Failures:** Volo Vault operations requiring price data become unavailable

### Likelihood Explanation

**Guaranteed Occurrence:** This DoS window occurs with 100% certainty during every version upgrade from v1 to v2.

**Attack Complexity:** None - this is not an attack but an operational certainty. Any user or protocol attempting legitimate operations during the migration window will be denied service.

**Feasibility Conditions:**
1. Package is upgraded, changing `constants::version()` from 1 to 2
2. Shared objects still have `version = 1` in storage  
3. Any user calls any oracle operation
4. `pre_check_version(1)` asserts `1 == 2`, which fails
5. Transaction aborts with incorrect_version error

**Operational Constraints:**
- Migration requires `OracleAdminCap` and must update both PriceOracle and OracleConfig
- If migration transaction fails (gas, concurrency, etc.), DoS continues
- No emergency override or fallback mechanism exists

### Recommendation

**Immediate Mitigation:**
Modify `pre_check_version()` to allow version ranges during migration:

```move
public fun pre_check_version(v: u64) {
    assert!(v <= constants::version(), error::incorrect_version())
}
```

This allows operations to continue during the migration window while still preventing downgrades.

**Better Long-term Design:**
1. Add a migration flag to indicate migration in progress
2. Separate read-only operations (like `get_token_price`) from write operations during migration
3. Implement a grace period where both versions are accepted
4. Add migration status checks that provide informative errors vs blocking all operations
5. Consider atomic migration as part of package upgrade hooks if available

**Invariant Checks:**
- Version must be less than or equal to current version (not strictly equal)
- Migration completion should emit events for monitoring
- Test cases should verify operations work during version transitions

**Test Cases:**
1. Verify `get_token_price` succeeds when `oracle.version < constants::version()`
2. Verify migration can be called multiple times safely (idempotent)
3. Test migration failure recovery scenarios
4. Verify operations resume after migration completes

### Proof of Concept

**Initial State (Version 1):**
- Package deployed with `constants::version() = 1`
- `PriceOracle` created with `version = 1` via: [13](#0-12) 
- All operations succeed: `pre_check_version(1)` checks `1 == 1` ✓

**After Package Upgrade (Before Migration):**
1. Admin upgrades package to version 2
2. Code now has `constants::version() = 2`
3. `PriceOracle.version` still equals 1 in storage
4. User calls `get_token_price(clock, price_oracle, oracle_id)`
5. Function calls `version_verification(price_oracle)` 
6. Which calls `pre_check_version(1)`
7. Assertion `1 == constants::version()` evaluates to `1 == 2`
8. **Transaction aborts with incorrect_version error**
9. Same failure occurs for ALL oracle operations

**Expected Behavior:** Operations should continue or gracefully degrade
**Actual Behavior:** Complete DoS until migration completes

**After Migration:**
1. Admin calls `oracle_manage::version_migrate(cap, oracle_config, price_oracle)`
2. Updates `oracle.version = 2`
3. Operations resume: `pre_check_version(2)` checks `2 == 2` ✓

**Success Condition:** User operations fail between step 2 and step 1 of migration, creating guaranteed DoS window.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_version.move (L13-15)
```text
    public fun pre_check_version(v: u64) {
        assert!(v == constants::version(), error::incorrect_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L28-28)
```text
    public fun version(): u64 { 2 }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L53-58)
```text
        transfer::share_object(PriceOracle {
            id: object::new(ctx),
            version: version::this_version(),
            price_oracles: table::new(ctx),
            update_interval: constants::default_update_interval(),
        });
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L65-67)
```text
    fun version_verification(oracle: &PriceOracle) {
        version::pre_check_version(oracle.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L70-72)
```text
    entry fun version_migrate(_: &OracleAdminCap, oracle: &mut PriceOracle) {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L74-77)
```text
    public(friend) fun oracle_version_migrate(_: &OracleAdminCap, oracle: &mut PriceOracle) {
        assert!(oracle.version <= version::this_version(), error::not_available_version());
        oracle.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L80-85)
```text
    public entry fun set_update_interval(
        _: &OracleAdminCap,
        price_oracle: &mut PriceOracle,
        update_interval: u64,
    ) {
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L90-98)
```text
    public entry fun register_token_price(
        _: &OracleAdminCap,
        clock: &Clock,
        price_oracle: &mut PriceOracle,
        oracle_id: u8,
        token_price: u256,
        price_decimal: u8,
    ) {
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L115-117)
```text
    public(friend) fun update_price(clock: &Clock, price_oracle: &mut PriceOracle, oracle_id: u8, token_price: u256) {
        // TODO: update_token_price can be merged into update_price
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L138-145)
```text
    public entry fun update_token_price(
        _: &OracleFeederCap,
        clock: &Clock,
        price_oracle: &mut PriceOracle,
        oracle_id: u8,
        token_price: u256,
    ) {
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-185)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L183-185)
```text
    public fun version_verification(cfg: &OracleConfig) {
        version::pre_check_version(cfg.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L14-17)
```text
    public fun version_migrate(cap: &OracleAdminCap, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle) {
        config::version_migrate(oracle_config);
        oracle::oracle_version_migrate(cap, price_oracle);
    }
```
