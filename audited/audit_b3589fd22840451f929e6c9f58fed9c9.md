### Title
Oracle Version Mismatch Causes Complete DoS Between Package Upgrade and Object Migration

### Summary
The oracle system uses a strict equality check for version validation that causes all oracle operations to fail immediately after a package upgrade until objects are migrated. This creates a critical DoS window where price feeds cannot be updated, prices cannot be read, and all vault/lending operations depending on oracle prices are blocked.

### Finding Description

The root cause is in the version verification mechanism. The `pre_check_version` function uses strict equality to validate versions: [1](#0-0) 

This strict check (==) is called by `version_verification` in the oracle module: [2](#0-1) 

ALL critical oracle operations invoke this verification:
- Reading prices: [3](#0-2) 
- Updating prices (internal): [4](#0-3) 
- Updating prices (external): [5](#0-4) 
- Batch updates: [6](#0-5) 
- Configuration changes: [7](#0-6) 
- Token registration: [8](#0-7) 

The config module has identical verification: [9](#0-8) 

The validated price update flow also checks version: [10](#0-9) 

The version constant is hardcoded in the constants module: [11](#0-10) 

Migration functions allow upgrading from older versions using <= check: [12](#0-11) [13](#0-12) 

However, these migrations must be called explicitly via: [14](#0-13) 

**Exploitation Path:**
1. Package upgrade occurs at block N, updating `constants::version()` from V to V+1
2. PriceOracle and OracleConfig objects still have `version = V`
3. Any transaction calling oracle operations executes `version_verification`
4. The check `assert!(V == V+1)` fails with `error::incorrect_version()`
5. All oracle operations revert until admin calls `oracle_manage::version_migrate`
6. If migration occurs at block N+100, 100 blocks of complete oracle DoS occur

### Impact Explanation

**Operational Impact - Complete Oracle System Failure:**
- **Price Feed Paralysis**: All price updates via `update_token_price`, `update_token_price_batch`, and `update_single_price` fail, causing stale oracle prices
- **Price Reading Blocked**: Vault operations calling `get_token_price` fail, preventing USD valuation calculations needed for deposits/withdrawals/operations
- **Configuration Locked**: All oracle configuration changes via `oracle_manage` functions fail
- **Downstream System Cascade**: Vault operations, lending protocols, and any DeFi integrations depending on these oracles cannot function

**Affected Systems:**
- Volo Vault cannot calculate total USD value or process user requests
- Lending protocols (Navi, Suilend integrations) cannot update collateral valuations
- Health factor checks become stale, risking liquidation miscalculations
- Users cannot deposit, withdraw, or interact with vault during the DoS window

**Severity Justification**: HIGH
- Complete operational disruption of core oracle infrastructure
- Cascading failure across all dependent systems
- Duration directly proportional to migration delay (could be hours if admin unavailable)
- No workaround available until migration completes

### Likelihood Explanation

**Realistic Exploitability:**
- **Precondition**: Package upgrade is a planned admin action, making this scenario guaranteed to occur on every version upgrade
- **No Attacker Required**: This is an architectural flaw triggered by normal upgrade procedures, not an active attack
- **Probability**: 100% occurrence on every package upgrade where migration isn't atomic
- **Operational Constraints**: Admin must manually call migration after upgrade; any delay (timezone differences, availability, transaction building time) extends the DoS window

**Feasibility Assessment:**
- The vulnerability requires no special capabilities or exploits
- It's triggered automatically by the version check mechanism
- The timing window is entirely dependent on operational procedures
- In production with 24/7 operations, even a 10-100 block delay (1-10 minutes) causes significant disruption

**Detection**: The DoS is immediately detectable (all oracle transactions fail), but this doesn't prevent the impact during the window.

### Recommendation

**Primary Fix - Implement Backward-Compatible Version Check:**

Replace the strict equality check in `pre_check_version` with a less-than-or-equal check to allow a grace period:

Modify `volo-vault/local_dependencies/protocol/oracle/sources/oracle_version.move`:
```move
public fun pre_check_version(v: u64) {
    // Allow current version and one previous version during migration window
    assert!(
        v == constants::version() || v == constants::version() - 1, 
        error::incorrect_version()
    )
}
```

**Alternative - Atomic Upgrade Pattern:**

Ensure migration is atomic with package upgrade by:
1. Including migration as part of upgrade transaction
2. Using programmable transaction blocks to bundle package upgrade + migration calls
3. Adding pre-upgrade checklist requiring migration readiness

**Additional Safeguards:**
1. Add version compatibility matrix allowing N-1 versions to operate temporarily
2. Emit events when version mismatches are detected (before failing)
3. Implement emergency version override for admin during migration windows
4. Add comprehensive migration tests simulating upgrade timing scenarios

**Test Cases to Add:**
- Test all oracle operations work with version N-1 when constant is N
- Test migration can be called idempotently
- Test that version N+2 objects correctly reject N constant
- Simulate 100-block delay between upgrade and migration

### Proof of Concept

**Initial State:**
- Oracle system deployed with `constants::version() = 2`
- PriceOracle object has `version = 2`
- OracleConfig object has `version = 2`
- System operating normally

**Attack Sequence:**
1. **Block N**: Admin publishes package upgrade with `constants::version() = 3`
2. **Block N+1**: User calls `oracle::get_token_price()` to read SUI price
   - Expected: Returns current price
   - Actual: Transaction aborts with `error::incorrect_version()` because `2 != 3`
3. **Block N+1**: Oracle feeder calls `oracle::update_token_price()` to update price
   - Expected: Price updates successfully
   - Actual: Transaction aborts with `error::incorrect_version()`
4. **Block N+1 to N+99**: All oracle operations continue failing
5. **Block N+100**: Admin calls `oracle_manage::version_migrate()`
   - Objects updated to `version = 3`
6. **Block N+101**: Oracle operations resume successfully

**Success Condition:**
Between blocks N+1 and N+100, all oracle transactions abort with version mismatch error, confirming 100 blocks of complete DoS.

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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L154-161)
```text
    public entry fun update_token_price_batch(
        cap: &OracleFeederCap,
        clock: &Clock,
        price_oracle: &mut PriceOracle,
        oracle_ids: vector<u8>,
        token_prices: vector<u256>,
    ) {
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-186)
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L187-190)
```text
    public(friend) fun version_migrate(cfg: &mut OracleConfig) {
        assert!(cfg.version <= version::this_version(), error::not_available_version());
        cfg.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-56)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
        config::version_verification(oracle_config);
        assert!(!config::is_paused(oracle_config), error::paused());
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L28-28)
```text
    public fun version(): u64 { 2 }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L14-17)
```text
    public fun version_migrate(cap: &OracleAdminCap, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle) {
        config::version_migrate(oracle_config);
        oracle::oracle_version_migrate(cap, price_oracle);
    }
```
