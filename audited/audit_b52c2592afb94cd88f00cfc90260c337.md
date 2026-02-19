### Title
Critical Protocol-Wide DoS During Version Migration Window

### Summary
After a package upgrade that increments `constants::version()` from 13 to 14, all protocol operations will abort with `incorrect_version` error until separate migration transactions complete for Storage, PriceOracle, OracleConfig, FlashLoanConfig, and Incentive modules. This creates a complete denial-of-service affecting all user deposits, withdrawals, borrows, repayments, flash loans, and even price oracle reads.

### Finding Description

The protocol implements version checking across all critical modules using a centralized `constants::version()` value. [1](#0-0) 

The `pre_check_version()` function enforces strict equality between stored versions and the constant: [2](#0-1) 

When a package upgrade occurs, the code changes but shared objects retain their old version field values. The Storage module calls `version_verification()` before all operations: [3](#0-2) 

This affects all lending operations:
- Deposits: [4](#0-3) 
- Withdrawals: [5](#0-4) 
- Borrows: [6](#0-5) 
- Repayments: [7](#0-6) 

Additionally, the oracle's `get_token_price()` function, critical for health factor calculations, also checks version: [8](#0-7) 

All Storage state-modifying friend functions call `version_verification()`: [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11) [13](#0-12) [14](#0-13) 

Migration requires separate admin transactions for each module: [15](#0-14) [16](#0-15) [17](#0-16) 

The error code returned is: [18](#0-17) 

### Impact Explanation

**Complete Protocol DoS:** From the moment of package upgrade until all migration transactions complete, the entire protocol is frozen for all users.

**Affected Operations:**
1. **All lending operations blocked** - Users cannot deposit, withdraw, borrow, or repay
2. **Oracle reads blocked** - Price queries fail, preventing any health factor calculations
3. **Flash loans blocked** - All flash loan operations abort
4. **Incentive operations blocked** - Users cannot claim rewards or interact with incentive systems
5. **Admin operations blocked** - Even protocol administrators cannot update configurations

**Severity:** CRITICAL - This affects 100% of protocol functionality with zero user recourse. Every user attempting any operation receives `incorrect_version` (error code 1400) abort.

**Who is Affected:** All protocol users, including:
- Lenders unable to withdraw their funds
- Borrowers unable to repay or manage positions (risk of liquidation if DoS is prolonged)
- Liquidators unable to execute liquidations
- Flash loan arbitrageurs unable to operate

**Duration Risk:** The DoS persists until ALL required migration transactions succeed:
- Storage migration
- PriceOracle migration  
- OracleConfig migration
- FlashLoanConfig migration
- IncentiveV2 migration
- IncentiveV3 migration

If any migration transaction fails due to gas issues, network congestion, or admin error, the DoS extends.

### Likelihood Explanation

**Probability:** HIGH - This vulnerability triggers with 100% certainty on every protocol upgrade where `constants::version()` is incremented.

**Preconditions:** 
- Package upgrade modifying `constants::version()` (normal protocol maintenance)
- No attacker needed - this is an architectural flaw

**Attack Complexity:** None - this is not an attack but an operational failure mode built into the design.

**Feasibility:** Guaranteed to occur unless:
1. Version is never incremented (prevents upgrades)
2. All migrations execute atomically with package upgrade (impossible in Sui - package upgrade and object mutations are separate transactions)
3. Admins execute all migrations within same block as upgrade (requires perfect coordination and no transaction failures)

**Detection/Mitigation Constraints:**
- Window between upgrade and migration completion is unavoidable
- Network congestion could delay migrations for minutes/hours
- Transaction failures require retry, extending DoS
- Users have no way to know when protocol will become operational again

**Economic Impact:** During DoS window:
- Borrowers cannot prevent liquidations
- Market opportunities missed
- User confidence damaged
- Protocol reputation harmed

### Recommendation

**Immediate Fix:** Implement version range checking instead of strict equality:

```move
// In version.move
public fun pre_check_version(v: u64) {
    // Allow current version or one version behind during migration window
    let current = constants::version();
    assert!(v == current || v == current - 1, error::incorrect_version())
}
```

**Better Solution:** Implement graceful migration pattern:

1. Add version compatibility window in constants:
```move
public fun version(): u64 {14}
public fun min_supported_version(): u64 {13}
```

2. Update pre_check_version:
```move
public fun pre_check_version(v: u64) {
    assert!(
        v >= constants::min_supported_version() && v <= constants::version(), 
        error::incorrect_version()
    )
}
```

3. After all objects migrated, increment `min_supported_version()` in next upgrade

**Additional Safeguards:**
- Add migration status tracking to monitor completion
- Implement batch migration function to update multiple objects atomically where possible
- Add migration deadline warnings before version increments
- Create migration health check endpoints

**Test Cases:**
1. Verify operations work with version N when constant is N+1 (during migration)
2. Verify version N-2 objects are rejected when constant is N
3. Test all migration paths complete successfully
4. Test partial migration scenarios (some objects migrated, others not)

### Proof of Concept

**Initial State:**
- Protocol deployed with `constants::version()` = 13
- Storage object has `version` field = 13
- PriceOracle object has `version` field = 13
- All other shared objects have `version` = 13

**Exploitation Steps:**

1. **Package Upgrade Transaction:**
   - Admin executes package upgrade
   - New package code has `constants::version()` = 14
   - All shared objects still have version = 13 in their fields

2. **User Attempts Deposit:**
   - User calls `deposit_coin<USDC>()` 
   - Function calls `storage::version_verification(storage)` (line 185 of lending.move)
   - Which calls `version::pre_check_version(storage.version)` where storage.version = 13
   - Assertion fails: `assert!(13 == 14, error::incorrect_version())`
   - Transaction aborts with error code 1400

3. **User Attempts Withdrawal:**
   - User calls `withdraw_coin<USDC>()`
   - Function calls `storage::version_verification(storage)` (line 226 of lending.move)
   - Same version mismatch
   - Transaction aborts with error code 1400

4. **User Attempts Price Query:**
   - Any operation needing prices calls `oracle::get_token_price()`
   - Function calls `version_verification(price_oracle)` (line 185 of oracle.move)
   - Assertion fails: `assert!(13 == 14, error::incorrect_version())`
   - Transaction aborts with error code 1400

**Expected Result:** Operations succeed or degrade gracefully during migration

**Actual Result:** All operations abort with error 1400 until admin completes migrations:
- `storage::version_migrate(&StorageAdminCap, &mut Storage)`
- `oracle_manage::version_migrate(&OracleAdminCap, &mut OracleConfig, &mut PriceOracle)`
- `flash_loan::version_migrate(&StorageAdminCap, &mut Config)`
- `incentive_v2::version_migrate(&OwnerCap, &mut Incentive)`
- `manage::incentive_v3_version_migrate(&StorageAdminCap, &mut IncentiveV3)`

**Success Condition:** Protocol remains operational (possibly in degraded mode) throughout upgrade/migration process

## Notes

This is a systemic architectural vulnerability affecting the Navi lending protocol (local dependency), not the Volo vault itself. However, since Volo integrates with Navi through the health limiter and adaptors, any Navi upgrade would indirectly impact Volo's ability to interact with Navi positions.

The vulnerability exists because Sui Move package upgrades and shared object mutations occur in separate transactions, creating an unavoidable window where code version and data version are mismatched. The strict equality check provides no grace period for migration completion.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L14-14)
```text
    public fun version(): u64 {13}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/version.move (L13-15)
```text
    public fun pre_check_version(v: u64) {
        assert!(v == constants::version(), error::incorrect_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L145-147)
```text
    public fun version_verification(storage: &Storage) {
        version::pre_check_version(storage.version)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L149-152)
```text
    public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
        assert!(storage.version < version::this_version(), error::not_available_version());
        storage.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L469-469)
```text
        version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L485-485)
```text
        version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L507-507)
```text
        version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L516-516)
```text
        version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L525-525)
```text
        version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L534-534)
```text
        version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L185-185)
```text
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L226-226)
```text
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L276-276)
```text
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L320-320)
```text
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L74-77)
```text
    public(friend) fun oracle_version_migrate(_: &OracleAdminCap, oracle: &mut PriceOracle) {
        assert!(oracle.version <= version::this_version(), error::not_available_version());
        oracle.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L185-185)
```text
        version_verification(price_oracle);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_manage.move (L14-17)
```text
    public fun version_migrate(cap: &OracleAdminCap, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle) {
        config::version_migrate(oracle_config);
        oracle::oracle_version_migrate(cap, price_oracle);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/error.move (L2-2)
```text
    public fun incorrect_version(): u64 {1400}
```
