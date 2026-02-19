### Title
Version Rollback Incompatibility Causes Permanent DoS on All User Positions

### Summary
The protocol's version management system uses strict equality checks that prevent safe rollback from version 13 to version 12. If a critical bug requires emergency rollback by redeploying version 12 code, all existing user positions become permanently inaccessible because the shared Storage object retains version=13 while the redeployed contract expects version=12, causing all operations to abort.

### Finding Description

**Root Cause:**

The protocol implements a version management system with two critical components that prevent rollback:

1. **Exact Version Equality Check**: The `pre_check_version()` function enforces strict equality between the Storage object's version field and the contract's hardcoded version constant. [1](#0-0) 

2. **Forward-Only Migration**: The `version_migrate()` function only allows upgrading to higher versions, not downgrading. [2](#0-1) 

The current version is hardcoded as 13: [3](#0-2) 

**Execution Path:**

Every lending operation (deposit, withdraw, borrow, repay) calls `storage::version_verification()` before executing: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The Storage struct maintains a version field that gets checked: [8](#0-7) 

**Why Rollback Fails:**

In an emergency rollback scenario:
1. Storage shared object has `version: u64 = 13`
2. Admin redeploys version 12 contract with `constants::version() = 12`
3. All user operations call `version_verification(storage)`
4. This calls `pre_check_version(13)` which asserts `13 == 12`
5. Assertion fails with `error::incorrect_version()` (code 1400) [9](#0-8) 

The `version_migrate()` function cannot help because it checks `storage.version < version::this_version()`, which evaluates to `13 < 12 = false`, aborting with `error::not_available_version()`.

### Impact Explanation

**Concrete Harm:**
- **All user funds become permanently locked**: Users cannot deposit, withdraw, borrow, or repay
- **Existing positions cannot be managed**: No way to close positions or prevent liquidations
- **Protocol-wide DoS**: Affects every user with active positions in the lending protocol
- **No recovery mechanism**: The version mismatch cannot be resolved without deploying a new Storage object and manually migrating all state

**Affected Parties:**
- All users with supply balances stored in `ReserveData.supply_balance`
- All users with borrow positions stored in `ReserveData.borrow_balance`  
- Treasury funds in `ReserveData.treasury_balance`
- All collateral and loan tracking in `Storage.user_info`

**Severity Justification:**
This is a HIGH severity issue because:
1. Complete loss of access to user funds (DoS, not theft, but equally damaging)
2. Affects 100% of protocol users
3. No built-in recovery mechanism
4. Occurs in precisely the scenario where quick remediation is most critical (emergency bug fix)

### Likelihood Explanation

**Realistic Scenario:**
This vulnerability manifests in a legitimate operational scenario:
1. Version 13 is deployed and users interact with the protocol
2. Critical bug is discovered in version 13 (e.g., price oracle manipulation, liquidation logic error)
3. Team attempts emergency rollback by redeploying version 12 contract code
4. All existing positions immediately become inaccessible

**Feasibility:**
- **No attacker required**: This is an operational vulnerability, not an exploit
- **Preconditions are natural**: Version upgrades and potential rollbacks are standard protocol operations
- **Execution is automatic**: The DoS occurs immediately upon version 12 redeployment
- **Detection is certain**: All user transactions will fail with `incorrect_version` error

**Probability:**
While the protocol team may intend to always move forward with versions, the lack of rollback capability creates operational risk. In blockchain protocols, the ability to quickly revert to a known-good state is a critical safety mechanism. The probability increases if:
- Complex features are added in version 13
- External dependencies change behavior
- Unforeseen interactions emerge post-deployment

### Recommendation

**Immediate Fix:**

1. **Modify version check to support version ranges** instead of exact equality:
   ```move
   public fun pre_check_version(v: u64) {
       // Allow current version or one version back
       assert!(v >= constants::version() - 1 && v <= constants::version(), 
               error::incorrect_version())
   }
   ```

2. **Add emergency rollback function** with admin capability:
   ```move
   public entry fun emergency_rollback(_: &StorageAdminCap, storage: &mut Storage, target_version: u64) {
       assert!(target_version >= constants::version() - 1, error::not_available_version());
       assert!(target_version <= constants::version(), error::not_available_version());
       storage.version = target_version;
   }
   ```

3. **Implement version compatibility matrix** to explicitly define which versions can interoperate.

**Long-term Solution:**

1. **Add graceful degradation mode**: Allow read-only operations when version mismatch is detected
2. **Implement state migration utilities**: Functions to export/import user positions between Storage versions
3. **Version-specific operation routing**: Route operations through version-appropriate logic paths
4. **Comprehensive upgrade testing**: Include rollback scenarios in the test suite

**Test Cases:**

1. Test rollback from v13 to v12 with active positions
2. Test user operations immediately after rollback
3. Test partial rollback (some operations on v13, some on v12)
4. Test version_migrate with both upgrade and downgrade scenarios

### Proof of Concept

**Initial State:**
- Protocol deployed at version 13
- User A has deposited 1000 USDC (storage.reserves[0].supply_balance.user_state[A] = 1000e9)
- User B has borrowed 500 USDC (storage.reserves[0].borrow_balance.user_state[B] = 500e9)
- Storage.version = 13

**Rollback Sequence:**

1. **Critical bug discovered in version 13**: Admin decides to rollback

2. **Admin redeploys version 12 contract**: 
   - New contract has `constants::version() = 12`
   - Storage object still exists with `version = 13`

3. **User A attempts to withdraw funds**:
   ```
   TX: entry_withdraw<USDC>(clock, oracle, storage, pool, 0, 100, incentive_v2, incentive_v3, ctx)
   → lending::withdraw_coin() called
   → storage::version_verification(storage) called
   → version::pre_check_version(13) called
   → assert!(13 == 12, error::incorrect_version())
   → ABORT with code 1400
   ```

4. **User B attempts to repay loan**:
   ```
   TX: entry_repay<USDC>(clock, oracle, storage, pool, 0, repay_coin, 50, incentive_v2, incentive_v3, ctx)
   → lending::repay_coin() called
   → storage::version_verification(storage) called  
   → version::pre_check_version(13) called
   → assert!(13 == 12, error::incorrect_version())
   → ABORT with code 1400
   ```

5. **Admin attempts to migrate version downward**:
   ```
   TX: version_migrate(admin_cap, storage)
   → assert!(13 < 12, error::not_available_version())
   → ABORT with code 1401
   ```

**Result:**
- Users cannot access their 1500 USDC total value locked
- Protocol is completely non-functional
- Only recovery option is deploying new Storage and manually migrating all positions

**Success Condition:**
The vulnerability is confirmed when all user operations abort with `incorrect_version` error code 1400 after redeploying version 12 code while Storage retains version 13.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/version.move (L13-15)
```text
    public fun pre_check_version(v: u64) {
        assert!(v == constants::version(), error::incorrect_version())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L32-40)
```text
    struct Storage has key, store {
        id: UID,
        version: u64,
        paused: bool, // Whether the pool is paused
        reserves: Table<u8, ReserveData>, // Reserve list. like: {0: ReserveData<USDT>, 1: ReserveData<ETH>}
        reserves_count: u8, // Total reserves count
        users: vector<address>, // uset list, like [0x01, 0x02]
        user_info: Table<address, UserInfo>
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L149-152)
```text
    public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
        assert!(storage.version < version::this_version(), error::not_available_version());
        storage.version = version::this_version();
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L13-14)
```text
    // version
    public fun version(): u64 {13}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L184-186)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L225-226)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L275-276)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L319-320)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/error.move (L2-3)
```text
    public fun incorrect_version(): u64 {1400}
    public fun not_available_version(): u64 {1401}
```
