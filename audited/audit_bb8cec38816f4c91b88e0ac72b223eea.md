### Title
Non-Atomic Version Migration Allows Cross-Module State Corruption During Protocol Upgrades

### Summary
During protocol upgrades from version 13 to 14, the code logic changes atomically via package upgrade, but shared object version fields update non-atomically through separate `version_migrate()` calls. Cross-module operations that don't verify all participating object versions can execute with mismatched version states, potentially corrupting protocol state when logic assumptions change between versions.

### Finding Description

**Root Cause:**

The version system uses a hardcoded constant that changes atomically during package upgrade: [1](#0-0) [2](#0-1) 

However, shared objects (Storage, FlashLoanConfig, Incentive, IncentiveV2, IncentiveV3, PriceOracle, OracleConfig) maintain independent version fields that must be migrated separately: [3](#0-2) [4](#0-3) 

**Critical Gap in Version Verification:**

Most operations check their primary object's version: [5](#0-4) [6](#0-5) 

However, **cross-module operations fail to verify all participating object versions**. The flash loan repay function modifies Storage without checking its version: [7](#0-6) [8](#0-7) 

The loan function verifies FlashLoanConfig version but repay operates on Storage with no version check: [9](#0-8) 

Similarly, incentive operations verify Incentive version but not Storage version when calling update_reward: [10](#0-9) 

**Upgrade Window Scenarios:**

After package upgrade (code at v14), during partial migration:

**Scenario 1: FlashLoanConfig migrated to v14, Storage still at v13**
- New flash loans succeed (Config v14 passes check)
- Repay executes v14 logic on Storage v13 state (no version check)
- If v14 changes interest rate calculations, fee structures, or state layout, Storage v13 gets corrupted with v14 assumptions

**Scenario 2: Incentive modules migrated, Storage not migrated**
- Incentive operations succeed on their objects
- But update_reward modifies Storage v13 using v14 code without verification
- State corruption if reward calculation logic changed

**Additional Issue - Pause Mechanism Blocked:**

The pause mechanism itself requires version verification, preventing safe migration: [11](#0-10) 

Admins cannot pause Storage at v13 to safely migrate because `set_pause` requires Storage to already be at v14.

### Impact Explanation

**Concrete Harms:**

1. **State Corruption Risk:** If v14 changes interest rate calculations, reserve factor formulas, or index update logic, executing v14 code on v13 Storage state produces incorrect:
   - Supply/borrow indices leading to wrong debt/collateral balances
   - Fee accumulations causing fund loss or improper distribution
   - Treasury balances affecting protocol revenue

2. **Version-Dependent Impact:** The actual severity depends on what changes in v14:
   - Logic changes (formulas, rates, caps): HIGH - incorrect calculations
   - Data structure changes (field additions/removals): CRITICAL - memory corruption
   - Parameter changes (constants, thresholds): MEDIUM - unexpected behavior

3. **Unavoidable Window:** Every protocol upgrade creates this vulnerability window. With 7 shared objects requiring individual migration, the window persists across multiple transactions.

4. **No Safe Migration Path:** Admins cannot pause the system before migration (pause requires correct version), forcing a choice between:
   - Accepting operations during migration (unsafe)
   - Migrating all objects in exact sequence hoping no users interact (impractical)

**Who Is Affected:**

- All protocol users during any upgrade window
- Particularly users with active flash loans or incentive positions
- Protocol treasury (incorrect fee calculations)

### Likelihood Explanation

**Attack Complexity:** MEDIUM
- Requires protocol upgrade to be in progress (admin action)
- But doesn't require attacker capabilities beyond normal user operations
- Window exists during EVERY upgrade

**Preconditions:**
1. Admin performs package upgrade (constants::version() changes to 14)
2. Admin begins migrating shared objects (some at v14, some at v13)
3. User executes flash loan, incentive claim, or other cross-module operation
4. Operation succeeds with mismatched versions

**Feasibility:** HIGH
- Upgrade windows are operational necessity, not attacker-created
- Any user with active positions can trigger during window
- No special knowledge or capabilities required
- Multi-block migration window (7 separate transactions) ensures opportunity

**Detection Difficulty:** HIGH
- No on-chain signals distinguish safe from unsafe migration states
- Users cannot verify all dependent object versions before transactions
- Silent corruption - operations succeed without errors

**Probability:** GUARANTEED during upgrades
- Occurs during every version upgrade by design
- Cannot be prevented without code changes
- Migration sequence determines which operations are unsafe

### Recommendation

**Immediate Mitigation:**

1. **Add Storage Version Verification to Cross-Module Operations:**

In `flash_loan::repay`, add before line 182:
```move
storage::version_verification(storage);
```

In `incentive::update_reward`, add before line 193:
```move
storage::version_verification(storage);
```

2. **Implement Atomic Migration Entry Point:**

Create a new entry function that migrates all related objects in a single transaction:
```move
public entry fun atomic_version_migrate(
    _: &StorageAdminCap,
    storage: &mut Storage,
    flash_config: &mut FlashLoanConfig,
    incentive: &mut Incentive,
    incentive_v2: &mut IncentiveV2,
    incentive_v3: &mut IncentiveV3,
    oracle: &mut PriceOracle,
    oracle_config: &mut OracleConfig,
) {
    // Verify all objects are at the same old version
    let old_version = storage.version;
    assert!(flash_config.version == old_version, ERROR_VERSION_MISMATCH);
    assert!(incentive.version == old_version, ERROR_VERSION_MISMATCH);
    // ... check all objects
    
    // Atomically update all versions
    let new_version = version::this_version();
    storage.version = new_version;
    flash_config.version = new_version;
    incentive.version = new_version;
    // ... update all objects
}
```

3. **Version-Agnostic Pause Mechanism:**

Allow pausing without version verification:
```move
public entry fun emergency_pause(_: &OwnerCap, storage: &mut Storage) {
    storage.paused = true;
    emit(EmergencyPaused {timestamp: clock::timestamp_ms(clock)})
}
```

**Long-term Solution:**

4. **Pre-Migration Version Compatibility Check:**

Add assertion in `version_migrate` to prevent premature migration:
```move
public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
    assert!(storage.version < version::this_version(), error::not_available_version());
    
    // NEW: Verify all dependent objects are ready
    assert!(
        all_dependent_objects_at_current_version(),
        error::dependent_objects_not_migrated()
    );
    
    storage.version = version::this_version();
}
```

**Test Cases:**

```move
#[test]
#[expected_failure(abort_code = ERROR_VERSION_MISMATCH)]
fun test_flash_repay_rejects_mismatched_storage_version() {
    // Setup: Storage v13, FlashLoanConfig v14, code v14
    // Attempt repay
    // Should fail at version check
}

#[test]
#[expected_failure(abort_code = ERROR_VERSION_MISMATCH)]
fun test_incentive_update_rejects_mismatched_storage_version() {
    // Setup: Incentive v14, Storage v13
    // Attempt update_reward
    // Should fail at version check
}
```

### Proof of Concept

**Initial State:**
- Protocol at version 13 (all objects and code aligned)
- User has active flash loan with Receipt<USDC> for 1000 USDC

**Upgrade Sequence:**

**Transaction 1 (Admin):** Package upgrade
- `constants::version()` now returns 14
- All code updated to v14 logic
- All shared objects still have version = 13

**Transaction 2 (Admin):** Migrate FlashLoanConfig
- `flash_loan::version_migrate(config)` succeeds
- FlashLoanConfig.version = 14
- Storage.version still = 13

**Transaction 3 (User):** Flash loan repay
```move
flash_loan::repay<USDC>(
    clock,
    storage,      // version = 13
    pool,
    receipt,      // valid receipt from before upgrade
    user_address,
    repay_balance
);
```

**Expected Result:** 
Operation should fail because Storage version doesn't match code version

**Actual Result:**
Operation succeeds because `repay()` doesn't check Storage version:
- Line 182: `logic::update_state_of_all(clock, storage)` executes v14 code
- Line 186: `storage::get_index(storage, asset_id)` reads v13 state
- Line 189: `logic::cumulate_to_supply_index(storage, asset_id, ...)` writes v14 calculations to v13 state

**Impact:** If v14 changed interest rate formulas or index calculations, Storage v13 now contains corrupted state from v14 logic assumptions.

**Notes**

The vulnerability is inherent in the protocol's upgrade design, not a single code bug. The atomicity issue exists because:

1. Sui Move package upgrades change code atomically but don't affect shared object state
2. The version system correctly identifies this by storing versions in each object
3. However, version checks are inconsistently applied - only at single-module boundaries
4. Cross-module operations bypass this protection by checking only one object's version

This is a **protocol-level design flaw** affecting upgrade safety, distinct from typical implementation bugs. Every upgrade creates exposure until all dependent objects are migrated, with no safe migration path provided.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L14-14)
```text
    public fun version(): u64 {13}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/version.move (L5-7)
```text
    public fun this_version(): u64 {
        constants::version()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L132-132)
```text
            version: version::this_version(),
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L242-246)
```text
    public entry fun set_pause(_: &OwnerCap, storage: &mut Storage, val: bool) {
        version_verification(storage);

        storage.paused = val;
        emit(Paused {paused: val})
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L184-186)
```text
        storage::when_not_paused(storage);
        storage::version_verification(storage);

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L141-142)
```text
    public(friend) fun loan<CoinType>(config: &Config, _pool: &mut Pool<CoinType>, _user: address, _loan_amount: u64): (Balance<CoinType>, Receipt<CoinType>) {
        version_verification(config);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L175-183)
```text
    public(friend) fun repay<CoinType>(clock: &Clock, storage: &mut Storage, _pool: &mut Pool<CoinType>, _receipt: Receipt<CoinType>, _user: address, _repay_balance: Balance<CoinType>): Balance<CoinType> {
        let Receipt {user, asset, amount, pool, fee_to_supplier, fee_to_treasury} = _receipt;
        assert!(user == _user, error::invalid_user());
        assert!(pool == object::uid_to_address(pool::uid(_pool)), error::invalid_pool());

        // handler logic
        {
            logic::update_state_of_all(clock, storage);
            let asset_id = get_storage_asset_id_from_coin_type(storage, type_name::into_string(type_name::get<CoinType>()));
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L189-190)
```text
            logic::cumulate_to_supply_index(storage, asset_id, scaled_fee_to_supplier);
            logic::update_interest_rate(storage, asset_id);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L310-311)
```text
    fun base_claim_reward<CoinType>(incentive: &mut Incentive, bal: &mut IncentiveBal<CoinType>, clock: &Clock, storage: &mut Storage, account: address): Balance<CoinType> {
        update_reward(incentive, clock, storage, bal.asset, account);
```
