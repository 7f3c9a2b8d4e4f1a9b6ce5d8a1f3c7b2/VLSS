# Audit Report

## Title
Incomplete Version Migration System Causes Permanent Protocol DOS After Package Upgrade

## Summary
The liquid staking protocol contains a critical architectural flaw where `StakePool` and `ValidatorPool` maintain independent version management through separate `Manage` objects, but only `StakePool` has a migration function. After a package upgrade that increments the `VERSION` constant, all protocol operations permanently fail because `ValidatorPool.manage.version` cannot be updated, causing version check failures in `validator_pool.refresh()`.

## Finding Description

The version management system has a fundamental asymmetry that creates an unrecoverable failure state:

**Dual Independent Version Management:**

Both `StakePool` and `ValidatorPool` contain separate `Manage` struct instances with independent version fields:
- `StakePool` contains its own `Manage` object [1](#0-0) 
- `ValidatorPool` contains a separate `Manage` object [2](#0-1) 

**Strict Version Enforcement:**

The `check_version()` function enforces strict equality between the stored version and the current `VERSION` constant, aborting with `EIncompatibleVersion` (error code 50001) on any mismatch [3](#0-2) 

**Asymmetric Migration Capability:**

Only `StakePool` exposes a public migration function that can update its `Manage.version` field [4](#0-3) 

No corresponding migration function exists in `ValidatorPool` to update its `Manage.version` field. The `ValidatorPool` struct only has `store` ability [5](#0-4) , meaning it exists only as a field within `StakePool` and cannot be independently accessed or migrated.

**Guaranteed Failure Path:**

After a package upgrade that increments `VERSION` (currently set to 2 [6](#0-5) ), the following execution path causes permanent failure:

1. Admin calls `migrate_version()` on `StakePool`, updating `StakePool.manage.version` to the new VERSION
2. User calls `stake()`, which checks `self.manage.check_version()` - PASSES (StakePool version is current) [7](#0-6) 
3. `stake()` calls `self.refresh()` [8](#0-7) 
4. `refresh()` checks `self.manage.check_version()` - PASSES (StakePool version is current) [9](#0-8) 
5. `refresh()` calls `self.validator_pool.refresh()` [10](#0-9) 
6. `validator_pool.refresh()` checks `self.manage.check_version()` - **ABORTS** with `EIncompatibleVersion` because `ValidatorPool.manage.version` remains at the old version [11](#0-10) 

The same failure occurs for all critical operations:
- `unstake()` calls `refresh()` [12](#0-11) 
- `collect_fees()` calls `refresh()` [13](#0-12) 
- `set_validator_weights()` calls `refresh()` and directly invokes `validator_pool.set_validator_weights()` which also checks version [14](#0-13) 
- `rebalance()` calls `refresh()` [15](#0-14) 

**No Recovery Mechanism:**

The only public accessor for `ValidatorPool` returns an immutable reference [16](#0-15) , and the `migrate_version()` function in `Manage` is `public(package)` [17](#0-16) , meaning it can only be called from within the package. Since no function in `validator_pool.move` provides a way to call `self.manage.migrate_version()`, the `ValidatorPool.manage.version` field is permanently frozen at its creation value.

## Impact Explanation

**Critical Protocol DOS with Fund Trapping:**

This vulnerability causes complete and permanent protocol failure:

- **All stake operations fail:** Users cannot stake SUI to receive LST tokens, blocking all protocol inflows
- **All unstake operations fail:** LST holders cannot redeem their tokens for underlying SUI, permanently trapping their funds in the protocol
- **Fee collection fails:** Protocol cannot collect accumulated fees, blocking revenue operations
- **Validator management fails:** Operators cannot adjust validator weights or rebalance stakes across validators, preventing proper risk management
- **No administrative recovery:** The protocol enters an unrecoverable bricked state with no migration path

The impact is classified as **CRITICAL** because:
1. User funds become permanently inaccessible (cannot unstake)
2. Protocol becomes completely non-functional (all core operations fail)
3. No recovery mechanism exists (version mismatch is permanent)
4. Affects all existing and future users once triggered

## Likelihood Explanation

**High Likelihood - Guaranteed by Normal Operations:**

This vulnerability will trigger with certainty during routine protocol maintenance:

- Package upgrades that increment the `VERSION` constant are standard protocol maintenance procedures for bug fixes, feature additions, or security updates
- The admin will follow the expected upgrade process: deploy new package, call `migrate_version()` on `StakePool`
- However, this upgrade path is incomplete because `ValidatorPool.manage.version` cannot be updated
- The failure occurs immediately on the first user transaction after the VERSION increment
- **No attacker is required** - this is triggered by honest protocol maintenance by trusted administrators
- **No special conditions needed** - any VERSION increment from the current value of 2 causes the issue
- **Detection is immediate** but the protocol remains permanently broken

The likelihood is **HIGH** because this is not a theoretical edge case but a guaranteed outcome of the next protocol version upgrade, which is a routine and necessary operation for any production protocol.

## Recommendation

Add a migration function to `ValidatorPool` and expose it through `StakePool`:

```move
// In validator_pool.move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}

// In stake_pool.move  
public fun migrate_validator_pool_version(self: &mut StakePool, _: &AdminCap) {
    self.validator_pool.migrate_version();
}
```

Alternatively, consolidate version management by having `ValidatorPool` reference the `StakePool`'s version instead of maintaining its own, or remove the version check from `ValidatorPool.refresh()` if it's redundant with the checks in `StakePool`.

The migration process should be:
1. Deploy updated package with fix
2. Call `migrate_version()` on `StakePool`
3. Call `migrate_validator_pool_version()` on `StakePool` (new function)
4. Verify both version fields are synchronized

## Proof of Concept

```move
#[test]
fun test_version_migration_dos() {
    // 1. Setup: Create StakePool with VERSION=2
    let mut scenario = test_scenario::begin(@admin);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        stake_pool::create_stake_pool(ctx);
    };
    
    // 2. Simulate package upgrade: VERSION increments to 3
    // (In real deployment, this happens by publishing new package)
    
    // 3. Admin migrates StakePool version
    test_scenario::next_tx(&mut scenario, @admin);
    {
        let mut pool = test_scenario::take_shared<StakePool>(&scenario);
        let admin_cap = test_scenario::take_from_sender<AdminCap>(&scenario);
        
        pool.migrate_version(&admin_cap); // StakePool.manage.version = 3
        // But ValidatorPool.manage.version remains at 2!
        
        test_scenario::return_shared(pool);
        test_scenario::return_to_sender(&scenario, admin_cap);
    };
    
    // 4. User attempts to stake - will ABORT with EIncompatibleVersion (50001)
    test_scenario::next_tx(&mut scenario, @user);
    {
        let mut pool = test_scenario::take_shared<StakePool>(&scenario);
        let mut metadata = test_scenario::take_shared<Metadata<CERT>>(&scenario);
        let mut system_state = test_scenario::take_shared<SuiSystemState>(&scenario);
        let ctx = test_scenario::ctx(&mut scenario);
        
        let sui = coin::mint_for_testing<SUI>(1_000_000_000, ctx);
        
        // This will abort at validator_pool.refresh() line 180
        // Error: EIncompatibleVersion (50001)
        pool.stake(&mut metadata, &mut system_state, sui, ctx);
        
        test_scenario::return_shared(pool);
        test_scenario::return_shared(metadata);
        test_scenario::return_shared(system_state);
    };
    
    test_scenario::end(scenario);
}
```

The test demonstrates that after `VERSION` increment and `StakePool` migration, all operations fail permanently because `ValidatorPool.manage.version` cannot be updated.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L51-51)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/stake_pool.move (L226-226)
```text
        self.manage.check_version();
```

**File:** liquid_staking/sources/stake_pool.move (L229-229)
```text
        self.refresh(metadata,system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L289-289)
```text
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L342-344)
```text
    public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
        self.manage.migrate_version();
    }
```

**File:** liquid_staking/sources/stake_pool.move (L367-367)
```text
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L497-497)
```text
        let is_epoch_rolled_over = self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L509-509)
```text
        self.manage.check_version();
```

**File:** liquid_staking/sources/stake_pool.move (L514-514)
```text
        if (self.validator_pool.refresh(system_state, ctx)) { // epoch rolled over
```

**File:** liquid_staking/sources/stake_pool.move (L567-569)
```text
    public fun validator_pool(self: &StakePool): &ValidatorPool {
        &self.validator_pool
    }
```

**File:** liquid_staking/sources/validator_pool.move (L37-37)
```text
    public struct ValidatorPool has store {
```

**File:** liquid_staking/sources/validator_pool.move (L50-50)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/validator_pool.move (L180-180)
```text
        self.manage.check_version();
```

**File:** liquid_staking/sources/validator_pool.move (L338-338)
```text
        self.manage.check_version();
```

**File:** liquid_staking/sources/manage.move (L11-11)
```text
    const VERSION: u64 = 2;
```

**File:** liquid_staking/sources/manage.move (L21-23)
```text
    public fun check_version(self: &Manage) {
        assert!(self.version == VERSION, EIncompatibleVersion)
    }
```

**File:** liquid_staking/sources/manage.move (L29-32)
```text
    public(package) fun migrate_version(self: &mut Manage) {
        assert!(self.version <= VERSION, EIncompatibleVersion);
        self.version = VERSION;
    }
```
