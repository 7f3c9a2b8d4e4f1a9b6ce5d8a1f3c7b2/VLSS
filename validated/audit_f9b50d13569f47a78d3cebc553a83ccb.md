# Audit Report

## Title
Incomplete Version Migration Causes Permanent Pool Lock After Package Upgrade

## Summary
The VERSION migration mechanism is fundamentally broken due to incomplete migration logic. When upgrading the VERSION constant, the `migrate_version()` function only updates the StakePool's version but fails to migrate the ValidatorPool's version, causing permanent operational DoS where all user operations (stake/unstake) fail, locking 100% of user funds with no recovery path.

## Finding Description

The version control system uses a global VERSION constant that enforces strict compatibility through exact equality checks. [1](#0-0) [2](#0-1) 

Both StakePool and ValidatorPool maintain **independent** `manage: Manage` fields with separate version tracking: [3](#0-2) [4](#0-3) 

**Root Cause:** The migration function only updates StakePool's version, leaving ValidatorPool's version unchanged: [5](#0-4) 

All critical operations perform multi-layer version checks. The `stake()` function checks the StakePool version, then calls `refresh()` which delegates to `validator_pool.refresh()`: [6](#0-5) [7](#0-6) 

The `validator_pool.refresh()` function has its own version check that fails when the ValidatorPool version is outdated: [8](#0-7) 

**Why Protection Fails:** There is no public or package-level function in ValidatorPool to migrate its version. The ValidatorPool.manage field is not exposed through any accessor or migration function. The only public accessor returns an immutable reference: [9](#0-8) 

All critical operations that call `refresh()` will fail:
- **stake()**: [10](#0-9) 
- **unstake()**: [11](#0-10) 
- **collect_fees()**: [12](#0-11) 
- **set_validator_weights()**: [13](#0-12) [14](#0-13) 
- **rebalance()**: [15](#0-14) 

## Impact Explanation

**Severity: CRITICAL - Complete Operational DoS**

When VERSION changes (e.g., 2→3):

**Before migration:** All operations fail at StakePool's version check.

**After calling `migrate_version()`:** Pool remains broken because ValidatorPool's version is still at the old value. All operations that call `refresh()` fail at `validator_pool.refresh()`'s version check with `EIncompatibleVersion` error.

**Impact Quantification:**
- **100% of user funds locked**: Users cannot unstake their LST tokens to retrieve underlying SUI
- **100% operational downtime**: No new stakes can be processed
- **Admin operations blocked**: Cannot collect fees or rebalance validators
- **No recovery path**: Even with AdminCap access, there is no function to fix ValidatorPool's version
- **Permanent loss of protocol functionality**: Requires emergency package upgrade to fix

This breaks the fundamental security guarantee that after proper migration, the protocol should remain operational. All core protocol functionality is permanently disabled.

## Likelihood Explanation

**Likelihood: CERTAIN (100%)**

This is not a potential vulnerability - it is a **guaranteed outcome** of any VERSION upgrade:

1. **Automatically Triggered**: Occurs during normal package upgrade operations when VERSION constant changes
2. **No Attacker Required**: This is a design flaw in the migration mechanism, not an attack scenario
3. **Deterministic Failure**: The version check enforces strict equality [2](#0-1)  - when ValidatorPool.version=2 and VERSION=3, the assertion `assert!(2 == 3)` always fails with mathematical certainty
4. **Universal Impact**: Affects all existing pools immediately upon upgrade
5. **No Bypass Possible**: The strict equality check cannot be circumvented

Even with AdminCap access, there is no way to fix ValidatorPool's version since no migration function exists for it. The migration mechanism is fundamentally incomplete.

## Recommendation

Add a migration function to update ValidatorPool's version. The fix requires two changes:

**1. Add a package-level function in validator_pool.move:**
```move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

**2. Update the migrate_version function in stake_pool.move to migrate both components:**
```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version(); // Add this line
}
```

This ensures both StakePool and ValidatorPool versions are synchronized during migration, preventing the operational DoS.

## Proof of Concept

The vulnerability can be demonstrated by analyzing the execution flow when VERSION changes:

**Test Scenario:**
```
Given:
- Initial state: VERSION = 2, StakePool.manage.version = 2, ValidatorPool.manage.version = 2
- All operations work correctly

When:
- Package upgraded with VERSION = 3
- Admin calls migrate_version() -> only updates StakePool.manage.version to 3
- ValidatorPool.manage.version remains at 2

Then:
- User calls stake():
  1. Line 226: self.manage.check_version() passes (StakePool version = 3 = VERSION) ✓
  2. Line 229: self.refresh() is called
  3. Line 509: self.manage.check_version() passes (StakePool version = 3 = VERSION) ✓
  4. Line 514: self.validator_pool.refresh() is called
  5. Line 180 in validator_pool.move: self.manage.check_version() FAILS
     - ValidatorPool.manage.version = 2
     - VERSION = 3
     - assert!(2 == 3, EIncompatibleVersion) ✗
  6. Transaction aborts with EIncompatibleVersion

Result: All operations permanently fail. Protocol is completely unusable.
```

The mathematical certainty of `assert!(2 == 3)` failing makes this a deterministic vulnerability with 100% reproduction rate on every VERSION upgrade.

### Citations

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

**File:** liquid_staking/sources/stake_pool.move (L51-51)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/stake_pool.move (L219-229)
```text
    public fun stake(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ): Coin<CERT> {
        self.manage.check_version();
        self.manage.check_not_paused();

        self.refresh(metadata,system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L280-289)
```text
    public fun unstake(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        lst: Coin<CERT>,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.manage.check_not_paused();
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L342-344)
```text
    public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
        self.manage.migrate_version();
    }
```

**File:** liquid_staking/sources/stake_pool.move (L359-367)
```text
    public fun collect_fees(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        _: &AdminCap,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L452-461)
```text
    public fun set_validator_weights(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        _: &OperatorCap,
        validator_weights: VecMap<address, u64>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L489-497)
```text
    public fun rebalance(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        self.manage.check_not_paused();
        let is_epoch_rolled_over = self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L509-514)
```text
        self.manage.check_version();
        self.manage.check_not_paused();

        let old_total_supply = self.total_sui_supply();

        if (self.validator_pool.refresh(system_state, ctx)) { // epoch rolled over
```

**File:** liquid_staking/sources/stake_pool.move (L567-569)
```text
    public fun validator_pool(self: &StakePool): &ValidatorPool {
        &self.validator_pool
    }
```

**File:** liquid_staking/sources/validator_pool.move (L50-50)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/validator_pool.move (L175-180)
```text
    public(package) fun refresh(
        self: &mut ValidatorPool, 
        system_state: &mut SuiSystemState, 
        ctx: &mut TxContext
    ): bool {
        self.manage.check_version();
```

**File:** liquid_staking/sources/validator_pool.move (L332-338)
```text
    public (package) fun set_validator_weights(
        self: &mut ValidatorPool,
        validator_weights: VecMap<address, u64>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
```
