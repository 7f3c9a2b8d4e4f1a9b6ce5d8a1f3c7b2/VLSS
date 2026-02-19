### Title
Partial Manage Migration Causes Permanent Protocol DoS Due to Independent Version Checks in Embedded ValidatorPool

### Summary
The `StakePool::migrate_version()` function only migrates the `StakePool`'s own `Manage` struct version, but does not migrate the embedded `ValidatorPool`'s independent `Manage` struct version. Since `ValidatorPool` functions perform independent version checks and there is no function to migrate `ValidatorPool`'s version, calling `migrate_version()` on `StakePool` alone permanently bricks the entire liquid staking protocol, preventing all stake, unstake, and rebalancing operations.

### Finding Description

**Root Cause:**

Both `StakePool` and `ValidatorPool` maintain separate instances of the `Manage` struct:
- [1](#0-0) 
- [2](#0-1) 

The `Manage` struct contains a version field that must match the `VERSION` constant for operations to proceed: [3](#0-2) [4](#0-3) 

The `StakePool::migrate_version()` function only updates its own `Manage` instance: [5](#0-4) 

**Why Protections Fail:**

1. There is **no function** to migrate `ValidatorPool`'s `Manage` version - searching the entire codebase shows zero instances of accessing `validator_pool.manage`.

2. `ValidatorPool` is embedded within `StakePool` and only provides immutable external access: [6](#0-5) 

3. Critical `ValidatorPool` functions perform independent version checks:
   - [7](#0-6) 
   - [8](#0-7) 

**Execution Path:**

1. Protocol upgrade changes `VERSION` constant from 1 to 2
2. Admin calls `StakePool::migrate_version()` - only migrates `StakePool.manage.version = 2`
3. `ValidatorPool.manage.version` remains at 1 (unmigrated)
4. User calls `stake()` → `refresh()` → `validator_pool.refresh()`
5. At line 180 of `validator_pool.move`, `check_version()` asserts `1 == 2` → **FAILS with EIncompatibleVersion**

Same failure occurs for:
- All unstake operations: [9](#0-8) 
- All rebalancing operations: [10](#0-9) 
- Validator weight updates: [11](#0-10) 

### Impact Explanation

**Operational Impact (CRITICAL):**
- **Complete DoS** of all staking operations - users cannot stake SUI for LST
- **Complete DoS** of all unstaking operations - users cannot redeem LST for SUI  
- **Complete DoS** of validator rebalancing - operators cannot adjust weights
- **Complete DoS** of epoch refresh - rewards cannot be distributed

**Custody Impact (HIGH):**
- All user funds already staked remain locked in validators indefinitely
- No recovery mechanism exists - the protocol is **permanently bricked**
- Requires complete contract redeployment and migration to fix

**Affected Parties:**
- All LST holders cannot unstake their funds
- New users cannot stake
- Protocol operators cannot perform any maintenance
- Protocol fee collection also fails: [12](#0-11) 

**Severity Justification:**
This is a CRITICAL severity issue causing complete and irreversible protocol failure with no workaround. Unlike a typical version mismatch that could be fixed by migration, this issue has **no recovery path** because there is no function to migrate the embedded `ValidatorPool`'s version.

### Likelihood Explanation

**Reachable Entry Point:**
Triggered during normal protocol upgrade procedures when admin calls the provided `migrate_version()` function.

**Feasible Preconditions:**
- Protocol upgrade that changes the `VERSION` constant (standard practice)
- Admin follows documented migration pattern by calling `StakePool::migrate_version()`
- No warning or documentation indicates `ValidatorPool` also needs migration

**Execution Practicality:**
- Admin action required, but through legitimate upgrade procedures
- Occurs **immediately** upon first user transaction after partial migration
- No way to detect or prevent before deployment

**Probability:** 
**VERY HIGH** - This will occur on ANY protocol version upgrade where:
1. The `VERSION` constant is incremented
2. Admin follows the existing `migrate_version()` pattern
3. No code changes are made to address this issue

This is not a hypothetical attack but an **inevitable operational failure** during standard upgrade procedures.

### Recommendation

**Immediate Fix:**
Add a function to migrate the embedded `ValidatorPool`'s `Manage` version. Modify `stake_pool.move`:

```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    // Also migrate the embedded ValidatorPool's Manage
    self.validator_pool.manage.migrate_version();
}
```

However, since `validator_pool` is a private field, the better approach is to add a package-visible function in `validator_pool.move`:

```move
public(package) fun migrate_manage_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

Then update `StakePool::migrate_version()`:

```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_manage_version();
}
```

**Invariant Check:**
Add a test that verifies both `StakePool` and `ValidatorPool` `Manage` versions are synchronized after migration.

**Deployment Note:**
For the current deployed version, if `migrate_version()` has already been called, the protocol is permanently bricked and requires redeployment with proper migration path.

### Proof of Concept

**Initial State:**
- Protocol deployed with `VERSION = 1`
- Both `StakePool.manage.version = 1` and `ValidatorPool.manage.version = 1`
- Users have staked funds, protocol is operational

**Exploit Steps:**

1. **Protocol Upgrade:**
   - Deploy new code with `VERSION = 2` in `manage.move`

2. **Admin Migration (following documented pattern):**
   ```
   StakePool::migrate_version(stake_pool, admin_cap)
   ```
   - Result: `StakePool.manage.version = 2`, `ValidatorPool.manage.version = 1` (unmigrated)

3. **Any User Operation:**
   ```
   StakePool::stake_entry(stake_pool, metadata, system_state, sui_coin, ctx)
   ```
   
   **Execution trace:**
   - Line 183: `self.manage.check_version()` → PASSES (StakePool version = 2)
   - Line 226: `self.manage.check_version()` → PASSES
   - Line 229: `self.refresh(metadata, system_state, ctx)`
   - Line 509: `self.manage.check_version()` → PASSES
   - Line 514: `self.validator_pool.refresh(system_state, ctx)` called
   - Line 180 in validator_pool.move: `self.manage.check_version()` → **ABORTS with EIncompatibleVersion (50001)**

**Expected Result:**
Stake operation completes successfully.

**Actual Result:**
Transaction aborts with error code 50001 (`EIncompatibleVersion`). All subsequent stake, unstake, rebalance, and fee collection operations permanently fail. Protocol is bricked with no recovery path.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L51-51)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/stake_pool.move (L287-289)
```text
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

**File:** liquid_staking/sources/stake_pool.move (L366-367)
```text
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L460-466)
```text
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);
        self.validator_pool.set_validator_weights(
            validator_weights,
            system_state,
            ctx
        );
```

**File:** liquid_staking/sources/stake_pool.move (L495-498)
```text
        self.manage.check_version();
        self.manage.check_not_paused();
        let is_epoch_rolled_over = self.refresh(metadata, system_state, ctx);
        self.validator_pool.rebalance(option::none(), system_state, ctx);
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
