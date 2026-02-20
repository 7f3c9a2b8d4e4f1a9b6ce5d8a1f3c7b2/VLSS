# Audit Report

## Title
ValidatorPool Version Desynchronization Causes Complete Protocol DoS During Version Upgrades

## Summary
The liquid staking protocol maintains two independent version control mechanisms in `StakePool` and `ValidatorPool`, but the admin's `migrate_version()` function only updates `StakePool`'s version. When the protocol's VERSION constant is upgraded, `ValidatorPool` remains at the old version, causing all critical operations to abort with `EIncompatibleVersion` and permanently locking the protocol.

## Finding Description

The protocol uses a `Manage` struct for version control [1](#0-0) , with VERSION currently set to 2 [2](#0-1) .

Both `StakePool` and `ValidatorPool` maintain **separate, independent** `Manage` instances:
- `StakePool` has its own `manage` field [3](#0-2) 
- `ValidatorPool` has its own `manage` field [4](#0-3) 

These are initialized separately during construction:
- `StakePool` initialization [5](#0-4) 
- `ValidatorPool` initialization [6](#0-5) 

**The Critical Flaw:**

When an admin performs version migration [7](#0-6) , it only updates `StakePool`'s version via the `manage::migrate_version()` function [8](#0-7) . The `ValidatorPool`'s version is **never updated**.

All critical operations call `StakePool::refresh()`, which internally invokes `ValidatorPool::refresh()` [9](#0-8) . The `ValidatorPool::refresh()` function immediately checks version compatibility [10](#0-9)  using strict equality enforcement [11](#0-10) .

**Execution Path When VERSION is Upgraded:**
1. Developers update: `const VERSION: u64 = 3;`
2. Admin calls `migrate_version()` → `StakePool.manage.version = 3` ✓, but `ValidatorPool.manage.version = 2` ✗
3. Any user attempts to stake, unstake, or rebalance
4. Function calls `refresh()` → `validator_pool.refresh()`
5. Version check fails: `assert!(2 == 3)` → Transaction aborts with `EIncompatibleVersion`

**All Operations Blocked:**
- `stake()` calls refresh [12](#0-11) 
- `unstake()` calls refresh [13](#0-12) 
- `rebalance()` calls refresh [14](#0-13) 
- `set_validator_weights()` calls refresh [15](#0-14) 

Additionally, `refresh()` is responsible for converting inactive stakes to active stakes [16](#0-15) . Without functioning `refresh()`, all pending stakes become permanently locked.

**No Recovery Mechanism:**

The `validator_pool` field has only an immutable getter [17](#0-16) . There is no function in `ValidatorPool` to update its `manage.version` after desynchronization occurs (verified via grep search showing `migrate_version` only exists in `manage.move` and `stake_pool.move`, not in `validator_pool.move`).

## Impact Explanation

**Complete Protocol DoS:** All user-facing operations (stake, unstake) and operator functions (rebalance, set_validator_weights) become permanently unusable after VERSION upgrade because `ValidatorPool::refresh()` enforces strict version equality and aborts all transactions.

**Pending Stake Lock:** Inactive stakes awaiting epoch activation cannot be converted to active stakes because the conversion logic in `refresh()` is blocked. In Sui's staking model, stakes activate in the next epoch, so pending stakes will naturally exist during normal operations.

**No Immediate Recovery:** The current codebase provides no mechanism to update `ValidatorPool.manage.version`. A new package upgrade would be required to add a migration function for `ValidatorPool`, but the protocol remains broken until that fix is deployed.

**Severity: CRITICAL** - Complete protocol failure affecting all users with no immediate recovery path.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** because it represents incomplete migration infrastructure that will deterministically trigger during the next protocol version upgrade:

**Triggering Scenario:**
1. Protocol operates with `VERSION = 2`
2. Developers need to upgrade `VERSION = 3` for any protocol enhancement or security patch
3. Admin follows standard procedure and calls `migrate_version()`
4. Protocol immediately breaks - all operations abort with `EIncompatibleVersion`

**No Attacker Required:** This is a design flaw in the migration logic. Normal protocol maintenance (version upgrades) guarantees this failure unless developers proactively add `ValidatorPool` migration logic before bumping `VERSION`.

**Realism:** Version upgrades are essential for protocol evolution and security patches. The incomplete migration function in the current codebase makes this failure path inevitable on the next version upgrade.

## Recommendation

Add a migration function for `ValidatorPool` to ensure both version fields are synchronized:

**In `validator_pool.move`, add:**
```move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

**In `stake_pool.move`, update the existing `migrate_version` function:**
```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version(); // Add this line
}
```

This ensures both `StakePool` and `ValidatorPool` version fields are updated atomically during migration.

## Proof of Concept

A test demonstrating this vulnerability would require:
1. Setting up a `StakePool` with `ValidatorPool` at VERSION=2
2. Simulating a VERSION upgrade to 3 in the code
3. Calling `migrate_version()` to update only `StakePool`
4. Attempting any operation (stake/unstake/rebalance)
5. Observing the transaction abort with `EIncompatibleVersion` when `ValidatorPool::refresh()` executes

The vulnerability path is deterministic and verified through code analysis showing the incomplete migration logic and separate version control mechanisms.

### Citations

**File:** liquid_staking/sources/manage.move (L6-9)
```text
    public struct Manage has store {
        version: u64,
        paused: bool,
    }
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

**File:** liquid_staking/sources/stake_pool.move (L51-51)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/stake_pool.move (L168-168)
```text
                manage: manage::new(),
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

**File:** liquid_staking/sources/stake_pool.move (L461-461)
```text
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L497-497)
```text
        let is_epoch_rolled_over = self.refresh(metadata, system_state, ctx);
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

**File:** liquid_staking/sources/validator_pool.move (L50-50)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/validator_pool.move (L75-75)
```text
            manage: manage::new(),
```

**File:** liquid_staking/sources/validator_pool.move (L180-180)
```text
        self.manage.check_version();
```

**File:** liquid_staking/sources/validator_pool.move (L240-246)
```text
            if (self.validator_infos[i].inactive_stake.is_some() 
                && self.validator_infos[i].inactive_stake.borrow().stake_activation_epoch() <= ctx.epoch()
            ) {
                let inactive_stake = self.take_all_inactive_stake(i);
                let fungible_staked_sui = system_state.convert_to_fungible_staked_sui(inactive_stake, ctx);
                self.join_fungible_staked_sui_to_validator(i, fungible_staked_sui);
            };
```
