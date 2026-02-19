# Audit Report

## Title
Dual Manage Instances Cause Protocol-Wide DoS After Version Upgrade

## Summary
The liquid staking protocol creates two separate `Manage` instances—one in `StakePool` and one in `ValidatorPool`—but only provides a migration function for the `StakePool` instance. After a version upgrade, the unmigrated `ValidatorPool` Manage instance will fail version checks, causing complete protocol DoS for all staking, unstaking, and rebalancing operations.

## Finding Description

The Volo liquid staking protocol uses a `Manage` struct to track version and paused state for protocol upgrades. [1](#0-0)  However, this struct is instantiated **twice** per `StakePool`:

1. `StakePool` creates its own `Manage` instance [2](#0-1)  which is initialized in the constructor [3](#0-2) 

2. `ValidatorPool` (nested within `StakePool`) creates a **separate** `Manage` instance [4](#0-3)  which is also initialized independently [5](#0-4) 

The `Manage` struct enforces version compatibility through a check function [6](#0-5)  that compares the instance's version against a hardcoded `VERSION` constant. [7](#0-6) 

**The Critical Flaw:**

Only the `StakePool`'s `Manage` instance has a migration path through the admin-controlled `migrate_version()` function. [8](#0-7) 

However, `ValidatorPool` still performs version checks on its **own unmigrated** `Manage` instance in critical functions like `refresh()` [9](#0-8)  and `set_validator_weights()`. [10](#0-9) 

**There is no function to migrate `ValidatorPool`'s Manage instance**—the field is private to the module and no migration function exists.

**Execution Path to DoS:**

When the `VERSION` constant is upgraded (e.g., from 2 to 3):
1. Admin calls `migrate_version()` to update `StakePool`'s Manage from v2 to v3
2. `StakePool`'s Manage is now at v3, but `ValidatorPool`'s Manage remains at v2
3. User calls `stake_entry()` [11](#0-10)  which calls `stake()` [12](#0-11)  which calls `refresh()` [13](#0-12) 
4. `refresh()` calls `validator_pool.refresh()` which checks `self.manage.check_version()` (ValidatorPool's Manage)
5. This check fails with `EIncompatibleVersion` [14](#0-13)  because ValidatorPool's Manage is still v2 while VERSION constant is v3

The migration module only handles v1-to-v2 protocol migration [15](#0-14)  and does not provide any mechanism to update ValidatorPool's internal Manage instance.

## Impact Explanation

**Complete Protocol Denial of Service:**

All core protocol operations fail after version upgrade:
- `stake_entry()` / `stake()` - users cannot stake SUI
- `unstake_entry()` / `unstake()` - users cannot unstake or withdraw funds [16](#0-15) 
- `rebalance()` - operators cannot maintain validator distribution [17](#0-16) 
- `set_validator_weights()` - operators cannot update validator allocation [18](#0-17) 
- `collect_fees()` - admins cannot collect protocol fees [19](#0-18) 

**Who is Affected:**
- All users with staked SUI (funds locked, cannot unstake)
- All potential stakers (cannot enter protocol)
- Protocol operators (cannot maintain system health)
- The protocol's entire liquid staking functionality becomes unusable

While user funds are not at direct risk of theft, they become **locked** until an emergency contract upgrade fixes the dual-Manage architecture. This represents a high-severity availability issue that affects 100% of protocol operations and all users.

## Likelihood Explanation

**Certainty: 100% on next version upgrade**

This is not an attack vector—it's a **guaranteed architectural failure** that occurs during routine protocol maintenance:

1. **Trigger**: Admin performs legitimate version upgrade by calling `migrate_version()` after updating the `VERSION` constant in code
2. **Preconditions**: None beyond the version constant change, which is a normal part of protocol evolution
3. **Complexity**: Zero—no attacker actions required, happens automatically
4. **Detection**: Immediately obvious as all user operations begin failing
5. **Probability**: 100% certain on the next version upgrade attempt

The dual `Manage` instances are created at protocol initialization and cannot be reconciled through any existing function. There is no attack path to exploit—this is a design flaw that manifests during normal protocol upgrades.

## Recommendation

**Immediate Fix:**

Add a migration function to update ValidatorPool's Manage instance:

```move
// In stake_pool.move
public fun migrate_validator_pool_version(self: &mut StakePool, _: &AdminCap) {
    self.validator_pool.migrate_manage_version();
}

// In validator_pool.move
public(package) fun migrate_manage_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

**Long-term Solution:**

Consider consolidating to a single `Manage` instance at the `StakePool` level and removing the redundant instance from `ValidatorPool`. Pass the `Manage` reference to ValidatorPool functions when needed instead of storing a duplicate.

**Migration Process:**

For the next upgrade, ensure both `migrate_version()` and `migrate_validator_pool_version()` are called in sequence before unpausing the protocol.

## Proof of Concept

The vulnerability manifests through normal version upgrade flow:

```move
// Test scenario (conceptual - would require full test setup):
// 1. Initial state: VERSION = 2, both Manage instances at v2
// 2. Deploy new contract with VERSION = 3
// 3. Admin calls stake_pool.migrate_version() - only updates StakePool's Manage to v3
// 4. User calls stake_entry() with valid SUI
// 5. Transaction aborts with EIncompatibleVersion (50001) at validator_pool.refresh()
//    because ValidatorPool.manage.version = 2 while VERSION = 3

#[test]
#[expected_failure(abort_code = 50001)] // EIncompatibleVersion
fun test_dos_after_version_upgrade() {
    // Setup: create StakePool with VERSION = 2, both Manages at v2
    // Action: update VERSION to 3 in code, call migrate_version()
    // Result: stake_pool.manage.version = 3, validator_pool.manage.version = 2
    // User stake attempt: fails with EIncompatibleVersion
}
```

The proof is in the code structure itself: there exists no code path to update ValidatorPool's Manage version, making the DoS inevitable upon version upgrade.

### Citations

**File:** liquid_staking/sources/manage.move (L3-3)
```text
    const EIncompatibleVersion: u64 = 50001;
```

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

**File:** liquid_staking/sources/stake_pool.move (L51-51)
```text
        manage: Manage,
```

**File:** liquid_staking/sources/stake_pool.move (L168-168)
```text
                manage: manage::new(),
```

**File:** liquid_staking/sources/stake_pool.move (L176-186)
```text
    public entry fun stake_entry(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let cert = self.stake(metadata, system_state, sui, ctx);
        transfer::public_transfer(cert, ctx.sender());
    }
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

**File:** liquid_staking/sources/stake_pool.move (L268-289)
```text
    public entry fun unstake_entry(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        cert: Coin<CERT>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let sui = self.unstake(metadata, system_state, cert, ctx);
        transfer::public_transfer(sui, ctx.sender());
    }

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

**File:** liquid_staking/sources/stake_pool.move (L503-514)
```text
    public fun refresh(
        self: &mut StakePool, 
        metadata: &Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        ctx: &mut TxContext
    ): bool {
        self.manage.check_version();
        self.manage.check_not_paused();

        let old_total_supply = self.total_sui_supply();

        if (self.validator_pool.refresh(system_state, ctx)) { // epoch rolled over
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

**File:** liquid_staking/sources/validator_pool.move (L338-338)
```text
        self.manage.check_version();
```

**File:** liquid_staking/sources/migration/migrate.move (L1-11)
```text
/// Module: Migration
/// migrate from volo v1 to volo v2
/// migration will be only executed once
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
/// 6. unpause the pool (after migration)
module liquid_staking::migration {
```
