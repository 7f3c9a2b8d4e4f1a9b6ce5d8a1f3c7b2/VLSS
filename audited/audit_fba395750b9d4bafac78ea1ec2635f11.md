# Audit Report

## Title
Non-Atomic Version Migration Leaves ValidatorPool Unmigrated, Causing Complete Protocol DoS

## Summary
The `migrate_version()` function only migrates StakePool's version while leaving the embedded ValidatorPool's version unmigrated. After migration, all core operations abort with `EIncompatibleVersion` when invoking ValidatorPool methods, permanently bricking the liquid staking protocol until a new package deployment.

## Finding Description

StakePool and ValidatorPool maintain independent version control through separate `Manage` structs stored as fields within each struct. [1](#0-0) [2](#0-1) 

When an admin calls `StakePool.migrate_version()`, it only updates the StakePool's Manage struct: [3](#0-2) 

This calls the Manage module's migrate_version which updates only that specific Manage instance to the current VERSION constant: [4](#0-3) [5](#0-4) 

The critical failure occurs because ValidatorPool operations enforce strict version compatibility checks. The `refresh()` function immediately calls version check: [6](#0-5) 

Similarly, `set_validator_weights()` enforces version compatibility: [7](#0-6) 

The version check enforces strict equality and aborts on mismatch: [8](#0-7) 

All critical StakePool operations invoke ValidatorPool methods that perform these checks. The `stake()` function calls refresh which triggers validator_pool.refresh(): [9](#0-8) [10](#0-9) 

The `unstake()` function follows the same path: [11](#0-10) 

The `set_validator_weights()` operator function directly calls validator_pool methods: [12](#0-11) 

**There is no mechanism to migrate ValidatorPool's version separately.** The ValidatorPool module contains no `migrate_version()` function. The only accessor for validator_pool returns an immutable reference: [13](#0-12) 

## Impact Explanation

After calling `migrate_version()` during a version upgrade (e.g., VERSION 2→3), the protocol enters a permanently broken state:
- StakePool.manage.version = 3 (migrated)
- ValidatorPool.manage.version = 2 (unmigrated)

All user operations immediately abort with `EIncompatibleVersion` error code 50001:
- **stake/unstake**: Abort when refresh() → validator_pool.refresh() → check_version() fails
- **rebalance**: Aborts through the same path  
- **collect_fees**: Cannot collect protocol fees due to refresh() requirement
- **set_validator_weights**: Aborts directly when calling validator_pool methods

This constitutes complete protocol DoS with all user funds locked. Users cannot unstake their SUI, new users cannot stake, and operators cannot perform maintenance. The protocol becomes entirely non-functional with no recovery mechanism except deploying a new package version with a fix.

This is CRITICAL severity because it causes permanent protocol failure during routine administrative operations.

## Likelihood Explanation

**Certainty: 100% on next version upgrade**

The `migrate_version()` function with AdminCap requirement is the standard mechanism for version upgrades. This is normal protocol maintenance, not an attack vector.

The execution path is straightforward:
1. Developers increment VERSION constant in manage.move (e.g., 2→3)
2. Deploy the package upgrade
3. Admin calls `migrate_version()` on existing StakePool objects
4. Protocol immediately enters broken state on first user operation

The VERSION constant is already set to 2, and the complete migrate_version() infrastructure exists, indicating version upgrades are expected protocol operations. This vulnerability will trigger with 100% certainty on the next version upgrade.

The issue manifests immediately and unavoidably on the first user or operator transaction after migration.

## Recommendation

Add a function to migrate the ValidatorPool's version. One approach:

```move
// In stake_pool.move
public fun migrate_validator_pool_version(self: &mut StakePool, _: &AdminCap) {
    self.validator_pool.migrate_version();
}

// In validator_pool.move  
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

Alternatively, modify the existing migrate_version to handle both:

```move
// In stake_pool.move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version(); // Add this line
}
```

The migration procedure should atomically update both Manage structs to ensure version consistency.

## Proof of Concept

```move
#[test]
fun test_version_migration_dos() {
    // 1. Setup: Create StakePool with VERSION=2
    // 2. Simulate upgrade: Change VERSION to 3
    // 3. Call migrate_version() on StakePool
    // 4. Attempt stake operation
    // 5. Assert: Transaction aborts with EIncompatibleVersion (50001)
    // 6. Verify: StakePool.manage.version=3, ValidatorPool.manage.version=2
    // 7. Confirm: All operations (stake, unstake, rebalance) fail
}
```

The test would demonstrate that after calling `migrate_version()` with VERSION incremented, the protocol becomes completely non-functional due to ValidatorPool's unmigrated version.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L43-53)
```text
    public struct StakePool has key, store {
        id: UID,
        fee_config: FeeConfig,
        fees: Balance<SUI>,
        boosted_balance: Balance<SUI>,
        boosted_reward_amount: u64,
        accrued_reward_fees: u64,
        validator_pool: ValidatorPool,
        manage: Manage,
        extra_fields: Bag
    }
```

**File:** liquid_staking/sources/stake_pool.move (L226-229)
```text
        self.manage.check_version();
        self.manage.check_not_paused();

        self.refresh(metadata,system_state, ctx);
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

**File:** liquid_staking/sources/stake_pool.move (L567-569)
```text
    public fun validator_pool(self: &StakePool): &ValidatorPool {
        &self.validator_pool
    }
```

**File:** liquid_staking/sources/validator_pool.move (L37-53)
```text
    public struct ValidatorPool has store {
        /// Sui Pool as a buffer for stake/unstake operations.
        sui_pool: Balance<SUI>,
        /// Validators holding stake in vSui.
        validator_infos: vector<ValidatorInfo>,
        /// Total Sui managed by vSui.
        /// total_sui_supply = sum(validator_infos.total_sui_amount) + sui_pool
        total_sui_supply: u64,
        /// The epoch at which the pool was last refreshed.
        last_refresh_epoch: u64,
        /// Total weight of all the validators
        total_weight: u64,
        /// Manage of the struct
        manage: Manage,
        /// Extra fields for future-proofing.
        extra_fields: Bag
    }
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
