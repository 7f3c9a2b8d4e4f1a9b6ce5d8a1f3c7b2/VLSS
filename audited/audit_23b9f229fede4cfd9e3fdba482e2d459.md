### Title
Partial Migration DoS: ValidatorPool Version Cannot Be Migrated Leading to Complete Protocol Freeze

### Summary
The `migrate_version()` function only migrates the `StakePool`'s version but cannot migrate the embedded `ValidatorPool`'s version, as no such function exists. This creates a version mismatch that causes all critical operations (stake, unstake, rebalance) to fail with `EIncompatibleVersion`, resulting in complete protocol-wide DoS until a package upgrade adds the missing migration capability.

### Finding Description

Both `StakePool` and `ValidatorPool` maintain independent `Manage` instances with version fields: [1](#0-0) [2](#0-1) 

The `Manage` module enforces version compatibility through `check_version()`: [3](#0-2) 

Only `StakePool` has a migration function that updates its own `Manage` version: [4](#0-3) 

This function only migrates `StakePool.manage` but does NOT migrate the embedded `ValidatorPool.manage`. There is no function anywhere in the codebase to migrate `ValidatorPool`'s version.

**Critical dependency chain**: All core StakePool operations call `ValidatorPool` functions that perform version checks: [5](#0-4) [6](#0-5) 

When users call operations like `stake_entry()`, the execution path is:
1. `stake_entry()` → `stake()` → `refresh()` (StakePool version checks pass)
2. `refresh()` → `validator_pool.refresh()` (ValidatorPool version check FAILS) [7](#0-6) [8](#0-7) 

The only accessor function returns an immutable reference, preventing external migration: [9](#0-8) 

### Impact Explanation

**Complete Protocol Denial of Service:**

If `migrate_version()` is called on `StakePool` while `ValidatorPool` remains at an older version, ALL critical operations become permanently unusable:

- **stake/delegate_stake**: Fails when calling `validator_pool.refresh()`
- **unstake**: Fails when calling `validator_pool.refresh()` 
- **rebalance**: Fails when calling `validator_pool.refresh()`
- **collect_fees**: Fails when calling `validator_pool.refresh()`
- **set_validator_weights**: Fails when calling `validator_pool.set_validator_weights()`

This affects:
- **All users**: Cannot stake or unstake, funds are locked in the protocol
- **Protocol operators**: Cannot rebalance, collect fees, or manage validator weights
- **Protocol health**: Staking rewards cannot be distributed, validator weights frozen

The protocol remains frozen until a package upgrade adds a `ValidatorPool` migration function. During this period, the liquid staking protocol is completely non-functional, though existing LST holders still technically own their proportional share of staked SUI.

### Likelihood Explanation

**HIGH Likelihood** - This vulnerability is highly likely to manifest:

**Reachable Entry Point**: Any user can trigger the DoS by calling public entry functions: [10](#0-9) 

**Feasible Preconditions**: 
1. Admin calls `stake_pool::migrate_version()` during a version upgrade (standard admin operation)
2. No function exists to migrate `ValidatorPool` - the admin literally cannot prevent this
3. The version mismatch persists indefinitely

**Execution Practicality**: 
- Requires only a standard user transaction (stake/unstake)
- No special permissions needed
- Guaranteed to trigger on every operation that touches `ValidatorPool`

**Design Flaw**: The architecture inherently creates this vulnerability:
- Both objects initialize with the same version at creation
- Future version bumps require migrating both objects
- Only one can be migrated, the other has no migration path

**No Recovery Path**: Without a package upgrade, there is no way to:
- Access `ValidatorPool.manage` mutably from external code
- Bypass the version check in `ValidatorPool` functions  
- Restore protocol functionality

### Recommendation

**Immediate Fix**: Add a migration function for `ValidatorPool` in `stake_pool.move`:

```move
public fun migrate_validator_pool_version(self: &mut StakePool, _: &AdminCap) {
    self.validator_pool.manage.migrate_version();
}
```

This requires adding a `public(package)` accessor in `validator_pool.move`:

```move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

**Alternative Fix**: Modify the single `migrate_version()` function to migrate both:

```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version(); // Add this line
}
```

**Best Practice**: Implement a unified version management system where a single version field governs both `StakePool` and `ValidatorPool`, eliminating the possibility of version mismatches.

**Testing**: Add regression tests that:
1. Verify both versions are migrated together
2. Confirm all operations work after migration
3. Test that attempting partial migration is prevented or handled correctly

### Proof of Concept

**Initial State:**
- `manage.VERSION = 2` (current constant value)
- Protocol deployed: `StakePool.manage.version = 2`, `ValidatorPool.manage.version = 2`

**Scenario 1: Future Version Upgrade**
1. Developers bump `manage.VERSION` to `3` in a package upgrade
2. Admin calls `stake_pool::migrate_version(stake_pool, admin_cap)`
3. Result: `StakePool.manage.version = 3`, `ValidatorPool.manage.version = 2` (unchanged)

**Scenario 2: User Transaction Fails**
1. User calls `stake_entry(stake_pool, metadata, system_state, sui_coin)`
2. Execution path:
   - Line 183: `self.manage.check_version()` → checks `2 == 3`? **WAIT** - StakePool is now 3, so this passes
   - Line 226: `self.manage.check_version()` → passes (StakePool is 3)
   - Line 229: calls `self.refresh()`
   - Line 509: `self.manage.check_version()` → passes (StakePool is 3)
   - Line 514: calls `self.validator_pool.refresh()`
   - validator_pool.move Line 180: `self.manage.check_version()` → checks `2 == 3`? **FAILS**
3. Transaction aborts with error code `EIncompatibleVersion` (50001)

**Expected Result**: User successfully stakes SUI and receives LST tokens

**Actual Result**: Transaction reverts with `EIncompatibleVersion`, user cannot stake

**Success Condition**: Protocol is frozen - all stake, unstake, rebalance, and validator management operations fail until `ValidatorPool` version is somehow migrated (which is impossible without adding the missing function).

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

**File:** liquid_staking/sources/stake_pool.move (L342-344)
```text
    public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
        self.manage.migrate_version();
    }
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

**File:** liquid_staking/sources/manage.move (L21-23)
```text
    public fun check_version(self: &Manage) {
        assert!(self.version == VERSION, EIncompatibleVersion)
    }
```
