### Title
Incomplete Version Migration Causes Protocol-Wide DoS After Package Upgrade

### Summary
The `migrate_version()` function only updates the StakePool's version but fails to migrate the nested ValidatorPool's version, causing all staking operations to revert with version mismatch errors after any package upgrade. This results in a complete denial of service for the liquid staking protocol until a new package version with a fix is deployed.

### Finding Description

The `migrate_version()` function in StakePool only migrates the StakePool's own Manage instance but does not migrate the nested ValidatorPool's Manage instance. [1](#0-0) [2](#0-1) 

Both StakePool and ValidatorPool contain separate Manage instances with version tracking: [3](#0-2) [4](#0-3) 

When a package upgrade increments the VERSION constant, the admin calls `migrate_version()` which only updates StakePool's version. However, ValidatorPool's critical functions check their own Manage version: [5](#0-4) [6](#0-5) 

The version check compares against the global VERSION constant: [7](#0-6) 

After migration, when users call `stake()` or `unstake()`, the execution path is:
1. StakePool.refresh() checks StakePool's version (passes - was migrated)
2. StakePool.refresh() calls ValidatorPool.refresh()
3. ValidatorPool.refresh() checks ValidatorPool's version (FAILS - not migrated)
4. Transaction aborts with EIncompatibleVersion [8](#0-7) 

There is no public or package-level function to migrate ValidatorPool's Manage instance, making the DoS permanent until a new package version is deployed.

### Impact Explanation

**Complete Protocol DoS**: After any version upgrade, all core liquid staking functionality becomes non-operational:
- `stake_entry()` and `delegate_stake_entry()` - users cannot stake SUI
- `unstake_entry()` - users cannot unstake or withdraw funds
- `rebalance()` - epoch rollovers and validator rebalancing fail
- `set_validator_weights()` - operator cannot adjust validator weights

**Affected Parties**: All protocol users are locked out from staking/unstaking operations. Funds remain safe but completely inaccessible for normal operations until a fix is deployed and upgraded.

**Duration**: Permanent until new package version with fix is deployed, tested, and upgraded through governance.

**Severity**: HIGH - This is a critical operational failure that breaks all user-facing functionality during routine protocol maintenance.

### Likelihood Explanation

**Certainty**: This vulnerability WILL manifest on every package upgrade where VERSION is incremented, which is standard practice for version management.

**Preconditions**: 
- Package upgrade that increments VERSION constant (routine maintenance)
- Admin calls `migrate_version()` as required (documented procedure)
- Any user attempts to stake/unstake (normal user behavior)

**Complexity**: No attack complexity - this is a code bug that automatically triggers during normal operations. The first user action after migration will encounter the DoS.

**Detection**: Will be immediately detected upon first stake/unstake attempt, but by then migration is complete and protocol is stuck.

**Probability**: CERTAIN - Not theoretical or edge case. This is guaranteed to occur on every version upgrade unless specifically noticed and manually worked around.

### Recommendation

**Immediate Fix**: Modify `migrate_version()` in StakePool to also migrate the ValidatorPool's version:

```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version(); // Add this
}
```

Add a public migration function in ValidatorPool:

```move
// In validator_pool.move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

**Verification**: Add integration test that:
1. Deploys v1 with VERSION=1
2. Creates StakePool with user stakes
3. Upgrades to v2 with VERSION=2
4. Calls migrate_version()
5. Verifies stake/unstake operations succeed (should fail without fix)

**Additional**: Consider adding a single global Manage instance shared between StakePool and ValidatorPool to prevent such inconsistencies, or implement recursive migration that walks all nested structures.

### Proof of Concept

**Initial State**:
- Protocol deployed with VERSION=2
- StakePool created with active user stakes
- Both StakePool.manage.version and ValidatorPool.manage.version = 2

**Exploit Steps**:

1. **Admin performs routine package upgrade**:
   - Deploy new package with VERSION=3 in manage.move
   - This is standard version increment for package upgrades

2. **Admin migrates version** (required step):
   ```
   tx: stake_pool::migrate_version(&mut pool, &admin_cap)
   ```
   - Result: StakePool.manage.version = 3
   - Result: ValidatorPool.manage.version = 2 (not updated!)

3. **Any user attempts to stake**:
   ```
   tx: stake_pool::stake_entry(&mut pool, &mut metadata, &mut system_state, sui_coin)
   ```
   - Execution: stake() → refresh() → self.manage.check_version() ✓ (passes, version=3)
   - Execution: refresh() → validator_pool.refresh()
   - Execution: validator_pool.refresh() → self.manage.check_version()
   - Check: ValidatorPool.manage.version (2) == VERSION (3)
   - **Result: ABORT with EIncompatibleVersion (50001)**

4. **All subsequent operations fail**:
   - unstake_entry() - aborts
   - rebalance() - aborts  
   - set_validator_weights() - aborts

**Expected Result**: After migration, all operations should succeed with version checks passing.

**Actual Result**: Protocol completely non-functional with all operations reverting on version mismatch.

**Success Condition**: Any stake/unstake transaction after migrate_version() triggers the permanent DoS.

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

**File:** liquid_staking/sources/validator_pool.move (L334-338)
```text
        validator_weights: VecMap<address, u64>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
```
