### Title
Non-Atomic Version Migration Leaves ValidatorPool Unmigrated, Causing Complete Protocol DoS

### Summary
The `migrate_version()` function only migrates the StakePool's version but fails to migrate the embedded ValidatorPool's version, creating a critical inconsistency. After migration, all core operations (stake, unstake, rebalance, collect_fees) fail when they invoke ValidatorPool operations that check version compatibility, permanently bricking the liquid staking protocol.

### Finding Description

The StakePool contains an embedded ValidatorPool, and both maintain independent version control through separate `Manage` structs: [1](#0-0) [2](#0-1) 

When an admin calls `StakePool.migrate_version()`, it only updates the StakePool's version: [3](#0-2) 

This calls the Manage module's migrate_version: [4](#0-3) 

However, this **only migrates `self.manage.version`** (the StakePool's Manage struct), leaving the ValidatorPool's separate Manage struct at the old version. There is no public or package-visible function to migrate the ValidatorPool's version separately.

The VERSION constant defines the expected version: [5](#0-4) 

The critical failure occurs because ValidatorPool operations verify version compatibility: [6](#0-5) [7](#0-6) 

The version check enforces strict equality: [8](#0-7) 

All critical StakePool operations invoke ValidatorPool methods that perform these checks: [9](#0-8) [10](#0-9) [11](#0-10) 

### Impact Explanation

**Direct Operational Impact - Complete Protocol DoS:**
After calling `migrate_version()` during a version upgrade (e.g., VERSION 2→3):
- StakePool.manage.version = 3
- ValidatorPool.manage.version = 2 (unmigrated)

All user operations immediately fail:
- **stake/unstake**: Fail when calling `refresh()` → `validator_pool.refresh()` → `check_version()` aborts with `EIncompatibleVersion`
- **rebalance**: Fails identically through the same path
- **collect_fees**: Cannot collect protocol fees, blocking admin operations
- **set_validator_weights**: Fails directly when calling `validator_pool.set_validator_weights()` → `check_version()`

**Fund Impact:**
All user funds remain locked in the protocol. Users cannot unstake their SUI, and new users cannot stake. The protocol becomes completely non-functional with no recovery mechanism except a code upgrade and re-deployment.

**Affected Parties:**
- All LST holders: Cannot redeem their staked SUI
- All potential stakers: Cannot participate in liquid staking
- Protocol operators: Cannot rebalance validators or collect fees
- Protocol: Complete loss of functionality and user trust

This is a **CRITICAL** severity issue because it causes permanent protocol failure during routine version upgrades.

### Likelihood Explanation

**Certainty: 100% on next version upgrade**

**Reachable Entry Point:**
The admin function `migrate_version()` is the standard mechanism for version upgrades, requiring only AdminCap.

**Feasible Preconditions:**
This occurs during normal protocol maintenance when developers:
1. Update the VERSION constant in manage.move (e.g., 2→3)
2. Admin calls `migrate_version()` as intended
3. System enters broken state immediately

**Execution Practicality:**
This is not an exploit but an inevitable consequence of the current design. The presence of the `migrate_version()` function and VERSION constant indicates version upgrades are expected protocol operations.

**Detection:**
The issue manifests immediately on the first user operation after migration, making it impossible to miss but also impossible to prevent once migration is called.

**Probability:**
Given that VERSION=2 already exists and migrate_version() is implemented, future version upgrades are clearly planned. This vulnerability will trigger with 100% certainty on the next upgrade unless fixed.

### Recommendation

**Immediate Fix:**
Modify `StakePool.migrate_version()` to atomically migrate both the StakePool and embedded ValidatorPool:

```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.manage.migrate_version(); // Add this line
}
```

However, this requires making ValidatorPool.manage accessible, which may require:

**Option 1:** Add a package-level function in validator_pool.move:
```move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

Then call it from StakePool.migrate_version():
```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version();
}
```

**Option 2:** Expose a mutable reference accessor:
```move
public(package) fun manage_mut(self: &mut ValidatorPool): &mut Manage {
    &mut self.manage
}
```

**Invariant to Enforce:**
Add an assertion in critical operations to detect version mismatches:
```move
assert!(
    self.manage.version == self.validator_pool.manage.version,
    EVersionMismatch
);
```

**Test Cases:**
1. Test that calling migrate_version() updates both StakePool and ValidatorPool versions
2. Test that all operations (stake/unstake/rebalance/collect_fees/set_validator_weights) succeed after migration
3. Test version mismatch detection if versions diverge

### Proof of Concept

**Initial State:**
- VERSION constant = 2
- StakePool deployed with version = 2
- ValidatorPool deployed with version = 2
- System functioning normally

**Attack Sequence:**

**Step 1:** Developers prepare version upgrade
- Update VERSION constant in manage.move from 2 to 3
- Publish package upgrade

**Step 2:** Admin migrates StakePool
```move
stake_pool::migrate_version(&mut stake_pool, &admin_cap);
```
- Result: StakePool.manage.version = 3
- Result: ValidatorPool.manage.version = 2 (unchanged)

**Step 3:** User attempts to stake
```move
stake_pool::stake_entry(&mut stake_pool, &mut metadata, &mut system_state, sui_coin, ctx);
```

**Execution Path:**
1. `stake_entry()` calls `stake()`
2. `stake()` at line 226 calls `self.manage.check_version()` ✓ PASSES (StakePool version = 3 = VERSION)
3. `stake()` at line 229 calls `self.refresh()`
4. `refresh()` at line 514 calls `self.validator_pool.refresh()`
5. `validator_pool.refresh()` at line 180 calls `self.manage.check_version()`
6. **ABORT**: `assert!(self.version == VERSION)` fails because ValidatorPool.version = 2 ≠ VERSION = 3
7. Transaction reverts with error code `EIncompatibleVersion = 50001`

**Expected Result:** Stake succeeds and user receives LST tokens

**Actual Result:** Transaction aborts with `EIncompatibleVersion`, protocol completely unusable

**Success Condition:** All staking, unstaking, rebalancing, and fee collection operations permanently fail. The protocol is bricked until a code fix and redeployment.

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
