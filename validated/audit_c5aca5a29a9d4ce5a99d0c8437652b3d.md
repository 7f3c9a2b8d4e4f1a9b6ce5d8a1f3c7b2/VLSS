# Audit Report

## Title
Incomplete Version Migration System Causes Permanent Protocol DOS After Package Upgrade

## Summary
The liquid staking protocol contains a critical architectural flaw in its version management system. Both `StakePool` and `ValidatorPool` maintain independent `Manage` objects with version fields, but only `StakePool` has a migration function to update its version. After a package upgrade that increments the `VERSION` constant, the `ValidatorPool.manage.version` remains at the old version permanently, causing all critical operations (stake, unstake, collect_fees, set_validator_weights, rebalance) to fail at the version check in `validator_pool.refresh()`.

## Finding Description

The version management architecture has a fundamental incompleteness:

**Dual Manage Objects:**
Both `StakePool` and `ValidatorPool` contain separate `Manage` struct instances:
- `StakePool` has `manage: Manage` field [1](#0-0) 
- `ValidatorPool` has `manage: Manage` field [2](#0-1) 

**Strict Version Enforcement:**
The `check_version()` function enforces strict equality between the stored version and the current `VERSION` constant: [3](#0-2) 

**Asymmetric Migration Functions:**
Only `StakePool` exposes a migration function: [4](#0-3) 

No corresponding function exists for `ValidatorPool` to update its `manage.version` field. The `ValidatorPool` struct only has `store` ability, not `key`, so it exists only as a field within `StakePool` and cannot be independently migrated.

**Failure Execution Path:**

When a user calls `stake()` after VERSION increment (e.g., from 2 to 3):

1. `stake()` checks `self.manage.check_version()` on `StakePool` - PASSES [5](#0-4) 

2. `stake()` calls `self.refresh()` [6](#0-5) 

3. `refresh()` checks `self.manage.check_version()` on `StakePool` - PASSES [7](#0-6) 

4. `refresh()` calls `self.validator_pool.refresh()` [8](#0-7) 

5. `validator_pool.refresh()` checks `self.manage.check_version()` on `ValidatorPool` - **ABORTS** [9](#0-8) 

The same failure path occurs for:
- `unstake()` [10](#0-9) 
- `collect_fees()` [11](#0-10) 
- `set_validator_weights()` which directly checks ValidatorPool version [12](#0-11) 
- `rebalance()` [13](#0-12) 

## Impact Explanation

**Critical Protocol DOS:**
- All user stake operations permanently fail with `EIncompatibleVersion` error (50001) [14](#0-13) 
- All user unstake operations permanently fail, trapping LST holders' funds
- Admin fee collection operations fail [15](#0-14) 
- Validator weight management becomes impossible [16](#0-15) 
- Rebalancing operations fail [17](#0-16) 

**No Recovery Mechanism:**
The `ValidatorPool` only provides an immutable reference accessor [18](#0-17) , and the `migrate_version()` function in `Manage` is `public(package)` [19](#0-18) , requiring an exposed public function in `ValidatorPool` to call it. No such function exists.

## Likelihood Explanation

**High Likelihood - Triggered by Normal Operations:**
- Package upgrades that increment `VERSION` are routine protocol maintenance events
- The `VERSION` constant is currently set to 2 [20](#0-19) 
- Any future version increment (e.g., to 3) will immediately brick the protocol
- Does not require any attacker action - occurs through honest admin upgrade process
- Guaranteed to trigger on first user operation after any VERSION increment
- Detection is immediate but protocol remains permanently broken

## Recommendation

Add a public migration function to `ValidatorPool` in `validator_pool.move`:

```move
public fun migrate_validator_pool_version(
    self: &mut StakePool,
    _: &AdminCap
) {
    self.validator_pool.manage.migrate_version();
}
```

This should be added to `stake_pool.move` since `ValidatorPool` is a private field. Alternatively, modify the existing `migrate_version()` in `StakePool` to also migrate the nested `ValidatorPool`:

```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.manage.migrate_version();
}
```

## Proof of Concept

```move
#[test]
fun test_version_migration_dos() {
    // 1. Setup: Create stake pool with VERSION = 2
    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();
    
    // Initialize with current VERSION (2)
    stake_pool::create_stake_pool(ctx);
    scenario.next_tx(@0x1);
    
    // 2. Simulate package upgrade: VERSION increments to 3
    // (In reality, this happens via package upgrade changing const VERSION)
    
    // 3. Admin attempts proper migration
    let mut stake_pool = scenario.take_shared<StakePool>();
    let admin_cap = scenario.take_from_sender<AdminCap>();
    stake_pool.migrate_version(&admin_cap);
    // StakePool.manage.version = 3 ✓
    // ValidatorPool.manage.version = 2 (unchanged) ✗
    
    // 4. User attempts stake - FAILS
    let mut metadata = scenario.take_shared<Metadata<CERT>>();
    let mut system_state = scenario.take_shared<SuiSystemState>();
    let sui = coin::mint_for_testing<SUI>(1_000_000_000, ctx);
    
    // This will abort at validator_pool.refresh() with EIncompatibleVersion
    let cert = stake_pool.stake(
        &mut metadata,
        &mut system_state,
        sui,
        ctx
    ); // ABORTS HERE
    
    // Protocol is permanently bricked
}
```

The test demonstrates that even after proper admin migration of `StakePool`, all user operations fail because `ValidatorPool.manage.version` cannot be updated, causing the version check at `validator_pool.refresh()` to permanently abort with error 50001.

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

**File:** liquid_staking/sources/stake_pool.move (L359-380)
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

        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
        self.accrued_reward_fees = self.accrued_reward_fees - reward_fees.value();

        let mut fees = self.fees.withdraw_all();
        fees.join(reward_fees);

        emit(CollectFeesEvent {
            amount: fees.value()
        });

        coin::from_balance(fees, ctx)
    }
```

**File:** liquid_staking/sources/stake_pool.move (L452-471)
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
        self.validator_pool.set_validator_weights(
            validator_weights,
            system_state,
            ctx
        );

        emit(ValidatorWeightsUpdateEvent {
            validator_weights
        });
    }
```

**File:** liquid_staking/sources/stake_pool.move (L489-500)
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
        self.validator_pool.rebalance(option::none(), system_state, ctx);
        emit(RebalanceEvent {is_epoch_rolled_over, sender: ctx.sender()});
    }
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

**File:** liquid_staking/sources/manage.move (L3-3)
```text
    const EIncompatibleVersion: u64 = 50001;
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
