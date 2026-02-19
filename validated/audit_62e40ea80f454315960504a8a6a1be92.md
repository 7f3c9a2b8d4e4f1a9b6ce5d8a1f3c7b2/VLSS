# Audit Report

## Title
Partial Version Migration Causes Complete System DoS Due to Independent ValidatorPool Version

## Summary
The `migrate_version()` function only updates the `StakePool`'s version but leaves the embedded `ValidatorPool`'s version unchanged. Since both structures maintain independent `Manage` instances with version checks, and there is no mechanism to migrate `ValidatorPool`'s version, all critical liquid staking operations fail after package upgrades, resulting in permanent DoS.

## Finding Description

The liquid staking system has a critical architectural flaw in its version migration design. Both `StakePool` and `ValidatorPool` maintain independent `Manage` instances for version tracking: [1](#0-0) [2](#0-1) 

When administrators call `migrate_version()` during a package upgrade, it only updates the `StakePool`'s version: [3](#0-2) 

This delegates to the `Manage` module which updates only that specific instance: [4](#0-3) 

However, the embedded `ValidatorPool`'s `Manage` instance remains at the old version. The problem manifests when operations call `ValidatorPool::refresh()`, which enforces strict version equality: [5](#0-4) [6](#0-5) 

All critical user operations depend on `refresh()` which calls into `ValidatorPool`: [7](#0-6) [8](#0-7) 

Similarly, unstaking operations are blocked: [9](#0-8) 

The `ValidatorPool` also enforces version checks in other critical operations like weight setting: [10](#0-9) 

**Critical Finding:** There is no public or package-level function in `ValidatorPool` that allows migrating its version. The only accessor returns an immutable reference: [11](#0-10) 

## Impact Explanation

This vulnerability causes **complete and permanent DoS** of the entire liquid staking protocol:

1. **All user stake operations fail**: `stake_entry()` and `delegate_stake_entry()` abort when `ValidatorPool::refresh()` checks its version
2. **All user unstake operations fail**: `unstake()` similarly aborts during refresh
3. **Admin fee collection fails**: `collect_fees()` requires refresh to succeed
4. **Operator rebalancing fails**: `rebalance()` and `set_validator_weights()` cannot execute

The impact is catastrophic because:
- All users are locked out from staking and unstaking
- Accumulated fees become inaccessible
- Validator rebalancing is impossible, leading to suboptimal staking distribution
- **No recovery path exists** - the `ValidatorPool.manage` field is private with no migration mechanism

The system becomes a frozen, unusable state with all SUI locked in the protocol.

## Likelihood Explanation

**Certainty: 100% - Occurs deterministically on every version upgrade**

This is not a theoretical vulnerability but an inevitable consequence of the current architecture:

1. **Normal Administrative Path**: Version migration via `migrate_version()` is the standard procedure during package upgrades when the `VERSION` constant is incremented
2. **No Special Preconditions**: Any package upgrade that bumps `VERSION` will trigger this
3. **No Defensive Code**: There is no fallback mechanism or alternative version update path for `ValidatorPool`
4. **Architectural Guarantee**: The independent `Manage` instances in both structs ensure version desynchronization after migration

## Recommendation

Add a version migration path for `ValidatorPool`. The recommended fix:

1. Add a package-level function to `ValidatorPool`:
```move
public(package) fun migrate_validator_pool_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

2. Update `StakePool::migrate_version()` to also migrate the embedded `ValidatorPool`:
```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_validator_pool_version();
}
```

Alternatively, consider consolidating to a single `Manage` instance shared between both structures to eliminate version desynchronization risks.

## Proof of Concept

```move
#[test_only]
module liquid_staking::version_dos_test {
    use liquid_staking::stake_pool::{Self, StakePool, AdminCap};
    use liquid_staking::cert::{Self, Metadata, CERT};
    use sui::test_scenario::{Self as ts};
    use sui::coin;
    use sui_system::sui_system::{Self, SuiSystemState};
    
    #[test]
    fun test_version_migration_causes_dos() {
        let mut scenario = ts::begin(@0xA);
        
        // Setup: Create stake pool
        {
            let ctx = ts::ctx(&mut scenario);
            stake_pool::create_stake_pool(ctx);
        };
        
        ts::next_tx(&mut scenario, @0xA);
        
        // Simulate version migration (in real scenario, VERSION constant would be bumped)
        {
            let mut stake_pool = ts::take_shared<StakePool>(&scenario);
            let admin_cap = ts::take_from_sender<AdminCap>(&scenario);
            
            // Admin migrates StakePool version
            stake_pool.migrate_version(&admin_cap);
            
            ts::return_to_sender(&scenario, admin_cap);
            ts::return_shared(stake_pool);
        };
        
        ts::next_tx(&mut scenario, @0xB);
        
        // Attempt user stake operation - THIS WILL FAIL
        // In real scenario after VERSION bump, ValidatorPool::refresh() 
        // will abort with EIncompatibleVersion because:
        // - StakePool.manage.version = NEW_VERSION
        // - ValidatorPool.manage.version = OLD_VERSION (never migrated)
        {
            let mut stake_pool = ts::take_shared<StakePool>(&scenario);
            let mut metadata = ts::take_shared<Metadata<CERT>>(&scenario);
            let mut system_state = ts::take_shared<SuiSystemState>(&scenario);
            let sui = coin::mint_for_testing<sui::sui::SUI>(1_000_000_000, ts::ctx(&mut scenario));
            
            // This line will abort when ValidatorPool checks its version
            // if VERSION was incremented: assert!(2 == 3) fails
            stake_pool.stake_entry(&mut metadata, &mut system_state, sui, ts::ctx(&mut scenario));
            
            ts::return_shared(system_state);
            ts::return_shared(metadata);
            ts::return_shared(stake_pool);
        };
        
        ts::end(scenario);
    }
}
```

**Note:** The test demonstrates the vulnerable code path. In a real deployment scenario, when the package is upgraded with `VERSION` incremented (e.g., from 2 to 3), calling `migrate_version()` will desynchronize the versions, and all subsequent operations will abort at `ValidatorPool::refresh()` with `EIncompatibleVersion`.

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

**File:** liquid_staking/sources/manage.move (L29-32)
```text
    public(package) fun migrate_version(self: &mut Manage) {
        assert!(self.version <= VERSION, EIncompatibleVersion);
        self.version = VERSION;
    }
```
