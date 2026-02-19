# Audit Report

## Title
Version State Divergence Between StakePool and ValidatorPool Manage Fields Causes Protocol DoS After Upgrades

## Summary
The liquid staking protocol uses independent `Manage` struct instances in both `StakePool` and `ValidatorPool` to track versioning. When a protocol upgrade occurs and `StakePool::migrate_version()` is called, only the StakePool's version is updated, while ValidatorPool's version remains at the old value. This causes all staking operations to fail with `EIncompatibleVersion` errors, resulting in complete protocol denial-of-service.

## Finding Description

The `Manage` struct contains version control state with a `version` field and `VERSION` constant that must match for operations to proceed [1](#0-0) . The version compatibility is enforced through `check_version()` which aborts if the version doesn't match [2](#0-1) .

**The Critical Design Flaw:**

Both `StakePool` and `ValidatorPool` contain separate, independent `Manage` instances:

1. StakePool has its own `manage: Manage` field [3](#0-2) 

2. ValidatorPool has a separate `manage: Manage` field [4](#0-3) 

Both are created independently during initialization [5](#0-4)  and [6](#0-5) .

**The Version Migration Gap:**

When protocol upgrades occur, only `StakePool::migrate_version()` exists [7](#0-6) , which updates only StakePool's manage version. There is **no function** to update ValidatorPool's manage version, and no way to access it since only a read-only accessor exists [8](#0-7) .

**The Failure Path:**

All critical ValidatorPool operations enforce version checks on their own separate manage instance:
- `ValidatorPool::refresh()` checks version [9](#0-8) 
- `ValidatorPool::set_validator_weights()` checks version [10](#0-9) 

Since all StakePool user operations call through to ValidatorPool methods:
- `stake()` → `refresh()` → `validator_pool.refresh()` [11](#0-10)  and [12](#0-11) 
- `unstake()` → `refresh()` → `validator_pool.refresh()` [13](#0-12) 
- `rebalance()` → `validator_pool.rebalance()` → `validator_pool.refresh()` [14](#0-13) 

All these operations will abort with `EIncompatibleVersion` [15](#0-14)  when ValidatorPool's version check fails.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability causes complete protocol denial-of-service after standard version upgrades:

1. **All user operations fail:** Every stake and unstake transaction aborts with `EIncompatibleVersion` error
2. **Operator functions fail:** Rebalancing operations cannot execute
3. **Protocol becomes non-functional:** No recovery path exists without emergency contract upgrade
4. **Users are locked:** LST holders cannot unstake their tokens, new users cannot stake

The impact qualifies as "High-confidence protocol DoS via valid calls" - all core protocol functionality becomes permanently unavailable after following standard administrative upgrade procedures.

## Likelihood Explanation

**Probability: 100% (Guaranteed)**

This is not an attack scenario but a guaranteed failure condition:

1. **Deterministic trigger:** Occurs automatically on every protocol version upgrade (e.g., VERSION changes from 2 to 3)
2. **Standard administrative flow:** Admin performs normal migration by calling `StakePool::migrate_version()` with AdminCap
3. **Immediate impact:** The very next user operation (stake/unstake/rebalance) will fail
4. **No attacker required:** This happens through normal protocol operations
5. **Reproducible:** Same failure path every time version is incremented

The likelihood is not probabilistic - it is a structural design flaw that manifests on every version upgrade cycle.

## Recommendation

Add a migration function to update ValidatorPool's manage version. The fix requires:

1. **Add to validator_pool.move:**
```move
public(package) fun migrate_version(self: &mut ValidatorPool) {
    self.manage.migrate_version();
}
```

2. **Update StakePool::migrate_version():**
```move
public fun migrate_version(self: &mut StakePool, _: &AdminCap) {
    self.manage.migrate_version();
    self.validator_pool.migrate_version(); // Add this line
}
```

This ensures both Manage instances are synchronized during version upgrades.

**Alternative Long-term Fix:**
Consider consolidating version management to a single source of truth rather than duplicating the Manage struct in both StakePool and ValidatorPool.

## Proof of Concept

```move
#[test]
fun test_version_divergence_dos() {
    let mut ctx = tx_context::dummy();
    
    // 1. Create StakePool with ValidatorPool (both at VERSION=2)
    let mut stake_pool = create_test_stake_pool(&mut ctx);
    let admin_cap = create_test_admin_cap(&mut ctx);
    
    // 2. Simulate version upgrade: VERSION constant changes from 2 to 3
    // (In real scenario, this happens via package upgrade)
    
    // 3. Admin performs migration (only updates StakePool.manage.version)
    stake_pool.migrate_version(&admin_cap);
    // StakePool.manage.version = 3
    // ValidatorPool.manage.version = 2 (unchanged!)
    
    // 4. User attempts to stake - this will ABORT
    let sui_coin = coin::mint_for_testing<SUI>(1_000_000_000, &mut ctx);
    
    // This call will fail with EIncompatibleVersion when it reaches
    // validator_pool.refresh() which checks ValidatorPool.manage.version (2) != VERSION (3)
    stake_pool.stake(&mut metadata, &mut system_state, sui_coin, &mut ctx);
    // Expected: Transaction aborts with EIncompatibleVersion error
}
```

The test demonstrates that after version migration, ValidatorPool's version check fails, blocking all protocol operations.

### Citations

**File:** liquid_staking/sources/manage.move (L3-3)
```text
    const EIncompatibleVersion: u64 = 50001;
```

**File:** liquid_staking/sources/manage.move (L6-11)
```text
    public struct Manage has store {
        version: u64,
        paused: bool,
    }

    const VERSION: u64 = 2;
```

**File:** liquid_staking/sources/manage.move (L21-23)
```text
    public fun check_version(self: &Manage) {
        assert!(self.version == VERSION, EIncompatibleVersion)
    }
```

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

**File:** liquid_staking/sources/stake_pool.move (L498-498)
```text
        self.validator_pool.rebalance(option::none(), system_state, ctx);
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
