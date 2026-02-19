# Audit Report

## Title
Migration Blocked by Incorrect Zero Collected Rewards Assumption

## Summary
The `init_objects()` function in the migration module contains a flawed assertion that assumes `collected_rewards` will be non-zero before the first migration. However, this field is initialized to zero and never incremented in the codebase, causing legitimate first-time migration attempts to fail when the V1 pool has zero collected rewards.

## Finding Description

The migration initialization function contains a problematic assertion that prevents valid migrations. [1](#0-0) 

The comment indicates this check is meant to "avoid double migration" by verifying `collected_rewards != 0`, with the assumption it will be "set to 0 in the first migration." However, this assumption is fundamentally backwards.

The `collected_rewards` field in `NativePool` is initialized to zero at deployment. [2](#0-1) 

Critical evidence shows this field is **never incremented** in the codebase. It can only be decremented or set to zero. [3](#0-2) 

Furthermore, all V1 pool entry functions that could potentially accumulate rewards are deprecated and abort immediately. [4](#0-3) 

The migration already has a robust anti-replay mechanism through `mark_cap_created()` that uses dynamic field checks. [5](#0-4) 

This check is called before the problematic assertion [6](#0-5)  and already prevents double migration by aborting if the `CAP_CREATED` dynamic field exists, making the `collected_rewards` assertion redundant and harmful.

## Impact Explanation

This creates a **critical operational DoS** for the migration process:

1. **Blocked Protocol Upgrade**: If `collected_rewards` is legitimately zero, the migration from V1 to V2 cannot be initiated, preventing the protocol upgrade pathway entirely.

2. **User Impact**: Users remain stuck with the deprecated V1 pool where all staking/unstaking operations abort with `E_DEPRECATED`, effectively freezing their funds until the assertion issue is resolved.

3. **Scenarios Affected**:
   - Fresh deployments that were immediately deprecated without reward accumulation
   - Test/staging environments
   - Pools where all collected rewards were withdrawn before migration
   - Any valid scenario where `collected_rewards` equals zero

4. **No Workaround**: Since the check occurs in `init_objects()` (the first required migration step) and `OwnerCap` is needed to call it, there is no way to bypass this without code changes.

The severity is **Medium-to-High** because while it requires specific preconditions (zero collected rewards), it completely blocks a critical operational flow when those conditions exist.

## Likelihood Explanation

**Likelihood: Medium**

The `init_objects()` function is a public entry point callable by the owner with valid `OwnerCap`. [7](#0-6) 

**Feasible Preconditions**:
1. `NativePool` deployed with `collected_rewards = 0` (guaranteed by initialization)
2. Pool never accumulated rewards before deprecation (possible if immediately deprecated or in test deployments)
3. OR all collected rewards were previously withdrawn
4. Migration attempt initiated

**No Attack Required**: This is not an attack scenario but a design flaw that occurs through normal operations. The owner attempting a legitimate migration would encounter this issue.

**Probability Factors**:
- **High** if this is a fresh deployment or test environment
- **Medium** if the V1 pool operated briefly before deprecation
- **Low** if the V1 pool operated extensively and accumulated rewards before deprecation

The likelihood is realistic because the codebase provides no mechanism to increment `collected_rewards` from its initial zero value, and all reward-related operations are deprecated.

## Recommendation

Remove the flawed `collected_rewards != 0` assertion at line 74, as the anti-replay protection is already provided by `mark_cap_created()` at line 70. The corrected function should be:

```move
public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {
    // ensure this function is only called once
    native_pool.mark_cap_created();
    
    // Remove the flawed assertion:
    // assert!(native_pool.mut_collected_rewards() != 0, 0);
    
    native_pool.set_pause(owner_cap, true);
    
    // ... rest of function
}
```

The `mark_cap_created()` function already provides robust double-migration prevention by checking for the existence of the `CAP_CREATED` dynamic field and aborting if it exists.

## Proof of Concept

```move
#[test]
fun test_migration_blocked_by_zero_collected_rewards() {
    use liquid_staking::native_pool;
    use liquid_staking::ownership;
    use liquid_staking::migration;
    use sui::test_scenario;
    
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    
    // 1. Initialize NativePool (collected_rewards = 0)
    native_pool::test_init(test_scenario::ctx(&mut scenario));
    test_scenario::next_tx(&mut scenario, owner);
    
    // 2. Create OwnerCap
    ownership::test_create_owner_cap(test_scenario::ctx(&mut scenario));
    test_scenario::next_tx(&mut scenario, owner);
    
    let mut pool = test_scenario::take_shared<native_pool::NativePool>(&scenario);
    let owner_cap = test_scenario::take_from_sender<ownership::OwnerCap>(&scenario);
    
    // 3. Verify collected_rewards is 0 (as per initialization)
    assert!(native_pool::mut_collected_rewards(&mut pool) == 0, 0);
    
    // 4. Attempt migration - this will ABORT due to the assertion
    // assert!(native_pool.mut_collected_rewards() != 0, 0); fails
    migration::init_objects(&owner_cap, &mut pool, test_scenario::ctx(&mut scenario));
    // Expected: Transaction aborts with error code 0
    
    test_scenario::return_shared(pool);
    test_scenario::return_to_sender(&scenario, owner_cap);
    test_scenario::end(scenario);
}
```

This test demonstrates that a legitimate first-time migration attempt will abort when `collected_rewards` is zero, which is the guaranteed initial state and cannot be changed due to deprecated functions.

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L67-67)
```text
    public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {
```

**File:** liquid_staking/sources/migration/migrate.move (L70-70)
```text
        native_pool.mark_cap_created();
```

**File:** liquid_staking/sources/migration/migrate.move (L72-74)
```text
        // sanity check to avoid double migration
        // collected_rewards will be set to 0 in the first migration
        assert!(native_pool.mut_collected_rewards() != 0, 0);
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L177-177)
```text
            collected_rewards: 0,
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L269-271)
```text
    public entry fun update_rewards(self: &mut NativePool, clock: &Clock, value: u64, _operator_cap: &OperatorCap) {
        abort E_DEPRECATED
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L470-476)
```text
        if (collectable_reward > self.collected_rewards) {
            // all rewards was collected
            collectable_reward = self.collected_rewards;
            self.collected_rewards = 0;
        } else {
            self.collected_rewards = self.collected_rewards - collectable_reward;
        };
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L599-604)
```text
    public(package) fun mark_cap_created(self: &mut NativePool) {
        if (dynamic_field::exists_<vector<u8>>(&self.id, CAP_CREATED)) {
            abort 0;
        };
        dynamic_field::add(&mut self.id, CAP_CREATED, true);
    }
```
