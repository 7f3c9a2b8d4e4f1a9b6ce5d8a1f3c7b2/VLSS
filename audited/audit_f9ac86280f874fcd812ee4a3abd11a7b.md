### Title
Migration Blocked by Incorrect Zero Collected Rewards Assumption

### Summary
The `init_objects()` function contains a flawed assertion that assumes `collected_rewards` will always be non-zero before the first migration. However, this field is initialized to zero and never incremented in the codebase, which can incorrectly block valid first-time migration attempts when the V1 pool legitimately has zero collected rewards.

### Finding Description

The migration initialization function contains a problematic assertion: [1](#0-0) 

The comment indicates this is meant to "avoid double migration" by checking that `collected_rewards != 0`, with the assumption it will be "set to 0 in the first migration." However, this assumption is fundamentally flawed.

The `collected_rewards` field in `NativePool` is initialized to zero: [2](#0-1) 

Critical evidence shows this field is **never incremented** in the codebase. It can only be decremented or set to zero: [3](#0-2) 

Furthermore, all V1 pool entry functions that could potentially operate on rewards are deprecated: [4](#0-3) 

The migration already has a robust anti-replay mechanism through `mark_cap_created()`: [5](#0-4) 

This dynamic field check at line 70 already prevents double migration, making the `collected_rewards` assertion redundant and harmful.

### Impact Explanation

This creates a **critical operational DoS** for the migration process:

1. **Blocked Protocol Upgrade**: If `collected_rewards` is legitimately zero, the migration from V1 to V2 cannot be initiated, preventing the protocol upgrade pathway entirely.

2. **User Impact**: Users remain stuck with the deprecated V1 pool where all staking/unstaking operations abort with `E_DEPRECATED`, effectively freezing their funds until the assertion issue is resolved.

3. **Scenarios Affected**:
   - Fresh deployments that were immediately deprecated without reward accumulation
   - Test/staging environments
   - Pools where all collected rewards were withdrawn before migration
   - Any valid scenario where `collected_rewards` equals zero

4. **No Workaround**: Since the check occurs in `init_objects()` (the first required migration step) and `OwnerCap` is needed to call it, there is no way to bypass this without code changes.

The severity is Medium-to-High because while it requires specific preconditions (zero collected rewards), it completely blocks a critical operational flow when those conditions exist.

### Likelihood Explanation

**Likelihood: Medium**

**Reachable Entry Point**: The `init_objects()` function is a public entry point callable by the owner: [6](#0-5) 

**Feasible Preconditions**:
1. `NativePool` deployed with `collected_rewards = 0` (guaranteed by init)
2. Pool never accumulated rewards before deprecation (possible if immediately deprecated or in test deployments)
3. OR all collected rewards were previously withdrawn
4. Migration attempt initiated

**No Attack Required**: This is not an attack scenario but a design flaw that can occur through normal operations. The owner attempting a legitimate migration would encounter this issue.

**Probability Factors**:
- **High** if this is a fresh deployment or test environment
- **Medium** if the V1 pool operated briefly before deprecation
- **Low** if the V1 pool operated extensively and accumulated rewards before deprecation

The likelihood is realistic because the codebase provides no mechanism to increment `collected_rewards` from its initial zero value, and all reward-related operations are deprecated.

### Recommendation

**Immediate Fix**: Remove the flawed assertion at line 74: [7](#0-6) 

The `mark_cap_created()` check at line 70 already provides robust protection against double migration through dynamic field verification. The `collected_rewards` check is redundant and based on an incorrect assumption.

**Alternative Fix** (if additional validation desired): Check a different invariant that is guaranteed to change during migration, such as verifying the migration storage hasn't been created yet by checking object existence, or rely solely on the dynamic field mechanism.

**Testing**: Add test cases covering:
1. Migration with `collected_rewards = 0`
2. Migration after all fees collected
3. Attempted double migration (should fail at `mark_cap_created()`)
4. Fresh deployment immediate migration scenario

### Proof of Concept

**Initial State**:
- `NativePool` deployed with `collected_rewards = 0` (as per init)
- All V1 functions deprecated (abort `E_DEPRECATED`)
- Owner attempts migration to V2

**Execution Steps**:
1. Owner calls `init_objects(owner_cap, native_pool, ctx)`
2. Function reaches line 74: `assert!(native_pool.mut_collected_rewards() != 0, 0)`
3. `mut_collected_rewards()` returns reference to `collected_rewards` which equals 0
4. Assertion fails: `assert!(0 != 0, 0)` → **Transaction aborts with error code 0**

**Expected Result**: Migration should proceed successfully since this is a valid first migration attempt and `mark_cap_created()` dynamic field doesn't exist yet.

**Actual Result**: Transaction aborts, blocking all migration attempts until code is changed or `collected_rewards` is manually set to a non-zero value (which requires code modification since no public function can modify it).

**Success Condition for Exploit**: Simply attempt migration on any V1 pool instance where `collected_rewards` equals zero - the transaction will fail, demonstrating the DoS condition.

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L67-67)
```text
    public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {
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
