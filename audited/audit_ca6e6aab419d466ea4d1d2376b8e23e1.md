### Title
Validator Set Desynchronization Leading to Permanent DoS on Validator Removal

### Summary
The ValidatorSet struct maintains validators in dual storage: a `VecMap<address, u64>` and a `vector<address>`. The `update_validators` function only modifies the VecMap without updating the sorted vector, requiring a separate `sort_validators` call. If validators are added without sorting, the cleanup logic in `remove_stakes` will abort with `E_NOT_FOUND` when attempting to remove validators, permanently blocking validator removal and unstaking operations.

### Finding Description

The ValidatorSet struct stores validators in two separate data structures [1](#0-0) .

When `update_validators` is called, it only modifies the `validators` VecMap through the `update_validator` helper function [2](#0-1) , and sets `is_sorted` to false but does NOT update `sorted_validators` [3](#0-2) .

The `sort_validators` function must be called separately to rebuild `sorted_validators` from the VecMap [4](#0-3) .

The critical vulnerability occurs in `remove_stakes` cleanup logic. When a validator's vault is empty and has priority 0, the function attempts to remove it from both storage structures. It removes from the VecMap successfully, but then tries to find the validator in `sorted_validators` and asserts it exists [5](#0-4) . If the validator was never added to `sorted_validators` (because `sort_validators` wasn't called after `update_validators`), the assertion at line 272 fails with `E_NOT_FOUND`, causing the transaction to abort.

Additionally, the migration function `export_stakes_from_v1` only iterates through `sorted_validators` [6](#0-5) , meaning any validators not in the sorted list would be skipped during migration, leaving their stakes stranded.

### Impact Explanation

**Operational Impact:**
- Validators added without subsequent sorting cannot be removed from the system
- Any unstake operation that triggers validator cleanup (when vault is empty and priority is 0) will permanently fail with `E_NOT_FOUND`
- This blocks the protocol's ability to clean up inactive validators
- Users cannot unstake from affected validators, creating a DoS condition

**Fund Impact:**
- During migration via `export_stakes_from_v1`, unsorted validators are skipped (line 318 only uses `sorted_validators`), leaving their stakes unexported
- Stakes in unsorted validators become inaccessible through normal migration flows
- This can trap significant SUI amounts if validators with stakes are not properly sorted

**Severity:** HIGH - While this requires operational error (forgetting to call `sort_validators`), the impact is permanent DoS on validator removal and potential fund trapping during migration.

### Likelihood Explanation

**Feasibility:**
The vulnerability can occur through the following realistic scenarios:

1. **Historical State:** If the protocol was previously deployed and `update_validators` was called without `sort_validators` before the entry functions were deprecated [7](#0-6) , desynchronized state could persist.

2. **Package-Internal Calls:** The functions are `public(package)` visibility, allowing calls from within the liquid_staking package. While the test function correctly calls both [8](#0-7) , there's no enforcement preventing direct `update_validators` calls.

3. **Operational Error:** No runtime check enforces that `sorted_validators` is synchronized before critical operations like `remove_stakes` or `export_stakes_from_v1`.

**Probability:** MEDIUM-HIGH if the protocol was actively used before deprecation, LOW if the deployment is fresh and only test functions were used. The lack of synchronization checks means any past operational error creates permanent vulnerability.

### Recommendation

**Immediate Fix:**
1. Add synchronization check in `remove_stakes` before attempting removal:
```move
// Before line 271, add:
if (!vec_map::contains(&self.validators, &validator)) {
    return // Validator already removed
};
```

2. Enforce atomic updates by making `update_validators` call `sort_validators` automatically:
```move
public(package) fun update_validators(self: &mut ValidatorSet, validators: vector<address>, priorities: vector<u64>) {
    // ... existing update logic ...
    if (length > 0) {
        sort_validators(self); // Auto-sort after updates
    };
}
```

3. Add invariant validation function:
```move
public fun validate_sync(self: &ValidatorSet): bool {
    vec_map::size(&self.validators) == vector::length(&self.sorted_validators)
}
```

4. Add migration safety check in `export_stakes_from_v1` to warn about unsorted validators:
```move
// After line 318:
assert!(self.is_sorted, E_NOT_SORTED);
```

**Long-term Fix:**
Redesign to use single source of truth - either store only the VecMap and compute sorted list on-demand for reads, or maintain synchronization invariant through private modification functions.

### Proof of Concept

**Initial State:**
- ValidatorSet exists with synchronized `validators` VecMap and `sorted_validators`
- Both contain validators A, B, C with priorities

**Step 1 - Desynchronization:**
- Call `update_validators` with new validator D, priority 100
- Result: `validators` VecMap = {A, B, C, D}, `sorted_validators` = [A, B, C]
- `is_sorted` = false

**Step 2 - Add Stakes:**
- Call `add_stake` for validator D with StakedSui
- Result: Vault created for D, stakes stored

**Step 3 - Set Priority to Zero:**
- Call `update_validators` with validator D, priority 0
- Result: `validators` VecMap = {A, B, C, D(0)}

**Step 4 - Attempt Removal:**
- Call `remove_stakes` for validator D with requested_amount covering all stakes
- Execution reaches line 260: vault.gap == vault.length (empty)
- Line 264: Gets priority from VecMap (0) ✓
- Line 270: Removes from VecMap ✓
- Line 271: `vector::index_of(&sorted_validators, &D)` returns (false, _) ✗
- Line 272: `assert!(exist, E_NOT_FOUND)` **ABORTS**

**Expected:** Validator D should be removed successfully
**Actual:** Transaction aborts with E_NOT_FOUND (303)
**Success Condition:** Validator D cannot be removed, creating permanent DoS

### Citations

**File:** liquid_staking/sources/volo_v1/validator_set.move (L52-58)
```text
    public struct ValidatorSet has key, store {
        id: UID,
        vaults: Table<address, Vault>, // validator => Vault
        validators: VecMap<address, u64>,
        sorted_validators: vector<address>,
        is_sorted: bool,
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L115-149)
```text
    public(package) fun sort_validators(self: &mut ValidatorSet) {
        let mut i = 0;
        let len = vec_map::size<address, u64>(&self.validators);
        let mut sorted = vector::empty<address>();
        while (i < len) {
            let (vldr_address_ref, vldr_prior_ref) = vec_map::get_entry_by_idx(&self.validators, i);
            let vldr_prior = *vldr_prior_ref;
            let sorted_len = vector::length(&sorted);

            if (vldr_prior == 0 || sorted_len == 0) {
                vector::push_back(&mut sorted, *vldr_address_ref);
            } else {
                let mut j = 0;

                while (j < sorted_len) {
                    let j_vldr_address_ref = vector::borrow(&sorted, j);
                    let j_vldr_prior = vec_map::get(&self.validators, j_vldr_address_ref);

                    if (*j_vldr_prior < vldr_prior) {
                        break
                    };

                    j = j + 1;
                };
                vector::insert(&mut sorted, *vldr_address_ref, j);
            };

            i = i + 1;
        };
        event::emit(ValidatorsSorted{
            validators: sorted,
        });
        self.is_sorted = true;
        self.sorted_validators = sorted;
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L152-172)
```text
    public(package) fun update_validators(self: &mut ValidatorSet, validators: vector<address>, priorities: vector<u64>) {
        let length = vector::length(&validators);
        assert!(length < MAX_VLDRS_UPDATE, E_TOO_MANY_VLDRS);
        assert!(length == vector::length(&priorities), E_BAD_ARGS);

        let mut i = 0;
        while (i < length) {
            let vldr_address = *vector::borrow(&validators, i);
            let vldr_prior = *vector::borrow(&priorities, i);

            update_validator(self, vldr_address, vldr_prior);

            i = i + 1;
        };

        if (length > 0) {
            self.is_sorted = false;
        };

        assert!(vec_map::size(&self.validators) < MAX_VLDRS_UPDATE, E_TOO_MANY_VLDRS);
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L174-184)
```text
    fun update_validator(self: &mut ValidatorSet, validator: address, priority: u64) {
        if (vec_map::contains<address, u64>(&self.validators, &validator)) {
            *vec_map::get_mut<address, u64>(&mut self.validators, &validator) = priority;
        } else {
            vec_map::insert(&mut self.validators, validator, priority);
        };
        event::emit(ValidatorPriorUpdated{
            validator,
            priority
        });
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L260-280)
```text
        if (vault_mut_ref.gap == vault_mut_ref.length) {
            // when gap == length we don't have stakes on validator
            assert!(vault_mut_ref.total_staked == 0, E_BAD_CONDITION);
        
            let prior = *vec_map::get(&self.validators, &validator);
            if (prior == 0) {
                // priority is zero, it means that validator can be removed
                let v = table::remove(&mut self.vaults, validator);
                destroy_vault(v);

                vec_map::remove<address, u64>(&mut self.validators, &validator);
                let (exist, index) = vector::index_of(&self.sorted_validators, &validator);
                assert!(exist, E_NOT_FOUND);
                // we can do swap_revert, because it can be swapped only with inactive validator
                vector::swap_remove(&mut self.sorted_validators, index);
            } else {
                // table is empty, but validator still active => we can reset vault
                vault_mut_ref.gap = 0;
                vault_mut_ref.length = 0;
            };
        };
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L301-304)
```text
    public fun test_update_and_sort(self: &mut ValidatorSet, validators: vector<address>, priorities: vector<u64>) {
        update_validators(self, validators, priorities);
        sort_validators(self);
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L306-342)
```text
    public(package) fun export_stakes_from_v1(
        validator_set: &mut ValidatorSet,
        system_state: &mut SuiSystemState,
        max_iterations: u64,
        ctx: &mut TxContext
    ):(Balance<SUI>, u64, u64) {
        let mut i = 0;
        let mut iterations = max_iterations;
        let mut exported_count = 0;
        let mut exported_sui_amount = 0;
        let mut total_exported_sui = balance::zero<SUI>();

        let validators = validator_set.get_validators();

        while (i < validators.length() && iterations > 0) {
            let validator = *validators.borrow(i);

            if (!validator_set.vaults.contains(validator)) {
                i = i + 1;
                continue
            };

            let exported_sui = export_stakes(
                validator_set.vaults.borrow_mut(validators[i]),
                &mut iterations,
                &mut exported_count,
                &mut exported_sui_amount,
                system_state,
                ctx
            );

            total_exported_sui.join(exported_sui);
            i = i + 1;
        };

        (total_exported_sui, exported_count, exported_sui_amount)
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L260-262)
```text
    public entry fun update_validators(self: &mut NativePool, validators: vector<address>, priorities: vector<u64>, _operator_cap: &OperatorCap) {
        abort E_DEPRECATED
    }
```
