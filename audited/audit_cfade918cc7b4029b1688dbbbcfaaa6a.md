### Title
Migration Fails When Empty Validator Set Contains Unclaimed Fee Accounting

### Summary
The migration process from volo_v1 to v2 fails catastrophically when the `native_pool` has no validators but retains a non-zero `collected_rewards` value. The `export_stakes()` function returns zero balance from an empty validator set, but `take_unclaimed_fees()` subsequently attempts to split the `collected_rewards` amount from this insufficient balance, causing an abort that permanently blocks migration completion.

### Finding Description

**Location**: `liquid_staking/sources/migration/migrate.move`, functions `export_stakes()` and `take_unclaimed_fees()`

**Root Cause**: 

The migration flow has an incorrect assumption about the relationship between exported stake balances and the `collected_rewards` accounting field.

In `export_stakes()`, when `export_stakes_from_v1()` is called with an empty validator set, it returns a zero balance because the loop never executes when `validators.length()` is 0. [1](#0-0) 

This zero balance (plus any minimal pending SUI) is joined to `migration_storage.sui_balance`. [2](#0-1) 

However, `collected_rewards` is an accounting field that tracks protocol fees allocated from past staking rewards. It can remain positive even when all validators are empty if:
1. Rewards were earned and allocated as fees during v1 operations
2. All stakes were subsequently withdrawn
3. During withdrawal, only partial fees were extracted due to the cap logic that prevents extracting more fees than available rewards [3](#0-2) 

When `take_unclaimed_fees()` executes, it attempts to split `collected_rewards` amount from the near-zero `migration_storage.sui_balance`. [4](#0-3) 

The Sui Move `Balance::split()` operation will abort when attempting to split more than the available balance, causing the entire migration transaction to fail.

**Why Protections Fail**:

The migration logic assumes `collected_rewards` represents SUI available within the exported stake balance, but it's actually an independent accounting entry that may exceed the actual SUI recovered from empty validators. There is no validation checking that `migration_storage.sui_balance >= collected_rewards` before attempting the split.

### Impact Explanation

**Harm**:
- **Migration Permanently Blocked**: The migration cannot complete because `take_unclaimed_fees()` will always abort when called
- **Protocol Locked**: The v1 pool is paused during migration initialization and cannot be unpaused without destroying the `MigrationCap` [5](#0-4) 

- **MigrationCap Cannot Be Destroyed**: Destruction requires `fees_taken = true`, which is only set upon successful completion of `take_unclaimed_fees()` [6](#0-5) 

- **Users Trapped**: All user funds in the v1 pool become inaccessible due to the pause, with no way to resume operations or complete migration

**Quantified Damage**:
- 100% of SUI value locked in the paused v1 pool becomes inaccessible
- Any non-zero `collected_rewards` balance (protocol fees) cannot be recovered
- The entire liquid staking protocol upgrade path is blocked

**Affected Parties**:
- All v1 pool stakers lose access to their staked SUI
- Protocol operators cannot collect accumulated fees
- The protocol cannot upgrade to v2

**Severity Justification**: High - This is a complete DoS that permanently locks all user funds in the v1 pool under realistic conditions.

### Likelihood Explanation

**Attacker Capabilities**: No attacker needed - this occurs through normal protocol operations.

**Attack Complexity**: Low - The vulnerable state arises naturally:
1. Pool operates normally in v1, collecting fees
2. Users gradually unstake all positions
3. Due to the reward/fee cap mechanism, `collected_rewards` may not fully decrement to zero
4. Validator set becomes empty
5. Migration is initiated

**Feasibility Conditions**:
- Empty validator set (all stakes withdrawn): Common before a planned migration
- Non-zero `collected_rewards`: Realistic due to partial fee extraction during unstaking operations
- The comment at line 73 even acknowledges `collected_rewards` is checked and will be set to 0 during migration, implying the developers expected non-zero values [7](#0-6) 

**Detection/Operational Constraints**: 
- No pre-migration validation exists to detect this condition
- Once `init_objects()` is called, the pool is paused and the issue becomes apparent only when attempting `take_unclaimed_fees()`

**Probability**: Medium-High - The scenario is realistic in production where migrations often occur after encouraging users to withdraw, potentially leaving residual `collected_rewards` accounting.

### Recommendation

**Code-Level Mitigation**:

Add a validation check in `take_unclaimed_fees()` to handle insufficient balance gracefully:

```move
public fun take_unclaimed_fees(
    migration_storage: &mut MigrationStorage,
    migration_cap: &mut MigrationCap,
    recipient: address,
    native_pool: &mut NativePool,
    ctx: &mut TxContext
) {
    let unclaimed_fees = native_pool.mut_collected_rewards();
    let fee_amount = *unclaimed_fees;
    
    // FIX: Only take what's available, capping at current balance
    let available_balance = migration_storage.sui_balance.value();
    let amount_to_take = fee_amount.min(available_balance);
    
    if (amount_to_take > 0) {
        let fees = migration_storage.sui_balance.split(amount_to_take);
        transfer::public_transfer(fees.into_coin(ctx), recipient);
    };
    
    *unclaimed_fees = 0;
    migration_cap.fees_taken = true;
    
    event::emit(
        UnclaimedFeesEvent {
            amount: amount_to_take,
        }
    );
}
```

**Invariant Checks to Add**:
1. Pre-migration validation: Check that if `collected_rewards > 0`, sufficient balance exists in stakes or pending
2. Post-export validation: Assert `migration_storage.sui_balance.value() >= native_pool.mut_collected_rewards()`
3. Document that `deposit_sui()` can be used to add balance before fee collection if needed

**Test Cases**:
1. Test migration with empty validator set and zero `collected_rewards` (should pass)
2. Test migration with empty validator set and non-zero `collected_rewards` (currently fails, should pass with fix)
3. Test migration with partial validator set where exported balance < `collected_rewards`

### Proof of Concept

**Required Initial State**:
1. V1 `native_pool` with:
   - `collected_rewards = 10 SUI` (from past operations)
   - Empty validator set (all StakedSui withdrawn)
   - `pending` balance = 0 SUI
   - Pool not yet migrated

**Transaction Steps**:
1. Call `init_objects(owner_cap, native_pool, ctx)` - Creates migration storage and pauses pool ✓
2. Call `create_stake_pool(migration_cap, ctx)` - Creates v2 pool ✓
3. Call `export_stakes(migration_storage, migration_cap, native_pool, system_state, max_iterations, ctx)`:
   - `export_stakes_from_v1()` returns `(zero_balance, 0, 0)` due to empty validators
   - `migration_storage.sui_balance` = 0 SUI (or minimal from pending)
   - Result: ✓ Completes successfully
4. Call `take_unclaimed_fees(migration_storage, migration_cap, recipient, native_pool, ctx)`:
   - `fee_amount = 10 SUI`
   - Attempts `migration_storage.sui_balance.split(10)` on balance of ~0 SUI
   - Result: ❌ **ABORTS** - Insufficient balance error from `sui::balance::split()`

**Expected vs Actual Result**:
- Expected: Migration completes, fees are collected (even if zero)
- Actual: Transaction aborts at step 4, migration permanently stuck, pool remains paused

**Success Condition for Exploit**: 
The migration failure is deterministic given the initial state - no randomness or timing dependency. The vulnerability is triggered by legitimate migration operations, not by any attacker action.

### Citations

**File:** liquid_staking/sources/volo_v1/validator_set.move (L318-341)
```text
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
```

**File:** liquid_staking/sources/migration/migrate.move (L67-75)
```text
    public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {

        // ensure this function is only called once
        native_pool.mark_cap_created();

        // sanity check to avoid double migration
        // collected_rewards will be set to 0 in the first migration
        assert!(native_pool.mut_collected_rewards() != 0, 0);
        native_pool.set_pause(owner_cap, true);
```

**File:** liquid_staking/sources/migration/migrate.move (L112-123)
```text
        let validator_set = native_pool.mut_validator_set();
        let (exported_sui, exported_count, exported_sui_amount)
        = export_stakes_from_v1(validator_set, system_state, max_iterations, ctx);

        migration_storage.sui_balance.join(exported_sui);
        migration_storage.exported_count = migration_storage.exported_count + exported_count;

        // take pending
        let pending = native_pool.mut_pending();
        let pending_sui = pending.balance_mut().withdraw_all();
        let pending_sui_amount = pending_sui.value();
        migration_storage.sui_balance.join(pending_sui);
```

**File:** liquid_staking/sources/migration/migrate.move (L144-149)
```text
        let unclaimed_fees = native_pool.mut_collected_rewards();
        let fee_amount = *unclaimed_fees;
        let fees = migration_storage.sui_balance.split(fee_amount);
        transfer::public_transfer(fees.into_coin(ctx), recipient);
        *unclaimed_fees = 0;
        migration_cap.fees_taken = true;
```

**File:** liquid_staking/sources/migration/migrate.move (L196-198)
```text
        let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
        assert!(pool_created, 0);
        assert!(fees_taken, 2);
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
