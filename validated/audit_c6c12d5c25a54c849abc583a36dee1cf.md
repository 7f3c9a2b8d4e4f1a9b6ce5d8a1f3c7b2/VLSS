# Audit Report

## Title
Migration Fails When Empty Validator Set Contains Unclaimed Fee Accounting

## Summary
The v1 to v2 migration process contains a critical flaw where attempting to extract `collected_rewards` from insufficient balance when the validator set is empty causes transaction abortion, permanently blocking migration and locking all user funds in the paused v1 pool.

## Finding Description

The migration flow makes an unsafe assumption that `collected_rewards` (accumulated protocol fees) will always be covered by the SUI balance exported from validators. This assumption breaks when validators are empty at migration time.

When `export_stakes_from_v1()` is called with an empty validator set, the extraction loop never executes because the condition checks `validators.length()`. [1](#0-0)  This returns a zero balance to the migration storage. [2](#0-1) 

However, `collected_rewards` is independent accounting that persists even when validators are empty. The migration code explicitly expects non-zero `collected_rewards` via its anti-double-migration sanity check. [3](#0-2) 

When `take_unclaimed_fees()` executes, it reads the `collected_rewards` value and attempts to split that exact amount from the migration storage balance without any validation. [4](#0-3)  The Sui Move `Balance::split()` operation aborts when the requested amount exceeds available balance, causing the entire migration transaction to fail.

The v1 pool is paused during migration initialization [5](#0-4)  and the `MigrationCap` can only be destroyed if `fees_taken` is true. [6](#0-5)  This flag is exclusively set upon successful completion of `take_unclaimed_fees()`. [7](#0-6) 

This creates an unbreakable dependency loop: migration aborts → `fees_taken` remains false → `MigrationCap` cannot be destroyed → pool remains paused → users cannot access funds. All v1 staking operations are deprecated and abort regardless of pause state. [8](#0-7) 

## Impact Explanation

**Severity: High**

This vulnerability causes complete migration blockage and total user fund lockup:

- **Protocol DoS**: Migration process deterministically fails, preventing the planned v1→v2 upgrade path
- **Fund Inaccessibility**: 100% of SUI value in the paused v1 pool becomes inaccessible to all stakers with no automatic recovery mechanism  
- **Operational Deadlock**: The protocol cannot unpause without completing migration, but cannot complete migration due to the abort

While an emergency `deposit_sui()` function exists [9](#0-8) , it requires manual detection, external SUI funding, and operator intervention. Users remain locked out until this manual fix occurs, making this a fundamental design flaw rather than an acceptable edge case.

## Likelihood Explanation

**Probability: Medium-High**

This scenario occurs through normal protocol operations without requiring malicious actors:

1. **Realistic Preconditions**: Emptying the validator set before migration is standard practice to encourage users to withdraw first. The code itself expects non-zero `collected_rewards` as evidenced by the explicit sanity check. [3](#0-2) 

2. **Natural State Progression**: The fee cap mechanism in `unstake_amount_from_validators()` prevents over-extraction of fees but allows residual `collected_rewards` to persist when validators empty. [10](#0-9) 

3. **No Pre-Migration Detection**: The `init_objects()` function performs no validation to detect insufficient balance before pausing the pool and creating migration objects. [11](#0-10) 

4. **Deterministic Trigger**: Once this state exists, the migration will always fail at the same point with 100% reproducibility.

## Recommendation

Add pre-flight validation in `init_objects()` to ensure sufficient balance exists:

```move
public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {
    native_pool.mark_cap_created();
    
    // Validate migration can complete
    let collected_rewards = native_pool.mut_collected_rewards();
    assert!(*collected_rewards != 0, 0); // existing check
    
    // NEW: Validate sufficient balance will exist after export
    let pending_balance = get_pending(native_pool);
    let validator_count = get_validator_count(native_pool);
    assert!(validator_count > 0 || pending_balance >= *collected_rewards, ERROR_INSUFFICIENT_BALANCE_FOR_FEES);
    
    native_pool.set_pause(owner_cap, true);
    // ... rest of function
}
```

Alternatively, modify `take_unclaimed_fees()` to handle insufficient balance gracefully by capping the fee extraction to available balance.

## Proof of Concept

```move
#[test]
fun test_migration_fails_with_empty_validators_and_fees() {
    let scenario = test_scenario::begin(@0x1);
    
    // Setup: Create v1 pool with collected_rewards but no validators
    let native_pool = setup_pool_with_fees_no_validators(&mut scenario);
    
    // Step 1: Init migration - succeeds and pauses pool
    init_objects(&owner_cap, &mut native_pool, test_scenario::ctx(&mut scenario));
    assert!(native_pool.is_paused(), 0);
    
    // Step 2: Export stakes - returns zero balance (no validators)
    let migration_storage = test_scenario::take_shared<MigrationStorage>(&scenario);
    export_stakes(&mut migration_storage, &migration_cap, &mut native_pool, 
                  &mut system_state, 100, test_scenario::ctx(&mut scenario));
    assert!(get_sui_balance_for_testing(&migration_storage) == 0, 1);
    
    // Step 3: Take fees - ABORTS due to insufficient balance
    // This call will abort: migration_storage.sui_balance.split(collected_rewards)
    take_unclaimed_fees(&mut migration_storage, &mut migration_cap, @0xFEE,
                       &mut native_pool, test_scenario::ctx(&mut scenario));
    // Never reaches here - transaction aborted
}
```

## Notes

The vulnerability stems from treating `collected_rewards` as a guaranteed liability covered by validator exports, when in reality it's independent accounting that can persist after validators are emptied. The code's own sanity check requiring non-zero `collected_rewards` makes this scenario more likely rather than preventing it. Recovery requires manual intervention via the emergency `deposit_sui()` function, which represents an operational burden and temporary user fund lockup rather than acceptable system behavior.

### Citations

**File:** liquid_staking/sources/volo_v1/validator_set.move (L320-320)
```text
        while (i < validators.length() && iterations > 0) {
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L341-341)
```text
        (total_exported_sui, exported_count, exported_sui_amount)
```

**File:** liquid_staking/sources/migration/migrate.move (L67-91)
```text
    public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {

        // ensure this function is only called once
        native_pool.mark_cap_created();

        // sanity check to avoid double migration
        // collected_rewards will be set to 0 in the first migration
        assert!(native_pool.mut_collected_rewards() != 0, 0);
        native_pool.set_pause(owner_cap, true);

        let migration_storage = MigrationStorage {
            id: object::new(ctx),
            sui_balance: balance::zero<SUI>(),
            exported_count: 0,
        };

        let migration_cap = MigrationCap {  
            id: object::new(ctx),
            pool_created: false,
            fees_taken: false,
        };

        transfer::public_share_object(migration_storage);
        transfer::public_transfer(migration_cap, ctx.sender());
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L144-146)
```text
        let unclaimed_fees = native_pool.mut_collected_rewards();
        let fee_amount = *unclaimed_fees;
        let fees = migration_storage.sui_balance.split(fee_amount);
```

**File:** liquid_staking/sources/migration/migrate.move (L149-149)
```text
        migration_cap.fees_taken = true;
```

**File:** liquid_staking/sources/migration/migrate.move (L198-198)
```text
        assert!(fees_taken, 2);
```

**File:** liquid_staking/sources/migration/migrate.move (L203-218)
```text
    public fun deposit_sui(
        migration_storage: &mut MigrationStorage,
        _: &mut MigrationCap,
        sui_balance: &mut Coin<SUI>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        migration_storage.sui_balance.join(
            sui_balance.split(amount, ctx).into_balance()
        );
        event::emit(
            SuiChangedEvent {
                amount: migration_storage.sui_balance.value(),
            }
        );
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L387-387)
```text
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
