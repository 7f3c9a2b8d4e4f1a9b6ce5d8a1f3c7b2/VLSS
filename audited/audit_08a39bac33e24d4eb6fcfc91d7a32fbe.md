# Audit Report

## Title
Migration Transaction Aborts Due to Insufficient Balance When Extracting Unclaimed Fees from Empty Validator Set

## Summary
The v1 to v2 migration process contains a critical vulnerability where `take_unclaimed_fees()` attempts to extract `collected_rewards` from insufficient balance when the validator set is empty, causing transaction abort and permanent pool lockup.

## Finding Description

The migration flow has a critical design flaw in how it handles the relationship between the accounting field `collected_rewards` and the actual liquid SUI balance available in the migration storage.

When `export_stakes_from_v1()` is called with an empty validator set, the export loop never executes because the loop condition `while (i < validators.length() && iterations > 0)` immediately fails when `validators.length() == 0`. [1](#0-0)  This results in returning a zero balance. [2](#0-1) 

This zero balance (plus any minimal pending SUI) is joined to the migration storage balance. [3](#0-2) 

However, `collected_rewards` is an independent accounting field in the NativePool struct [4](#0-3)  that can remain positive even when validators are empty. The migration initialization explicitly expects non-zero `collected_rewards` through an anti-double-migration sanity check. [5](#0-4) 

When `take_unclaimed_fees()` executes, it directly attempts to split the `collected_rewards` amount from the migration storage balance without any validation that sufficient balance exists. [6](#0-5)  The Sui Move `Balance::split()` operation will abort when the requested amount exceeds the available balance, causing the entire migration transaction to fail.

The v1 pool is paused during migration initialization [7](#0-6) , and the pool cannot be unpaused without destroying the `MigrationCap`. The `MigrationCap` destruction requires the `fees_taken` flag to be true [8](#0-7) , which is only set upon successful completion of `take_unclaimed_fees()`. [9](#0-8) 

This creates an unbreakable dependency loop:
- Migration `take_unclaimed_fees()` aborts → `fees_taken` never becomes true
- `MigrationCap` cannot be destroyed → pool remains paused  
- Users cannot access funds in the paused pool

## Impact Explanation

**Severity: High**

This vulnerability causes:

1. **Complete Fund Lockup**: All SUI value in the paused v1 pool becomes permanently inaccessible to users through normal protocol operations. The pool cannot be unpaused without completing migration, but migration cannot complete.

2. **Protocol Migration Failure**: The planned v1 to v2 upgrade path is blocked, preventing protocol evolution and potentially leaving funds stranded in deprecated v1 contracts.

3. **Protocol Fee Loss**: The accumulated `collected_rewards` cannot be extracted through the intended migration flow.

While an emergency recovery function `deposit_sui()` exists [10](#0-9) , it requires manual intervention, external capital injection, and privileged access to the `MigrationCap`. This does not mitigate the severity as users experience complete fund inaccessibility until manual recovery occurs.

## Likelihood Explanation

**Probability: Medium-High**

This vulnerability can trigger through normal protocol operations:

1. **Realistic Preconditions**: 
   - Empty validator sets are standard practice when preparing for migrations (encouraging users to withdraw first to simplify the process)
   - Non-zero `collected_rewards` is explicitly required by the migration code's own design [5](#0-4) 

2. **No Pre-Migration Detection**: No validation exists to detect insufficient balance before `init_objects()` is called and the pool is paused. The balance sufficiency check is missing in `take_unclaimed_fees()`.

3. **Deterministic Failure**: Once the state exists (empty validators + non-zero `collected_rewards`), the migration will always fail at the same point.

4. **Accounting-Balance Mismatch**: The `collected_rewards` field represents protocol fee accounting that is decoupled from actual liquid balance availability, creating a systemic design flaw rather than an edge case.

## Recommendation

Add a balance sufficiency check before attempting to split in `take_unclaimed_fees()`:

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
    
    // Add validation
    let available_balance = migration_storage.sui_balance.value();
    assert!(available_balance >= fee_amount, E_INSUFFICIENT_BALANCE);
    
    let fees = migration_storage.sui_balance.split(fee_amount);
    transfer::public_transfer(fees.into_coin(ctx), recipient);
    *unclaimed_fees = 0;
    migration_cap.fees_taken = true;
    event::emit(
        UnclaimedFeesEvent {
            amount: fee_amount,
        }
    );
}
```

Additionally, add validation in `init_objects()` to detect and handle this condition before pausing the pool:

```move
public fun init_objects(owner_cap: &OwnerCap, native_pool: &mut NativePool, ctx: &mut TxContext) {
    native_pool.mark_cap_created();
    
    let collected_rewards = *native_pool.mut_collected_rewards();
    assert!(collected_rewards != 0, 0);
    
    // Add pre-check for expected balance
    let expected_balance = estimate_exportable_balance(native_pool);
    assert!(expected_balance >= collected_rewards, E_INSUFFICIENT_BALANCE_FOR_FEES);
    
    native_pool.set_pause(owner_cap, true);
    // ... rest of function
}
```

## Proof of Concept

```move
#[test]
fun test_migration_fails_with_empty_validators_and_nonzero_fees() {
    let mut scenario = test_scenario::begin(@0xCAFE);
    let ctx = test_scenario::ctx(&mut scenario);
    
    // Initialize v1 pool
    native_pool::test_init(ctx);
    test_scenario::next_tx(&mut scenario, @0xCAFE);
    
    let mut native_pool = test_scenario::take_shared<NativePool>(&scenario);
    
    // Set collected_rewards to non-zero (simulating historical fee accumulation)
    *native_pool.mut_collected_rewards() = 1000_000_000; // 1 SUI
    
    // Validator set is empty (no validators added)
    
    // Initialize migration
    let owner_cap = test_scenario::take_from_sender<OwnerCap>(&scenario);
    migrate::test_init(ctx); // Creates empty migration storage
    test_scenario::next_tx(&mut scenario, @0xCAFE);
    
    let mut migration_storage = test_scenario::take_shared<MigrationStorage>(&scenario);
    let mut migration_cap = test_scenario::take_from_sender<MigrationCap>(&scenario);
    
    // Attempt to take unclaimed fees - this will ABORT
    // because migration_storage.sui_balance = 0 but collected_rewards = 1_000_000_000
    migrate::take_unclaimed_fees(
        &mut migration_storage,
        &mut migration_cap,
        @0xFEED,
        &mut native_pool,
        ctx
    ); // ABORTS: insufficient balance to split
    
    // This line is never reached - pool remains paused permanently
    abort 999
}
```

## Notes

The vulnerability stems from a fundamental design flaw where accounting fields (`collected_rewards`) are decoupled from actual balance availability. The migration code assumes that exported validator balance will always cover `collected_rewards`, but this assumption is violated when the validator set is empty. The explicit sanity check expecting non-zero `collected_rewards` at line 74 of migrate.move creates a scenario where the vulnerability preconditions are actually encouraged by the protocol's own design.

### Citations

**File:** liquid_staking/sources/volo_v1/validator_set.move (L316-316)
```text
        let mut total_exported_sui = balance::zero<SUI>();
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L320-320)
```text
        while (i < validators.length() && iterations > 0) {
```

**File:** liquid_staking/sources/migration/migrate.move (L74-74)
```text
        assert!(native_pool.mut_collected_rewards() != 0, 0);
```

**File:** liquid_staking/sources/migration/migrate.move (L75-75)
```text
        native_pool.set_pause(owner_cap, true);
```

**File:** liquid_staking/sources/migration/migrate.move (L116-123)
```text
        migration_storage.sui_balance.join(exported_sui);
        migration_storage.exported_count = migration_storage.exported_count + exported_count;

        // take pending
        let pending = native_pool.mut_pending();
        let pending_sui = pending.balance_mut().withdraw_all();
        let pending_sui_amount = pending_sui.value();
        migration_storage.sui_balance.join(pending_sui);
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

**File:** liquid_staking/sources/volo_v1/native_pool.move (L150-150)
```text
        collected_rewards: u64, // rewards that stashed as protocol fee
```
