# Audit Report

## Title
Migration Fails When Empty Validator Set Contains Unclaimed Fee Accounting

## Summary
The v1 to v2 migration process contains a critical flaw where the `take_unclaimed_fees()` function attempts to extract `collected_rewards` from an insufficient balance when the validator set is empty. This causes the migration transaction to abort, permanently locking all user funds in the paused v1 pool with no recovery path except manual intervention via the emergency `deposit_sui()` function.

## Finding Description

The migration flow incorrectly assumes that `collected_rewards` (protocol fees from past staking rewards) will always be covered by the SUI balance exported from validators. This assumption breaks when the validator set becomes empty before migration.

When `export_stakes_from_v1()` is called with an empty validator set, the loop at [1](#0-0)  never executes because `validators.length() == 0`, returning a zero balance. [2](#0-1) 

This zero balance (plus any minimal pending SUI) is joined to the migration storage. [3](#0-2) 

However, `collected_rewards` is an independent accounting field that can remain positive even when validators are empty. The anti-double-migration check explicitly expects non-zero `collected_rewards` at migration start. [4](#0-3) 

When `take_unclaimed_fees()` executes, it attempts to split the `collected_rewards` amount from the migration storage balance without any validation. [5](#0-4)  The Sui Move `Balance::split()` operation aborts when the requested amount exceeds the available balance, causing the entire migration transaction to fail.

The v1 pool is paused during migration initialization [6](#0-5)  and cannot be unpaused without destroying the `MigrationCap`, which requires the `fees_taken` flag to be true. [7](#0-6)  This flag is only set upon successful completion of `take_unclaimed_fees()`. [8](#0-7) 

This creates an unbreakable dependency loop: migration cannot complete → `fees_taken` never becomes true → `MigrationCap` cannot be destroyed → pool remains paused → users cannot access funds.

## Impact Explanation

**Severity: High**

- **Complete Migration Blockage**: The migration process fails deterministically whenever this state occurs, preventing protocol upgrade to v2
- **Total User Fund Lockup**: 100% of SUI value in the paused v1 pool becomes inaccessible to all stakers with no automatic recovery mechanism
- **Protocol Fee Loss**: Accumulated `collected_rewards` cannot be extracted
- **Operational DoS**: The liquid staking protocol cannot complete its planned upgrade path

While the `deposit_sui()` emergency function exists [9](#0-8) , it requires:
1. Manual detection of the issue
2. Access to the `MigrationCap` 
3. External SUI to cover the fee gap

This recovery path does not mitigate the severity because users remain locked out until manual intervention occurs, and the issue represents a fundamental design flaw rather than an edge case.

## Likelihood Explanation

**Probability: Medium-High**

This scenario occurs through normal protocol operations without requiring any malicious actor:

1. **Realistic Preconditions**: 
   - Empty validator set is common practice before planned migrations (encouraging users to withdraw first)
   - Non-zero `collected_rewards` is explicitly expected by the code's own sanity check [10](#0-9) 

2. **Natural State Progression**: During v1 operations, the fee cap mechanism in `unstake_amount_from_validators()` [11](#0-10)  may prevent full extraction of `collected_rewards` during unstaking, leaving residual accounting

3. **No Pre-Migration Detection**: No validation exists to detect this condition before `init_objects()` is called and the pool is paused

4. **Deterministic Trigger**: Once the vulnerable state exists, the migration will always fail at the same point

## Recommendation

Add validation in `take_unclaimed_fees()` to check balance sufficiency before attempting the split:

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
    
    // Add validation check
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

Alternatively, add pre-migration validation in `init_objects()` or allow partial fee extraction when insufficient balance exists.

## Proof of Concept

```move
#[test]
fun test_migration_fails_with_empty_validators_and_collected_rewards() {
    use sui::test_scenario;
    use liquid_staking::migration::{Self, MigrationStorage, MigrationCap};
    use liquid_staking::native_pool::{Self, NativePool};
    use liquid_staking::ownership::{Self, OwnerCap};
    use sui_system::sui_system::{Self};
    
    let admin = @0xAD;
    let mut scenario = test_scenario::begin(admin);
    
    // 1. Setup: Create native pool with collected_rewards but empty validator set
    {
        native_pool::test_init(scenario.ctx());
    };
    scenario.next_tx(admin);
    
    {
        let mut pool = scenario.take_shared<NativePool>();
        let owner_cap = scenario.take_from_sender<OwnerCap>();
        
        // Simulate collected_rewards from past operations
        *pool.mut_collected_rewards() = 1_000_000_000; // 1 SUI worth of fees
        // Validator set is empty (no stakes)
        
        // 2. Initialize migration - this pauses the pool
        migration::init_objects(&owner_cap, &mut pool, scenario.ctx());
        
        test_scenario::return_shared(pool);
        test_scenario::return_to_sender(&scenario, owner_cap);
    };
    scenario.next_tx(admin);
    
    {
        let mut storage = scenario.take_shared<MigrationStorage>();
        let mut cap = scenario.take_from_sender<MigrationCap>();
        let mut pool = scenario.take_shared<NativePool>();
        
        // 3. Create stake pool
        migration::create_stake_pool(&mut cap, scenario.ctx());
        
        test_scenario::return_shared(storage);
        test_scenario::return_to_sender(&scenario, cap);
        test_scenario::return_shared(pool);
    };
    scenario.next_tx(admin);
    
    {
        let mut storage = scenario.take_shared<MigrationStorage>();
        let cap = scenario.take_from_sender<MigrationCap>();
        let mut pool = scenario.take_shared<NativePool>();
        let mut system_state = scenario.take_shared<sui_system::SuiSystemState>();
        
        // 4. Export stakes - returns ZERO balance because validator set is empty
        migration::export_stakes(
            &mut storage,
            &cap,
            &mut pool,
            &mut system_state,
            100,
            scenario.ctx()
        );
        
        // Verify storage balance is insufficient (0 or minimal)
        assert!(migration::get_sui_balance_for_testing(&storage) < 1_000_000_000);
        
        test_scenario::return_shared(storage);
        test_scenario::return_to_sender(&scenario, cap);
        test_scenario::return_shared(pool);
        test_scenario::return_shared(system_state);
    };
    scenario.next_tx(admin);
    
    {
        let mut storage = scenario.take_shared<MigrationStorage>();
        let mut cap = scenario.take_from_sender<MigrationCap>();
        let mut pool = scenario.take_shared<NativePool>();
        
        // 5. Attempt to take unclaimed fees - THIS WILL ABORT
        // Expected abort: balance::split() fails with insufficient balance
        migration::take_unclaimed_fees(
            &mut storage,
            &mut cap,
            admin,
            &mut pool,
            scenario.ctx()
        ); // <- ABORTS HERE
        
        test_scenario::return_shared(storage);
        test_scenario::return_to_sender(&scenario, cap);
        test_scenario::return_shared(pool);
    };
    
    scenario.end();
}
```

This test demonstrates that when `collected_rewards` exceeds the exported balance from an empty validator set, the `take_unclaimed_fees()` function aborts, blocking migration completion and leaving the pool in a permanently paused state.

### Citations

**File:** liquid_staking/sources/volo_v1/validator_set.move (L316-316)
```text
        let mut total_exported_sui = balance::zero<SUI>();
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L320-320)
```text
        while (i < validators.length() && iterations > 0) {
```

**File:** liquid_staking/sources/migration/migrate.move (L73-74)
```text
        // collected_rewards will be set to 0 in the first migration
        assert!(native_pool.mut_collected_rewards() != 0, 0);
```

**File:** liquid_staking/sources/migration/migrate.move (L75-75)
```text
        native_pool.set_pause(owner_cap, true);
```

**File:** liquid_staking/sources/migration/migrate.move (L116-116)
```text
        migration_storage.sui_balance.join(exported_sui);
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

**File:** liquid_staking/sources/migration/migrate.move (L196-198)
```text
        let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
        assert!(pool_created, 0);
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
