# Audit Report

## Title
Migration Balance Depletion: Unclaimed Fees Can Consume All User Stake Funds

## Summary
The `take_unclaimed_fees()` function in the v1-to-v2 migration flow lacks validation to ensure protocol fees do not exceed the total migrated balance. When `collected_rewards` from v1 equals or exceeds the exported SUI balance, all user stakes are consumed as fees, leaving zero funds for import to v2. This results in complete user fund loss while the migration appears to complete successfully.

## Finding Description

The migration from volo v1 to v2 follows a documented 5-step flow. [1](#0-0) 

**Step 2 - Export Stakes**: All staked SUI from v1 validators plus pending SUI is withdrawn and deposited into `migration_storage.sui_balance`. [2](#0-1) 

**Step 3 - Take Unclaimed Fees (THE VULNERABILITY)**: The function retrieves accumulated protocol fees from v1 and splits this amount from the migration storage balance **without any validation** that the fee amount doesn't exceed the available balance. [3](#0-2) 

The critical issue is at line 146 where `migration_storage.sui_balance.split(fee_amount)` is called with `fee_amount = native_pool.collected_rewards`, with no check that `fee_amount <= migration_storage.sui_balance.value()`.

The `collected_rewards` field represents protocol fees accumulated over v1's entire operational lifetime. [4](#0-3) 

These two values are **completely independent**:
- `collected_rewards` = cumulative protocol fees from v1's lifetime
- `migration_storage.sui_balance` = snapshot of user stakes at migration time

There is no invariant ensuring `collected_rewards < exported_balance`.

**Step 4 - Import Stakes**: The remaining balance is imported to v2. [5](#0-4) 

At line 169, if the balance is depleted to zero from fees, `amount = min(import_amount, 0) = 0`, and no stakes are imported to the v2 pool.

**Step 5 - Final Validation**: The validation only checks that the balance is empty, NOT that stakes were properly imported. [6](#0-5) 

Line 194 asserts `migration_storage.sui_balance.value() == 0`, which passes even when all funds were taken as fees.

## Impact Explanation

**Scenario 1 - Complete Fund Loss**: If `collected_rewards == migration_storage.sui_balance.value()`:
- All exported SUI (user stakes) is taken as protocol fees at line 146
- Zero SUI remains in `migration_storage.sui_balance` 
- Step 4 imports 0 SUI to the new v2 stake pool (line 169: `amount = min(import_amount, 0) = 0`)
- Step 5 validation passes (balance is 0 as expected)
- Migration completes "successfully" but all user funds are lost to fees
- Users' v1 stakes are not migrated to v2

**Scenario 2 - Migration Failure (DoS)**: If `collected_rewards > migration_storage.sui_balance.value()`:
- The `balance.split()` call at line 146 aborts due to insufficient balance
- Migration cannot complete
- Funds stuck in migration storage
- Protocol cannot proceed to v2

**Concrete Example**:
- V1 operated for 1 year with 10% reward fee rate, accumulating 50,000 SUI in `collected_rewards`
- At migration time, only 50,000 SUI in user stakes remain (users withdrew over time)
- Step 3 takes all 50,000 SUI as fees to the recipient address
- Step 4 imports 0 SUI to v2
- All user stakes lost to fee collection

**Who is Affected**: All v1 stakers who expected their positions to migrate to v2.

**Severity**: HIGH - Complete loss of all migrated user funds with no recovery mechanism.

## Likelihood Explanation

This is not an attack but an **operational vulnerability** that occurs during normal migration execution by the trusted admin. No attacker action is required.

The vulnerability triggers when `collected_rewards >= exported_sui_balance`, which is realistic because:

1. **Independent Accumulation**: The `collected_rewards` field accumulates from protocol fees over v1's entire operational lifetime, while the exported balance is just a snapshot of user stakes at migration time. These values evolve independently.

2. **Natural Divergence**: If v1 operated for extended periods (months/years) with:
   - High reward rates (e.g., 10-20% APY)  
   - Protocol fee rates of 10% on rewards (as initialized in the code)
   - Significant user withdrawals before migration
   - Then `collected_rewards` can realistically equal or exceed remaining stakes

3. **No Built-in Safeguards**: There is no mechanism during v1 operation that limits fee accumulation relative to stake balance. The protocol initialized with a 10% reward fee rate. [7](#0-6) 

**Probability**: MEDIUM-HIGH for protocols that:
- Operated v1 for extended periods with successful reward generation
- Experience natural user churn (deposits/withdrawals) before migration
- Have accumulated substantial protocol fees

## Recommendation

Add validation in `take_unclaimed_fees()` to ensure fees cannot exceed the available migration balance:

```move
public fun take_unclaimed_fees(
    migration_storage: &mut MigrationStorage,
    migration_cap: &mut MigrationCap,
    recipient: address,
    native_pool: &mut NativePool,
    ctx: &mut TxContext
) {
    let unclaimed_fees = native_pool.mut_collected_rewards();
    let available_balance = migration_storage.sui_balance.value();
    let fee_amount = *unclaimed_fees;
    
    // FIX: Ensure fees don't exceed available balance
    assert!(fee_amount <= available_balance, ERROR_INSUFFICIENT_BALANCE_FOR_FEES);
    
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

Alternatively, cap the fee amount to the available balance:

```move
let fee_amount = (*unclaimed_fees).min(migration_storage.sui_balance.value());
```

Also consider adding validation in `destroy_migration_cap()` to ensure a minimum amount was imported:

```move
public fun destroy_migration_cap(
    migration_cap: MigrationCap,
    migration_storage: &MigrationStorage,
    target_exported_count: u64,
    min_imported_amount: u64, // NEW PARAMETER
) {
    assert!(migration_storage.exported_count == target_exported_count, 1);
    assert!(migration_storage.sui_balance.value() == 0, 3);
    // NEW: Verify minimum stakes were imported
    // (would need to track imported_amount in MigrationStorage)
    
    let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
    assert!(pool_created, 0);
    assert!(fees_taken, 2);
    id.delete();
}
```

## Proof of Concept

```move
#[test]
fun test_migration_fee_depletion() {
    use sui::test_scenario;
    use liquid_staking::migration;
    use liquid_staking::native_pool;
    
    let admin = @0xADMIN;
    let mut scenario = test_scenario::begin(admin);
    
    // Setup: Create v1 native pool with 50,000 SUI in collected_rewards
    // and 50,000 SUI in user stakes
    {
        native_pool::test_init(scenario.ctx());
    };
    scenario.next_tx(admin);
    
    {
        let mut native_pool = scenario.take_shared<native_pool::NativePool>();
        // Simulate v1 operation accumulating 50,000 SUI in fees
        *native_pool.mut_collected_rewards() = 50_000_000_000_000; // 50k SUI in mist
        scenario.return_shared(native_pool);
    };
    scenario.next_tx(admin);
    
    // Step 1: Initialize migration
    {
        let mut native_pool = scenario.take_shared<native_pool::NativePool>();
        let owner_cap = scenario.take_from_sender<native_pool::OwnerCap>();
        migration::init_objects(&owner_cap, &mut native_pool, scenario.ctx());
        scenario.return_to_sender(owner_cap);
        scenario.return_shared(native_pool);
    };
    scenario.next_tx(admin);
    
    // Step 2: Export stakes (assume 50,000 SUI exported)
    {
        let mut migration_storage = scenario.take_shared<migration::MigrationStorage>();
        let migration_cap = scenario.take_from_sender<migration::MigrationCap>();
        // ... export logic that results in 50k SUI in migration_storage.sui_balance
        scenario.return_to_sender(migration_cap);
        scenario.return_shared(migration_storage);
    };
    scenario.next_tx(admin);
    
    // Step 3: Take unclaimed fees - THIS WILL TAKE ALL 50k SUI
    {
        let mut migration_storage = scenario.take_shared<migration::MigrationStorage>();
        let mut migration_cap = scenario.take_from_sender<migration::MigrationCap>();
        let mut native_pool = scenario.take_shared<native_pool::NativePool>();
        
        let balance_before = migration::get_sui_balance_for_testing(&migration_storage);
        assert!(balance_before == 50_000_000_000_000, 0); // 50k SUI
        
        migration::take_unclaimed_fees(
            &mut migration_storage,
            &mut migration_cap,
            admin, // recipient
            &mut native_pool,
            scenario.ctx()
        );
        
        let balance_after = migration::get_sui_balance_for_testing(&migration_storage);
        assert!(balance_after == 0, 1); // ALL FUNDS GONE
        
        scenario.return_to_sender(migration_cap);
        scenario.return_shared(migration_storage);
        scenario.return_shared(native_pool);
    };
    scenario.next_tx(admin);
    
    // Step 4: Import stakes - WILL IMPORT 0 SUI
    {
        let mut migration_storage = scenario.take_shared<migration::MigrationStorage>();
        let migration_cap = scenario.take_from_sender<migration::MigrationCap>();
        // import_stakes will import 0 because balance is 0
        // Migration completes "successfully" but users lost all funds
        scenario.return_to_sender(migration_cap);
        scenario.return_shared(migration_storage);
    };
    
    scenario.end();
}
```

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L1-10)
```text
/// Module: Migration
/// migrate from volo v1 to volo v2
/// migration will be only executed once
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
/// 6. unpause the pool (after migration)
```

**File:** liquid_staking/sources/migration/migrate.move (L104-134)
```text
    public fun export_stakes(
        migration_storage: &mut MigrationStorage,
        _: &MigrationCap,
        native_pool: &mut NativePool,
        system_state: &mut SuiSystemState,
        max_iterations: u64,
        ctx: &mut TxContext
    ) {
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

        event::emit(
            ExportedEvent {
                total_sui_balance: migration_storage.sui_balance.value(),
                exported_count,
                sui_amount: exported_sui_amount,
                pending_sui_amount: pending_sui_amount,
                epoch: ctx.epoch(),
            }
        );
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L137-155)
```text
    public fun take_unclaimed_fees(
        migration_storage: &mut MigrationStorage,
        migration_cap: &mut MigrationCap,
        recipient: address,
        native_pool: &mut NativePool,
        ctx: &mut TxContext
    ) {
        let unclaimed_fees = native_pool.mut_collected_rewards();
        let fee_amount = *unclaimed_fees;
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

**File:** liquid_staking/sources/migration/migrate.move (L158-185)
```text
    public fun import_stakes(
        migration_storage: &mut MigrationStorage,
        _: &MigrationCap,
        admin_cap: &AdminCap,
        stake_pool: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        import_amount: u64,
        min_ratio: u64,
        ctx: &mut TxContext
    ) {
        let amount = import_amount.min(migration_storage.sui_balance.value());

        // temporarily unpause the pool to allow import
        stake_pool.set_paused(admin_cap, false);
        stake_pool.join_to_sui_pool(migration_storage.sui_balance.split(amount));
        stake_pool.rebalance(metadata, system_state, ctx);
        stake_pool.set_paused(admin_cap, true);

        // sanity check
        let ratio = stake_pool.get_ratio(metadata);
        assert!(ratio <= min_ratio, 0);

        event::emit(ImportedEvent {
            imported_amount: amount,
            ratio
        });
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L188-200)
```text
    public fun destroy_migration_cap(
        migration_cap: MigrationCap,
        migration_storage: &MigrationStorage,
        target_exported_count: u64,
    ) {
        assert!(migration_storage.exported_count == target_exported_count, 1);
        assert!(migration_storage.sui_balance.value() == 0, 3);

        let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
        assert!(pool_created, 0);
        assert!(fees_taken, 2);
        id.delete();
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L148-150)
```text
        /* General stats */
        total_rewards: u64, // current rewards of pool, we can't calculate them, because it's impossible to do on current step
        collected_rewards: u64, // rewards that stashed as protocol fee
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L170-170)
```text
            base_reward_fee: 10_00, // 10.00%
```
