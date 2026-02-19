### Title
Migration Steps Can Be Executed Out of Order Leading to Unrecoverable Migration Failure

### Summary
The migration flow from volo_v1 to v2 lacks enforcement of the documented step ordering (steps 2-4: export stakes, take fees, import stakes). If `import_stakes` is called before `take_unclaimed_fees` and imports more balance than remains for fees, the migration becomes unrecoverable because fees cannot be taken and the migration cap cannot be destroyed.

### Finding Description

The migration flow is documented as requiring a specific order: [1](#0-0) 

However, the code lacks enforcement mechanisms:

1. **No ordering checks**: The `take_unclaimed_fees` function has no check to ensure exports are complete before fees are taken [2](#0-1) 

2. **No idempotency protection**: Missing `assert!(!migration_cap.fees_taken, X)` at function start to prevent multiple calls

3. **Import can drain balance prematurely**: The `import_stakes` function can be called before fees are taken, potentially leaving insufficient balance [3](#0-2) 

4. **Destroy requires fees_taken**: The migration cannot complete without fees being taken [4](#0-3) 

**Critical failure path**: Line 146 performs `migration_storage.sui_balance.split(fee_amount)` which will abort if insufficient balance exists. If imports happen first, this line will fail, making fees uncollectable and migration uncompletable.

### Impact Explanation

**Concrete Harm:**
- Migration becomes permanently stuck in incomplete state
- Protocol fees (tracked in `collected_rewards`) cannot be collected, representing direct fund loss to fee recipient
- All migrated SUI is in the new pool but migration process cannot be finalized
- System left in inconsistent state requiring emergency intervention or redeployment

**Quantified Impact:**
- If `collected_rewards` = 100 SUI and all 1050 SUI is imported before fees are taken, 100 SUI of protocol fees is permanently unrecoverable
- Migration storage balance = 0, making `split(100)` impossible
- Cannot destroy migration cap due to `assert!(fees_taken, 2)` check

**Affected Parties:**
- Protocol fee recipients lose unclaimed fees
- Entire liquid staking migration fails
- System operators must implement recovery mechanisms

### Likelihood Explanation

**Attacker Capabilities:**
- Requires holding `MigrationCap` (transferred to operator during initialization) [5](#0-4) 

**Attack Complexity:**
- Simple operational error: calling functions in wrong order
- Can happen through mistake or malicious intent by operator
- No technical barriers once MigrationCap is held

**Feasibility Conditions:**
- Operator performs steps 2→4→3 instead of documented 2→3→4
- Or performs step 4 multiple times before step 3, importing too much

**Probability Reasoning:**
- While requires trusted operator mistake/malice, lack of safeguards makes errors likely during complex multi-step migrations
- No warnings or checks to prevent operational errors
- Human error probability is non-trivial in multi-transaction flows

### Recommendation

**Code-Level Mitigation:**

1. Add state tracking to `MigrationCap`:
```move
public struct MigrationCap has key, store {
    id: UID,
    pool_created: bool,
    fees_taken: bool,
    exports_complete: bool,  // ADD THIS
}
```

2. Add idempotency check to `take_unclaimed_fees`:
```move
assert!(!migration_cap.fees_taken, E_FEES_ALREADY_TAKEN);
```

3. Add ordering check to `import_stakes`:
```move
assert!(migration_cap.fees_taken, E_MUST_TAKE_FEES_FIRST);
```

4. Add balance verification before taking fees:
```move
assert!(migration_storage.sui_balance.value() >= fee_amount, E_INSUFFICIENT_BALANCE_FOR_FEES);
```

**Test Cases:**
- Test calling import before take_unclaimed_fees (should fail)
- Test calling take_unclaimed_fees twice (should fail second time)
- Test calling steps in correct order (should succeed)
- Test partial imports before fees (should fail when insufficient balance)

### Proof of Concept

**Initial State:**
- NativePool with 1000 SUI staked + 50 SUI pending
- `collected_rewards` = 100 SUI
- Migration initialized, pool paused

**Attack Sequence:**

1. Call `export_stakes` with `max_iterations` sufficient to export all:
   - Exports 1000 SUI from stakes
   - Withdraws 50 SUI from pending
   - `migration_storage.sui_balance` = 1050 SUI

2. Call `import_stakes` with `import_amount` = 1050:
   - Splits all 1050 SUI from storage
   - Imports to new pool
   - `migration_storage.sui_balance` = 0 SUI
   - `migration_cap.fees_taken` = false (fees not yet taken)

3. Attempt to call `take_unclaimed_fees`:
   - `fee_amount` = 100 SUI (from `collected_rewards`)
   - Attempts `migration_storage.sui_balance.split(100)`
   - **ABORTS** - insufficient balance (0 < 100)

4. Attempt to call `destroy_migration_cap`:
   - Checks `assert!(fees_taken, 2)`
   - **FAILS** - fees_taken is still false

**Result:** Migration permanently stuck. Cannot take fees (no balance), cannot complete migration (fees_taken requirement unsatisfied).

### Citations

**File:** liquid_staking/sources/migration/migrate.move (L4-9)
```text
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
```

**File:** liquid_staking/sources/migration/migrate.move (L83-90)
```text
        let migration_cap = MigrationCap {  
            id: object::new(ctx),
            pool_created: false,
            fees_taken: false,
        };

        transfer::public_share_object(migration_storage);
        transfer::public_transfer(migration_cap, ctx.sender());
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
