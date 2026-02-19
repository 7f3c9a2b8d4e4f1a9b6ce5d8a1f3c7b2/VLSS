### Title
Incomplete Migration: Protocol Fees (collectable_fee) Not Migrated from V1 to V2

### Summary
The v1 to v2 migration flow fails to migrate accumulated protocol fees stored in the `collectable_fee` Coin<SUI> field of the NativePool object. While the migration handles the `collected_rewards` counter, it does not extract the actual fee coins, leaving protocol revenue stranded in the deprecated v1 contract and requiring manual administrative recovery.

### Finding Description

The migration module implements a multi-step process to migrate from volo v1 (NativePool) to v2 (StakePool). However, it contains a critical omission in fee handling. [1](#0-0) 

The NativePool contains two fee-related fields:
- `collectable_fee`: A `Coin<SUI>` that accumulates actual unstake fees and reward fees
- `collected_rewards`: A `u64` counter tracking reward fees for accounting

During unstaking operations, fees are added to the `collectable_fee` coin: [2](#0-1) 

The migration flow processes fees in the `take_unclaimed_fees` step: [3](#0-2) 

This function only handles the `collected_rewards` counter by:
1. Reading the counter value from native_pool
2. Splitting that amount from the migration_storage sui_balance (which came from exported stakes)
3. Transferring it to the recipient
4. Setting collected_rewards to 0

**Critical Issue**: The actual `collectable_fee` Coin<SUI> object is never accessed or migrated. It remains in the deprecated NativePool object after migration completes.

The migration flow consists of: [4](#0-3) 

None of these steps extract the collectable_fee coin. The export_stakes function only withdraws staked assets: [5](#0-4) 

Additionally, while most v1 entry functions are deprecated and abort immediately, the `collect_fee` function does NOT have the deprecation abort: [6](#0-5) 

This function only checks version compatibility and pause status, but doesn't abort with `E_DEPRECATED` like other functions do.

### Impact Explanation

**Direct Impact**:
- All protocol fees accumulated in `collectable_fee` before migration are left in the deprecated v1 NativePool
- These fees represent protocol revenue from unstake fees and reward fees that should be automatically migrated to v2
- The amount depends on pre-migration activity but could be substantial for active pools

**Custody Integrity Impact**:
- Protocol funds are in the wrong location (deprecated v1 contract instead of active v2 contract)
- Violates the expectation that migration is complete and all assets are properly transferred
- Creates operational risk if administrators don't realize fees remain in v1

**Recovery Complexity**:
- While technically recoverable via calling `collect_fee` on the v1 NativePool with OwnerCap, this requires:
  - Awareness that fees were left behind
  - Manual intervention to unpause v1 pool (if paused) and collect fees
  - Additional transactions and gas costs
  - Potential confusion about which pool to interact with

**Severity**: Medium - Funds are not permanently lost but migration is incomplete, requiring manual administrative recovery and creating operational risk.

### Likelihood Explanation

**Probability**: High - This occurs on every migration if any fees have accumulated before migration starts.

**Preconditions**:
- Normal protocol operation before migration will naturally accumulate fees in `collectable_fee`
- Any unstake operations before migration add fees to this coin
- Migration is executed following the documented flow

**Execution**: This is not an attack but an operational failure. The incomplete migration logic automatically leaves fees behind whenever the migration process is executed.

**Detection**: The issue may not be immediately apparent since:
- Migration events don't include collectable_fee status
- The v2 pool appears to function normally
- Only administrators checking v1 pool state post-migration would notice the stranded fees

**No Attack Required**: This is a migration implementation bug, not requiring any malicious actor. It affects the protocol's own fund management integrity.

### Recommendation

**Immediate Fix**: Add a step to the migration flow to collect the `collectable_fee` from NativePool before or during migration:

```move
// Add to migration flow (after step 2, before step 3):
public fun collect_v1_fees(
    native_pool: &mut NativePool,
    owner_cap: &OwnerCap,
    recipient: address,
    ctx: &mut TxContext
) {
    // Collect any remaining fees from v1 pool
    native_pool.collect_fee(recipient, owner_cap, ctx);
}
```

**Alternative approach**: Modify the `take_unclaimed_fees` function to also extract the collectable_fee coin: [7](#0-6) 

Add a package-visible getter function and use it in migration to extract the collectable_fee coin directly.

**Testing Requirements**:
1. Add comprehensive migration integration tests covering:
   - Migration with accumulated fees in collectable_fee
   - Verification that all funds (stakes + fees) are properly migrated
   - Ratio correctness after migration
   - v1 pool state verification post-migration
2. Add assertions in `destroy_migration_cap` to verify v1 pool has no remaining balances
3. Test partial migration scenarios and error recovery

**Version Management**: The migration should also call the native_pool's migrate function to update its version field: [8](#0-7) 

This ensures proper version tracking even though v1 is being deprecated.

### Proof of Concept

**Initial State**:
1. V1 NativePool deployed and operational
2. Users stake and unstake, accumulating fees in `collectable_fee`
3. Example: 100 SUI accumulated in collectable_fee from past unstakes

**Migration Execution**:
1. Call `init_objects` - pauses pool, checks collected_rewards != 0
2. Call `create_stake_pool` - creates v2 StakePool
3. Call `export_stakes` - withdraws all staked assets from v1, adds to migration_storage
4. Call `take_unclaimed_fees` - extracts collected_rewards amount from migration_storage, sets collected_rewards=0
   - Note: This does NOT touch the collectable_fee Coin
5. Call `import_stakes` - imports stakes into v2 pool
6. Call `destroy_migration_cap` - verifies migration complete

**Actual Result**:
- V2 StakePool has all the staked assets
- V1 NativePool still contains 100 SUI in collectable_fee
- These 100 SUI are protocol fees that should have been migrated

**Expected Result**:
- All funds including collectable_fee should be migrated to v2 or transferred to protocol treasury
- V1 NativePool should have zero remaining balances

**Verification**:
After migration, query v1 NativePool and check `coin::value(&native_pool.collectable_fee)` - it will be non-zero if fees accumulated before migration.

### Notes

This issue highlights the lack of comprehensive migration testing. A proper test suite would have:
1. Verified complete fund migration (stakes + all fee types)
2. Checked v1 pool has zero balances post-migration
3. Validated ratio correctness across the migration
4. Tested edge cases like partial migrations or failures

The VERSION=2 constant in manage.move correctly indicates v2 exists, and the migration infrastructure is present. However, the migration implementation is incomplete, specifically regarding the collectable_fee coin migration. This is a Medium severity finding as it affects fund custody integrity and requires manual recovery, though funds are not permanently lost.

### Citations

**File:** liquid_staking/sources/volo_v1/native_pool.move (L124-155)
```text
    public struct NativePool has key {
        id: UID,

        pending: Coin<SUI>, // pending SUI that should be staked
        collectable_fee: Coin<SUI>, // owner fee
        validator_set: ValidatorSet, // pool validator set
        ticket_metadata: unstake_ticket::Metadata,

        /* Store active stake of each epoch */
        total_staked: Table<u64, u64>,
        staked_update_epoch: u64,

        /* Fees */
        base_unstake_fee: u64, // percent of fee per 1 SUI
        unstake_fee_threshold: u64, // percent of active stake
        base_reward_fee: u64, // percent of rewards

        /* Access */
        version: u64,
        paused: bool,

        /* Limits */
        min_stake: u64, // all stakes should be greater than

        /* General stats */
        total_rewards: u64, // current rewards of pool, we can't calculate them, because it's impossible to do on current step
        collected_rewards: u64, // rewards that stashed as protocol fee

        /* Thresholds */
        rewards_threshold: u64, // percent of rewards that possible to increase
        rewards_update_ts: u64, // timestamp when we updated rewards last time
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L478-481)
```text
        // extract our fees
        assert!(balance::value(&total_removed_balance) >= fee + collectable_reward, E_NOT_ENOUGH_BALANCE);
        let fee_balance = balance::split(&mut total_removed_balance, fee + collectable_reward);
        coin::join(&mut self.collectable_fee, coin::from_balance(fee_balance, ctx));
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L527-538)
```text
    public entry fun collect_fee(self: &mut NativePool, to: address, _owner_cap: &OwnerCap, ctx: &mut TxContext) {
        assert_version(self);
        when_not_paused(self);

        let value = coin::value(&self.collectable_fee);
        transfer::public_transfer(coin::split(&mut self.collectable_fee, value, ctx), to);

        event::emit(FeeCollectedEvent{
            to,
            value,
        })
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L557-566)
```text
    entry fun migrate(self: &mut NativePool, _owner_cap: &OwnerCap) {
        assert!(self.version < VERSION, E_INCOMPATIBLE_VERSION);

        event::emit(MigratedEvent {
            prev_version: self.version,
            new_version: VERSION,
        });

        self.version = VERSION;
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L594-596)
```text
    public(package) fun mut_pending(self: &mut NativePool): &mut Coin<SUI> {
        &mut self.pending
    }
```

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
