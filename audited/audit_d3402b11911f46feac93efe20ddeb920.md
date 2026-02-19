### Title
Premature Pool Activation During Partial Migration Breaks LST-to-SUI Ratio Invariant

### Summary
The migration process from v1 to v2 allows an admin to unpause the StakePool after only partial stake import, even though `check_version()` passes. This creates an undercollateralized state where the full LST supply exists but only partial SUI backing is present, violating the critical LST-to-SUI ratio invariant and causing direct fund loss for existing LST holders.

### Finding Description

The vulnerability exists in the interaction between the version check system and the migration flow: [1](#0-0) 

When a new v2 StakePool is created during migration, it is initialized with `VERSION=2` and `paused=true`: [2](#0-1) [3](#0-2) 

The migration flow allows multiple calls to `import_stakes` with partial amounts: [4](#0-3) 

**Root Cause:** The `set_paused` function requires only `AdminCap` and performs only a version check, with no validation that migration is complete: [5](#0-4) 

The MigrationCap tracks migration state but is never checked by `set_paused`. The migration comments indicate the pool should remain paused until after migration completes: [6](#0-5) 

However, this intended flow has no programmatic enforcement. An admin can call `set_paused(false)` at any time after pool creation, even with partial migration.

**Why Existing Protections Fail:**

1. `check_version()` passes immediately since the new pool starts at VERSION=2
2. The ratio invariant checks in stake/unstake only validate local transaction consistency, not global state correctness: [7](#0-6) [8](#0-7) 

These checks ensure `lst_out / sui_in ≤ old_lst_supply / old_sui_supply` but cannot detect that `old_lst_supply / old_sui_supply` itself is incorrect due to partial migration.

3. The `destroy_migration_cap` validation ensures complete migration before cap destruction but doesn't prevent premature unpausing: [9](#0-8) 

### Impact Explanation

**Direct Fund Loss:** When the pool is unpaused with only partial SUI imported:

Assume v1 had 1000 SUI backing 1000 CERT (1:1 ratio). After importing only 500 SUI:
- v2 has 500 SUI total supply
- CERT metadata shows 1000 total supply  
- Actual ratio: 0.5 SUI per CERT (should be 1.0)

**Impact on Existing CERT Holders:**
- User with 100 CERT expects 100 SUI
- Actually receives: (500 × 100) / 1000 = 50 SUI
- **Loss: 50% of funds**

**Impact on New Stakers:**
- User stakes 100 SUI (99 after fees)
- Receives: (1000 × 99) / 500 = 198 CERT
- Expected: ~99 CERT
- **Gain: ~2x tokens (extracting value from existing holders)**

**Bank Run Risk:** Only 500 SUI backs 1000 CERT. First unstakers succeed; later unstakers face insufficient liquidity.

**Severity:** Critical - direct loss of user funds, breaks fundamental LST peg invariant, affects all existing LST holders proportionally to how much of the migration is incomplete.

### Likelihood Explanation

**Feasibility Conditions:**
- Requires admin to call `set_paused(false)` during active migration
- Does NOT require malicious admin - honest operational error during complex multi-step migration
- No programmatic guardrails prevent this action
- Admin might reasonably assume safety because `check_version()` passes

**Attack Complexity:** 
- Not an "attack" but an operational error
- Migration is multi-step process with no atomic guarantees
- Admin could unpause thinking one import completed the migration when more remains
- No warning or reversion when unpausing during incomplete migration

**Detection/Prevention:**
- No on-chain enforcement
- Off-chain monitoring would need to track MigrationStorage balance and compare to expected total
- Error is permanent once users interact with incorrect ratio

**Probability:** Medium-High for operational error during migration execution, especially given:
- Complex migration flow with 6+ steps
- No status tracking visible to admin besides external balance checks
- Version check passing gives false confidence

### Recommendation

**Add Migration Completion Check:**

Modify `set_paused` in `stake_pool.move` to accept an optional MigrationCap parameter. When unpausing, require either:
1. MigrationCap is provided AND has been destroyed (proving migration complete), OR
2. Pool was never in migration (no MigrationCap ever existed for this pool)

```move
public fun set_paused(
    self: &mut StakePool, 
    _: &AdminCap, 
    paused: bool,
    // Require proof of completed migration when unpausing
    migration_completed: Option<MigrationCompletionProof>
) {
    self.manage.check_version();
    
    // When unpausing, verify migration is complete if applicable
    if (!paused && option::is_some(&migration_completed)) {
        let proof = option::destroy_some(migration_completed);
        // Validate proof shows migration cap was properly destroyed
        verify_migration_completion(proof);
    };
    
    self.manage.set_paused(paused);
    emit(SetPausedEvent {paused});
}
```

**Alternative Simpler Fix:**

Add a flag to MigrationStorage indicating migration is active. Check this flag in `set_paused`:

```move
public fun set_paused(self: &mut StakePool, _: &AdminCap, paused: bool) {
    self.manage.check_version();
    
    // Prevent unpausing during active migration
    assert!(paused || !is_migration_active(self), EMigrationInProgress);
    
    self.manage.set_paused(paused);
    emit(SetPausedEvent {paused});
}
```

**Test Cases:**
1. Verify cannot unpause pool while MigrationCap exists
2. Verify cannot unpause pool while MigrationStorage has non-zero balance
3. Verify can unpause only after `destroy_migration_cap` succeeds
4. Verify ratio remains consistent if attempting partial migration then full continuation

### Proof of Concept

**Initial State:**
- v1 NativePool: 1000 SUI staked, 1000 CERT minted (1:1 ratio)
- Users hold 1000 CERT tokens

**Migration Steps:**

1. Admin calls `init_objects` → v1 paused, MigrationCap created
2. Admin calls `create_stake_pool` → v2 StakePool created (VERSION=2, paused=true)
3. Admin calls `export_stakes` → exports all 1000 SUI to MigrationStorage
4. Admin calls `import_stakes(amount=500)` → imports only 500 SUI to v2
   - v2 now has: total_sui_supply = 500, total_lst_supply = 1000
   - MigrationStorage has: 500 SUI remaining
   - Pool is re-paused after import

**Vulnerability Trigger:**

5. **Admin mistakenly calls `set_paused(admin_cap, false)`** → pool unpaused
   - ✓ check_version() passes (already at VERSION=2)
   - ✓ No MigrationCap check performed
   - Pool now operational with broken ratio

**Expected Result:** Transaction should revert with "Migration incomplete" error

**Actual Result:** Pool successfully unpauses

**Exploitation:**

6. User A (existing CERT holder) calls `unstake_entry` with 100 CERT:
   - Expects: 100 SUI  
   - Receives: (500 × 100) / 1000 = 50 SUI
   - **Loss: 50 SUI**

7. User B (new staker) calls `stake_entry` with 100 SUI:
   - After 1% fee: 99 SUI deposited
   - Receives: (1000 × 99) / 500 = 198 CERT
   - **Unfair gain: ~99 extra CERT tokens**

**Success Condition:** Both transactions succeed with incorrect ratios, violating the fundamental LST peg invariant and causing measurable fund loss for existing holders.

### Citations

**File:** liquid_staking/sources/manage.move (L13-15)
```text
    public(package) fun new(): Manage {
        Manage { version: current_version(), paused: true }
    }
```

**File:** liquid_staking/sources/manage.move (L21-23)
```text
    public fun check_version(self: &Manage) {
        assert!(self.version == VERSION, EIncompatibleVersion)
    }
```

**File:** liquid_staking/sources/stake_pool.move (L149-172)
```text
    fun create_lst_with_validator_pool(
        validator_pool: ValidatorPool,
        ctx: &mut TxContext
    ): (AdminCap, StakePool) {
        let uid = object::new(ctx);

        let fee_config = fee_config::new(ctx);

        (
            AdminCap { id: object::new(ctx) },

            StakePool {
                id: uid,
                fee_config: fee_config,
                fees: balance::zero(),
                boosted_balance: balance::zero(),
                boosted_reward_amount: 0,
                accrued_reward_fees: 0,
                validator_pool,
                manage: manage::new(),
                extra_fields: bag::new(ctx)
            }
        )
    }
```

**File:** liquid_staking/sources/stake_pool.move (L255-261)
```text
        // invariant: lst_out / sui_in <= old_lst_supply / old_sui_supply
        // -> lst_out * old_sui_supply <= sui_in * old_lst_supply
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L323-328)
```text
        // invariant: sui_out / lst_in <= old_sui_supply / old_lst_supply
        // -> sui_out * old_lst_supply <= lst_in * old_sui_supply
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L336-340)
```text
    public fun set_paused(self: &mut StakePool, _: &AdminCap, paused: bool) {
        self.manage.check_version();
        self.manage.set_paused(paused);
        emit(SetPausedEvent {paused});
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
