# Audit Report

## Title
Incomplete Migration Allows Permanent Loss of User Funds Due to Unverified Export Completion

## Summary
The v1 to v2 migration can be finalized before all staked assets are exported, permanently locking user funds. The `destroy_migration_cap` function accepts a caller-provided count without verifying all validator vaults are fully exported, allowing premature migration completion.

## Finding Description

The `destroy_migration_cap` function validates migration completion by comparing `migration_storage.exported_count` against a caller-provided `target_exported_count` parameter, without verifying this target represents the actual total number of stakes in the v1 system. [1](#0-0) 

The function only checks:
1. `exported_count == target_exported_count` (caller-provided value)
2. `sui_balance == 0` (all exported SUI was imported)  
3. `pool_created` and `fees_taken` flags

**Why This Fails:**

The v1 `ValidatorSet` stores stakes in vaults with `gap` and `length` fields tracking removal progress. Each vault is fully exported when `gap == length`. [2](#0-1) 

The `export_stakes` function iterates through stakes while `vault.gap < vault.length`, but stops when iterations run out. The operator can stop calling this function before all vaults are exhausted. [3](#0-2) 

There is **no check** in `destroy_migration_cap` that verifies all vaults have reached `gap == length` (fully exported state). The protocol provides no way to query the actual total number of stakes across all vaults.

**No Recovery Path:**

Once `destroy_migration_cap` is called, the `MigrationCap` is permanently consumed and destroyed. The `init_objects` function can only be called once due to the `mark_cap_created` protection: [4](#0-3) [5](#0-4) 

All v1 staking and unstaking functions are deprecated and abort with `E_DEPRECATED`, making remaining stakes permanently inaccessible: [6](#0-5) [7](#0-6) 

## Impact Explanation

**HIGH Severity - Permanent Fund Loss**

- **Direct Impact**: User funds (StakedSui objects) remaining in v1 vaults become permanently locked with zero recovery mechanism
- **Affected Users**: Any users whose stakes were not exported before migration completion. With thousands of stakes across validators, a significant portion could remain unexported
- **Loss Amount**: Proportional to the number of unexported stakes - potentially substantial given the scale of v1 operations
- **Invariant Violation**: Directly violates the fund custody invariant - users cannot access their principal through any means:
  - Cannot unstake from v1 (all functions deprecated)
  - Cannot continue migration (cap destroyed, cannot be recreated)  
  - No emergency recovery mechanism exists

This represents unrecoverable permanent loss of user deposits, justifying HIGH severity.

## Likelihood Explanation

**MEDIUM to HIGH Likelihood - Realistic Operational Error**

This is an **operational error** scenario rather than a malicious attack:

1. **Realistic Preconditions**:
   - Operator has legitimate access to MigrationCap (trusted role)
   - With gas limits and thousands of stakes, `export_stakes` must be called multiple times
   - No on-chain verification of progress or completeness exists

2. **Error Path**:
   - Operator calls `export_stakes` multiple times but loses track of progress
   - Operator checks that `sui_balance == 0` (all exported funds were imported) 
   - This falsely signals migration completion
   - Operator provides partial count as `target_exported_count`
   - `destroy_migration_cap` accepts the partial count and succeeds

3. **Why This Will Occur**:
   - Single-shot irreversible operation with no rollback capability
   - Complex multi-step process prone to human error
   - No programmatic safeguards against premature completion
   - Balance being zero creates false confidence that migration is complete
   - Off-chain tracking required but not enforced on-chain

The combination of complexity, irreversibility, and lack of safeguards makes this error scenario highly probable in production.

## Recommendation

Add explicit validation that all vaults have completed export before allowing migration cap destruction:

```move
public fun destroy_migration_cap(
    migration_cap: MigrationCap,
    migration_storage: &MigrationStorage,
    validator_set: &ValidatorSet, // Add reference to check completion
    target_exported_count: u64,
) {
    // Existing checks
    assert!(migration_storage.exported_count == target_exported_count, 1);
    assert!(migration_storage.sui_balance.value() == 0, 3);
    
    // NEW: Verify all vaults are fully exported
    let validators = validator_set.get_validators();
    let mut i = 0;
    while (i < validators.length()) {
        let validator = validators[i];
        if (validator_set.vaults.contains(validator)) {
            let vault = validator_set.vaults.borrow(validator);
            assert!(vault.gap == vault.length, 4); // All stakes exported
        };
        i = i + 1;
    };
    
    let MigrationCap{ id, pool_created, fees_taken } = migration_cap;
    assert!(pool_created, 0);
    assert!(fees_taken, 2);
    id.delete();
}
```

Additionally, provide a read function to get the total number of stakes remaining:

```move
public fun get_remaining_stakes_count(validator_set: &ValidatorSet): u64 {
    let validators = validator_set.get_validators();
    let mut remaining = 0;
    let mut i = 0;
    while (i < validators.length()) {
        let validator = validators[i];
        if (validator_set.vaults.contains(validator)) {
            let vault = validator_set.vaults.borrow(validator);
            remaining = remaining + (vault.length - vault.gap);
        };
        i = i + 1;
    };
    remaining
}
```

## Proof of Concept

Due to the complexity of setting up a full migration environment with v1 stakes, v2 pool, and system state, a complete PoC would require extensive test infrastructure. However, the vulnerability is evident from the code structure:

1. The `destroy_migration_cap` function accepts `target_exported_count` as a parameter without validation
2. There is no check that iterates through vaults to verify `gap == length`
3. The `mark_cap_created` protection prevents recovery
4. All v1 functions abort with `E_DEPRECATED`

The exploit requires:
- Multiple calls to `export_stakes` with limited iterations
- Call to `import_stakes` to zero the balance
- Call to `destroy_migration_cap` with partial count
- Result: unexported stakes permanently locked

### Citations

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

**File:** liquid_staking/sources/volo_v1/validator_set.move (L44-49)
```text
    public struct Vault has store {
        stakes: ObjectTable<u64, StakedSui>,
        gap: u64,
        length: u64,
        total_staked: u64,
    }
```

**File:** liquid_staking/sources/volo_v1/validator_set.move (L344-366)
```text
    fun export_stakes(
        vault: &mut Vault,
        iterations: &mut u64,
        exported_count: &mut u64,
        exported_sui_amount: &mut u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ):(Balance<SUI>) {
        let mut exported_sui = balance::zero<SUI>();
        
        while (*iterations > 0 && vault.gap < vault.length) {
            let staked_sui_to_withdraw = object_table::remove(&mut vault.stakes, vault.gap);
            vault.gap = vault.gap + 1; // increase table gap
            let withdrawn = sui_system::request_withdraw_stake_non_entry(system_state, staked_sui_to_withdraw, ctx);

            *exported_sui_amount = *exported_sui_amount + withdrawn.value();
            *exported_count = *exported_count + 1;
            *iterations = *iterations - 1;

            exported_sui.join(withdrawn);
        };
        exported_sui
    }
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L53-53)
```text
    const E_DEPRECATED: u64 = 999;
```

**File:** liquid_staking/sources/volo_v1/native_pool.move (L385-421)
```text
    public entry fun stake(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, coin: Coin<SUI>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    // exchange SUI to CERT, add SUI to pending and try to stake pool
    public fun stake_non_entry(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, coin: Coin<SUI>, ctx: &mut TxContext): Coin<CERT> {
        abort E_DEPRECATED
    }

    // stake pending
    fun stake_pool(self: &mut NativePool, wrapper: &mut SuiSystemState, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    /// merge ticket with it burning to make instant unstake
    public entry fun unstake(self: &mut NativePool, metadata: &mut Metadata<CERT>, wrapper: &mut SuiSystemState, cert: Coin<CERT>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    public entry fun mint_ticket(self: &mut NativePool, metadata: &mut Metadata<CERT>, cert: Coin<CERT>, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    /// burns CERT and put output amount of SUI to it
    /// In case if issued ticket supply greater than active stake ticket should be locked until next epoch
    public fun mint_ticket_non_entry(self: &mut NativePool, metadata: &mut Metadata<CERT>, cert: Coin<CERT>, ctx: &mut TxContext): UnstakeTicket {
        abort E_DEPRECATED
    }

    // burn ticket to release unstake
    public entry fun burn_ticket(self: &mut NativePool, wrapper: &mut SuiSystemState, ticket: UnstakeTicket, ctx: &mut TxContext) {
        abort E_DEPRECATED
    }

    public fun burn_ticket_non_entry(self: &mut NativePool, wrapper: &mut SuiSystemState, ticket: UnstakeTicket, ctx: &mut TxContext): Coin<SUI> {
        abort E_DEPRECATED
    }
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
