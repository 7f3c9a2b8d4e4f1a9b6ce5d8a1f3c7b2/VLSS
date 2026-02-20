# Audit Report

## Title
First-Depositor Attack via Ratio Check Bypass Enables Complete Fund Theft During Migration

## Summary
A critical vulnerability in the liquid staking pool allows complete theft of migrated funds through a special case bypass in the ratio invariant check. When the pool contains SUI but has zero LST supply (a realistic post-migration state), an attacker can mint LST tokens at a 1:1 ratio and immediately drain all pool funds with minimal capital investment.

## Finding Description

The vulnerability exists in the `stake()` function's ratio invariant check, which contains a special case bypass that permits staking when `old_sui_supply > 0 && old_lst_supply == 0`. [1](#0-0) 

When LST supply is zero, the conversion function `sui_amount_to_lst_amount()` returns a 1:1 ratio regardless of the existing pool SUI balance. [2](#0-1) 

**How the Vulnerable State Occurs:**

The protocol uses a single shared `Metadata<CERT>` object to track total CERT supply globally. [3](#0-2) 

During migration, the `import_stakes()` function imports SUI directly to the v2 pool without minting any LST tokens via `join_to_sui_pool()`. [4](#0-3) 

If all v1 users unstake before migration (burning all CERT globally), remaining SUI from accumulated fees, unclaimed rewards, or rounding dust is imported to v2, creating the vulnerable state: `total_sui_supply > 0` but `total_lst_supply == 0`.

**Exploitation Sequence:**

1. **Initial State**: v2 pool contains 10,000 SUI from migration, global CERT supply is 0

2. **Attack Phase 1** - Attacker stakes 1 SUI via the public `stake_entry()` function [5](#0-4) :
   - After 0.1% fee deduction [6](#0-5) , 0.999 SUI is deposited
   - `sui_amount_to_lst_amount()` returns 0.999 LST (1:1 ratio due to zero supply)
   - Normal ratio check would fail: `0.999 * 10000 <= 0.999 * 0` → `9990 <= 0` is FALSE
   - Special case condition passes: `10000 > 0 && 0 == 0` → TRUE, bypassing protection
   - Attacker now owns 100% of LST supply

3. **Attack Phase 2** - Attacker immediately unstakes 0.999 LST:
   - Conversion calculates proportional SUI: `(10000.999 * 0.999) / 0.999 = 10000.999`
   - Unstake ratio check passes because attacker owns 100% of supply [7](#0-6) 
   - After unstake fees, attacker receives approximately 10,000 SUI
   - Pool completely drained

**Why Existing Protections Fail:**

The migration sanity check's `get_ratio()` function returns 0 when LST supply is zero, allowing the vulnerable state to persist after import. [8](#0-7) 

The pause mechanism doesn't prevent this attack because the admin must unpause the pool for normal operations post-migration. [9](#0-8) 

## Impact Explanation

**Critical Severity:**

1. **Complete Fund Theft**: An attacker can extract 100% of migrated pool funds. In the example scenario, 9,999 SUI profit from 1 SUI investment represents a 999,900% ROI.

2. **No Recovery Mechanism**: Once exploited, stolen funds cannot be recovered and pool integrity cannot be restored.

3. **Undermines Migration Process**: The entire v1 to v2 migration becomes a honeypot where legitimate users' proportional value in migrated reserves is stolen.

4. **Affects Multiple Parties**:
   - Protocol: Complete loss of migrated treasury/fee reserves
   - Legitimate users: No assets available to stake against post-migration
   - v1 users: Proportional value in migrated reserves stolen if they burned CERT expecting fair migration

## Likelihood Explanation

**Medium-High Likelihood:**

**Attacker Requirements:**
- No special privileges required - only access to public entry function
- Minimal capital needed (0.1 SUI minimum stake amount)
- Must be first staker after pool unpause post-migration

**Attack Complexity:**
- LOW: Simple two-transaction sequence (stake → unstake)
- No complex timing requirements beyond being first after unpause
- Easily executable via standard wallet or script
- Can monitor blockchain for pool unpause transaction and frontrun legitimate stakers

**Realistic Preconditions:**

The vulnerable state occurs in realistic migration scenarios:
- Clean migration strategy requires v1 deprecation, causing users to unstake
- Remaining SUI from accumulated fees, rounding dust, and unclaimed rewards would be migrated
- Admin must unpause pool for normal operations, creating the exploitation window

The migration design encourages this flow through its multi-step process where SUI import happens after CERT burning.

## Recommendation

**Immediate Fix:**

Remove the special case bypass or restrict it to a privileged initialization function. Modify the ratio check to always enforce the invariant:

```move
// Remove the special case entirely
assert!(
    (lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply,
    ERatio
);
```

**Alternative Secure Approaches:**

1. **Protected First Stake**: Add an admin-only function for the first stake that properly mints LST tokens proportional to existing SUI.

2. **Migration Atomicity**: Ensure migration mints the correct amount of LST tokens when importing SUI to maintain proper ratio from the start.

3. **Pre-stake During Migration**: Before unpausing, have the admin perform a protected first stake that establishes the correct ratio.

## Proof of Concept

```move
#[test]
fun test_first_depositor_attack() {
    // Setup: Create scenario where pool has 10,000 SUI but 0 LST supply after migration
    let mut scenario = test_scenario::begin(@attacker);
    
    // Step 1: Initialize pool with migrated state (10,000 SUI, 0 CERT)
    let (mut stake_pool, mut metadata, mut system_state) = setup_migrated_pool(&mut scenario);
    
    // Verify initial state
    assert!(stake_pool.total_sui_supply() == 10_000_000_000_000, 0); // 10,000 SUI
    assert!(metadata.get_total_supply_value() == 0, 1); // 0 CERT
    
    // Step 2: Attacker stakes 1 SUI
    stake_pool.set_paused(&admin_cap, false);
    let attacker_sui = coin::mint_for_testing<SUI>(1_000_000_000, scenario.ctx()); // 1 SUI
    let cert = stake_pool.stake(&mut metadata, &mut system_state, attacker_sui, scenario.ctx());
    
    // Verify attacker received ~0.999 CERT (after 0.1% fee)
    assert!(cert.value() > 999_000_000 && cert.value() < 1_000_000_000, 2);
    
    // Step 3: Attacker immediately unstakes to drain pool
    let sui_back = stake_pool.unstake(&mut metadata, &mut system_state, cert, scenario.ctx());
    
    // Verify attacker extracted almost all pool funds
    assert!(sui_back.value() > 9_990_000_000_000, 3); // ~9,990+ SUI stolen
    
    // Pool is now drained
    test_scenario::end(scenario);
}
```

### Citations

**File:** liquid_staking/sources/stake_pool.move (L31-31)
```text
    const MIN_STAKE_AMOUNT: u64 = 1_00_000_000; // 0.1 SUI
```

**File:** liquid_staking/sources/stake_pool.move (L176-186)
```text
    public entry fun stake_entry(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let cert = self.stake(metadata, system_state, sui, ctx);
        transfer::public_transfer(cert, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L257-261)
```text
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L325-328)
```text
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L592-594)
```text
        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return 0
        };
```

**File:** liquid_staking/sources/stake_pool.move (L636-638)
```text
        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return sui_amount
        };
```

**File:** liquid_staking/sources/cert.move (L62-66)
```text
        transfer::share_object(Metadata<CERT> {
                id: object::new(ctx),
                version: VERSION,
                total_supply: supply,
        });
```

**File:** liquid_staking/sources/migration/migrate.move (L173-173)
```text
        stake_pool.join_to_sui_pool(migration_storage.sui_balance.split(amount));
```

**File:** liquid_staking/sources/manage.move (L25-27)
```text
    public fun check_not_paused(self: &Manage) {
        assert!(!self.paused, EIncompatiblePaused)
    }
```
