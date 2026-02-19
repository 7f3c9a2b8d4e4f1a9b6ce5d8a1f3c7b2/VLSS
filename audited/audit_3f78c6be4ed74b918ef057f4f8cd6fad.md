### Title
First-Depositor Attack via Ratio Check Bypass Enables Complete Fund Theft During Migration

### Summary
The special case condition at line 259 bypasses the critical ratio invariant when `old_sui_supply > 0 && old_lst_supply == 0`, allowing the first staker to mint LST at a 1:1 ratio regardless of existing pool SUI balance. This enables a first-depositor attack where an attacker can stake a minimal amount (e.g., 1 SUI) when the pool contains migrated funds, receive 100% LST ownership, and immediately unstake to extract nearly all pool assets. The vulnerability manifests during migration scenarios where v1 CERT tokens are completely burned before importing SUI to the v2 pool.

### Finding Description

The vulnerability originates from a special case bypass in the `stake()` function that was likely intended to enable pool restart after migration but instead creates a severe first-depositor attack vector.

**Root Cause:**

The ratio invariant check is bypassed when the pool has SUI but zero LST supply: [1](#0-0) 

When `old_lst_supply == 0`, the conversion function returns a 1:1 ratio regardless of existing pool balance: [2](#0-1) 

**How This State Occurs:**

The protocol uses a single shared `Metadata<CERT>` object for tracking total CERT supply across the entire protocol: [3](#0-2) 

During migration, SUI is imported directly to the v2 pool WITHOUT minting any LST: [4](#0-3) 

If all v1 users unstake before migration (burning all CERT globally), then remaining SUI (fees, unclaimed rewards) is imported to v2, creating the dangerous state: `total_sui_supply > 0` but `total_lst_supply == 0`.

**Exploitation Path:**

1. **Initial State**: v2 pool has 10,000 SUI imported from migration, 0 global CERT supply
2. **Attack Phase 1**: Attacker stakes 1 SUI
   - Receives 0.999 LST at 1:1 ratio (after 0.1% fee)
   - Special case bypasses ratio protection
   - Attacker now owns 100% of LST supply
3. **Attack Phase 2**: Attacker immediately unstakes 0.999 LST
   - Conversion extracts proportional SUI: [5](#0-4) 
   - Receives (10,000.999 × 0.999) / 0.999 = 10,000.999 SUI (minus fees)
   - Pool completely drained

**Why Protections Fail:**

The unstake ratio check passes because the attacker owns 100% of supply, making the exchange rate appear fair: [6](#0-5) 

### Impact Explanation

**Direct Harm:**
- Complete theft of all migrated SUI funds from the v2 pool
- In a realistic migration scenario with 10,000 SUI migrated, attacker profits ~9,990 SUI from 1 SUI investment (999,000% ROI)
- Protocol loses all imported assets intended for legitimate stakers

**Affected Parties:**
- Protocol: Complete loss of migrated treasury/fee reserves
- Legitimate users: No assets available to stake against post-migration
- v1 users: If they burned CERT expecting fair migration, their proportional value is stolen

**Severity Justification:**
CRITICAL severity due to:
- 100% fund extraction possible with minimal capital
- Attack executable in two simple transactions by any user
- No recovery mechanism once exploited
- Undermines entire migration process integrity

### Likelihood Explanation

**Attacker Capabilities:**
- Requires no special privileges, only access to public `stake_entry` function
- Needs minimal capital (0.1 - 1 SUI) to execute
- Must be first staker after pool is unpaused post-migration

**Attack Complexity:**
- LOW: Two-transaction sequence (stake → unstake)
- No timing complexity beyond being first after unpause
- Easily executable via standard wallet or script

**Feasibility Conditions:**
The vulnerable state occurs when:
1. **Migration scenario**: All v1 CERT burned (users unstaked), then SUI imported to v2 for fees/reserves
2. **Fresh deployment**: Admin adds initial SUI liquidity before any user stakes

The migration scenario is realistic because:
- Clean migration strategy would deprecate v1, requiring users to unstake
- Remaining SUI (accumulated fees, rounding dust, unclaimed rewards) would be migrated
- The migration sanity check allows `ratio == 0` when LST supply is zero: [7](#0-6) 

**Probability Assessment:**
MEDIUM-HIGH likelihood because:
- Migration design encourages complete v1 burnout before importing
- Admin must unpause pool for normal operations, creating exploitation window
- Attacker can monitor chain for pool unpause event and frontrun legitimate stakers
- No mitigation prevents first-depositor attack once vulnerable state exists

### Recommendation

**Immediate Mitigation:**

1. **Mint Initial LST During Migration**: In `import_stakes`, mint proportional CERT to a reserve address equal to imported SUI amount:
   ```move
   // After line 173 in migrate.move
   let reserve_lst = metadata.mint(amount, ctx);
   transfer::public_transfer(reserve_lst, RESERVE_ADDRESS);
   ```

2. **Add Minimum LST Supply Check**: Before allowing stakes when LST supply is low: [8](#0-7) 
   ```move
   if (old_sui_supply > MIN_SUI_THRESHOLD && old_lst_supply == 0) {
       abort E_UNSAFE_POOL_STATE
   };
   ```

3. **Remove Dangerous Special Case**: The bypass at line 259 should be removed entirely. If migration requires special handling, use a dedicated migration-only mint function with explicit admin authorization rather than a blanket bypass in the public stake path.

**Invariant Checks:**
- Assert `total_lst_supply > 0` whenever `total_sui_supply > MIN_THRESHOLD`
- Enforce minimum initial liquidity deposit with corresponding LST mint
- Add migration completion flag that prevents stake until proper LST/SUI ratio established

**Test Cases:**
- Test migration with complete v1 CERT burnout scenario
- Verify first staker cannot extract disproportionate value
- Test edge case: SUI > 0, LST = 0 must revert or require special admin action
- Validate ratio invariants hold across all stake/unstake sequences post-migration

### Proof of Concept

**Required Initial State:**
- v2 StakePool migrated with 10,000 SUI via `import_stakes`
- Global CERT total supply: 0 (all v1 users unstaked)
- Pool status: UNPAUSED (step 6 of migration complete)

**Transaction Sequence:**

**TX 1 - Attacker Stakes:**
```
stake_entry(stake_pool, metadata, system_state, Coin<SUI>(1_000_000_000))

Expected: Receive ~1 LST proportional to pool ratio
Actual: Receives 0.999 LST (1:1 ratio) despite pool having 10,000 SUI
Result: Attacker owns 100% of LST supply with 0.999 CERT
```

**TX 2 - Attacker Unstakes:**
```
unstake_entry(stake_pool, metadata, system_state, Coin<CERT>(999_000_000))

Expected: Receive ~1 SUI proportional to attacker's ownership
Actual: Receives ~9,991 SUI (nearly entire pool balance)
Result: Pool drained from 10,000.999 SUI to ~10 SUI (only fees remain)
```

**Success Condition:**
- Attacker balance: +9,990 SUI (from 1 SUI investment)
- Pool balance: ~10 SUI remaining (>99.9% stolen)
- Attack ROI: ~999,000%

**Verification:**
The special case bypass allows the attack: [9](#0-8) 

The 1:1 conversion enables disproportionate minting: [10](#0-9)

### Citations

**File:** liquid_staking/sources/stake_pool.move (L232-233)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);
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

**File:** liquid_staking/sources/stake_pool.move (L628-645)
```text
    public fun sui_amount_to_lst_amount(
        self: &StakePool, 
        metadata: &Metadata<CERT>,
        sui_amount: u64
    ): u64 {
        let total_sui_supply = self.total_sui_supply();
        let total_lst_supply = metadata.get_total_supply_value();

        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return sui_amount
        };

        let lst_amount = (total_lst_supply as u128)
            * (sui_amount as u128)
            / (total_sui_supply as u128);

        lst_amount as u64
    }
```

**File:** liquid_staking/sources/stake_pool.move (L657-659)
```text
        let sui_amount = (total_sui_supply as u128)
            * (lst_amount as u128) 
            / (total_lst_supply as u128);
```

**File:** liquid_staking/sources/cert.move (L51-67)
```text
    fun init(witness: CERT, ctx: &mut TxContext) {
        // create coin with metadata
        let (treasury_cap, metadata) = coin::create_currency<CERT>(
            witness, DECIMALS, b"vSUI", b"Volo Staked SUI",
            b"Volo's SUI staking solution provides the best user experience and highest level of decentralization, security, combined with an attractive reward mechanism and instant staking liquidity through a bond-like synthetic token called voloSUI.",
            option::some<Url>(url::new_unsafe_from_bytes(b"https://volo.fi/vSUI.png")),
            ctx
        );
        transfer::public_freeze_object(metadata);
        // destroy treasury_cap and store it custom Metadata object
        let supply = coin::treasury_into_supply(treasury_cap);
        transfer::share_object(Metadata<CERT> {
                id: object::new(ctx),
                version: VERSION,
                total_supply: supply,
        });
    }
```

**File:** liquid_staking/sources/migration/migrate.move (L173-173)
```text
        stake_pool.join_to_sui_pool(migration_storage.sui_balance.split(amount));
```
