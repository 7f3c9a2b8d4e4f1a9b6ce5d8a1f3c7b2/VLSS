### Title
Protocol Brick Risk: Forgotten Migration After Module Upgrade Causes Complete DoS

### Summary
The `cert.move` module uses a version mismatch check that will cause all staking and unstaking operations to fail if the module is upgraded with an incremented `VERSION` constant but the `migrate()` function is not called. This operational error would completely brick the liquid staking protocol until the migration is manually executed.

### Finding Description

The `cert.move` module implements version management through a hardcoded `VERSION` constant and a `version` field in the `Metadata<CERT>` object: [1](#0-0) 

The `Metadata<CERT>` struct tracks its version: [2](#0-1) 

All critical mint and burn operations enforce strict version equality through `assert_version()`: [3](#0-2) [4](#0-3) [5](#0-4) 

The version check implementation aborts if there's any mismatch: [6](#0-5) 

The migration function exists but must be manually called: [7](#0-6) 

**Root Cause:** The protocol requires two separate steps during module upgrades: (1) deploying the new module code with incremented `VERSION`, and (2) calling `migrate()` to update the shared `Metadata<CERT>` object. There is no automatic mechanism linking these steps or preventing operations until migration completes.

**Execution Path:**
1. User calls `stake_entry()` or `unstake_entry()` in `stake_pool.move`
2. These call `metadata.mint()` or `metadata.burn_coin()` respectively: [8](#0-7) [9](#0-8) 

3. If `metadata.version` (1) ≠ `VERSION` (2), `assert_version()` aborts with `E_INCOMPATIBLE_VERSION`
4. All staking and unstaking operations fail

### Impact Explanation

**Operational Impact - Complete Protocol DoS:**
- All user staking operations (`stake_entry`, `delegate_stake_entry`) become unusable
- All user unstaking operations (`unstake_entry`) become unusable  
- Users cannot stake new SUI or retrieve their staked SUI
- The entire liquid staking protocol is effectively bricked

**Duration:** The DoS persists until an operator with `OwnerCap` calls the `migrate()` function. This could range from minutes to hours or days depending on:
- Time to detect the issue (only discovered when users attempt transactions)
- Operator availability and response time
- Transaction submission and execution time

**Who is Affected:**
- All protocol users attempting to stake or unstake
- Protocol reputation and user trust
- Integration partners relying on the LST

**Severity Justification:** HIGH - While user funds remain safe (not stolen or lost), the complete inability to access or interact with the protocol constitutes a critical operational failure. The protocol's core functionality is entirely disabled.

### Likelihood Explanation

**Operational Error Scenario - HIGH Likelihood:**

This is not an attack but a realistic operational mistake:

**Preconditions:**
- Module upgrade changing `VERSION` from 1 to 2 (routine maintenance/feature addition)
- Operator oversight in not immediately calling `migrate()` after deployment

**Feasibility:** VERY HIGH
- Module upgrades are standard protocol operations
- Migration is a separate manual transaction requiring `OwnerCap`
- No built-in safeguards prevent transactions between upgrade and migration
- No automated deployment script enforces migration as atomic with upgrade
- Human error in operations is realistic and well-documented in DeFi history

**Detection Constraints:**
- Issue only manifests when first user attempts to stake/unstake post-upgrade
- No pre-upgrade validation checks
- No graceful degradation or warning system

**Probability Reasoning:**
Given the multi-step manual process and lack of safeguards, the probability of this occurring during a module upgrade cycle is significant. Even with documented procedures, operational errors happen, especially during off-hours deployments or emergency upgrades.

### Recommendation

**Immediate Mitigation:**

1. **Add Pre-Transaction Check in Entry Functions:**
Modify `stake_entry()` and `unstake_entry()` to provide clear error messaging:

```move
// In stake_pool.move, before calling metadata.mint()
assert!(
    metadata.version() == cert::current_version(),
    EMigrationRequired
);
```

2. **Implement Version Grace Period:**
Modify `assert_version()` in `cert.move` to allow one version behind:

```move
fun assert_version(metadata: &Metadata<CERT>) {
    assert!(
        metadata.version == VERSION || metadata.version == VERSION - 1,
        E_INCOMPATIBLE_VERSION
    );
}
```

3. **Automated Deployment Script:**
Create a deployment script that atomically:
    - Upgrades the module
    - Immediately calls `migrate()` in the same epoch
    - Validates successful migration before declaring upgrade complete

4. **Add Upgrade Lock:**
Add a safety mechanism in the module:

```move
public struct UpgradeLock has store {
    in_progress: bool,
    target_version: u64
}
```

When upgrade starts, set `in_progress = true` and block all user operations until migration completes.

5. **Monitoring & Alerting:**
    - Monitor for version mismatches in real-time
    - Alert operators immediately if `metadata.version < cert::VERSION`
    - Add health check endpoint exposing version status

**Test Cases:**

```move
#[test]
#[expected_failure(abort_code = E_INCOMPATIBLE_VERSION)]
fun test_mint_fails_without_migration() {
    // 1. Initialize with VERSION = 1
    // 2. Simulate upgrade: set VERSION = 2
    // 3. Attempt mint() without calling migrate()
    // 4. Assert it fails with E_INCOMPATIBLE_VERSION
}

#[test]
fun test_migration_before_operations() {
    // 1. Initialize with VERSION = 1
    // 2. Simulate upgrade: set VERSION = 2
    // 3. Call migrate()
    // 4. Verify mint() and burn() succeed
}
```

### Proof of Concept

**Initial State:**
- `cert.move` deployed with `VERSION = 1`
- `Metadata<CERT>` shared object created with `version = 1`
- Users successfully staking and unstaking

**Upgrade Sequence:**
1. **T0:** Protocol team upgrades `cert.move` module, changing `const VERSION: u64 = 2;`
2. **T0+1 min:** Upgrade transaction confirmed, new module code active
3. **T0+2 min:** Operator intends to call `migrate()` but is delayed (meeting, timezone, oversight)
4. **T0+5 min:** User Alice attempts: `stake_pool::stake_entry(pool, metadata, system, 1000 SUI)`
5. **Execution Flow:**
   - `stake_entry()` → `stake()` (line 219-265)
   - Line 253: calls `metadata.mint(lst_mint_amount, ctx)`
   - Inside `cert::mint()` line 83: calls `assert_version(metadata)`
   - Line 119: checks `metadata.version (1) == VERSION (2)`
   - **ABORT** with `E_INCOMPATIBLE_VERSION (0x1)`
6. **Result:** Alice's transaction fails, funds returned, but protocol unusable
7. **T0+10 min:** User Bob attempts unstake, same failure at `burn_coin()`
8. **T0+30 min:** Support tickets flood in, team realizes migration was forgotten
9. **T0+45 min:** Operator with `OwnerCap` calls `cert::migrate(metadata, owner_cap)`
10. **T0+46 min:** Protocol restored, all operations resume

**Expected:** Operations should work immediately after upgrade  
**Actual:** Complete DoS for 45 minutes due to forgotten migration step  
**Success Condition for Vulnerability:** Any mint/burn operation fails with `E_INCOMPATIBLE_VERSION` when `metadata.version < VERSION`

### Citations

**File:** liquid_staking/sources/cert.move (L27-27)
```text
    const VERSION: u64 = 1;
```

**File:** liquid_staking/sources/cert.move (L42-46)
```text
    public struct Metadata<phantom T> has key, store {
        id: UID,
        version: u64, // Track the current version of the shared object
        total_supply: Supply<T>,
    }
```

**File:** liquid_staking/sources/cert.move (L80-87)
```text
    public(package) fun mint(
        metadata: &mut Metadata<CERT>, shares: u64, ctx: &mut TxContext
    ): Coin<CERT> {
        assert_version(metadata);

        let minted_balance = balance::increase_supply(&mut metadata.total_supply, shares);
        coin::from_balance(minted_balance, ctx)
    }
```

**File:** liquid_staking/sources/cert.move (L90-95)
```text
    public(package) fun burn_coin(
        metadata: &mut Metadata<CERT>, coin: Coin<CERT>
    ): u64 {
        assert_version(metadata);
        balance::decrease_supply(&mut metadata.total_supply, coin::into_balance(coin))
    }
```

**File:** liquid_staking/sources/cert.move (L98-101)
```text
    public(package) fun burn_balance(metadata: &mut Metadata<CERT>, balance: Balance<CERT>): u64 {
        assert_version(metadata);
        balance::decrease_supply(&mut metadata.total_supply, balance)
    }
```

**File:** liquid_staking/sources/cert.move (L105-114)
```text
    entry fun migrate(metadata: &mut Metadata<CERT>, _owner_cap: &OwnerCap) {
        assert!(metadata.version < VERSION, E_INCOMPATIBLE_VERSION);

        event::emit(MigratedEvent {
            prev_version: metadata.version,
            new_version: VERSION,
        });

        metadata.version = VERSION;
    }
```

**File:** liquid_staking/sources/cert.move (L118-120)
```text
    fun assert_version(metadata: &Metadata<CERT>) {
        assert!(metadata.version == VERSION, E_INCOMPATIBLE_VERSION);
    }
```

**File:** liquid_staking/sources/stake_pool.move (L253-253)
```text
        let lst = metadata.mint(lst_mint_amount, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L330-330)
```text
        metadata.burn_coin(lst);
```
