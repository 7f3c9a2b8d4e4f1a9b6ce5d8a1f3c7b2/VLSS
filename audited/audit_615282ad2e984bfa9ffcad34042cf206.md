### Title
Lending Market Registry Lacks Version Migration Mechanism, Causing Permanent DoS of Market Creation

### Summary
The Suilend `Registry` shared object lacks both an admin capability and a version migration function. When `CURRENT_VERSION` is increased in a package upgrade, the existing `Registry` object retains its old version value, causing the version check in `create_lending_market()` to permanently fail. This prevents the creation of any new lending markets, effectively bricking the registry with no recovery path.

### Finding Description

The `Registry` struct in the lending market registry module has a `version` field that is initialized to `CURRENT_VERSION` during module initialization: [1](#0-0) 

The public `create_lending_market()` function enforces a strict version equality check before allowing market creation: [2](#0-1) 

**Root Cause:** The module provides no mechanism to update the `Registry` object's version field:
1. No admin capability struct exists (unlike other protocol components that have `AdminCap`, `OwnerCap`, `StorageAdminCap`, etc.)
2. No `migrate()` or `version_migrate()` function exists
3. The `Registry` is a shared object with only one public function (`create_lending_market`)

**Why Protections Fail:** 

The comparison at line 35 uses strict equality (`==`) rather than a range check. When the package is upgraded and `CURRENT_VERSION` constant increases (e.g., from 1 to 2), the shared `Registry` object's `version` field remains at its original value (1). The assertion `assert!(registry.version == CURRENT_VERSION, EIncorrectVersion)` will always fail, permanently blocking all market creation.

For comparison, other protocol components properly implement version migration. For example, the `LendingMarket` itself has a migration function that allows the owner to update the version: [3](#0-2) 

Similarly, the protocol's `Storage` object implements the standard migration pattern with an admin capability: [4](#0-3) [5](#0-4) 

**Clarification on Existing Markets:**

Note that existing `LendingMarket` objects remain accessible and functional. They are separate shared objects with their own version fields and migration functions. The vulnerability specifically affects the **Registry's** ability to create **new** markets, not access to existing ones.

### Impact Explanation

**Concrete Harm:**
- The `Registry` becomes permanently bricked after any package upgrade that increases `CURRENT_VERSION`
- No new lending markets can be created through the only authorized path
- The protocol loses core extensibility and scalability functionality
- Recovery requires deploying an entirely new registry contract and migrating all market tracking

**Protocol Damage:**
- Complete loss of market creation capability (100% DoS of this functionality)
- Fragmentation of protocol state across multiple registry deployments
- Inability to support new market types or configurations post-upgrade

**Affected Parties:**
- Protocol developers/deployers who cannot create new markets after upgrades
- Future users who cannot access new lending markets
- The Volo protocol itself, which depends on Suilend lending markets through its adaptor integration

**Severity Justification:**
HIGH severity is appropriate because:
1. Complete and permanent loss of a core protocol function
2. Inevitable occurrence with routine version upgrades
3. No workaround or recovery mechanism exists
4. Forces costly redeployment and state migration

### Likelihood Explanation

**Certainty of Occurrence:**
This is not a probabilistic attack—it is a **deterministic failure** that occurs with 100% certainty whenever:
1. The package undergoes an upgrade
2. The `CURRENT_VERSION` constant is increased (standard versioning practice)
3. The existing `Registry` shared object continues to exist

**Preconditions:**
- Package upgrade event (routine protocol maintenance)
- Version increment follows semantic versioning (expected developer behavior)
- No special attacker capabilities required

**Execution Path:**
1. Initial state: Registry deployed with `version: 1`, code has `CURRENT_VERSION = 1`
2. Package upgrade: Code updated to `CURRENT_VERSION = 2`
3. Shared Registry object: Still has `version: 1` (immutable without migration function)
4. Any call to `create_lending_market()`: Assertion at line 35 fails with `EIncorrectVersion`
5. Result: Permanent DoS, no recovery possible

**Probability:** 100% upon first version increment

### Recommendation

**Code-Level Mitigation:**

Add a registry admin capability and version migration function following the established pattern in the codebase:

```move
// Add admin capability struct
public struct RegistryAdminCap has key, store {
    id: UID,
}

// Modify init to create and transfer admin cap
fun init(ctx: &mut TxContext) {
    let registry = Registry {
        id: object::new(ctx),
        version: CURRENT_VERSION,
        lending_markets: table::new(ctx),
    };
    transfer::share_object(registry);
    
    // Create and transfer admin cap
    let admin_cap = RegistryAdminCap {
        id: object::new(ctx),
    };
    transfer::transfer(admin_cap, tx_context::sender(ctx));
}

// Add migration entry function
public entry fun migrate(_: &RegistryAdminCap, registry: &mut Registry) {
    assert!(registry.version < CURRENT_VERSION, EIncorrectVersion);
    registry.version = CURRENT_VERSION;
}
```

**Invariant Checks:**
- Before upgrade: Verify admin cap exists and is controlled
- After upgrade: Call `migrate()` to update registry version before any market creation attempts
- Add monitoring: Alert if `registry.version < CURRENT_VERSION` detected

**Test Cases:**
1. Test version migration: Deploy v1, upgrade to v2, call migrate(), verify create_lending_market() succeeds
2. Test without migration: Deploy v1, upgrade to v2, verify create_lending_market() fails with EIncorrectVersion
3. Test migration authorization: Verify only admin cap holder can call migrate()
4. Test version progression: Ensure migrate() only allows forward version updates

### Proof of Concept

**Initial State:**
- Registry deployed with `version: 1`
- Module code has `CURRENT_VERSION = 1`
- Market creation works normally

**Upgrade Sequence:**

Step 1: Package upgrade executed
```
sui client upgrade --gas-budget 100000000
```
Result: Module code now has `CURRENT_VERSION = 2`, but shared Registry object still has `version: 1`

Step 2: Attempt to create new lending market
```
sui client call --function create_lending_market \
  --module lending_market_registry \
  --package <PACKAGE_ID> \
  --args <REGISTRY_ID> \
  --type-args "0x123::my_market::MarketType"
```

**Expected Behavior:** Market creation succeeds and returns (LendingMarketOwnerCap, LendingMarket)

**Actual Result:** Transaction fails with error `EIncorrectVersion` (error code 1)
- Assertion at line 35 evaluates: `1 == 2` → false
- Function aborts, no market created
- Registry permanently unusable

**Success Condition for Vulnerability:** The transaction consistently fails with `EIncorrectVersion` after version upgrade, with no available function to update the registry's version field.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move (L15-28)
```text
    public struct Registry has key {
        id: UID,
        version: u64,
        lending_markets: Table<TypeName, ID>,
    }

    fun init(ctx: &mut TxContext) {
        let registry = Registry {
            id: object::new(ctx),
            version: CURRENT_VERSION,
            lending_markets: table::new(ctx),
        };

        transfer::share_object(registry);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move (L31-40)
```text
    public fun create_lending_market<P>(
        registry: &mut Registry,
        ctx: &mut TxContext,
    ): (LendingMarketOwnerCap<P>, LendingMarket<P>) {
        assert!(registry.version == CURRENT_VERSION, EIncorrectVersion);

        let (owner_cap, lending_market) = lending_market::create_lending_market<P>(ctx);
        table::add(&mut registry.lending_markets, type_name::get<P>(), object::id(&lending_market));
        (owner_cap, lending_market)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L950-953)
```text
    entry fun migrate<P>(_: &LendingMarketOwnerCap<P>, lending_market: &mut LendingMarket<P>) {
        assert!(lending_market.version <= CURRENT_VERSION - 1, EIncorrectVersion);
        lending_market.version = CURRENT_VERSION;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L28-30)
```text
    struct StorageAdminCap has key, store {
        id: UID,
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L149-152)
```text
    public entry fun version_migrate(_: &StorageAdminCap, storage: &mut Storage) {
        assert!(storage.version < version::this_version(), error::not_available_version());
        storage.version = version::this_version();
    }
```
