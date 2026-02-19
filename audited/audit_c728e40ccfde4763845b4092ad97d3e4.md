### Title
Registry Does Not Enforce LendingMarket Sharing, Enabling Permanent Market Type Denial-of-Service

### Summary
The `create_lending_market` function returns the `LendingMarket<P>` object directly to the caller without enforcing that it must be shared via `transfer::share_object`. An attacker can create a market for any type P, receive the object, and transfer it to themselves instead of sharing it. This permanently blocks that market type since the registry prevents duplicate type registrations, and there are no admin functions to remove registry entries.

### Finding Description

The vulnerability exists in the `create_lending_market` function which creates a new lending market and records its ID in the registry, but returns both the owner capability and the lending market object itself to the caller. [1](#0-0) 

The function calls `lending_market::create_lending_market<P>(ctx)` to create the market, then immediately adds the type-to-ID mapping using `table::add`, which will abort if the type already exists. The critical flaw is that it returns the `LendingMarket<P>` object to the caller, who has complete control over its disposition.

The `LendingMarket` struct has `key, store` abilities but not `drop`, meaning it cannot be destroyed and must either be transferred or shared: [2](#0-1) 

For the protocol to work as intended, the `LendingMarket` must be a shared object accessible to all users. The Suilend adaptor in the Volo vault expects to receive a mutable reference to a shared `LendingMarket`: [3](#0-2) 

However, the registry module contains no functions to retrieve, verify, or remove registered market IDs - it is write-only: [4](#0-3) 

The root cause is the absence of any mechanism to ensure the returned `LendingMarket` object is shared. In Sui Move, when a function returns an object with `key, store`, the caller can choose to:
1. Share it via `transfer::share_object` (making it globally accessible)
2. Transfer it to an address via `transfer::transfer` (making it owned/private)
3. Store it in another object

The registry performs no verification of what the caller does with the object, and `table::add` ensures no second market of the same type can ever be registered.

### Impact Explanation

**Operational Impact - Permanent Denial of Service:**
- An attacker can permanently block creation of legitimate shared markets for any type
- Once a type is registered with a non-shared market, no one can create a replacement
- Users and protocols depending on accessing `&mut LendingMarket<P>` as a shared object will fail
- The vault's Suilend adaptor and any other integrations become non-functional for blocked types

**Security Integrity Impact:**
- Breaks the core protocol invariant: "one market per type" accessible to all users
- No recovery mechanism exists - the registry has zero admin functions
- The attack is irreversible without a complete protocol upgrade

**Quantified Damage:**
- Cost to attacker: Single transaction gas fee per market type blocked
- Impact scope: Can block critical market types (e.g., MainMarket, USDC market)
- Affected parties: All users and protocols attempting to interact with blocked market types
- Duration: Permanent until protocol upgrade

This satisfies the "Operational Impact" criterion: meaningful DoS via valid user actions where markets become inaccessible.

### Likelihood Explanation

**Reachable Entry Point:**
The `create_lending_market` function is public and requires no special capabilities: [5](#0-4) 

**Feasible Preconditions:**
- Attacker only needs access to a shared Registry object (created in init)
- No admin privileges required
- No economic preconditions (beyond gas)

**Execution Practicality:**
Attack sequence is trivial:
1. Call `registry::create_lending_market<TargetType>(registry, ctx)`
2. Receive `(owner_cap, lending_market)` tuple
3. Call `transfer::transfer(lending_market, attacker_address)` instead of `transfer::share_object(lending_market)`
4. Market type is now permanently blocked

All steps are valid Move operations with no special checks or gates.

**Economic Rationality:**
- Attack cost: ~0.001 SUI gas per type (negligible)
- No collateral or stake required
- No detection mechanisms in place
- No penalties or reversibility

The attack is highly practical and economically viable for a malicious actor.

### Recommendation

**Immediate Fix - Auto-share the market:**
Modify `create_lending_market` to automatically share the `LendingMarket` object before returning:

```move
public fun create_lending_market<P>(
    registry: &mut Registry,
    ctx: &mut TxContext,
): LendingMarketOwnerCap<P> {
    assert!(registry.version == CURRENT_VERSION, EIncorrectVersion);
    
    let (owner_cap, lending_market) = lending_market::create_lending_market<P>(ctx);
    table::add(&mut registry.lending_markets, type_name::get<P>(), object::id(&lending_market));
    
    // AUTO-SHARE: Ensure market is accessible to all
    transfer::share_object(lending_market);
    
    owner_cap  // Return only the capability
}
```

**Additional Safeguards:**
1. Add admin capability to remove corrupted registry entries
2. Add getter function to verify registered market IDs
3. Add validation that retrieved objects are actually shared
4. Consider using dynamic fields instead of returning objects directly

**Test Cases:**
1. Verify market is automatically shared after creation
2. Verify shared market is accessible via its registered ID
3. Test that duplicate type registration still fails appropriately
4. Add admin recovery function tests

### Proof of Concept

**Initial State:**
- Registry is deployed and shared
- No market exists for type `MainMarket`

**Attack Transaction:**
```move
// Transaction by attacker
public entry fun exploit(registry: &mut Registry, ctx: &mut TxContext) {
    // Step 1: Create market (registers type in table)
    let (owner_cap, lending_market) = registry::create_lending_market<MainMarket>(registry, ctx);
    
    // Step 2: Transfer to self instead of sharing
    transfer::transfer(lending_market, tx_context::sender(ctx));
    transfer::transfer(owner_cap, tx_context::sender(ctx));
    
    // Result: MainMarket type is registered but object is owned, not shared
}
```

**Expected vs Actual Result:**

*Expected:* `LendingMarket<MainMarket>` should be a shared object accessible via `&mut LendingMarket<MainMarket>` in subsequent transactions.

*Actual:* 
- Registry contains entry: `TypeName::MainMarket -> ObjectID(0xABC...)`
- Object `0xABC...` is owned by attacker, not shared
- Any subsequent call to `update_suilend_position_value<_, MainMarket>` fails because it cannot access a shared `&mut LendingMarket<MainMarket>`
- Attempt to create new market fails: `table::add` aborts with duplicate key error

**Success Condition:**
Market type is permanently blocked. Verification:
1. `table::contains(&registry.lending_markets, type_name::get<MainMarket>())` returns `true`
2. No shared object of type `LendingMarket<MainMarket>` exists
3. Calling `create_lending_market<MainMarket>` again aborts with `table::add` error
4. Protocol functionality requiring shared market access is broken

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move (L1-41)
```text
/// Top level object that tracks all lending markets.
/// Ensures that there is only one LendingMarket of each type.
/// Anyone can create a new LendingMarket via the registry.
module suilend::lending_market_registry {
    use std::type_name::{Self, TypeName};
    use sui::table::{Self, Table};
    use suilend::lending_market::{Self, LendingMarket, LendingMarketOwnerCap};

    // === Errors ===
    const EIncorrectVersion: u64 = 1;

    // === Constants ===
    const CURRENT_VERSION: u64 = 1;

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
    }

    public fun create_lending_market<P>(
        registry: &mut Registry,
        ctx: &mut TxContext,
    ): (LendingMarketOwnerCap<P>, LendingMarket<P>) {
        assert!(registry.version == CURRENT_VERSION, EIncorrectVersion);

        let (owner_cap, lending_market) = lending_market::create_lending_market<P>(ctx);
        table::add(&mut registry.lending_markets, type_name::get<P>(), object::id(&lending_market));
        (owner_cap, lending_market)
    }
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L43-55)
```text
    public struct LendingMarket<phantom P> has key, store {
        id: UID,
        version: u64,
        reserves: vector<Reserve<P>>,
        obligations: ObjectTable<ID, Obligation<P>>,
        // window duration is in seconds
        rate_limiter: RateLimiter,
        fee_receiver: address, // deprecated
        /// unused
        bad_debt_usd: Decimal,
        /// unused
        bad_debt_limit_usd: Decimal,
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-28)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
```
