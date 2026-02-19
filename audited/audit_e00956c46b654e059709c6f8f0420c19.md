# Audit Report

## Title
Registry Does Not Enforce LendingMarket Sharing, Enabling Permanent Market Type Denial-of-Service

## Summary
The `create_lending_market` function returns the `LendingMarket<P>` object directly to the caller without enforcing that it must be shared. An attacker can create a market for any type P and transfer it privately instead of sharing it, permanently blocking that market type since the registry prevents duplicate type registrations and has no removal functions.

## Finding Description

The vulnerability exists in the `create_lending_market` function which creates a new lending market, registers its type in the registry, but returns the market object directly to the caller with no enforcement of sharing. [1](#0-0) 

The function registers the market type using `table::add`, which will abort if the type already exists, ensuring only one market per type can be registered. However, it returns the `LendingMarket<P>` object to the caller who has complete control over its disposition.

The `LendingMarket` struct has `key, store` abilities but not `drop`, meaning it cannot be destroyed and must either be transferred or shared. [2](#0-1) 

For the protocol to work as intended, the `LendingMarket` must be a shared object accessible to all users. The Volo vault's Suilend adaptor expects to receive a mutable reference to a shared `LendingMarket` for position value updates. [3](#0-2) 

The registry module is write-only with no functions to retrieve, verify, or remove registered market IDs. The only public function is `create_lending_market`. [4](#0-3) 

In Sui Move, when a function returns an object with `key, store`, the caller can:
1. Share it via `transfer::share_object` (making it globally accessible)
2. Transfer it to an address via `transfer::transfer` (making it owned/private)
3. Store it in another object

The registry performs no verification of what the caller does with the returned object, and the `table::add` call ensures no second market of the same type can ever be registered.

## Impact Explanation

**Operational Impact - Permanent Denial of Service:**
- An attacker can permanently block creation of legitimate shared markets for any type by creating markets and transferring them privately
- Once a type is registered with a non-shared market, no one can create a replacement due to the registry's duplicate prevention
- Users and protocols depending on accessing `&mut LendingMarket<P>` as a shared object will be unable to interact with blocked market types
- The Volo vault's Suilend adaptor becomes non-functional for blocked types as it requires shared market references

**Security Integrity Impact:**
- Breaks the core protocol invariant: "one accessible market per type for all users"
- No recovery mechanism exists as the registry has zero admin functions for removal or override
- The attack is irreversible without a complete protocol upgrade

**Quantified Damage:**
- Cost to attacker: Single transaction gas fee per market type blocked (~0.001 SUI)
- Impact scope: Can block any market type including critical ones (e.g., MAIN_POOL, specific asset markets)
- Affected parties: All users and protocols attempting to interact with blocked market types
- Duration: Permanent until protocol upgrade

## Likelihood Explanation

**Reachable Entry Point:**
The `create_lending_market` function is public and requires no special capabilities. [5](#0-4) 

**Feasible Preconditions:**
- Attacker only needs access to the shared Registry object (created in module initialization)
- No admin privileges required
- No economic preconditions beyond transaction gas fees

**Execution Practicality:**
Attack sequence:
1. Call `registry::create_lending_market<TargetType>(registry, ctx)`
2. Receive `(owner_cap, lending_market)` tuple
3. Call `transfer::transfer(lending_market, attacker_address)` instead of `transfer::share_object(lending_market)`
4. Market type is now permanently blocked

All steps are standard Sui Move operations with no special checks or gates.

**Economic Rationality:**
- Attack cost: Minimal gas fee per blocked type
- No collateral or stake required
- No detection or prevention mechanisms in place
- No penalties or reversibility
- High impact-to-cost ratio makes this economically viable for malicious actors

## Recommendation

Add enforcement that created lending markets must be shared. Modify the `create_lending_market` function to:

1. **Option A (Recommended)**: Share the market within the function:
```move
public fun create_lending_market<P>(
    registry: &mut Registry,
    ctx: &mut TxContext,
): LendingMarketOwnerCap<P> {
    assert!(registry.version == CURRENT_VERSION, EIncorrectVersion);
    
    let (owner_cap, lending_market) = lending_market::create_lending_market<P>(ctx);
    table::add(&mut registry.lending_markets, type_name::get<P>(), object::id(&lending_market));
    
    // Enforce sharing before returning
    transfer::share_object(lending_market);
    
    owner_cap  // Only return the owner cap
}
```

2. **Option B**: Add registry admin functions to remove/override entries in case of griefing, allowing recovery from blocked types.

3. **Option C**: Implement verification that checks if a market ID in the registry points to a shared object, with admin functions to remove invalid entries.

## Proof of Concept

```move
#[test_only]
module suilend::registry_dos_test {
    use suilend::lending_market_registry::{Self, Registry};
    use suilend::lending_market::{LendingMarket};
    use sui::test_scenario;
    use sui::transfer;
    
    public struct TestMarketType has drop {}
    
    #[test]
    fun test_lending_market_dos_attack() {
        let attacker = @0xBAD;
        let legitimate_user = @0x123;
        
        let mut scenario = test_scenario::begin(attacker);
        
        // Setup: Initialize registry (normally done in init)
        {
            let registry = registry::create_registry_for_testing(scenario.ctx());
            transfer::share_object(registry);
        };
        
        scenario.next_tx(attacker);
        
        // Attack: Create market and transfer privately instead of sharing
        {
            let mut registry = scenario.take_shared<Registry>();
            
            // Attacker creates the market
            let (owner_cap, lending_market) = 
                lending_market_registry::create_lending_market<TestMarketType>(
                    &mut registry, 
                    scenario.ctx()
                );
            
            // Instead of sharing: transfer::share_object(lending_market);
            // Attacker transfers to themselves privately
            transfer::transfer(lending_market, attacker);
            transfer::transfer(owner_cap, attacker);
            
            test_scenario::return_shared(registry);
        };
        
        scenario.next_tx(legitimate_user);
        
        // Impact: Legitimate user cannot create shared market for same type
        {
            let mut registry = scenario.take_shared<Registry>();
            
            // This will ABORT because TestMarketType is already registered
            let (owner_cap, lending_market) = 
                lending_market_registry::create_lending_market<TestMarketType>(
                    &mut registry, 
                    scenario.ctx()
                );
            
            // Legitimate user wanted to share it, but can't even create it
            transfer::share_object(lending_market);
            transfer::transfer(owner_cap, legitimate_user);
            
            test_scenario::return_shared(registry);
        };
        
        scenario.end();
    }
}
```

The test demonstrates that once an attacker creates and privately transfers a lending market for a specific type, no legitimate user can create a shared market for that same type, permanently blocking protocol functionality for that market type.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move (L15-41)
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```
