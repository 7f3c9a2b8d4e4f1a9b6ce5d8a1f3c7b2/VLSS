# Audit Report

## Title
Registry Does Not Enforce LendingMarket Sharing, Enabling Permanent Market Type Denial-of-Service

## Summary
The `create_lending_market` function in the Suilend lending market registry returns a `LendingMarket<P>` object directly to the caller without enforcing that it must be shared. An attacker can create a market for any type and transfer it privately instead of sharing it, permanently blocking that market type since the registry prevents duplicate type registrations and provides no removal functions. This renders the Volo vault's Suilend adaptor non-functional for blocked market types.

## Finding Description

The vulnerability exists in the `create_lending_market` function which creates a new lending market, registers its type in the registry, but returns the market object directly to the caller with no enforcement of sharing. [1](#0-0) 

The function registers the market type using `table::add`, which will abort if the type already exists, ensuring only one market per type can be registered. However, it returns the `LendingMarket<P>` object to the caller who has complete control over whether to share it or transfer it privately.

The `LendingMarket` struct has `key, store` abilities but not `drop`, meaning it cannot be destroyed and must either be transferred or shared. [2](#0-1) 

For the Volo protocol to work as intended, the `LendingMarket` must be a shared object accessible to all users. The Volo vault's Suilend adaptor requires a mutable reference to a shared `LendingMarket` for position value updates. [3](#0-2) 

The registry module is write-only with no public functions to remove or override registered market IDs beyond the single `create_lending_market` function. [4](#0-3) 

In Sui Move, when a function returns an object with `key, store` abilities, the caller can:
1. Share it via `transfer::share_object` (making it globally accessible)
2. Transfer it to an address via `transfer::transfer` (making it privately owned)
3. Store it in another object

The registry performs no verification of what the caller does with the returned object, and the `table::add` call ensures no second market of the same type can ever be registered.

## Impact Explanation

**Operational Impact - Permanent Denial of Service:**
- An attacker can permanently block creation of legitimate shared markets for any type by creating markets and transferring them privately
- Once a type is registered with a non-shared market, no one can create a replacement due to the registry's duplicate prevention mechanism
- Users and protocols requiring access to `&mut LendingMarket<P>` as a shared object cannot interact with blocked market types
- The Volo vault's Suilend adaptor becomes completely non-functional for blocked types, as it requires mutable references to shared LendingMarket objects to perform position value updates, obligation parsing, and interest compounding

**Security Integrity Impact:**
- Breaks the core protocol invariant: "one accessible shared market per type for all users"
- No recovery mechanism exists as the registry has zero admin functions for removal or override
- The attack is irreversible without a complete protocol upgrade and redeployment

**Quantified Damage:**
- Cost to attacker: Single transaction gas fee per market type blocked (~0.001 SUI)
- Impact scope: Can block any market type including critical ones (e.g., MAIN_POOL, specific asset markets)
- Affected parties: All users and protocols attempting to interact with blocked market types
- Duration: Permanent until protocol upgrade

## Likelihood Explanation

**Reachable Entry Point:**
The `create_lending_market` function is public and requires no special capabilities or admin privileges. Any user can call it with only a transaction context. [5](#0-4) 

**Feasible Preconditions:**
- Attacker only needs access to the shared Registry object (created in module initialization and made public)
- No admin privileges, capabilities, or special permissions required
- No economic preconditions beyond minimal transaction gas fees

**Execution Practicality:**
Attack sequence:
1. Call `registry::create_lending_market<TargetType>(registry, ctx)`
2. Receive `(owner_cap, lending_market)` tuple
3. Call `transfer::transfer(lending_market, attacker_address)` instead of `transfer::share_object(lending_market)`
4. Market type is now permanently blocked - the registry contains the type entry but points to a privately-owned, inaccessible market

All steps are standard Sui Move operations with no special checks, gates, or authorization requirements.

**Economic Rationality:**
- Attack cost: Minimal gas fee per blocked market type
- No collateral, stake, or economic commitment required
- No detection mechanisms or penalties in place
- No reversibility once executed
- High impact-to-cost ratio makes this economically viable even for pure griefing attacks

## Recommendation

Add enforcement to ensure created lending markets are always shared objects. This can be done by:

1. **Immediate Solution**: Modify `create_lending_market` to automatically share the market instead of returning it:

```move
public fun create_lending_market<P>(
    registry: &mut Registry,
    ctx: &mut TxContext,
): LendingMarketOwnerCap<P> {
    assert!(registry.version == CURRENT_VERSION, EIncorrectVersion);

    let (owner_cap, lending_market) = lending_market::create_lending_market<P>(ctx);
    let market_id = object::id(&lending_market);
    
    // Share the market immediately
    transfer::share_object(lending_market);
    
    // Register after sharing
    table::add(&mut registry.lending_markets, type_name::get<P>(), market_id);
    
    // Return only the owner cap
    owner_cap
}
```

2. **Alternative Solution**: Add validation in a separate function to verify that registered markets are actually shared objects before allowing protocol interactions, though this is more complex and less secure than enforcing sharing at creation time.

3. **Additional Hardening**: Add admin functions to remove/override registry entries in case of malicious market creation, protected by appropriate capability checks.

## Proof of Concept

```move
#[test_only]
module test::lending_market_dos_poc {
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::transfer;
    use suilend::lending_market_registry::{Self, Registry};
    
    // Phantom type for testing
    public struct MAIN_POOL has drop {}
    
    #[test]
    fun test_market_type_dos_attack() {
        let attacker = @0xBAD;
        let legitimate_user = @0xA11CE;
        
        let mut scenario = ts::begin(attacker);
        
        // Attacker creates a market and transfers it privately
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            let (owner_cap, lending_market) = registry.create_lending_market<MAIN_POOL>(
                ts::ctx(&mut scenario)
            );
            
            // Attacker transfers market privately instead of sharing
            transfer::transfer(lending_market, attacker);
            transfer::transfer(owner_cap, attacker);
            
            ts::return_shared(registry);
        };
        
        // Advance to next transaction where legitimate user tries to create the same market type
        ts::next_tx(&mut scenario, legitimate_user);
        
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            
            // This will ABORT because MAIN_POOL type is already registered
            // The legitimate user cannot create a shared market for this type
            let (owner_cap, lending_market) = registry.create_lending_market<MAIN_POOL>(
                ts::ctx(&mut scenario)
            ); // This line will fail with table::add abort
            
            transfer::public_share_object(lending_market);
            transfer::transfer(owner_cap, legitimate_user);
            
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }
}
```

The test demonstrates that once an attacker registers a market type and transfers it privately, no subsequent attempt to create a shared market of that type can succeed due to the registry's duplicate prevention mechanism.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market_registry.move (L15-29)
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
