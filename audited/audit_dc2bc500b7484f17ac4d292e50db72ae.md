### Title
Unsafe Version Migration Allows Skipping Multiple Versions Without State Migration, Breaking Fee Claiming Functionality

### Summary
The `migrate()` function in Suilend's lending_market allows upgrading from version (CURRENT_VERSION - 2) or any older version directly to CURRENT_VERSION without performing proper state migration. This leaves migrated LendingMarkets missing critical dynamic fields like `FeeReceivers`, causing the `claim_fees()` function to permanently abort and lock protocol fees in reserves.

### Finding Description

The `migrate()` function performs insufficient version validation and no state migration: [1](#0-0) 

With CURRENT_VERSION set to 7: [2](#0-1) 

The assertion `lending_market.version <= CURRENT_VERSION - 1` allows migration from version 6, 5, 4, 3, 2, 1, or any earlier version. The function only updates the version number without adding any missing state or dynamic fields.

When creating new LendingMarkets, the `FeeReceivers` dynamic field is properly initialized: [3](#0-2) 

However, the `migrate()` function does not add this dynamic field to old LendingMarkets. The `claim_fees()` function unconditionally borrows this dynamic field without checking its existence: [4](#0-3) 

When the dynamic field doesn't exist, the `dynamic_field::borrow()` call will abort, permanently blocking fee collection. The LendingMarket struct also contains deprecated fields that indicate structural evolution over time: [5](#0-4) 

### Impact Explanation

**Direct Fund Impact**: Protocol fees accumulated in reserves become permanently inaccessible. After migrating a LendingMarket that lacks the `FeeReceivers` dynamic field, any attempt to call `claim_fees()` will abort at the dynamic field borrow operation. This locks all protocol earnings (both liquidity fees and cToken fees) in the reserve forever, preventing the protocol from collecting its rightful revenue.

**Operational Impact**: The fee claiming mechanism is a critical protocol function. Once broken by an unsafe migration, it cannot be fixed without deploying new contract code, as the LendingMarket is already at CURRENT_VERSION and cannot be migrated again.

**Affected Parties**: 
- Protocol operators lose access to accumulated fees
- The protocol's economic model is broken for migrated markets
- Lenders are indirectly affected as protocol fees cannot be redistributed or used for protocol operations

**Severity**: HIGH - This permanently locks protocol funds and breaks critical functionality through a predictable code path that any owner performing a standard migration would trigger.

### Likelihood Explanation

**Reachable Entry Point**: The `migrate()` function is an entry function callable by the LendingMarketOwnerCap holder (the legitimate owner).

**Feasible Preconditions**: 
1. A LendingMarket was created in version 5, 4, 3, 2, 1, or earlier (before `FeeReceivers` dynamic field was introduced)
2. The owner decides to upgrade to version 7 using the provided `migrate()` function
3. The owner later attempts to claim accumulated fees using `claim_fees()`

**Execution Practicality**: This is a straightforward operational flow with no complex attack vectors. The owner follows normal upgrade procedures:
- Call `migrate()` with LendingMarketOwnerCap
- Migration succeeds and updates version to 7
- Call `claim_fees()` to collect protocol revenue
- Transaction aborts due to missing dynamic field

**Economic Rationality**: The owner has legitimate incentives to both upgrade their LendingMarket to the latest version and claim accumulated fees. This is standard protocol maintenance.

**Probability**: HIGH if any LendingMarkets exist from versions before the `FeeReceivers` dynamic field was added. Every such market that undergoes migration will experience this issue.

### Recommendation

Implement proper state migration with version-specific upgrade paths:

1. **Add version-specific migration logic**:
```move
entry fun migrate<P>(_: &LendingMarketOwnerCap<P>, lending_market: &mut LendingMarket<P>) {
    assert!(lending_market.version <= CURRENT_VERSION - 1, EIncorrectVersion);
    
    // Migrate from older versions step-by-step
    if (lending_market.version < VERSION_WITH_FEE_RECEIVERS) {
        // Add FeeReceivers dynamic field if missing
        if (!dynamic_field::exists_(&lending_market.id, FeeReceiversKey {})) {
            dynamic_field::add(
                &mut lending_market.id,
                FeeReceiversKey {},
                FeeReceivers { 
                    receivers: vector[lending_market.fee_receiver], 
                    weights: vector[100],
                    total_weight: 100 
                }
            );
        }
    }
    
    // Add other version-specific migrations here
    
    lending_market.version = CURRENT_VERSION;
}
```

2. **Add safety checks in `claim_fees()`**:
```move
entry fun claim_fees<P, T>(...) {
    assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
    
    // Safety check for missing dynamic field
    assert!(
        dynamic_field::exists_(&lending_market.id, FeeReceiversKey {}),
        EMissingFeeReceivers
    );
    
    let fee_receivers: &FeeReceivers = dynamic_field::borrow(...);
    // ... rest of function
}
```

3. **Add test cases**:
    - Test migration from each old version to CURRENT_VERSION
    - Verify all dynamic fields exist after migration
    - Test `claim_fees()` functionality post-migration
    - Test that deprecated fields are handled correctly

### Proof of Concept

**Initial State**:
- LendingMarket exists with version = 5 (before FeeReceivers was added)
- LendingMarket has accumulated fees in reserves
- Owner holds LendingMarketOwnerCap

**Transaction Steps**:

1. **Owner calls migrate()**:
   - Input: LendingMarketOwnerCap, LendingMarket with version = 5
   - Check passes: 5 <= (7 - 1) = 6 ✓
   - Version updated: 5 → 7
   - FeeReceivers dynamic field: NOT ADDED
   - Result: Migration succeeds

2. **Owner calls claim_fees()**:
   - Input: LendingMarket with version = 7, reserve_array_index
   - Version check passes: 7 == 7 ✓
   - Execution reaches line 1146-1149
   - Attempts: `dynamic_field::borrow(&lending_market.id, FeeReceiversKey {})`
   - FeeReceivers does not exist
   - Result: **Transaction ABORTS** - fees permanently locked

**Expected vs Actual**:
- Expected: Migration should ensure all required state exists; claim_fees should succeed
- Actual: Migration skips state initialization; claim_fees aborts permanently

**Success Condition**: After migration from version 5→7, calling `claim_fees()` should successfully distribute fees to receivers. Instead, it aborts and locks all protocol fees indefinitely.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L32-32)
```text
    const CURRENT_VERSION: u64 = 7;
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L189-194)
```text
        set_fee_receivers(
            &owner_cap,
            &mut lending_market,
            vector[tx_context::sender(ctx)],
            vector[100],
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L950-953)
```text
    entry fun migrate<P>(_: &LendingMarketOwnerCap<P>, lending_market: &mut LendingMarket<P>) {
        assert!(lending_market.version <= CURRENT_VERSION - 1, EIncorrectVersion);
        lending_market.version = CURRENT_VERSION;
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1146-1149)
```text
        let fee_receivers: &FeeReceivers = dynamic_field::borrow(
            &lending_market.id,
            FeeReceiversKey {},
        );
```
