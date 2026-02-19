# Audit Report

## Title
Vault Operations with Suilend Positions Experience Permanent DoS During Pyth Oracle Downtime

## Summary
When Pyth oracle price feeds stop updating for more than 60 seconds, vault operations involving Suilend positions cannot complete their mandatory value update step, causing the vault to become stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism. The vault remains inoperable until Pyth resumes providing fresh prices, blocking all deposits, withdrawals, and new operations.

## Finding Description

The vulnerability exists in the interaction between five critical components that create an unrecoverable stuck state:

**1. Pyth Price Staleness Check with No Grace Period**

Suilend's oracle module enforces a hardcoded 60-second maximum staleness for Pyth prices. [1](#0-0)  When the price timestamp exceeds this threshold, the function returns `option::none()` for the spot price rather than the actual price. [2](#0-1) 

**2. Abort on Stale Price Instead of Fallback**

The `update_price()` function in Suilend's reserve module receives the price from the oracle and immediately aborts with `EInvalidPrice` when the returned price is `None`. [3](#0-2)  This provides no fallback mechanism or grace period.

**3. Zero-Second Freshness Requirement for Position Valuation**

Suilend reserves enforce that prices must be updated in the same transaction (0-second staleness threshold). [4](#0-3)  The `assert_price_is_fresh()` function validates this constraint. [5](#0-4) 

When updating Suilend position values, the adaptor calls this assertion for both deposits and borrows, meaning reserve prices MUST be refreshed in the same transaction. [6](#0-5) [7](#0-6) 

**4. Mandatory Asset Value Updates in Operation Flow**

Vault operations follow a three-step pattern where the operation transitions the vault to `VAULT_DURING_OPERATION_STATUS`. [8](#0-7)  Before completing the operation, `check_op_value_update_record()` enforces that ALL borrowed assets must have their values updated. [9](#0-8)  

The enforcement logic iterates through all borrowed asset types and aborts with `ERR_USD_VALUE_NOT_UPDATED` if any asset is missing its update. [10](#0-9) 

**5. No Emergency Recovery Mechanism**

The admin's ability to disable the vault is explicitly blocked when the vault is in `VAULT_DURING_OPERATION_STATUS`. [11](#0-10)  The only way to exit this status is to successfully complete `end_op_value_update_with_bag()`, which transitions back to `VAULT_NORMAL_STATUS`. [12](#0-11) 

**Attack Flow:**

1. Operator calls `start_op_with_bag()` to begin a vault operation, borrowing a Suilend obligation asset
2. Pyth oracle stops updating (network issues, validator problems, bridge delays) for more than 60 seconds
3. Operator attempts to complete the operation by calling `refresh_reserve_price()` on the Suilend lending market [13](#0-12) 
4. This calls `reserve::update_price()` → `oracles::get_pyth_price_and_identifier()` which returns `None` for the stale price
5. `update_price()` aborts with `EInvalidPrice`, preventing the reserve price from being updated
6. Cannot call `update_suilend_position_value()` because `assert_price_is_fresh()` requires a fresh price (updated in the same transaction)
7. Cannot call `end_op_value_update_with_bag()` because `check_op_value_update_record()` detects the missing Suilend position update
8. Vault remains stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery path

## Impact Explanation

**Complete Operational Paralysis:**
- The vault enters an unrecoverable stuck state in `VAULT_DURING_OPERATION_STATUS`
- All vault functionality is blocked: deposits cannot be executed, withdrawals cannot be processed, new operations cannot start
- Users are unable to access their funds for the duration of the Pyth oracle outage
- Admin has no emergency override capability to recover the vault

**Affected Parties:**
- All vault users lose access to their deposited funds
- Vault operators cannot perform any management operations
- Protocol administrators have no recovery mechanism

**Severity Justification:**
- This represents a high-confidence protocol DoS that completely blocks vault operations
- While funds are not at risk of theft, they become completely inaccessible
- Duration is unbounded and depends entirely on external Pyth oracle infrastructure recovery
- No administrative intervention can resolve the issue
- The vulnerability affects protocol availability, a core security guarantee

## Likelihood Explanation

**Realistic Occurrence:**
- Pyth oracle downtime exceeding 60 seconds is a documented realistic scenario in production deployments
- Can occur due to: network congestion on source chains, validator node issues, cross-chain bridge delays, price publisher infrastructure problems
- No attacker action required - this is a pure dependency failure scenario

**Low Attack Complexity:**
- Triggered by normal vault operations during an external service outage
- Any operator performing routine vault rebalancing with Suilend positions is affected
- The operator may not realize Pyth is stale until mid-operation when attempting to complete step 3

**Execution Preconditions:**
- Vault must have at least one Suilend position
- Operator initiates an operation that borrows the Suilend position
- Pyth oracle experiences >60 seconds of downtime before the operation completes
- All preconditions are realistic and require no special privileges

## Recommendation

Implement a multi-layered recovery mechanism:

**1. Add Fallback Oracle Support:**
Modify Suilend's `update_price()` function to accept an alternative oracle source (e.g., Switchboard) when Pyth returns stale data. The comment in the oracle module already acknowledges this need for "falling back to a different oracle" but it's not implemented.

**2. Emergency Admin Override:**
Add an emergency function that allows admin to force-transition the vault out of `VAULT_DURING_OPERATION_STATUS` after a timeout period, with appropriate safety checks and logging.

**3. Graceful Degradation:**
Consider allowing operations to complete with a "last known good" price if the staleness is within acceptable bounds (e.g., 5 minutes) with appropriate risk warnings and reduced operation limits.

**4. Operation Timeout:**
Implement a maximum operation duration (e.g., 24 hours) after which the operation automatically rolls back and returns the vault to `VAULT_NORMAL_STATUS`.

## Proof of Concept

While a complete end-to-end test would require mocking Pyth oracle staleness (which involves time manipulation and external contract dependencies), the vulnerability can be demonstrated through code inspection of the execution path:

```move
// Conceptual PoC - demonstrates the stuck state logic

#[test]
#[expected_failure(abort_code = reserve::EInvalidPrice)]
fun test_vault_stuck_on_stale_pyth() {
    // 1. Start operation with Suilend position
    let (bag, tx, tx_update, ...) = operation::start_op_with_bag(
        &mut vault,
        /* include Suilend position */
    );
    
    // 2. Simulate Pyth staleness >60 seconds
    clock.increment_for_testing(61_000); // 61 seconds
    
    // 3. Attempt to refresh reserve price - ABORTS HERE
    lending_market::refresh_reserve_price(
        &mut lending_market,
        reserve_index,
        &clock,
        &stale_price_info // timestamp is 61+ seconds old
    );
    
    // 4. Cannot reach here - update_price aborted
    // 5. Cannot complete operation
    // 6. Vault stuck in VAULT_DURING_OPERATION_STATUS
}
```

The proof lies in the immutable logic flow: when Pyth is stale → `update_price()` aborts → reserve price cannot be refreshed → position value cannot be updated → operation cannot complete → vault is permanently stuck until Pyth recovers.

---

## Notes

**Critical Observations:**

1. **Dependency Chain Fragility**: The vulnerability stems from tight coupling between Volo's operation flow and Suilend's oracle integration without defensive fallback mechanisms.

2. **Design vs Implementation Gap**: The Suilend oracle module's comment explicitly mentions fallback handling ("so the caller can handle invalid prices gracefully by eg falling back to a different oracle"), but `update_price()` doesn't implement this - it simply aborts.

3. **Temporary but Unbounded**: While the DoS is technically temporary (ends when Pyth recovers), the duration is unbounded and could extend for hours or days, making it functionally equivalent to a permanent DoS from users' perspective.

4. **Production Risk**: Given that Pyth oracle outages have occurred in production on other chains, this is not a theoretical concern but a realistic operational risk for any vault holding Suilend positions.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L43-47)
```text
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L238-245)
```text
    public fun assert_price_is_fresh<P>(reserve: &Reserve<P>, clock: &Clock) {
        assert!(is_price_fresh(reserve, clock), EPriceStale);
    }

    public(package) fun is_price_fresh<P>(reserve: &Reserve<P>, clock: &Clock): bool {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;

        cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-588)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L68-68)
```text
        borrow_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/operation.move (L73-74)
```text
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-210)
```text
    public fun refresh_reserve_price<P>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
        price_info: &PriceInfoObject,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        reserve::update_price<P>(reserve, clock, price_info);
```
