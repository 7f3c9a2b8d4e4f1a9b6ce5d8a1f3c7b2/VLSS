### Title
Queue Operational Invariant Violation: No Minimum Fee Type Protection Allows Complete Oracle Submission DoS

### Summary
The `queue_remove_fee_coin_action::run<T>()` function lacks validation to prevent removing the last fee type from a Switchboard queue, allowing the queue authority to inadvertently leave the queue with zero accepted fee types. This violates the queue's operational invariant and causes complete denial of service for all oracle submissions, cascading to Volo vault price update failures.

### Finding Description

**Vulnerable Code Location:** [1](#0-0) 

The `run<T>()` function only validates queue version and authority but does not check if removing the fee type would leave the queue with zero accepted fee types.

**Root Cause:**

The underlying `remove_fee_type<T>()` function simply removes the fee type without any minimum constraint: [2](#0-1) 

**Why Existing Protections Fail:**

When a queue is initialized, it starts with exactly one fee type (SUI): [3](#0-2) 

If the authority removes all fee types (including SUI), the `fee_types` vector becomes empty. Subsequently, when oracles attempt to submit price updates, the validation check fails: [4](#0-3) 

Since `queue.has_fee_type<T>()` returns false for any coin type T when `fee_types` is empty, all oracle submissions abort with `EInvalidFeeType`, making the queue completely non-operational.

**Design Inconsistency:**

The Switchboard system demonstrates a clear design pattern of protecting queue operational invariants. For example, `queue_set_configs_action` explicitly validates minimum operational thresholds: [5](#0-4) 

The absence of similar protection for fee types represents an inconsistent protection gap.

### Impact Explanation

**Operational DoS Impact:**

1. **Oracle Submission Failure**: All oracles attempting to submit price updates to aggregators using the affected queue will fail, as no fee type is accepted for payment.

2. **Price Staleness**: Aggregators depending on the queue cannot receive fresh price data, causing their `max_timestamp_ms` to become stale beyond the configured update interval.

3. **Volo Vault Price Update Failure**: When the Volo vault attempts to read prices from these aggregators, it enforces a staleness check: [6](#0-5) 

If the staleness exceeds `update_interval` (default 1 minute), the vault operation fails with `ERR_PRICE_NOT_UPDATED`.

4. **Cascading Vault Operation Failures**: All vault operations requiring price data (deposits, withdrawals, operation start/end, valuation) become blocked: [7](#0-6) 

**Affected Parties:**
- All oracle operators servicing the queue
- All users of aggregators depending on the queue  
- All Volo vault users whose operations require price data from affected feeds

**Severity Justification:**
High severity due to complete operational DoS affecting critical price infrastructure, even though recovery is possible by re-adding fee types.

### Likelihood Explanation

**Realistic Misconfiguration Scenario:**

The authority may accidentally remove all fee types during routine fee type management:
1. Authority removes SUI to switch to a different primary fee token
2. Authority removes other added fee types during cleanup
3. Queue is left with zero fee types

**Reachable Entry Point:** [8](#0-7) 

This is a public entry function callable by the queue authority.

**Feasibility Assessment:**
- **Preconditions**: Requires queue authority access (trusted role, but misconfiguration not compromise)
- **Execution**: Simple repeated calls to `run<T>()` for each fee type
- **Detection**: No on-chain warnings; operators discover when submissions start failing
- **Operational Constraints**: While authority can recover by adding fee types back, there is an operational gap during which all oracle feeds are non-functional

**Probability**: Medium-to-high for accidental misconfiguration during fee type management operations, especially when migrating between different fee token strategies.

### Recommendation

**Code-Level Mitigation:**

Add minimum fee type validation to `queue_remove_fee_coin_action::validate()`:

```move
public fun validate(
    queue: &Queue,
    ctx: &mut TxContext
) {
    assert!(queue.version() == EXPECTED_QUEUE_VERSION, EInvalidQueueVersion);
    assert!(queue.has_authority(ctx), EInvalidAuthority);
    // Add this check:
    assert!(queue.fee_types().length() > 1, ECannotRemoveLastFeeType);
}
```

Add error constant:
```move
#[error]
const ECannotRemoveLastFeeType: vector<u8> = b"Cannot remove last fee type";
```

**Invariant Check:**

Ensure `fee_types.length() >= 1` is maintained at all times, consistent with the existing invariant protections for `min_attestations > 0` and `oracle_validity_length_ms > 0`.

**Test Cases:**

1. Test attempting to remove the only fee type (should fail)
2. Test removing a fee type when multiple exist (should succeed)
3. Test removing all but one fee type in sequence (last removal should fail)
4. Test oracle submission after attempted last fee type removal (should still work)

### Proof of Concept

**Initial State:**
- Queue initialized with default fee type SUI
- No additional fee types added
- Queue has active aggregators with oracle feeds

**Attack Sequence:**

1. Queue authority calls `queue_remove_fee_coin_action::run<SUI>(queue, ctx)`
   - Validation passes (authority check, version check)
   - `queue.remove_fee_type<SUI>()` executes
   - `fee_types` vector becomes empty

2. Oracle attempts to submit price update via `aggregator_submit_result_action::run<SUI>(...)`
   - Reaches validation at line 94
   - `queue.has_fee_type<SUI>()` returns false (empty vector)
   - Transaction aborts with `EInvalidFeeType`

3. Oracle tries alternative fee types (USDC, etc.)
   - All attempts fail with same error
   - No valid fee type exists

4. Volo vault calls `get_asset_price(oracle_config, clock, asset_type)`
   - Reads aggregator's stale timestamp
   - After 1 minute, staleness check fails
   - Transaction aborts with `ERR_PRICE_NOT_UPDATED`

**Expected vs Actual:**

**Expected**: System prevents removal of last fee type, maintaining queue operability

**Actual**: Last fee type removal succeeds, queue becomes non-operational until authority adds new fee type

**Success Condition**: The validation check fails when attempting to remove the last fee type, maintaining the operational invariant `fee_types.length() >= 1`.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_remove_fee_coin_action.move (L38-47)
```text
public entry fun run<T>(
    queue: &mut Queue,
    ctx: &mut TxContext
) {   
    validate(
        queue,
        ctx,
    );
    actuate<T>(queue);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L134-134)
```text
            fee_types: vector::singleton(type_name::get<Coin<SUI>>()),
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/queue.move (L202-208)
```text
public (package) fun remove_fee_type<T>(queue: &mut Queue) {
    let (has_type, index) = queue.fee_types.index_of(&type_name::get<Coin<T>>());
    if (has_type == false) {
        return
    };
    queue.fee_types.swap_remove(index);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L94-95)
```text
    assert!(queue.has_fee_type<T>(), EInvalidFeeType);
    assert!(coin.value() >= queue.fee(), EInsufficientFee);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/queue/queue_set_configs_action.move (L35-36)
```text
    assert!(min_attestations > 0, EInvalidMinAttestations);
    assert!(oracle_validity_length_ms > 0, EInvalidOracleValidityLength);
```

**File:** volo-vault/sources/oracle.move (L134-135)
```text
    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/oracle.move (L258-260)
```text
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
```
