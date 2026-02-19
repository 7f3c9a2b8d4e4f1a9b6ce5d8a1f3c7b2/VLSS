### Title
Oracle Staleness Check Bypass with Future Timestamps Allows Stale Price Usage

### Summary
The `get_current_price` function in the Volo vault oracle module fails to validate price freshness when the Switchboard aggregator's `max_timestamp_ms` is in the future. Since the Switchboard oracle submission process does not prevent future timestamps, a malicious or misconfigured oracle provider can submit prices with far-future timestamps, causing the staleness check to be bypassed for extended periods, allowing critically stale prices to be used for vault operations.

### Finding Description

The vulnerability exists in the oracle price validation logic at two levels:

**1. Switchboard Submission Validation (Insufficient Future Timestamp Prevention)** [1](#0-0) 

The validation only checks that `timestamp_ms + max_staleness_ms >= now`, which prevents timestamps that are too old but does NOT prevent future timestamps. An oracle can submit a price with `timestamp_ms > now` and pass validation.

**2. Volo Vault Staleness Check (Bypassed for Future Timestamps)** [2](#0-1) 

The staleness check in `get_current_price` only executes when `now >= max_timestamp`. If `now < max_timestamp`, the condition at line 258 is false, the assertion at line 259 is skipped, and the price is returned without any freshness validation.

**3. CurrentResult Structure** [3](#0-2) 

The `CurrentResult` struct contains `timestamp_ms`, `min_timestamp_ms`, and `max_timestamp_ms`, but provides no built-in staleness validation threshold to consumers.

**Root Cause:** The conditional staleness check assumes timestamps are always in the past or present, but doesn't handle the case where malicious or misconfigured oracles submit future timestamps. This allows the staleness validation to be completely bypassed during the period when `now < max_timestamp_ms`.

**Execution Path:**
1. Oracle provider submits price at time T with timestamp T+X (where X is a large positive offset)
2. Switchboard validation passes: `(T+X) + max_staleness >= T` ✓
3. Price is stored in aggregator's `current_result` with `max_timestamp_ms = T+X`
4. Vault calls `get_current_price` at any time T' where T' < T+X
5. Condition `now >= max_timestamp` is false, staleness check is skipped
6. Stale price is returned and used for vault operations

### Impact Explanation

**Direct Fund Impact:**
- Vault operations (deposits, withdrawals, adaptors) rely on accurate pricing for asset valuations
- Stale prices cause incorrect USD value calculations, affecting share minting/burning ratios
- Arbitrageurs can exploit the price discrepancy between stale oracle prices and actual market prices
- Potential for systematic value extraction from the vault over extended periods

**Quantified Damage:**
- If an oracle submits a price with timestamp 1 year in the future, that price could be used for up to 1 year without any staleness check
- During high volatility periods (e.g., 50% price swings), using stale prices could result in massive valuation errors
- Example: If SUI price moves from $1 to $1.50, but vault uses stale $1 price, depositors receive 50% more shares than they should

**Affected Components:**
- All vault adaptors that rely on oracle pricing [4](#0-3) 
- Core vault valuation logic accessed via `get_asset_price` [5](#0-4) 

**Severity Justification:** HIGH - Violates critical invariant #5 (Oracle & Valuation staleness checks) and enables direct fund impact through pricing manipulation over extended time periods.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires control of a single Switchboard oracle provider (via compromise or malicious insider)
- Alternatively, legitimate oracle with significant clock skew can trigger this unintentionally
- No special permissions beyond normal oracle operation required

**Attack Complexity:**
- LOW - Single malicious oracle submission with future timestamp
- No complex transaction sequences or timing requirements
- Attack persists passively once future timestamp is in the system

**Feasibility Conditions:**
- Oracle provider trust model assumes honest majority, but single malicious oracle can trigger the vulnerability
- No monitoring or detection mechanisms for future timestamps in the current implementation
- The `update_price` function can be called by anyone [6](#0-5) 

**Probability:** MEDIUM-HIGH - While oracle providers are generally trusted, the lack of technical controls against future timestamps combined with potential clock synchronization issues makes this exploitable in practice.

### Recommendation

**Immediate Fix:**

Modify the staleness check in `get_current_price` to handle both past and future timestamps:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    // Reject future timestamps
    assert!(max_timestamp <= now, ERR_PRICE_NOT_UPDATED);
    
    // Check staleness for past timestamps
    assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    current_result.result().value() as u256
}
```

**Additional Hardening:**

Add timestamp validation in Switchboard submission to prevent future timestamps:

```move
// In aggregator_submit_result_action.move validate() function:
// Ensure timestamp is not in the future
assert!(timestamp_seconds * 1000 <= clock.timestamp_ms(), ETimestampInvalid);

// Ensure timestamp is not too stale
assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```

**Test Cases:**
1. Test oracle submission with timestamp > current time (should fail)
2. Test `get_current_price` with future `max_timestamp_ms` (should fail)
3. Test staleness over time as future timestamp becomes past timestamp
4. Test legitimate clock skew within acceptable bounds

### Proof of Concept

**Initial State:**
- Vault deployed with oracle config, `update_interval = 60000` (1 minute)
- Switchboard aggregator configured for asset price feed
- Current time T = 1000000

**Exploitation Steps:**

1. **T=1000000**: Malicious oracle submits price update
   - Price: $100 (current market price)
   - Timestamp: 2000000 (1,000,000ms in the future)
   - Switchboard validation: `2000000 + max_staleness >= 1000000` ✓ Passes

2. **T=1000000**: Aggregator computes `current_result`
   - `max_timestamp_ms = 2000000`
   - Price stored: $100

3. **T=1500000**: Market price changes to $150 (50% increase), but no new oracle update

4. **T=1500000**: Vault operation calls `get_current_price`
   - Condition: `1500000 >= 2000000`? FALSE
   - Staleness check SKIPPED
   - Returns: $100 (500,000ms stale price)

5. **T=1500000**: User deposits with $150 actual value
   - Vault values deposit at $100 (stale price)
   - User receives 50% more shares than deserved
   - Vault suffers 33% loss on this deposit

**Expected Result:** Price should be rejected as stale after 60 seconds (update_interval)

**Actual Result:** Stale price accepted for 1,000,000ms (16.7 minutes) without any freshness check, enabling systematic value extraction until timestamp 2000000 is reached.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L65-66)
```text
    // make sure that update staleness point is not in the future
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L12-22)
```text
public struct CurrentResult has copy, drop, store {
    result: Decimal,
    timestamp_ms: u64,
    min_timestamp_ms: u64,
    max_timestamp_ms: u64,
    min_result: Decimal,
    max_result: Decimal,
    stdev: Decimal,
    range: Decimal,
    mean: Decimal,
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```
