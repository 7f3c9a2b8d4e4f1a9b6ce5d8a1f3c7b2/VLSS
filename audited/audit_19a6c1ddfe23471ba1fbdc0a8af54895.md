### Title
Future Timestamp Bypass in Switchboard Oracle Staleness Validation Allows Use of Stale Prices

### Summary
The Switchboard oracle update mechanism fails to validate that timestamps are not in the future, despite code comments indicating this check should exist. This allows oracle updates with future timestamps to bypass staleness validation in the vault's `get_current_price()` function, enabling the use of potentially stale or manipulated prices in critical vault operations including deposits, withdrawals, and position valuations.

### Finding Description

The vulnerability exists in the Switchboard oracle update validation and its downstream consumption in the vault oracle system.

**Root Cause - Missing Future Timestamp Check:**

In the Switchboard update validation, there is a comment indicating future timestamps should be rejected, but the actual check does not enforce this: [1](#0-0) 

The check `timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms()` only validates that the timestamp is not too old (within the staleness window), but does NOT reject future timestamps. For example, if current time is 1000ms and timestamp is 2000000ms (far future), the check `2000000 + 300000 >= 1000` passes.

The timestamp is then included in the signed message without future validation: [2](#0-1) 

**Aggregator Accepts Future Timestamps:**

When the aggregator processes updates, it filters out stale updates but not future ones: [3](#0-2) 

The check `(results[idx].timestamp_ms + max_staleness_ms) < now_ms` only filters updates that are too old. A future timestamp passes because `(future_time + max_staleness) < current_time` evaluates to false.

The aggregator then sets `max_timestamp_ms` to include future timestamps: [4](#0-3) 

**Staleness Check Bypass in Vault Oracle:**

The vault oracle's `get_current_price()` function critically depends on proper timestamp validation: [5](#0-4) 

When `max_timestamp` is in the future (greater than `now`), the condition `now >= max_timestamp` is false, causing the staleness assertion to be completely skipped. The function returns the price without validating freshness.

**Contrast with Protocol Oracle:**

The protocol oracle (used for Pyth/Supra) correctly rejects future timestamps: [6](#0-5) 

This shows the intended security behavior that the Switchboard integration fails to implement.

**Critical Usage in Vault Operations:**

The vulnerable oracle is used in critical vault adaptors for position valuation: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Direct Fund Impact:**
- During volatile market conditions, stale prices can be exploited for arbitrage attacks
- If the real price drops but the oracle shows an old higher price (due to bypassed staleness check), attackers can withdraw at inflated share values, draining vault funds
- If the real price increases but the oracle shows an old lower price, attackers can deposit and receive more shares than deserved, diluting existing shareholders
- Position valuations in Cetus, Navi, and Momentum adaptors would use incorrect prices, leading to wrong collateral/debt calculations

**Security Integrity Impact:**
- A fundamental security control (staleness validation) is bypassed
- The code comments indicate developers intended to prevent future timestamps, representing a critical implementation gap
- This violates the oracle invariant that prices must be fresh and validated

**Operational Impact:**
- Stale prices could persist for extended periods (until blockchain time catches up to the future timestamp)
- The vault's `MAX_UPDATE_INTERVAL` of 60 seconds becomes meaningless if future timestamps bypass the check
- All downstream operations relying on price freshness are compromised

### Likelihood Explanation

**Reachable Entry Point:**
The attack uses the public entry function for oracle updates: [9](#0-8) 

**Feasible Preconditions:**
- Requires a valid oracle signature with a future timestamp
- This can occur through natural clock skew between oracle systems and Sui blockchain
- Oracle software bugs in timestamp generation
- Does NOT require malicious compromise of oracle keys—timing issues are realistic operational scenarios
- The mismatch between code comment and implementation suggests developers are unaware of this gap

**Execution Practicality:**
- Once a future-timestamped signature is obtained (through clock skew or oracle bugs), execution is straightforward
- Single transaction to submit the oracle update
- No complex state manipulation or transaction ordering required

**Economic Rationality:**
- Oracle update fee is minimal compared to potential arbitrage profits during volatile markets
- Attack becomes profitable when price movements exceed the fee cost
- Detection is difficult as the bypass appears as a valid oracle update

### Recommendation

**Immediate Fix - Add Future Timestamp Validation:**

In `aggregator_submit_result_action.move`, add explicit check for future timestamps:

```move
// Ensure timestamp is not in the future
assert!(timestamp_seconds * 1000 <= clock.timestamp_ms(), ETimestampInvalid);

// Ensure timestamp is not too old (existing check)
assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```

Location: After line 66 in: [10](#0-9) 

**Secondary Defense - Fix Vault Oracle:**

In `vault_oracle.move` `get_current_price()`, add explicit future timestamp check:

```move
let max_timestamp = current_result.max_timestamp_ms();

// Reject future timestamps
assert!(max_timestamp <= now, ERR_INVALID_TIMESTAMP);

// Check staleness for valid timestamps
assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

Location: Replace lines 258-260 in: [11](#0-10) 

**Test Cases:**
1. Test that oracle updates with timestamps > current blockchain time are rejected
2. Test that vault oracle properly validates timestamps before accepting prices
3. Test behavior with clock skew scenarios (±5 seconds tolerance may be acceptable)
4. Regression test ensuring staleness checks work correctly for past timestamps

### Proof of Concept

**Initial State:**
- Switchboard aggregator exists with `max_staleness_seconds = 300`
- Vault oracle configured with `update_interval = 60000ms` (60 seconds)
- Current blockchain time: `T0 = 1000000ms`
- Current price in aggregator: `$100`

**Attack Sequence:**

1. **Submit Future-Timestamped Update:**
   - Call `aggregator_submit_result_action::run()`
   - Parameters: `timestamp_seconds = 2000` (2,000,000ms, far in future)
   - Value: `$100` (same as current)
   - Valid oracle signature for this timestamp
   
2. **Validation Passes Incorrectly:**
   - Check at line 66: `2000000 + 300000 >= 1000000` → TRUE ✓
   - Update accepted despite future timestamp
   - Aggregator's `max_timestamp_ms` becomes `2000000ms`

3. **Wait for Real Price Movement:**
   - Time advances to `T1 = 1100000ms` (100 seconds later)
   - Real market price drops to `$90`
   - No new oracle updates submitted (oracle is stale)

4. **Exploit via Vault Operations:**
   - Call `vault_oracle::update_price()` 
   - Internally calls `get_current_price()`
   - At line 258: `1100000 >= 2000000` → FALSE
   - Staleness check SKIPPED
   - Returns `$100` instead of failing on staleness
   - Attacker withdraws at inflated `$100` price while real price is `$90`

**Expected Result:**
Price should be rejected as stale (no updates in 100 seconds exceeds 60 second interval)

**Actual Result:**
Price of `$100` accepted as fresh, bypassing staleness validation

**Success Condition:**
Attacker successfully uses stale price for profitable withdrawal, demonstrating complete bypass of staleness security control

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L65-66)
```text
    // make sure that update staleness point is not in the future
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L133-147)
```text
public entry fun run<T>(
    aggregator: &mut Aggregator,
    queue: &Queue,
    value: u128,
    neg: bool,
    timestamp_seconds: u64,
    oracle: &Oracle,
    signature: vector<u8>,
    clock: &Clock,
    fee: Coin<T>,
) {
    let value = decimal::new(value, neg);
    validate<T>(aggregator, queue, oracle, timestamp_seconds, &value, signature, clock, &fee);
    actuate(aggregator, queue, value, timestamp_seconds, oracle, clock, fee);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L108-130)
```text
public fun generate_update_msg(
    value: &Decimal,
    queue_key: vector<u8>,
    feed_hash: vector<u8>,
    slothash: vector<u8>,
    max_variance: u64,
    min_responses: u32,
    timestamp: u64,
): vector<u8> {
    let mut hasher = new();
    assert!(queue_key.length() == 32, EWrongQueueLength);
    assert!(feed_hash.length() == 32, EWrongFeedHashLength);
    assert!(slothash.length() == 32, EWrongSlothashLength);
    hasher.push_bytes(queue_key);
    hasher.push_bytes(feed_hash);
    hasher.push_decimal_le(value);
    hasher.push_bytes(slothash);
    hasher.push_u64_le(max_variance);
    hasher.push_u32_le(min_responses);
    hasher.push_u64_le(timestamp);
    let Hasher { buffer } = hasher;
    buffer
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L391-392)
```text
        min_timestamp_ms = u64::min(min_timestamp_ms, update.timestamp_ms);
        max_timestamp_ms = u64::max(max_timestamp_ms, update.timestamp_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L573-576)
```text
        // if there are no remaining iterations, or the current element is stale, break
        if (remaining_max_iterations == 0 || (results[idx].timestamp_ms + max_staleness_ms) < now_ms) {
            break
        };
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L55-61)
```text
    public fun is_oracle_price_fresh(current_timestamp: u64, oracle_timestamp: u64, max_timestamp_diff: u64): bool {
        if (current_timestamp < oracle_timestamp) {
            return false
        };

        return (current_timestamp - oracle_timestamp) < max_timestamp_diff
    }
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```
