### Title
Switchboard Oracle Staleness Check Bypass via Future Timestamps Allows Stale Price Acceptance

### Summary
The `get_current_price()` function in the vault oracle module contains a conditional staleness check that only validates price freshness when `now >= max_timestamp`. When a Switchboard aggregator returns a future timestamp, this check is completely bypassed, allowing arbitrarily stale prices to be accepted and stored. An attacker can exploit this via the public `update_price()` function to manipulate vault share valuations.

### Finding Description

The vulnerability exists in the `get_current_price()` function's staleness validation logic: [1](#0-0) 

The staleness check is only performed when `now >= max_timestamp`. If the Switchboard aggregator's `max_timestamp_ms()` value is in the future (i.e., `now < max_timestamp`), the condition evaluates to false and no staleness validation occurs. The function then returns the price without any freshness guarantee.

**Root Cause:**
The code incorrectly assumes that `max_timestamp` will always be in the past or equal to the current time. However, Switchboard's validation does not prevent future timestamps: [2](#0-1) 

This check ensures the update isn't too stale, but explicitly allows future timestamps. The `max_timestamp_ms` is computed as the maximum across all oracle updates, so if any oracle node submits a future timestamp (due to clock skew or malicious intent), the aggregator's `max_timestamp_ms` will be in the future.

**Exploitation Path:**
The `update_price()` function is publicly callable (in Sui, `public fun` can be called via programmable transaction blocks): [3](#0-2) 

When `update_price()` calls `get_current_price()` with an aggregator that has a future timestamp, the stale price is accepted and stored with `last_updated = now` (current time). This makes the stale price appear fresh to all subsequent consumers.

The stored price is then used throughout vault operations for USD valuation: [4](#0-3) 

Note that while `get_asset_price()` uses `.diff()` which handles both past and future timestamps correctly via absolute difference, the damage is already done because `update_price()` has stored the stale price with a current timestamp.

### Impact Explanation

**Direct Fund Impact:**
- Stale prices can be exploited to manipulate vault share valuations during deposits and withdrawals
- If the actual price has moved significantly since the stale price data, attackers can:
  - Deposit at artificially low prices to receive more shares than deserved
  - Withdraw at artificially high prices to extract more value than entitled
  - Bypass loss tolerance mechanisms by using favorable historical prices

**Example Scenario:**
1. Real SUI price: $1.10 (current market)
2. Stale Switchboard data contains: $1.00 (from 1 hour ago)
3. Aggregator has future timestamp due to oracle clock skew
4. Attacker calls `update_price()` to store $1.00 with current timestamp
5. Attacker deposits SUI, receiving shares valued at $1.00/SUI instead of $1.10/SUI
6. Attacker receives 10% more shares than deserved
7. When price corrects, attacker withdraws with 10% profit

**Severity Justification:**
This is HIGH severity because:
- Allows direct manipulation of vault asset valuations
- Affects all users interacting with the vault during the stale price window
- Can lead to measurable fund loss through share ratio manipulation
- The vault's loss tolerance mechanism is designed to prevent this type of value manipulation, but stale prices can bypass it

### Likelihood Explanation

**Reachable Entry Point:**
The attack requires only calling `update_price()`, which is a public function callable by anyone via Sui programmable transaction blocks (PTBs). No special privileges required.

**Feasible Preconditions:**
1. A Switchboard aggregator must have `max_timestamp_ms` in the future
2. This can occur through:
   - Oracle node clock skew (common in distributed systems)
   - Malicious oracle node (if compromised)
   - Network timing issues
3. The aggregator must be configured in the vault's oracle config (admin-set, but uses legitimate Switchboard infrastructure)

**Execution Practicality:**
1. Monitor Switchboard aggregators for future timestamps (publicly readable)
2. When detected, call `update_price()` in a PTB with deposit/withdrawal operations
3. All steps executable under normal Sui Move semantics
4. The check at line 237 ensures the aggregator matches the configured one, but this doesn't prevent the vulnerability

**Economic Rationality:**
- Zero cost to check for vulnerable aggregator states
- Transaction costs minimal (standard PTB gas)
- Profit scales with deposit size and price deviation magnitude
- Risk of detection low since update_price() is a legitimate public function

**Probability Assessment:**
MEDIUM-HIGH likelihood because:
- Clock skew in distributed oracle networks is not uncommon
- No active monitoring prevents future timestamps in Switchboard
- Attack window exists whenever oracle timestamps drift forward
- Completely passive monitoring can detect opportunities

### Recommendation

**Immediate Fix:**
Replace the conditional staleness check with an absolute difference check that handles both past and future timestamps:

```move
// BEFORE (lines 258-260):
if (now >= max_timestamp) {
    assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
};

// AFTER:
assert!(max_timestamp.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

This ensures staleness validation occurs regardless of whether the timestamp is in the past or future, using the same `.diff()` method that `get_asset_price()` already uses correctly.

**Additional Hardening:**
Consider adding an explicit future timestamp rejection:
```move
// Reject timestamps too far in the future (e.g., > 1 minute ahead)
assert!(max_timestamp <= now + ACCEPTABLE_CLOCK_SKEW, ERR_FUTURE_TIMESTAMP);
assert!(max_timestamp.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**Test Cases:**
1. Test `get_current_price()` with `max_timestamp` exactly equal to `now`
2. Test with `max_timestamp` 30 seconds in the past (should pass)
3. Test with `max_timestamp` > `update_interval` in the past (should fail)
4. Test with `max_timestamp` 30 seconds in the future (should fail with fix)
5. Test with `max_timestamp` > `update_interval` in the future (should fail)

### Proof of Concept

**Initial State:**
1. Vault has configured Switchboard aggregator for SUI price
2. Real SUI market price: $1.10
3. Switchboard aggregator contains stale price data: $1.00 (from 1 hour ago)
4. One oracle node has clock 2 minutes ahead, causing `max_timestamp_ms` = `now + 120000`

**Attack Transaction (via PTB):**
```
Transaction {
    // Step 1: Update to stale price (exploits the vulnerability)
    Call update_price(
        oracle_config,
        switchboard_aggregator,  // has max_timestamp in future
        clock,
        "SUI"
    );
    // Now oracle has $1.00 with last_updated = now
    
    // Step 2: Deposit SUI at manipulated price
    Call deposit(
        vault,
        reward_manager,
        1000 SUI,  // $1100 real value
        expected_shares: 1000,  // calculated at $1.00/SUI = $1000
        ...
    );
    // Receives shares worth $1100 for only $1000
}
```

**Expected Result (with vulnerability):**
- `get_current_price()` at line 258: condition `(now >= max_timestamp)` is FALSE
- Staleness check skipped
- Returns $1.00 price
- Price stored with `last_updated = now`
- Deposit executes at $1.00/SUI valuation
- Attacker receives 10% more shares than deserved

**Actual Result (with fix):**
- `get_current_price()` would use `max_timestamp.diff(now)` 
- Calculates absolute difference: `|max_timestamp - now| = 120000ms`
- Compares against `update_interval` (60000ms)
- `120000 >= 60000` → assertion fails with `ERR_PRICE_NOT_UPDATED`
- Transaction aborts, preventing stale price acceptance

**Success Condition:**
The vulnerability is confirmed if an attacker can successfully store a stale price by exploiting a future timestamp, then execute vault operations using that manipulated price.

### Citations

**File:** volo-vault/sources/oracle.move (L126-137)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
```

**File:** volo-vault/sources/oracle.move (L225-240)
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
```

**File:** volo-vault/sources/oracle.move (L258-260)
```text
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L66-66)
```text
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```
