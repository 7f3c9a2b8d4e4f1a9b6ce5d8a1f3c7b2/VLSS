### Title
Staleness Check Bypass When Switchboard Aggregator Reports Future Timestamps

### Summary
The `get_current_price()` function contains an asymmetric conditional that only validates price staleness when `now >= max_timestamp`, completely bypassing the staleness check when the Switchboard aggregator's `max_timestamp` is in the future. This allows potentially stale or manipulated oracle prices to be accepted and stored in the vault's pricing system, affecting all vault operations that depend on accurate price data.

### Finding Description

The vulnerability exists in the staleness validation logic: [1](#0-0) 

The code only performs staleness validation when `now >= max_timestamp`. If `max_timestamp > now` (a future timestamp), the conditional evaluates to false and the entire staleness check is skipped, allowing the function to return an unchecked price.

The root cause is that Switchboard's validation does not prevent future timestamps: [2](#0-1) 

This validation requires `timestamp_ms + max_staleness_ms >= clock.timestamp_ms()`, which is automatically satisfied when `timestamp_ms > clock.timestamp_ms()`. This design likely accommodates clock drift between oracle nodes, but the vault code fails to handle this defensively.

The Switchboard aggregator computes `max_timestamp_ms` as the maximum timestamp across all oracle updates: [3](#0-2) 

In contrast, the vault's `get_asset_price()` function correctly uses absolute difference to handle both past and future timestamps: [4](#0-3) 

### Impact Explanation

**Direct Fund Impact**: When `update_price()` calls `get_current_price()` with a bypassed staleness check, stale prices are stored in the vault's `OracleConfig` and marked with the current timestamp. This creates a false appearance of freshness: [5](#0-4) 

These incorrectly validated prices are used throughout the vault system for critical operations:

- **Vault Operations**: Adaptors use prices for USD valuation calculations during DeFi strategy execution [6](#0-5) 

- **DEX Price Validation**: Cetus adaptor validates pool prices against oracle prices [7](#0-6) 

**Quantified Harm**:
- Users depositing/withdrawing at incorrect share prices
- Vault loss tolerance checks operating on wrong valuations
- Potential for value extraction through price manipulation timing
- Health factor calculations in Navi adaptor using stale prices

**Affected Parties**: All vault depositors, withdrawers, and the protocol's risk management system.

### Likelihood Explanation

**Reachable Entry Points**: The vulnerability is exploitable through public functions:
- `update_price()` - directly calls `get_current_price()` [8](#0-7) 

- `add_switchboard_aggregator()` and `change_switchboard_aggregator()` - initialize prices via `get_current_price()` [9](#0-8) 

**Feasible Preconditions**: 
1. A Switchboard oracle submits a price update with `timestamp_seconds` set to a future time (even 1 minute ahead)
2. This timestamp passes Switchboard's validation and becomes the aggregator's `max_timestamp_ms`
3. The vault calls `get_current_price()` before blockchain time catches up to that timestamp

**Execution Practicality**: Once a future timestamp exists in the Switchboard aggregator (whether through oracle clock drift, misconfiguration, or intentional manipulation), the bypass occurs automatically with no additional attacker action required.

**Detection Constraints**: The vulnerability is persistent - once stale data is stored with a current timestamp, subsequent reads via `get_asset_price()` appear legitimate because the stored `last_updated` timestamp looks fresh.

**Probability**: MEDIUM-HIGH - The vulnerability is always present in the code. Exploitation depends on oracle timing behavior, but Switchboard explicitly allows future timestamps for operational reasons (clock drift tolerance).

### Recommendation

**Code-Level Mitigation**: Replace the asymmetric conditional check with absolute difference, matching the pattern used in `get_asset_price()`:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    // Use absolute difference to handle both past and future timestamps
    assert!(max_timestamp.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    current_result.result().value() as u256
}
```

**Invariant to Enforce**: Oracle price timestamps must be validated for staleness regardless of whether they are in the past or future relative to blockchain time.

**Test Cases**:
1. Test `get_current_price()` with `max_timestamp = now + 100` (future) - should abort
2. Test `get_current_price()` with `max_timestamp = now - update_interval - 1` (too old) - should abort  
3. Test `get_current_price()` with `max_timestamp = now ± (update_interval - 1)` (acceptable range) - should succeed

### Proof of Concept

**Initial State**:
- Vault has `OracleConfig` with `update_interval = 60_000` ms (1 minute)
- Switchboard aggregator configured for an asset

**Attack Sequence**:

1. **Oracle submits future timestamp** (t = 0):
   - Oracle node has clock drift or intentionally sets `timestamp_seconds = blockchain_time + 120` (2 minutes ahead)
   - Switchboard validation passes: `(blockchain_time + 120_000) + max_staleness >= blockchain_time` ✓
   - Aggregator's `max_timestamp_ms` becomes `blockchain_time + 120_000`

2. **Vault calls update_price()** (t = 0):
   - `get_current_price()` is called with `now = blockchain_time`
   - Check at line 258: `now >= max_timestamp` → `blockchain_time >= blockchain_time + 120_000` → FALSE
   - Staleness assertion at line 259 is **skipped entirely**
   - Function returns price without validation

3. **Stale price stored as fresh** (t = 0):
   - Price stored with `last_updated = blockchain_time` (current time)
   - Even though underlying oracle data could be hours old, it now appears fresh

4. **Impact propagates** (t = 0 onwards):
   - Subsequent `get_asset_price()` calls succeed because stored timestamp looks fresh
   - Vault operations use incorrect prices for valuations
   - Users deposit/withdraw at wrong share prices

**Expected Result**: Price staleness check should detect and reject the unchecked price.

**Actual Result**: Price is accepted without staleness validation and stored with current timestamp, creating false appearance of freshness throughout the system.

**Success Condition**: The transaction completes successfully and stores a potentially stale price, defeating the staleness protection mechanism entirely.

### Notes

While the issue title mentions "integer overflow," the actual vulnerability is a **logic error** in conditional validation, not arithmetic overflow. Move's type system would cause an abort on underflow if `now - max_timestamp` were attempted with `max_timestamp > now`, but the conditional prevents this subtraction from ever occurring - which is precisely the problem, as it also prevents the staleness check from executing.

The vulnerability does not require compromising the vault's admin or operator roles. It exploits a defensive coding flaw in how the vault handles external oracle data. Even if Switchboard oracles are generally trustworthy, the vault's validation logic should handle edge cases (like future timestamps due to clock drift) defensively, which it currently fails to do.

### Citations

**File:** volo-vault/sources/oracle.move (L135-135)
```text
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/oracle.move (L170-170)
```text
    let init_price = get_current_price(config, clock, aggregator);
```

**File:** volo-vault/sources/oracle.move (L234-234)
```text
    let current_price = get_current_price(config, clock, aggregator);
```

**File:** volo-vault/sources/oracle.move (L239-240)
```text
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L392-392)
```text
        max_timestamp_ms = u64::max(max_timestamp_ms, update.timestamp_ms);
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
```
