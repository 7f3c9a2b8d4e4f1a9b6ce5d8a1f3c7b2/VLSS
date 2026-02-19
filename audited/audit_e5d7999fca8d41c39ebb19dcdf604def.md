### Title
Switchboard Oracle Future Timestamp Attack Enables Complete Price Feed DoS

### Summary
The Switchboard oracle aggregator accepts future timestamps without upper bound validation, and subsequently rejects all updates with earlier timestamps globally across all oracles. This allows an attacker with a valid oracle signature to freeze the entire price feed by submitting a far-future timestamp, blocking legitimate updates and causing Volo vault operations to use stale prices or fail entirely.

### Finding Description

The vulnerability exists in the timestamp validation and update storage logic of the Switchboard oracle system:

**1. Weak Timestamp Validation** [1](#0-0) 

The validation only checks that `timestamp + staleness >= now`, which allows any future timestamp to pass. There is no upper bound check to prevent timestamps far in the future.

**2. Global Timestamp Blocking in Update Storage** [2](#0-1) 

When storing updates, the code rejects any new update with a timestamp less than the last stored update's timestamp. Critically, this check is **global across all oracles**, not per-oracle. The `last_idx` points to the most recently added update from any oracle, and any subsequent update with an earlier timestamp is rejected regardless of which oracle submits it. [3](#0-2) 

The `UpdateState` struct maintains only a single `curr_idx` for all oracles, confirming the global nature of the blocking.

**3. Future Timestamps Not Filtered in Staleness Check** [4](#0-3) 

The staleness check only filters out OLD timestamps (`timestamp + staleness < now`), but does not filter out future timestamps. Future-timestamped updates are included in the aggregator's valid updates and contribute to the median calculation.

**4. Volo Staleness Check Bypass** [5](#0-4) 

When Volo's `get_current_price()` retrieves the price, it only performs staleness validation when `now >= max_timestamp`. If `max_timestamp` is in the future (due to a future-timestamped update), the staleness check is completely skipped, and Volo accepts the price without validation.

**5. Public Entry Point** [6](#0-5) 

The `run()` function is a public entry function that anyone can call with a valid oracle signature, making this vulnerability easily exploitable.

### Impact Explanation

**Severity: HIGH - Complete Oracle DoS Leading to Protocol Failure**

1. **Complete Price Feed Freeze**: Once an attacker submits a future-timestamped update (e.g., timestamp = now + 1 year), ALL subsequent updates from ALL oracles with earlier timestamps (including legitimate current updates) are rejected. The entire aggregator is frozen until real time catches up to the fake future timestamp.

2. **Vault Operations Blocked**: Volo vault operations depend on fresh oracle prices. With the price feed frozen:
   - Deposit/withdrawal operations fail due to stale prices
   - DeFi adaptor operations (Cetus, Navi, Suilend) cannot execute
   - Vault valuation becomes incorrect, affecting all users

3. **No Recovery Without Admin Intervention**: Users cannot unfreeze the oracle through normal operations. The entire protocol becomes unusable until:
   - Real time catches up (if attacker set timestamp 1 year ahead, protocol is down for 1 year), OR
   - Admins deploy a new aggregator and reconfigure all systems

4. **Stale Price Exploitation**: Even before complete failure, the bypass of Volo's staleness check means the protocol may accept and use stale prices for critical operations, potentially enabling price manipulation attacks.

### Likelihood Explanation

**Likelihood: MEDIUM - Requires Valid Oracle Signature**

**Attacker Requirements:**
- Must obtain a valid oracle signature for a future timestamp
- Two realistic scenarios:
  1. **Compromised Oracle**: If an oracle's private key is compromised, the attacker can generate signatures for any timestamp/price combination
  2. **Oracle Software Bug**: Misconfigured or buggy oracle software that generates future timestamps

**Attack Complexity:**
- **Low** once prerequisite is met: Single transaction call to `run()` with valid signature
- **Immediate and Automatic Impact**: No additional steps needed; the DoS takes effect instantly
- **Undetectable Until Too Late**: Valid signature passes all checks; appears as legitimate update

**Feasibility Conditions:**
- Oracle private keys are high-value targets in DeFi systems
- Historical precedent exists for oracle compromises and software bugs
- The impact is severe enough to justify significant attacker effort
- No rate limiting or additional safeguards exist

**Economic Rationality:**
- **Low Attack Cost**: Single transaction with oracle fee
- **High Impact**: Complete protocol DoS affecting all users and TVL
- **Profitable Through**: Short positions on protocol tokens, exploiting stale prices before complete freeze, or competitive sabotage

### Recommendation

**Immediate Mitigation:**

1. **Add Upper Bound Timestamp Validation** [1](#0-0) 

Add a check immediately after the existing validation:
```
assert!(timestamp_seconds * 1000 <= clock.timestamp_ms() + ALLOWED_FUTURE_DRIFT_MS, ETimestampInFuture);
```
Where `ALLOWED_FUTURE_DRIFT_MS` is a small tolerance (e.g., 60 seconds) for clock drift.

2. **Add Future Timestamp Filter in Volo** [5](#0-4) 

Modify the staleness check to reject future timestamps:
```
let max_timestamp = current_result.max_timestamp_ms();
assert!(max_timestamp <= now, ERR_FUTURE_TIMESTAMP);
assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

3. **Fix Per-Oracle Timestamp Tracking** [2](#0-1) 

Consider maintaining per-oracle timestamp tracking instead of global blocking to prevent one oracle from blocking others.

**Testing Requirements:**
- Test case attempting to submit timestamp > now + drift tolerance
- Test case verifying legitimate updates succeed after fixing
- Test case confirming per-oracle independence if implementing recommendation 3

### Proof of Concept

**Initial State:**
- Switchboard aggregator configured with `max_staleness_seconds = 3600` (1 hour)
- Multiple oracles (Oracle A, B, C) providing price updates
- Current blockchain time: `now = 1000000000` ms
- Volo vault depends on this aggregator for asset pricing

**Attack Sequence:**

**Step 1:** Attacker obtains valid oracle signature for Oracle A with:
- `timestamp_seconds = 2000000` (future timestamp: now + 1000 seconds)
- `value = 100000000000` (legitimate-looking price)
- Valid signature from Oracle A's private key

**Step 2:** Attacker calls:
```
aggregator_submit_result_action::run(
    aggregator,
    queue,
    value: 100000000000,
    neg: false,
    timestamp_seconds: 2000000,  // Far future timestamp
    oracle: Oracle A,
    signature: valid_signature,
    clock,
    fee
)
```

**Step 3:** Validation passes: [1](#0-0) 
- Check: `2000000000 + 3600000 >= 1000000000` ✓ (passes)
- No upper bound check exists

**Step 4:** Update stored with future timestamp: [7](#0-6) 
- `timestamp_ms = 2000000000` is stored
- `curr_idx` now points to this future-timestamped update

**Step 5:** Legitimate oracles attempt updates:
- Oracle B tries to submit update with `timestamp = 1000010000` (10 seconds after now)
- Oracle C tries to submit update with `timestamp = 1000020000` (20 seconds after now)

**Step 6:** All legitimate updates REJECTED: [8](#0-7) 
- Check: `1000010000 < 2000000000` → returns early (rejected)
- Check: `1000020000 < 2000000000` → returns early (rejected)

**Result:**
- **Expected:** Legitimate updates accepted, future timestamp rejected
- **Actual:** Future timestamp accepted, all legitimate updates blocked
- **Impact:** Aggregator frozen for 1000 seconds; Volo vault cannot get fresh prices; all vault operations fail or use stale data
- **Success Condition:** Protocol DoS until `now >= 2000000000` or admin intervention

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L66-66)
```text
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L133-143)
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L30-33)
```text
public struct UpdateState has store {
    results: vector<Update>,
    curr_idx: u64,
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L243-257)
```text
public(package) fun add_result(
    aggregator: &mut Aggregator,
    result: Decimal,
    timestamp_ms: u64,
    oracle: ID,
    clock: &Clock,
) {
    let now_ms = clock.timestamp_ms();
    set_update(&mut aggregator.update_state, result, oracle, timestamp_ms);
    let mut current_result = compute_current_result(aggregator, now_ms);
    if (current_result.is_some()) {
        aggregator.current_result = current_result.extract();
        // todo: log the result
    };
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L310-315)
```text
    if (results.length() > 0) {
        let last_result = &results[last_idx];
        if (timestamp_ms < last_result.timestamp_ms) {
            return
        };
    };
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L574-576)
```text
        if (remaining_max_iterations == 0 || (results[idx].timestamp_ms + max_staleness_ms) < now_ms) {
            break
        };
```

**File:** volo-vault/sources/oracle.move (L258-260)
```text
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
```
