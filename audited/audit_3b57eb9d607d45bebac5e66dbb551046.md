### Title
Feed Hash Change Without Buffer Invalidation Causes Cross-Feed Data Contamination

### Summary
The `set_configs()` function allows changing the aggregator's `feed_hash` without clearing the existing update buffer, enabling data from different feeds to be mixed together in price calculations. When the Volo vault reads prices from such a contaminated aggregator, it may make critical operational decisions based on corrupted data mixing values from fundamentally different data sources or asset pairs.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The `set_configs()` function directly updates the `feed_hash` field without invalidating or clearing the `update_state.results` buffer. This buffer stores `Update` structs that were validated against the previous feed_hash.

When oracle updates are submitted, they are cryptographically validated against the current `feed_hash` through signature verification: [2](#0-1) 

However, when computing the current result, the system does not verify that buffered updates match the current feed_hash: [3](#0-2) 

The `valid_update_indices()` function only filters by staleness and oracle uniqueness, never checking feed_hash: [4](#0-3) 

**Execution Path:**
1. Aggregator has feed_hash A with valid updates in buffer (up to 16 updates stored in circular buffer)
2. Aggregator authority calls `aggregator_set_configs_action::run()` entry point: [5](#0-4) 
3. Feed_hash changes to B, but buffer retains updates from feed A
4. New oracle updates for feed_hash B are submitted and added to buffer
5. Buffer now contains: `[feed A updates, feed B updates]`
6. When `compute_current_result()` is invoked, it processes all non-stale updates regardless of feed_hash
7. Statistical calculations (median, mean, variance) mix data from both feeds
8. Volo vault reads this contaminated price via: [6](#0-5) 

### Impact Explanation

**Direct Impact on Volo Vault:**
The vault relies on Switchboard aggregator prices for critical operations including asset valuations, share calculations, and operational decisions. Contaminated price data has severe consequences:

1. **Asset Valuation Corruption:** If feed A represents BTC/USD and feed B represents ETH/USD, the mixed result would be a statistically meaningless number used to price either asset.

2. **Operation Safety Compromised:** The vault uses these prices to calculate total USD value and enforce loss tolerance per epoch. Contaminated prices could trigger incorrect loss tolerance violations or mask actual losses.

3. **Share Calculation Errors:** Price data affects deposit/withdrawal share calculations. Corrupted prices could lead to unfair share distribution between users.

4. **Statistical Integrity Loss:** Even when both feeds represent the same asset from different sources, mixing invalidates variance, standard deviation, and range calculations that may be used for risk assessment.

The vault's price staleness check only validates timestamp freshness, not feed integrity: [7](#0-6) 

**Severity:** Critical - Violates the "Oracle & Valuation" invariant requiring correct price handling and can directly impact fund valuations and operational decisions.

### Likelihood Explanation

**Reachable Entry Point:** The `aggregator_set_configs_action::run()` function is a public entry point accessible to the aggregator authority: [8](#0-7) 

**Feasible Preconditions:** 
- Aggregator authority role exists for legitimate feed management
- Updates remain valid for duration of `max_staleness_seconds` (can be hours or days)
- Feed configuration changes are normal administrative operations (e.g., migrating data sources, updating feed parameters)

**Execution Practicality:**
This is NOT about malicious authority behavior. Legitimate scenarios include:
1. Migrating from one data provider to another
2. Updating feed configuration with new parameters
3. Switching between test and production feeds
4. Correcting misconfigured feeds

The authority would naturally call `set_configs()` for any of these legitimate purposes without realizing the buffer contamination issue.

**No Detection Mechanism:** The system provides no warning, error, or event indicating that updates from different feeds are being mixed. The authority receives confirmation that the config was updated, unaware of the data integrity violation.

**Probability:** High - Feed configuration updates are expected administrative actions, and with longer staleness windows (common for less volatile assets), the buffer will contain multiple valid updates during configuration changes.

### Recommendation

**Immediate Fix:** Clear the update buffer when feed_hash changes:

```move
public(package) fun set_configs(
    aggregator: &mut Aggregator,
    feed_hash: vector<u8>,
    min_sample_size: u64,
    max_staleness_seconds: u64,
    max_variance: u64,
    min_responses: u32,
) {
    // If feed_hash is changing, clear the update buffer
    if (aggregator.feed_hash != feed_hash) {
        aggregator.update_state.results = vector::empty();
        aggregator.update_state.curr_idx = 0;
        // Reset current_result to zero values
        aggregator.current_result = CurrentResult {
            result: decimal::zero(),
            min_timestamp_ms: 0,
            max_timestamp_ms: 0,
            min_result: decimal::zero(),
            max_result: decimal::zero(),
            stdev: decimal::zero(),
            range: decimal::zero(),
            mean: decimal::zero(),
            timestamp_ms: 0,
        };
    };
    
    aggregator.feed_hash = feed_hash;
    aggregator.min_sample_size = min_sample_size;
    aggregator.max_staleness_seconds = max_staleness_seconds;
    aggregator.max_variance = max_variance;
    aggregator.min_responses = min_responses;
}
```

**Additional Safeguard:** Add feed_hash validation in `compute_current_result()` or store feed_hash with each update for verification.

**Test Cases:**
1. Verify buffer is cleared when feed_hash changes
2. Verify current_result is reset when feed_hash changes
3. Verify no cross-feed data contamination occurs during configuration updates
4. Test with various staleness windows and buffer fill levels

### Proof of Concept

**Initial State:**
- Aggregator with feed_hash = `FEED_A_HASH` (e.g., BTC/USD feed)
- `max_staleness_seconds = 3600` (1 hour)
- Buffer contains 10 valid updates for BTC/USD ranging from $60,000 to $61,000
- All updates are less than 1 hour old

**Transaction Sequence:**

**Step 1:** Authority calls `aggregator_set_configs_action::run()` to change feed:
```
feed_hash = FEED_B_HASH // ETH/USD feed
min_sample_size = 3
max_staleness_seconds = 3600
max_variance = 100000000000
min_responses = 5
```

**Step 2:** Oracle submits 5 new updates for ETH/USD ranging from $3,000 to $3,100

**Step 3:** Vault calls `get_current_price()` to read price

**Expected Result:** 
- Price should reflect only ETH/USD data (new feed)
- Or error indicating insufficient data for new feed

**Actual Result:**
- `compute_current_result()` processes all 15 updates (10 BTC + 5 ETH)
- Median calculation returns a value mixing $60,000 range with $3,000 range
- Statistical calculations (variance, std dev, range) are meaningless
- Vault caches and uses this corrupted price for critical operations

**Success Condition:** Demonstrating that `current_result` contains mixed data can be verified by:
1. Checking `min_result` and `max_result` span values from both feeds
2. Observing `range` value that would be impossibly large for a single asset
3. Confirming buffer length equals sum of both feed's updates

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L227-240)
```text
public(package) fun set_configs(
    aggregator: &mut Aggregator,
    feed_hash: vector<u8>,
    min_sample_size: u64,
    max_staleness_seconds: u64,
    max_variance: u64,
    min_responses: u32,
) {
    aggregator.feed_hash = feed_hash;
    aggregator.min_sample_size = min_sample_size;
    aggregator.max_staleness_seconds = max_staleness_seconds;
    aggregator.max_variance = max_variance;
    aggregator.min_responses = min_responses;
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L338-412)
```text
fun compute_current_result(aggregator: &Aggregator, now_ms: u64): Option<CurrentResult> {
    let update_state = &aggregator.update_state;
    let updates = &update_state.results;
    let mut update_indices = update_state.valid_update_indices(aggregator.max_staleness_seconds * 1000, now_ms);

    // if there are not enough valid updates, return
    if (update_indices.length() < aggregator.min_sample_size) {
        return option::none()
    };

    // if there's only 1 index, return the result
    if (update_indices.length() == 1) {
        let (result, timestamp_ms) = update_state.median_result(&mut update_indices);
        return option::some(CurrentResult {
            min_timestamp_ms: updates[update_indices[0]].timestamp_ms,
            max_timestamp_ms: updates[update_indices[0]].timestamp_ms,
            min_result: result,
            max_result: result,
            range: decimal::zero(),
            result,
            stdev: decimal::zero(),
            mean: result,
            timestamp_ms,
        })
    };

    let mut sum: u128 = 0;
    let mut min_result = decimal::max_value();
    let mut max_result = decimal::zero();
    let mut min_timestamp_ms = u64::max_value!();
    let mut max_timestamp_ms = 0;
    let mut mean: u128 = 0;
    let mut mean_neg: bool = false;
    let mut m2: u256 = 0;
    let mut m2_neg: bool = false;
    let mut count: u128 = 0;

    vector::do_ref!(&update_indices, |idx| {
        let update = &updates[*idx];
        let value = update.result.value();
        let value_neg = update.result.neg();
        count = count + 1;

        // Welford's online algorithm
        let (delta, delta_neg) = sub_i128(value, value_neg, mean, mean_neg);
        (mean, mean_neg) = add_i128(mean, mean_neg, delta / count, delta_neg);
        let (delta2, delta2_neg) = sub_i128(value, value_neg, mean, mean_neg);

        (m2, m2_neg) = add_i256(m2, m2_neg, (delta as u256) * (delta2 as u256), delta_neg != delta2_neg);

        sum = sum + value;
        min_result = decimal::min(&min_result, &update.result);
        max_result = decimal::max(&max_result, &update.result);
        min_timestamp_ms = u64::min(min_timestamp_ms, update.timestamp_ms);
        max_timestamp_ms = u64::max(max_timestamp_ms, update.timestamp_ms);
    });

    let variance = m2 / ((count - 1) as u256); 
    let stdev = sqrt(variance);
    let range = max_result.sub(&min_result);
    let (result, timestamp_ms) = update_state.median_result(&mut update_indices);
    
    // update the current result
    option::some(CurrentResult {
        min_timestamp_ms,
        max_timestamp_ms,
        min_result,
        max_result,
        range,
        result,
        stdev: decimal::new(stdev, false),
        mean: decimal::new(mean, false),
        timestamp_ms,
    })
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L558-598)
```text
fun valid_update_indices(update_state: &UpdateState, max_staleness_ms: u64, now_ms: u64): vector<u64> {
    let results = &update_state.results;
    let mut valid_updates = vector::empty<u64>();
    let mut seen_oracles = vec_set::empty<ID>();

    // loop backwards through the results
    let mut idx =  update_state.curr_idx;
    let mut remaining_max_iterations = u64::min(MAX_RESULTS, results.length());
    
    if (remaining_max_iterations == 0) {
        return valid_updates
    };

    loop {

        // if there are no remaining iterations, or the current element is stale, break
        if (remaining_max_iterations == 0 || (results[idx].timestamp_ms + max_staleness_ms) < now_ms) {
            break
        };

        let result = &results[idx];
        let oracle = result.oracle;
        

        if (!seen_oracles.contains(&oracle)) {
            seen_oracles.insert(oracle);
            valid_updates.push_back(idx);
        };

        // step backwards
        if (idx == 0) {
            idx = results.length() - 1;
        } else {
            idx = idx - 1;
        };

        remaining_max_iterations = remaining_max_iterations - 1;
    };

    valid_updates
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L72-80)
```text
    let update_msg = hash::generate_update_msg(
        value,
        oracle.queue_key(),
        aggregator.feed_hash(),
        x"0000000000000000000000000000000000000000000000000000000000000000",
        aggregator.max_variance(),
        aggregator.min_responses(),
        timestamp_seconds,
    );
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L77-103)
```text
public entry fun run(
    aggregator: &mut Aggregator,
    feed_hash: vector<u8>,
    min_sample_size: u64,
    max_staleness_seconds: u64,
    max_variance: u64,
    min_responses: u32,
    ctx: &mut TxContext
) {   
    validate(
        aggregator,
        feed_hash,
        min_sample_size,
        max_staleness_seconds,
        max_variance,
        min_responses,
        ctx
    );
    actuate(
        aggregator,
        feed_hash,
        min_sample_size,
        max_staleness_seconds,
        max_variance,
        min_responses
    );
}
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
