### Title
Oracle Configuration Attack via Switchboard Aggregator Authority Transfer

### Summary
The Volo vault accepts Switchboard aggregators without validating their authority ownership or configuration parameters. After an aggregator is added to the vault, its authority can transfer control to a malicious address who can weaken security settings (`min_sample_size=1`, `max_staleness_seconds=u64::MAX`), enabling price manipulation through a single compromised oracle that bypasses the vault's staleness protections.

### Finding Description

**Root Cause:**

The vault's `add_switchboard_aggregator` function accepts any Switchboard aggregator without validating:
1. Who controls the aggregator's authority
2. Whether the aggregator's configuration parameters are secure
3. Whether authority transfers occur post-addition [1](#0-0) 

**Attack Path:**

1. Volo admin adds a Switchboard aggregator (controlled by external party or later compromised)

2. The aggregator's authority invokes `aggregator_set_authority_action::run()` to transfer control to a malicious address with no restrictions: [2](#0-1) 

3. The new malicious authority calls `aggregator_set_configs_action::run()` to weaken security: [3](#0-2) 

The validation only requires `min_sample_size > 0` and `max_staleness_seconds > 0`, allowing: [4](#0-3) 

4. With `min_sample_size=1`, the aggregator accepts results from a single oracle: [5](#0-4) 

5. With `max_staleness_seconds` set to u64::MAX, extremely old data passes staleness checks: [6](#0-5) 

**Why Vault Protections Fail:**

The vault's `get_current_price` checks staleness using `max_timestamp_ms()` from the aggregator's result: [7](#0-6) 

However, `max_timestamp_ms()` reflects the oracle submission timestamp, not the aggregator's internal validation. A malicious oracle can submit manipulated prices with current timestamps that pass the vault's 1-minute staleness check while the aggregator accepts it due to weakened `min_sample_size` and `max_staleness_seconds` parameters.

### Impact Explanation

**Direct Fund Impact:**

Manipulated oracle prices directly affect vault operations:

1. **Deposit exploitation**: Attacker deposits when oracle reports artificially low principal price, receiving inflated shares: [8](#0-7) 

2. **Withdrawal exploitation**: Attacker withdraws when oracle reports artificially high principal price, receiving inflated coin amounts

3. **Loss tolerance bypass**: Manipulated prices can disguise losses or fake profits, bypassing the vault's loss tolerance mechanism

**Affected Parties:**
- All vault depositors suffer dilution from manipulated share calculations
- Protocol solvency at risk from systematic price manipulation
- Loss tolerance safeguards become ineffective

**Severity Justification:**
Critical - enables direct fund theft through price manipulation with potential for complete vault drainage if attack is sustained across multiple operations.

### Likelihood Explanation

**Attack Prerequisites:**

1. Volo admin adds a Switchboard aggregator where:
   - Admin doesn't control the aggregator authority, OR
   - The aggregator authority is later compromised

2. Attacker gains control of aggregator authority (via compromise or transfer)

3. Attacker has access to at least one oracle in the aggregator's queue

**Feasibility:**

- **Moderate complexity**: Requires multiple steps but no novel cryptographic breaks
- **Realistic scenario**: Third-party aggregators or shared aggregator infrastructure increases likelihood
- **No protocol-level detection**: Vault has no mechanism to detect authority changes or configuration weakening
- **Economic viability**: Profit from price manipulation can easily exceed attack costs (compromising single oracle + gas fees)

**Operational Constraints:**

The attack becomes more likely when:
- Volo uses community or shared Switchboard aggregators
- Aggregator authority is managed by external entities
- No monitoring exists for aggregator configuration changes

### Recommendation

**Immediate Mitigations:**

1. Add authority validation in `add_switchboard_aggregator`:
```
Assert that aggregator.authority() == admin_address or whitelisted_authorities
Validate min_sample_size >= safe_threshold (e.g., 5)
Validate max_staleness_seconds <= reasonable_maximum (e.g., 300 seconds)
```

2. Add configuration validation in `get_current_price`:
```
Assert aggregator.min_sample_size() >= minimum_required_oracles
Assert aggregator.max_staleness_seconds() <= maximum_allowed_staleness
```

3. Store expected aggregator authority in OracleConfig and validate it hasn't changed on each price fetch

4. Emit events when aggregator configuration changes are detected

**Long-term Solution:**

Deploy Volo-controlled Switchboard aggregators where the vault admin maintains exclusive authority, or implement a multi-signature authority scheme with governance oversight.

**Test Cases:**

1. Verify `add_switchboard_aggregator` rejects aggregators with unsafe configuration
2. Test that authority transfer detection prevents price fetching from compromised aggregators
3. Validate that `min_sample_size < minimum_threshold` is rejected
4. Confirm `max_staleness_seconds > maximum_allowed` is rejected

### Proof of Concept

**Initial State:**
- Volo vault is operational with 1000 shares, 1000 USD total value
- Attacker controls Switchboard aggregator authority for SUI/USD feed
- Legitimate SUI price: $1.00

**Attack Sequence:**

1. Attacker calls `aggregator_set_authority_action::run(aggregator, malicious_address)`

2. Malicious authority calls `aggregator_set_configs_action::run(aggregator, feed_hash, min_sample_size=1, max_staleness_seconds=u64::MAX, max_variance, min_responses=1)`

3. Malicious oracle submits SUI price = $0.01 with current timestamp

4. Aggregator accepts single oracle result (meets `min_sample_size=1`)

5. Attacker calls `update_price(oracle_config, aggregator, clock, "SUI")` 

6. Vault stores manipulated price $0.01 (passes staleness check due to current timestamp)

7. Attacker deposits 100 SUI (real value $100, reported as $1)

8. Attacker receives ~99 shares (should receive only 10 shares)

9. Malicious oracle updates SUI price to $1.00

10. Attacker withdraws 99 shares for ~$99 worth of SUI

**Expected vs Actual Result:**
- Expected: Deposit 100 SUI → receive 10 shares (at $1/SUI)
- Actual: Deposit 100 SUI → receive 99 shares (at $0.01/SUI) → withdraw for $99 profit

**Success Condition:** 
Attacker extracts ~$89 profit from vault through price manipulation enabled by weakened aggregator configuration.

### Citations

**File:** volo-vault/sources/manage.move (L99-108)
```text
public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_authority_action.move (L34-41)
```text
public entry fun run(
    aggregator: &mut Aggregator,
    new_authority: address,
    ctx: &mut TxContext
) {   
    validate(aggregator, ctx);
    actuate(aggregator, new_authority);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L43-47)
```text
    assert!(min_sample_size > 0, EInvalidMinSampleSize);
    assert!(max_variance > 0, EInvalidMaxVariance);
    assert!(feed_hash.length() == 32, EInvalidFeedHash);
    assert!(min_responses > 0, EInvalidMinResponses);
    assert!(max_staleness_seconds > 0, EInvalidMaxStalenessSeconds);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L338-346)
```text
fun compute_current_result(aggregator: &Aggregator, now_ms: u64): Option<CurrentResult> {
    let update_state = &aggregator.update_state;
    let updates = &update_state.results;
    let mut update_indices = update_state.valid_update_indices(aggregator.max_staleness_seconds * 1000, now_ms);

    // if there are not enough valid updates, return
    if (update_indices.length() < aggregator.min_sample_size) {
        return option::none()
    };
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-78)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
```
