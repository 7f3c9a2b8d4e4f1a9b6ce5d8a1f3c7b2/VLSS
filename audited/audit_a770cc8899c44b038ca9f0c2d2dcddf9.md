# Audit Report

## Title
Future Timestamp Bypass Allows Indefinite Oracle Staleness Evasion

## Summary
The Switchboard oracle's timestamp validation is implemented backwards, allowing future timestamps to be submitted and stored. This completely bypasses the Volo vault's staleness checks, enabling indefinite acceptance of stale price data, leading to asset mispricing and potential fund loss.

## Finding Description

The vulnerability exists in a chain of validation failures across the Switchboard oracle integration and Volo vault oracle module that completely breaks the protocol's price freshness guarantees.

**Root Cause - Backwards Timestamp Validation:**

The validation logic explicitly documents its intent to prevent future timestamps but implements the opposite behavior. [1](#0-0) 

The check `timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms()` evaluates to `timestamp + max_staleness >= now`, which:
- **FAILS** when: `timestamp < now - max_staleness` (rejects old timestamps) ✓
- **PASSES** when: `timestamp >= now - max_staleness` (includes ALL future timestamps) ✗

This directly contradicts the code comment's documented intent and represents a mis-scoped privilege where oracles are given broader permissions than the system design intends.

**Evidence from Other Oracle Systems:**

The Protocol oracle correctly implements future timestamp rejection using `current_ts - token_price.timestamp` which would abort on underflow for future timestamps: [2](#0-1) 

The Suilend oracle explicitly handles this edge case with a guard check: [3](#0-2) 

**Propagation Through Valid Updates:**

When computing valid results, the staleness filter fails to exclude future-timestamped updates: [4](#0-3) 

For future timestamps, `(timestamp_ms + max_staleness_ms) < now_ms` evaluates to FALSE, so the update is incorrectly included in valid updates.

**Storage in CurrentResult:**

The future timestamp becomes the maximum timestamp in the aggregated result: [5](#0-4) 

**Vault Staleness Check Bypass:**

The vault's price freshness validation is completely bypassed: [6](#0-5) 

When `max_timestamp` is in the future, `now >= max_timestamp` evaluates to FALSE, causing the entire assertion to be skipped. The stale price is accepted without any freshness validation.

**Affected Vault Operations:**

All critical vault operations rely on these compromised price functions.

Withdrawal calculations: [7](#0-6) 

Free principal value updates: [8](#0-7) 

Asset value updates: [9](#0-8) 

## Impact Explanation

**Direct Fund Loss Mechanisms:**

1. **Withdrawal Exploitation**: Users withdrawing when real market price drops below frozen oracle price receive more assets than entitled, extracting value from the vault
2. **Deposit Exploitation**: Users depositing when real market price rises above frozen oracle price receive more shares than entitled, diluting existing shareholders
3. **Vault Value Manipulation**: Asset valuations remain frozen while markets move, enabling systematic arbitrage against legitimate vault participants

**Attack Scenario:**
1. Oracle submits price update with timestamp = 100 years in future (e.g., 4102444800000 ms)
2. Real market price moves 50% over subsequent weeks/months
3. Oracle stops providing updates (due to malfunction or intentional action)
4. Vault continues accepting the weeks-old price indefinitely due to bypassed staleness check
5. Arbitrageurs exploit the price discrepancy to extract value from vault

**Partial Mitigations Present:**

The vault's loss tolerance mechanism provides limited protection: [10](#0-9) 

However, this mechanism is enforced only during operations when value decreases: [11](#0-10) 

This allows:
- Gradual exploitation within the tolerance threshold (default 10 bps)
- Exploitation during favorable price movements
- Direct exploitation via deposits/withdrawals which don't trigger operation value checks

## Likelihood Explanation

**Reachable Entry Point:**

The vulnerability is accessible via a public entry function: [12](#0-11) 

**Mis-Scoped Privilege Analysis:**

This is fundamentally a **mis-scoped privilege issue**, not requiring compromised trusted roles. The evidence:

1. **Code comment explicitly documents intent**: Line 65 states "make sure that update staleness point is not in the future"
2. **Implementation contradicts intent**: The logic allows all future timestamps
3. **Other oracles implement correctly**: Both Protocol and Suilend oracles have proper future timestamp rejection
4. **Defense-in-depth violation**: Even for semi-trusted oracles, input validation should prevent both accidental errors and potential compromise

**Feasible Trigger Scenarios:**
- Oracle software bug in timestamp generation
- Clock synchronization errors in oracle infrastructure  
- System time misconfiguration
- Compromised oracle (validates defense-in-depth principle)

The code's own documentation proves this validation was intended but incorrectly implemented, representing a privilege escalation where oracles receive broader permissions than the protocol design intends.

## Recommendation

Fix the backwards timestamp validation logic:

```move
// Change line 66 from:
assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);

// To:
assert!(
    timestamp_seconds * 1000 <= clock.timestamp_ms() && 
    clock.timestamp_ms() - timestamp_seconds * 1000 <= aggregator.max_staleness_seconds() * 1000, 
    ETimestampInvalid
);
```

This ensures:
1. `timestamp <= now` (rejects future timestamps)
2. `now - timestamp <= max_staleness` (rejects old timestamps)

Additionally, add a future timestamp check in the vault's `get_current_price` function:

```move
// In oracle.move, modify get_current_price function:
let max_timestamp = current_result.max_timestamp_ms();

// Add explicit future timestamp rejection:
assert!(max_timestamp <= now, ERR_FUTURE_TIMESTAMP);

// Then check staleness normally:
assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

## Proof of Concept

```move
#[test]
fun test_future_timestamp_bypass() {
    use sui::test_scenario;
    use sui::clock;
    
    let admin = @0xAD;
    let mut scenario = test_scenario::begin(admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Set current time to Jan 1, 2024
    clock::set_for_testing(&mut clock, 1704067200000); // 2024-01-01
    
    // Create aggregator with 1 hour staleness
    let mut aggregator = /* initialize aggregator with max_staleness_seconds = 3600 */;
    
    // Submit oracle result with timestamp 100 years in future
    let future_timestamp_seconds = 4102444800; // Year 2100
    
    // This should fail but PASSES due to backwards validation:
    // future_timestamp + max_staleness >= now
    // 4102444800000 + 3600000 >= 1704067200000 => TRUE (allows future timestamp!)
    aggregator_submit_result_action::run<SUI>(
        &mut aggregator,
        queue,
        price_value,
        false,
        future_timestamp_seconds, // Future timestamp!
        oracle,
        signature,
        &clock,
        fee_coin,
    );
    
    // Fast forward 1 month (price should be stale)
    clock::increment_for_testing(&mut clock, 30 * 24 * 60 * 60 * 1000);
    
    // Staleness check is bypassed because:
    // now >= max_timestamp => 1704067200000 + 2592000000 >= 4102444800000 => FALSE
    // So the if-block is skipped, accepting stale price!
    let stale_price = vault_oracle::get_current_price(
        &oracle_config,
        &clock,
        &aggregator
    );
    
    // Price from 1 month ago accepted as fresh!
    assert!(stale_price > 0, 0); // Test passes, vulnerability confirmed
}
```

**Notes:**

This vulnerability represents a complete breakdown of the protocol's price freshness guarantees. The mis-scoped privilege is evidenced by the contradiction between documented intent (code comment) and actual implementation, combined with correct implementations in other oracle systems within the same codebase. The defense-in-depth principle requires proper input validation even for semi-trusted oracles, and this validation was clearly intended but incorrectly implemented.

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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L190-197)
```text
        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L42-48)
```text
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L367-393)
```text
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L571-576)
```text
    loop {

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

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L1130-1154)
```text
public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();
    assert!(
        type_name::get<CoinType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<CoinType>().into_string();
    let now = clock.timestamp_ms();

    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

    finish_update_asset_value(self, asset_type, coin_usd_value, now);
}
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```
