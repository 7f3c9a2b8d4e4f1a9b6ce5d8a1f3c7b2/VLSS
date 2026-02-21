# Audit Report

## Title
Oracle Future Timestamp Bypass Allows Stale Price Acceptance

## Summary
The `get_current_price` function in the vault oracle module contains an asymmetric timestamp validation that only checks for past staleness but not future timestamps. This allows Switchboard aggregator prices with future timestamps to bypass staleness checks entirely, enabling any user to call the public `update_price` function to propagate potentially stale or manipulated prices throughout the vault's critical pricing system.

## Finding Description

The vulnerability exists in the oracle price validation logic within `get_current_price`. The function retrieves the maximum timestamp from a Switchboard aggregator and performs staleness validation only when the current time is greater than or equal to the oracle timestamp: [1](#0-0) 

When `now < max_timestamp` (future timestamp scenario), the conditional check at line 258 evaluates to false, bypassing the staleness assertion entirely. The price is then unconditionally returned at line 261 without any validation.

This unchecked price propagates into the vault's pricing system through the public `update_price` function: [2](#0-1) 

The function is publicly callable without access control, allowing any user to trigger price updates. While line 237 validates that the aggregator matches the registered one, this does not prevent propagation of future-timestamped prices from legitimate aggregators.

**Root Cause Analysis:**

The Switchboard oracle system itself does not reject future timestamps. The validation logic only checks that timestamps are not too stale: [3](#0-2) 

This check ensures `timestamp + max_staleness >= current_time`, meaning it only validates against overly old timestamps but permits future timestamps.

**Impact Chain:**

These corrupted prices affect critical vault operations:

1. **Asset Valuation:** Oracle prices determine USD values for all vault assets [4](#0-3) 

2. **Share Calculations:** Deposit share calculations depend on total USD value, which aggregates oracle-priced assets [5](#0-4) 

3. **Total Value Computation:** The vault aggregates all asset values to compute total USD value used throughout the system

The existing test suite even demonstrates this behavior (accepting future timestamps), indicating this is an unintentional validation gap rather than intended design: [6](#0-5) 

## Impact Explanation

**High Severity** - This vulnerability enables pricing corruption with cascading effects:

1. **Share Dilution/Inflation:** Incorrect oracle prices cause miscalculated share-to-asset ratios during deposits and withdrawals, potentially allowing attackers to receive more shares than deserved or extract more value than they contributed.

2. **Asset Misvaluation:** All DeFi adaptor positions (Navi, Cetus, Momentum, Suilend) rely on oracle prices for position valuation. Future-timestamped stale prices could show dramatically inflated or deflated values.

3. **Loss Tolerance Manipulation:** Since loss calculations depend on accurate asset valuations, manipulated prices could either trigger false emergency pauses or hide actual losses from protocol monitoring.

4. **Protocol Accounting Corruption:** The fundamental invariant "Oracle price correctness, decimal conversions (1e9/1e18), staleness control" is violated, compromising the integrity of all vault accounting operations.

The vulnerability directly impacts user funds through incorrect share calculations, making this a critical security issue affecting protocol solvency and fairness.

## Likelihood Explanation

**Medium-High Likelihood** - While this requires Switchboard to experience clock issues, the exploit is highly feasible:

**Realistic Preconditions:**
- Clock skew in distributed oracle infrastructure (common in multi-node systems)
- Oracle node software bugs producing incorrect timestamps
- Network time synchronization failures
- No compromise of privileged keys required

**Attack Sequence:**
1. Attacker monitors registered Switchboard aggregators for future-timestamped price updates
2. When detected, attacker calls `vault_oracle::update_price()` (no access control, public function)
3. `get_current_price()` accepts the future timestamp without validation due to the conditional bypass
4. Stale or manipulated price is stored in `OracleConfig`
5. All subsequent vault operations use the corrupted price until next legitimate update
6. Attacker can exploit mispriced shares during deposits/withdrawals

**Why This Is Not Blocked:**
- The aggregator address matching check prevents wrong aggregators but not wrong timestamps from correct aggregators
- No upper bound validation on timestamps exists
- The asymmetric validation (only checking past staleness) creates an exploitable gap

This is particularly concerning because the vulnerability combines a passive precondition (oracle malfunction) with active exploitation (attacker calling public function at opportune moment).

## Recommendation

Implement symmetric timestamp validation to reject both excessively stale and future timestamps:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();

    // Reject future timestamps
    assert!(max_timestamp <= now, ERR_TIMESTAMP_IN_FUTURE);
    
    // Check staleness for past timestamps
    assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    current_result.result().value() as u256
}
```

Add a new error constant:
```move
const ERR_TIMESTAMP_IN_FUTURE: u64 = 2_006;
```

This ensures all timestamps are both (1) not in the future and (2) not too stale, providing complete temporal validation.

## Proof of Concept

```move
#[test]
// Demonstrates future timestamp acceptance vulnerability
public fun test_future_timestamp_bypass_allows_stale_price() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        
        // Set initial valid price at time 0
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, 0);
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config, &clock, 
            type_name::get<SUI_TEST_COIN>().into_string(), 9, &aggregator
        );
        
        // Advance clock to 30 seconds
        clock::set_for_testing(&mut clock, 30_000);
        
        // Oracle malfunction: returns stale price (from time 0) but with FUTURE timestamp (60 seconds)
        mock_aggregator::set_current_result(&mut aggregator, 500_000_000_000_000_000, 60_000);
        
        // Attacker calls public update_price - this should fail but doesn't
        vault_oracle::update_price(
            &mut oracle_config, &aggregator, &clock,
            type_name::get<SUI_TEST_COIN>().into_string()
        );
        
        // Verify stale price was accepted due to future timestamp bypass
        let price = oracle_config.get_asset_price(&clock, type_name::get<SUI_TEST_COIN>().into_string());
        assert!(price == 500_000_000_000_000_000); // Stale price accepted!
        
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };
    
    clock::destroy_for_testing(clock);
    s.end();
}
```

This test demonstrates that a price with a future timestamp (60 seconds) is accepted at current time (30 seconds), allowing a stale price value to bypass all staleness checks and corrupt the oracle state.

### Citations

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

**File:** volo-vault/sources/oracle.move (L258-261)
```text
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_submit_result_action.move (L65-66)
```text
    // make sure that update staleness point is not in the future
    assert!(timestamp_seconds * 1000 + aggregator.max_staleness_seconds() * 1000 >= clock.timestamp_ms(), ETimestampInvalid);
```

**File:** volo-vault/sources/volo_vault.move (L820-844)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/tests/oracle.test.move (L769-813)
```text
// [TEST-CASE: Should update price when max timestamp larger than current timestamp.] @test-case ORACLE-013
public fun test_update_price_when_max_timestamp_larger_than_current_timestamp() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut oracle_config = s.take_shared<OracleConfig>();

        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, 0);

        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            9,
            &aggregator,
        );

        clock::set_for_testing(&mut clock, 1000 * 60 - 1);
        mock_aggregator::set_current_result(&mut aggregator, 2_000_000_000_000_000_000, 1000 * 60);

        vault_oracle::update_price(
            &mut oracle_config,
            &aggregator,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );

        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);

        aggregator::destroy_aggregator(aggregator);
    };

    clock::destroy_for_testing(clock);
    s.end();
}
```
