# Audit Report

## Title
Staleness Check Bypass When Switchboard Aggregator Reports Future Timestamps

## Summary
The `get_current_price()` function contains an asymmetric staleness validation that only checks when `now >= max_timestamp`, completely bypassing validation when the Switchboard aggregator's `max_timestamp` is in the future. This allows potentially unreliable oracle prices to be stored in the vault's pricing system and used for critical operations like withdrawals and DeFi strategy valuations.

## Finding Description

The vulnerability exists in the staleness validation logic within the `get_current_price()` function. [1](#0-0)  The code only performs staleness validation when `now >= max_timestamp`. When `max_timestamp > now` (a future timestamp), the conditional evaluates to false and the entire staleness check is skipped, allowing the function to return an unchecked price. [2](#0-1) 

The root cause is that Switchboard's validation in the `valid_update_indices` function does not prevent future timestamps. [3](#0-2)  This validation requires `timestamp_ms + max_staleness_ms >= now_ms`, which is automatically satisfied when `timestamp_ms > now_ms`. This design accommodates clock drift between oracle nodes, but the vault code fails to handle this defensively.

The Switchboard aggregator computes `max_timestamp_ms` as the maximum timestamp across all oracle updates. [4](#0-3)  If any oracle has a future timestamp, this becomes the aggregator's `max_timestamp_ms`.

In contrast, the vault's `get_asset_price()` function correctly uses the `diff()` method to compute absolute difference, handling both past and future timestamps symmetrically. [5](#0-4) 

**Execution Flow:**
1. A Switchboard oracle submits a price update with a future timestamp (due to clock drift or misconfiguration)
2. This timestamp passes Switchboard's validation and becomes the aggregator's `max_timestamp_ms`
3. Someone calls `update_price()` [6](#0-5)  which invokes `get_current_price()`
4. Since `max_timestamp > now`, the staleness check is bypassed entirely
5. The price is stored with the current timestamp [7](#0-6) 
6. The oracle data with problematic timestamp now appears fresh to all subsequent readers

## Impact Explanation

**Critical Fund Operations Affected:**

The incorrectly validated prices are used throughout the vault system for operations involving user funds:

1. **Withdrawals**: The vault calculates withdrawal amounts using oracle prices. [8](#0-7)  Users withdrawing when prices with bypassed staleness checks are active may receive incorrect amounts, leading to direct fund loss.

2. **Adaptor Valuations**: All adaptors use oracle prices for USD valuation calculations. The Navi adaptor [9](#0-8)  and Cetus adaptor [10](#0-9)  both rely on these prices. Incorrectly validated prices corrupt these valuations during DeFi strategy execution.

3. **DEX Price Validation**: The Cetus adaptor validates pool prices against oracle prices to detect manipulation. [11](#0-10)  Oracle prices that bypassed staleness validation weaken this protection mechanism.

**Persistent Nature**: Once oracle data with future timestamps is accepted and stored with a current timestamp via `update_price()`, subsequent reads via `get_asset_price()` appear legitimate because the stored `last_updated` timestamp looks fresh. This masks the timestamp discrepancy and creates a false appearance of price reliability that persists until the next update.

**Quantified Harm:**
- Direct user fund loss through incorrect withdrawal calculations
- Vault loss tolerance checks operating on potentially unreliable valuations
- Health factor calculations using unvalidated prices
- Potential for value extraction through timing of price-dependent operations when oracle timestamp anomalies occur

## Likelihood Explanation

**Reachable Entry Points**: 
The vulnerability is exploitable through the public `update_price()` function that anyone can call. [12](#0-11)  Additionally, the package-scoped functions `add_switchboard_aggregator()` [13](#0-12)  and `change_switchboard_aggregator()` [14](#0-13)  also initialize prices via `get_current_price()`.

**Feasible Preconditions**: 
The exploit requires only that a Switchboard oracle submits a price update with a future timestamp (even slightly ahead due to clock drift). Switchboard explicitly allows this through its validation logic that does not reject future timestamps, accommodating operational clock drift between oracle nodes in distributed systems.

**Execution Practicality**: 
Once a future timestamp exists in the Switchboard aggregator (whether through oracle clock drift, misconfiguration, or other operational issues), the bypass occurs automatically with no additional attacker action required. Anyone calling `update_price()` will trigger the vulnerability.

**Probability**: MEDIUM - The asymmetric staleness check is always present in the code. While exploitation depends on oracle timing behavior, Switchboard explicitly accommodates future timestamps for operational reasons (clock drift tolerance between nodes), making this scenario realistic and operationally expected in distributed systems.

## Recommendation

Modify `get_current_price()` to use symmetric timestamp validation similar to `get_asset_price()`. Replace the asymmetric check with an absolute difference check:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();

    // Use symmetric validation - reject if timestamp is too far in past OR future
    assert!(max_timestamp.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    
    current_result.result().value() as u256
}
```

This ensures that both past and future timestamps are validated against the `update_interval` threshold, preventing the bypass while still accommodating minor clock drift within acceptable bounds.

## Proof of Concept

```move
#[test]
public fun test_staleness_bypass_with_future_timestamp() {
    let mut s = test_scenario::begin(@0xa);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    
    s.next_tx(@0xa);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Create aggregator with future timestamp (2 minutes ahead)
        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        let future_timestamp = 120_000; // 2 minutes in future
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, future_timestamp);
        
        // Clock is at time 0, aggregator has timestamp 120_000
        // This should fail staleness check, but bypass occurs
        let price = vault_oracle::get_current_price(&oracle_config, &clock, &aggregator);
        
        // Price is accepted despite future timestamp
        assert!(price == 1_000_000_000_000_000_000);
        
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };
    
    clock::destroy_for_testing(clock);
    s.end();
}
```

## Notes

This vulnerability specifically affects the Volo vault's integration with Switchboard oracles. The asymmetric validation creates a window where oracle data with future timestamps can bypass staleness protection. While clock drift is a legitimate operational concern in distributed oracle systems, the vault should validate that timestamps are not too far in the future to maintain price reliability guarantees. The fix ensures symmetric validation while still accommodating reasonable clock drift within the configured `update_interval`.

### Citations

**File:** volo-vault/sources/oracle.move (L135-135)
```text
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
```

**File:** volo-vault/sources/oracle.move (L170-170)
```text
    let init_price = get_current_price(config, clock, aggregator);
```

**File:** volo-vault/sources/oracle.move (L207-207)
```text
    let init_price = get_current_price(config, clock, aggregator);
```

**File:** volo-vault/sources/oracle.move (L225-234)
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
```

**File:** volo-vault/sources/oracle.move (L240-240)
```text
    price_info.last_updated = now;
```

**File:** volo-vault/sources/oracle.move (L258-260)
```text
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
```

**File:** volo-vault/sources/oracle.move (L261-261)
```text
    current_result.result().value() as u256
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L391-392)
```text
        min_timestamp_ms = u64::min(min_timestamp_ms, update.timestamp_ms);
        max_timestamp_ms = u64::max(max_timestamp_ms, update.timestamp_ms);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L574-576)
```text
        if (remaining_max_iterations == 0 || (results[idx].timestamp_ms + max_staleness_ms) < now_ms) {
            break
        };
```

**File:** volo-vault/sources/volo_vault.move (L1017-1020)
```text
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L63-66)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```
