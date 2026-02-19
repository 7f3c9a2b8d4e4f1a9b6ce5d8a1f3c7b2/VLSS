### Title
Zero Oracle Price Causes Division by Zero DoS in Withdrawal and Adaptor Operations

### Summary
The `div_with_oracle_price()` function performs division by oracle price without validating that the price is non-zero. The vault oracle system retrieves prices from Switchboard aggregators without any zero-value checks, allowing zero prices to propagate through critical operations. This causes complete denial of service for user withdrawals and adaptor operations when oracle prices are zero.

### Finding Description

**Root Cause:**

The `div_with_oracle_price()` function divides by the oracle price parameter `v2` without any zero validation: [1](#0-0) 

The vault oracle system retrieves prices from Switchboard aggregators and returns them directly without checking if they are zero: [2](#0-1) 

When adding Switchboard aggregators, the initial price is fetched without validation: [3](#0-2) 

Switchboard aggregators are initialized with zero prices in their `CurrentResult`: [4](#0-3) 

The Switchboard `add_result()` function accepts `Decimal` results without validating for zero: [5](#0-4) 

**Critical Failure Points:**

1. **Withdrawal Operations** - When executing withdrawal requests, the oracle price is used to calculate withdrawal amounts: [6](#0-5) 

If `get_normalized_asset_price()` returns zero, the division in `div_with_oracle_price()` aborts the transaction.

2. **Cetus Adaptor Operations** - The adaptor divides by `price_b`: [7](#0-6) 

And divides by `relative_price_from_oracle`: [8](#0-7) 

Both divisions will abort if the respective prices are zero.

**Why Protections Fail:**

Unlike the separate `protocol/oracle` system which validates against `minimum_effective_price`: [9](#0-8) 

The vault's oracle system (`volo_vault::vault_oracle`) has NO such protection and directly interfaces with Switchboard without zero-price validation.

### Impact Explanation

**Complete Denial of Service:**

When any configured asset's oracle price becomes zero:

1. **User Withdrawals Blocked**: All calls to `withdraw_request_execute()` will abort with division by zero, preventing users from withdrawing their funds regardless of the vault's actual holdings.

2. **Adaptor Operations Fail**: Operations involving Cetus positions will abort, preventing:
   - Opening/closing positions
   - Rebalancing operations
   - Asset value calculations

3. **Cascading Effects**: 
   - Operators cannot complete vault operations that depend on these adaptors
   - The vault becomes stuck in `VAULT_DURING_OPERATION_STATUS`
   - Request buffers cannot be processed
   - Total USD value calculations may become stale

**Who Is Affected:**

All vault participants are affected:
- **Users**: Cannot withdraw funds even though they have valid shares
- **Operators**: Cannot perform operations requiring oracle prices
- **Protocol**: Operational capabilities completely halted for affected assets

**Severity Justification:**

This is **CRITICAL** because:
- Complete loss of withdrawal functionality (core protocol feature)
- No alternative path for users to access their funds
- Affects all users simultaneously
- No timeout or recovery mechanism exists
- Requires external oracle system fix to restore operations

### Likelihood Explanation

**Feasible Preconditions:**

Oracle prices can become zero in several realistic scenarios:

1. **Oracle Data Feed Malfunction**: Switchboard oracles fetch data from external sources. If these sources experience bugs, API failures, or return invalid data, oracles may report zero prices.

2. **Median Calculation**: If multiple oracle nodes report zero (due to synchronized failures or data source issues), the median calculation will return zero: [10](#0-9) 

3. **Asset Depegging/Market Crisis**: In extreme scenarios, if an asset's price crashes to near-zero or becomes illiquid, oracles might report zero or fail to get valid price data.

**No Attacker Capabilities Required:**

This is a **system failure vulnerability**, not an attack:
- No malicious actor needed
- No privileged access required
- No economic cost to trigger
- Simply requires oracle system to report zero (which is outside protocol control)

**Execution Practicality:**

The vulnerability triggers automatically:
1. Oracle price becomes zero (external event)
2. User attempts normal withdrawal → transaction aborts
3. Operator attempts adaptor operation → transaction aborts

**Detection Constraints:**

The protocol has NO monitoring or circuit breakers for zero prices. The only "detection" is when transactions start failing.

**Probability Reasoning:**

While not a daily occurrence, oracle failures and data feed issues are **well-documented risks** in DeFi:
- Chainlink, Pyth, and other oracles have experienced temporary failures
- Price feeds can return stale or invalid data
- External API dependencies create failure modes
- The probability is **non-zero and realistic** enough to warrant defensive checks

### Recommendation

**Immediate Fix:**

Add zero-price validation in the oracle module:

```move
// In volo-vault/sources/oracle.move, modify get_current_price():
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    let price = current_result.result().value() as u256;
    
    // ADD THIS CHECK:
    assert!(price > 0, ERR_INVALID_ORACLE_PRICE); // New error code needed
    
    price
}
```

**Additional Safeguards:**

1. Add minimum price configuration per asset (similar to protocol oracle system)
2. Implement circuit breaker for price anomalies
3. Add emergency pause mechanism when prices are invalid
4. Consider using the `protocol/oracle` system which has built-in protections

**Test Cases to Add:**

```move
#[test]
#[expected_failure(abort_code = ERR_INVALID_ORACLE_PRICE)]
public fun test_zero_price_rejection() {
    // Set oracle price to 0
    // Attempt withdrawal
    // Should abort with ERR_INVALID_ORACLE_PRICE
}

#[test]
#[expected_failure(abort_code = ERR_INVALID_ORACLE_PRICE)]
public fun test_cetus_adaptor_zero_price() {
    // Set price_b to 0
    // Attempt adaptor operation
    // Should abort before division
}
```

### Proof of Concept

**Initial State:**
- Vault has active deposits and withdrawal requests
- Oracle system configured with Switchboard aggregators
- All systems operational

**Trigger Scenario:**
1. Switchboard oracle data feed experiences malfunction
2. Multiple oracle nodes report price = 0 for USDC (or any configured asset)
3. Median calculation results in price = 0
4. `compute_current_result()` returns `CurrentResult` with `result.value() = 0`

**Exploitation Steps:**

```
Step 1: User calls withdraw_request_execute<USDC>()
  ↓
Step 2: Function calls get_normalized_asset_price() for USDC
  ↓  
Step 3: Returns normalized_price = 0
  ↓
Step 4: Calls div_with_oracle_price(usd_value_to_withdraw, 0)
  ↓
Step 5: Executes: v1 * ORACLE_DECIMALS / 0
  ↓
Result: ABORT with arithmetic error (division by zero)
```

**Expected Result:**
Withdrawal completes successfully with calculated amount based on oracle price.

**Actual Result:**
Transaction aborts. User cannot withdraw. All withdrawal operations for that asset type remain blocked until oracle price becomes non-zero.

**Success Condition:**
The vulnerability is confirmed when a zero oracle price causes immediate and complete denial of service for withdrawal and adaptor operations, with no recovery mechanism except external oracle fix.

### Citations

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/oracle.move (L158-184)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);

    emit(SwitchboardAggregatorAdded {
        asset_type,
        aggregator: aggregator.id().to_address(),
    });
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L201-211)
```text
        current_result: CurrentResult {
            result: decimal::zero(),
            min_timestamp_ms: 0,
            max_timestamp_ms: 0,
            min_result: decimal::zero(),
            max_result: decimal::zero(),
            stdev: decimal::zero(),
            range: decimal::zero(),
            mean: decimal::zero(),
            timestamp_ms: 0,
        },
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L350-362)
```text
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-52)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L63-66)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L38-41)
```text
        // check if the price is less than the minimum configuration value
        if (price < minimum_effective_price) {
            return false
        };
```
