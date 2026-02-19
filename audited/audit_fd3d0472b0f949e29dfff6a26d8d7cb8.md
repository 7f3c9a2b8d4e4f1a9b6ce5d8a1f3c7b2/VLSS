### Title
Arithmetic Overflow in Two's Complement Computation Causes DoS for Negative Zero Oracle Updates

### Summary
The `push_i128()` function in the Switchboard oracle hashing module contains an arithmetic overflow vulnerability when computing two's complement for negative zero (value=0, neg=true). The expression `u128::max_value!() - 0 + 1` attempts to compute 2^128, which exceeds the maximum u128 value and causes transaction abort, resulting in denial-of-service for oracle price feed updates.

### Finding Description

The vulnerability exists in the two's complement computation logic: [1](#0-0) 

When `value = 0` and `neg = true`, the computation becomes:
- `u128::max_value!()` = 2^128 - 1 = 340,282,366,920,938,463,463,374,607,431,768,211,455
- `u128::max_value!() - 0 + 1` = (2^128 - 1) + 1 = 2^128

Since 2^128 cannot be represented in u128 (maximum is 2^128 - 1), this causes arithmetic overflow. In Sui Move, arithmetic overflow results in transaction abort.

The vulnerability is triggered through the oracle update flow: [2](#0-1) 

The entry function accepts arbitrary `value: u128` and `neg: bool` parameters without validation, creates a Decimal, and passes it to the hashing function: [3](#0-2) 

The hash generation calls `push_decimal_le`, which unpacks the Decimal and invokes `push_i128_le` with the overflow-prone logic: [4](#0-3) 

No validation exists in the Decimal creation or aggregator validation logic to prevent this edge case: [5](#0-4) 

### Impact Explanation

This vulnerability causes **operational denial-of-service** for the Switchboard oracle price feed system. Any attempt to submit an oracle price update with value=0 and neg=true will result in transaction abort, preventing legitimate oracle updates from completing.

While negative zero is mathematically equivalent to positive zero and may seem nonsensical for price feeds, the system accepts arbitrary signed decimal inputs without validation. The Volo vault relies on these oracle feeds for critical pricing operations: [6](#0-5) 

If oracle updates fail due to this overflow, price staleness checks will trigger, potentially blocking vault operations that depend on fresh price data. This affects all vault users and operators who rely on accurate, up-to-date pricing information.

### Likelihood Explanation

The vulnerability has **HIGH likelihood** of exploitation:

**Attacker Capabilities**: Any user can call the public entry function with malicious parameters. No special permissions or oracle credentials are required to trigger the overflow - the validation occurs after the hash computation that causes the abort.

**Attack Complexity**: Trivial - simply call `aggregator_submit_result_action::run` with `value=0` and `neg=true`. No complex setup, timing, or state manipulation required.

**Feasibility**: The attack is fully executable under normal Move semantics. The overflow is deterministic and occurs during hash computation before any signature verification or fee checks.

**Economic Rationality**: Low cost (only transaction gas) to disrupt oracle feeds. While the attacker's own transaction fails, repeated attempts could create operational issues for oracle infrastructure and monitoring systems that must handle the failed transactions.

### Recommendation

Add validation to prevent negative zero before hash computation:

**Option 1**: Validate in `push_i128` and `push_i128_le`:
```move
public fun push_i128(self: &mut Hasher, value: u128, neg: bool) {
    // Normalize negative zero to positive zero
    let (normalized_value, normalized_neg) = if (value == 0) {
        (0, false)
    } else {
        (value, neg)
    };
    
    let signed_value: u128 = if (normalized_neg) {
        u128::max_value!() - normalized_value + 1
    } else {
        normalized_value
    };
    
    let mut bytes = bcs::to_bytes(&signed_value);
    vector::reverse(&mut bytes);
    self.buffer.append(bytes);
}
```

**Option 2**: Validate in the Decimal constructor:
```move
public fun new(value: u128, neg: bool): Decimal {
    // Normalize negative zero
    let normalized_neg = if (value == 0) { false } else { neg };
    Decimal { value, neg: normalized_neg }
}
```

**Option 3**: Add validation in the entry function:
```move
public entry fun run<T>(..., value: u128, neg: bool, ...) {
    // Reject negative zero
    assert!(!(value == 0 && neg == true), EInvalidNegativeZero);
    let value = decimal::new(value, neg);
    ...
}
```

**Recommended Approach**: Implement Option 2 (normalize in Decimal constructor) as it prevents the issue at the source and maintains mathematical correctness throughout the system. Add test cases to verify negative zero is handled correctly.

### Proof of Concept

**Initial State**:
- Deployed Switchboard oracle system with Aggregator and Queue
- Valid Oracle with unexpired registration

**Attack Steps**:
1. Call `aggregator_submit_result_action::run<SUI>()` with parameters:
   - `value: u128 = 0`
   - `neg: bool = true`
   - Other valid parameters (aggregator, oracle, signature, timestamp, fee)

**Expected Result**: Oracle price update succeeds with normalized zero value

**Actual Result**: Transaction aborts with arithmetic overflow error during `push_i128_le` execution when computing `u128::max_value!() + 1`

**Success Condition for Attack**: Transaction abort prevents oracle update, confirming DoS vulnerability

The overflow occurs at the arithmetic operation `u128::max_value!() - 0 + 1` which attempts to produce 2^128, exceeding u128 bounds and triggering Move's checked arithmetic abort.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L68-80)
```text
public fun push_i128(self: &mut Hasher, value: u128, neg: bool) {

    let signed_value: u128 = if (neg) {
        // Get two's complement by subtracting from 2^128
        u128::max_value!() - value + 1
    } else {
        value
    };

    let mut bytes = bcs::to_bytes(&signed_value);
    vector::reverse(&mut bytes);
    self.buffer.append(bytes);
}
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/hash.move (L98-101)
```text
public fun push_decimal_le(self: &mut Hasher, value: &Decimal) {
    let (value, neg) = decimal::unpack(*value);
    self.push_i128_le(value, neg);
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L17-19)
```text
public fun new(value: u128, neg: bool): Decimal {
    Decimal { value, neg }
}
```

**File:** volo-vault/sources/oracle.move (L224-247)
```text
// Update price inside vault_oracle (the switchboard aggregator price must be updated first)
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
