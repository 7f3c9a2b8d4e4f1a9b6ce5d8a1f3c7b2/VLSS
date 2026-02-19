### Title
Zero Oracle Price Causes Division-by-Zero Abort Breaking Withdrawals and Operations

### Summary
The `vault_oracle::get_normalized_asset_price()` function does not validate that oracle prices are greater than zero before returning them. When these zero prices are used in division operations during withdrawal processing or DeFi position valuation, they cause Move runtime aborts, completely blocking withdrawals and preventing vault operations from completing.

### Finding Description

**Root Cause:**

The oracle price retrieval function lacks zero-value validation. [1](#0-0)  Only checks for aggregator existence and staleness, but never validates `price_info.price > 0`. [2](#0-1)  The normalized price function directly passes through zero prices after decimal adjustment.

**Switchboard Aggregators Can Be Zero:**

Switchboard aggregators are initialized with zero values and remain zero until sufficient oracle updates are received. [3](#0-2)  The current_result is initialized with `decimal::zero()` values. [4](#0-3)  Directly reads and returns the aggregator value without validation.

**Critical Vulnerability Paths:**

1. **Withdrawal Path:** [5](#0-4)  Calls `div_with_oracle_price(usd_value, oracle_price)` which performs [6](#0-5)  `v1 * ORACLE_DECIMALS / v2` - if v2 (oracle price) is zero, Move runtime aborts on division by zero.

2. **Cetus Position Valuation:** [7](#0-6)  Directly divides by `price_b`, and [8](#0-7)  divides by `relative_price_from_oracle` - both cause aborts if prices are zero.

3. **Momentum Position Valuation:** [9](#0-8)  and [10](#0-9)  Same division-by-zero pattern as Cetus.

**Why Existing Protections Fail:**

The `safe_math::div()` function has protection [11](#0-10)  but it is **never used** for oracle price divisions - the code uses direct `/` operator instead.

### Impact Explanation

**Concrete Harm:**
- All withdrawal requests for assets with zero oracle prices become **permanently unexecutable** - user funds are locked
- Vault operations involving Cetus or Momentum positions with zero-priced tokens cannot complete value updates
- The vault enters a stuck state where it cannot transition from "during operation" back to "normal" status
- Affects all users attempting to withdraw the affected asset type

**Severity Justification:**
This is a **HIGH severity** operational DoS that completely blocks critical user-facing functions (withdrawals) and core vault operations. Unlike theoretical vulnerabilities, this has immediate, measurable impact: users cannot access their funds and the vault cannot function.

### Likelihood Explanation

**Feasibility:**
- Switchboard aggregators naturally start at zero and can remain zero if oracle feeds are not properly initialized
- No special attacker capabilities required - happens automatically with misconfigured or newly-added aggregators  
- Admin accidentally adding an aggregator before oracle feeds are live triggers this immediately
- Entry points are standard operation flows: `execute_withdraw`, `update_cetus_position_value`, `update_momentum_position_value`

**Probability:**
HIGH - This is not a rare edge case but a natural state for newly deployed or misconfigured price feeds. The vulnerability exists in production code paths that execute regularly.

### Recommendation

**Immediate Fix:**

1. Add zero-price validation in `vault_oracle::get_normalized_asset_price()`:
```move
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    assert!(price > 0, ERR_ZERO_PRICE); // ADD THIS CHECK
    let decimals = config.aggregators[asset_type].decimals;
    // ... rest of function
}
```

2. Add corresponding error constant:
```move
const ERR_ZERO_PRICE: u64 = 2_006;
```

3. For defense in depth, also validate in `get_asset_price()` before returning.

**Testing Requirements:**
- Unit test: Call `get_normalized_asset_price()` with zero-valued aggregator, expect abort with `ERR_ZERO_PRICE`
- Integration test: Attempt withdrawal with zero oracle price, verify graceful rejection instead of division-by-zero abort
- Integration test: Attempt Cetus/Momentum position value updates with zero prices, verify proper error handling

### Proof of Concept

**Initial State:**
1. Vault is deployed and operational with PrincipalCoinType = SUI
2. Admin adds Switchboard aggregator for SUI via `add_switchboard_aggregator()` 
3. Aggregator has not received oracle updates yet, price remains at initialized zero value

**Attack Sequence:**
1. User creates withdrawal request for SUI
2. Operator calls `execute_withdraw<SUI>(vault, clock, config, request_id, max_amount)`
3. Function calls `vault_oracle::get_normalized_asset_price(config, clock, "SUI")`
4. Returns 0 (no validation)
5. Executes `vault_utils::div_with_oracle_price(usd_value, 0)`
6. Computes `usd_value * 1e18 / 0`
7. **Move runtime aborts with arithmetic error**

**Expected Result:** Withdrawal should complete and user receives SUI

**Actual Result:** Transaction aborts, withdrawal cannot be processed, user funds remain locked

**Success Condition:** Any withdrawal attempt with zero oracle price causes immediate transaction failure, permanently blocking that withdrawal path until oracle price becomes non-zero.

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

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L175-220)
```text
public(package) fun new(
    queue: ID,
    name: String,
    authority: address,
    feed_hash: vector<u8>,
    min_sample_size: u64,
    max_staleness_seconds: u64,
    max_variance: u64,
    min_responses: u32,
    created_at_ms: u64,
    ctx: &mut TxContext,
): ID {

    let id = object::new(ctx);
    let aggregator_id = *(id.as_inner());
    let aggregator = Aggregator {
        id,
        queue,
        name,
        authority,
        feed_hash,
        min_sample_size,
        max_staleness_seconds,
        max_variance,
        min_responses,
        created_at_ms,
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
        update_state: UpdateState {
            results: vector::empty(),
            curr_idx: 0,
        },
        version: VERSION,
    };
    transfer::share_object(aggregator);
    aggregator_id
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

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-52)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L63-65)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-57)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
```

**File:** volo-vault/local_dependencies/protocol/math/sources/safe_math.move (L37-41)
```text
    public fun div(a: u256, b: u256): u256 {
         assert!(b > 0, SAFE_MATH_DIVISION_BY_ZERO);
         let c = a / b;
         return c
    }
```
