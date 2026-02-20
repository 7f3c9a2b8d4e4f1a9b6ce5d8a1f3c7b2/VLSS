# Audit Report

## Title
Zero Oracle Price Causes Division-by-Zero Abort Breaking Withdrawals and Operations

## Summary
The vault oracle system lacks validation that price feeds are non-zero before using them in division operations. When Switchboard aggregators are newly initialized or not properly configured, they return zero prices that cause Move runtime aborts during withdrawals and DeFi position valuations, resulting in a complete protocol DoS where users cannot access their funds and critical vault operations are blocked.

## Finding Description

The vault's oracle price retrieval and arithmetic operations contain a critical flaw: zero prices from Switchboard aggregators are not validated, allowing them to propagate into division operations that cause Move runtime aborts.

**Root Cause - Missing Zero Validation:**

The `get_asset_price` function retrieves and returns prices without validating they are non-zero [1](#0-0) , and `get_normalized_asset_price` passes through these zero prices after decimal adjustment [2](#0-1) . The `get_current_price` function reads values from Switchboard aggregators and returns them without validation [3](#0-2) .

**Switchboard Aggregators Initialize to Zero:**

Switchboard aggregators are created with all fields in `current_result` initialized to zero values via `decimal::zero()` [4](#0-3) , where `decimal::zero()` creates a Decimal with `value: 0` [5](#0-4) . These zero prices are stored without validation when adding aggregators [6](#0-5)  or updating prices [7](#0-6) .

**Critical Division-by-Zero Paths:**

1. **Withdrawal Execution:** The `execute_withdraw` function calculates withdrawal amounts by calling `div_with_oracle_price` with the oracle price [8](#0-7) . The `div_with_oracle_price` function performs direct division using the `/` operator [9](#0-8) . When the oracle price (v2 parameter) is zero, the Move runtime aborts with a division-by-zero error.

2. **Cetus Position Valuation:** The position value calculation divides by `price_b` to compute relative oracle prices [10](#0-9)  and also divides by `relative_price_from_oracle` during slippage validation [11](#0-10) . If either price is zero, the transaction aborts.

3. **Momentum Position Valuation:** Identical division-by-zero pattern exists when computing relative prices [12](#0-11)  and during slippage validation [13](#0-12) .

**Why Existing Protections Fail:**

While the protocol includes a `safe_math::div()` function with division-by-zero protection [14](#0-13) , the vulnerable code paths use the direct `/` operator instead, completely bypassing this protection.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes immediate and severe operational failure with direct user impact:

- **User Funds Locked:** All withdrawal requests for assets with zero oracle prices become permanently unexecutable until oracle prices are fixed. Users cannot access their deposited funds, creating a temporary but complete loss of fund accessibility.

- **Vault Operations Blocked:** The vault cannot complete DeFi position value updates for Cetus or Momentum positions containing zero-priced assets. This prevents the vault from transitioning from "during operation" status back to "normal" status, blocking all subsequent operations including deposits, withdrawals, and position management.

- **Protocol-Wide DoS:** Core user-facing functions (withdrawals) and critical vault operations become unavailable, affecting all users attempting to interact with the affected asset types. The impact persists until administrative intervention fixes the oracle configuration.

The impact is immediate, measurable, and affects protocol availability rather than just causing isolated transaction reverts.

## Likelihood Explanation

**Likelihood: HIGH**

This is not a theoretical edge case but a natural operational scenario that occurs during normal protocol operations:

- **Natural Occurrence:** Switchboard aggregators are initialized with zero values by design and remain at zero until sufficient oracle updates are received to meet the minimum sample size requirement. This is confirmed by the aggregator initialization code.

- **Operational Reality:** When protocol administrators add new asset types to the vault before oracle feeds are fully operational (a common practice during asset onboarding), zero prices are automatically stored and used in subsequent operations without any validation.

- **No Attack Required:** The vulnerability triggers automatically through normal protocol operations (`execute_withdraw`, `update_cetus_position_value`, `update_momentum_position_value`) without any malicious actor involvement. Regular users requesting withdrawals or operators performing routine position updates will trigger the abort.

- **High Probability Scenarios:** 
  - New asset onboarding before oracle stabilization
  - Temporary oracle feed interruptions
  - Aggregator reconfigurations
  - Any misconfiguration during asset setup

All trigger conditions are realistic operational scenarios that require no special privileges beyond the trusted operator role performing normal duties.

## Recommendation

Add zero-price validation at the oracle retrieval layer to prevent zero prices from propagating into arithmetic operations:

1. **Immediate Fix:** Add assertions in `get_asset_price` and `get_current_price` to ensure prices are greater than zero before returning them. This creates a clear failure mode with an explicit error message rather than a division-by-zero abort.

2. **During Onboarding:** Add validation in `add_switchboard_aggregator` to reject aggregators that return zero prices, forcing administrators to wait until oracle feeds are operational before adding assets to the vault.

3. **Safety Layer:** Consider using `safe_math::div()` for all division operations involving oracle prices as an additional layer of protection.

4. **Operational Guidance:** Implement operational procedures to verify oracle feeds are functional and returning valid prices before enabling new assets in the vault.

## Proof of Concept

The vulnerability can be demonstrated with a test that:
1. Creates a vault with a new asset type
2. Adds a Switchboard aggregator that returns zero price (simulating newly initialized aggregator)
3. User deposits funds and requests withdrawal
4. Operator attempts to execute withdrawal → transaction aborts with division-by-zero error
5. Operator attempts to update Cetus/Momentum position value with zero-priced asset → transaction aborts

The test would show that all critical operations involving the zero-priced asset result in Move runtime aborts, proving the DoS condition and user fund lock.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L10-15)
```text
public fun zero(): Decimal {
    Decimal {
        value: 0,
        neg: false
    }
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L49-52)
```text
    // Oracle price has 18 decimals
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
