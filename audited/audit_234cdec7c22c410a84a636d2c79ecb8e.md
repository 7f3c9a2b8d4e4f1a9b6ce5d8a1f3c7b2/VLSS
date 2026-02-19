### Title
Zero Oracle Price Causes Division by Zero in Vault Withdrawal and Valuation Operations

### Summary
The Volo vault oracle system fails to validate that oracle prices are non-zero before using them in division operations, analogous to the external report's zero-price edge case. When a Switchboard aggregator returns a zero price (during initialization or insufficient sample scenarios), the `div_with_oracle_price` utility function performs division by zero, causing transaction aborts that block withdrawals and corrupt asset valuations.

### Finding Description

**Vulnerability Classification**: This is an oracle price zero-value edge case, directly analogous to the external report where `price = 0` causes incorrect margin ratio computation.

**Root Cause in Volo**:

The vault oracle retrieves prices from Switchboard aggregators but only validates timestamp staleness, not whether the price is zero: [1](#0-0) 

The `get_current_price` function retrieves the aggregator's result without zero validation: [2](#0-1) 

Switchboard aggregators initialize with zero values: [3](#0-2) 

When insufficient valid samples exist, `compute_current_result` returns `option::none()` and the aggregator's `current_result` remains at its previous value (potentially zero): [4](#0-3) [5](#0-4) 

The critical vulnerability occurs in `div_with_oracle_price`, which performs division without zero-checking: [6](#0-5) 

**Exploit Path**:

1. **Withdrawal Execution** - The `execute_withdraw` function uses the unvalidated price as a divisor: [7](#0-6) 

When the oracle price is zero, the division operation `v1 * ORACLE_DECIMALS / v2` aborts, blocking all withdrawals.

2. **Asset Valuation** - Similar issues occur in valuation functions: [8](#0-7) [9](#0-8) 

When multiplying by zero price, asset values are calculated as zero, corrupting vault accounting.

**Why Protections Fail**:

Unlike the protocol oracle which validates minimum effective prices: [10](#0-9) [11](#0-10) 

The vault oracle has NO such validation. The protocol oracle also has tests confirming zero price rejection: [12](#0-11) 

### Impact Explanation

**Critical Impact - HIGH Severity**:

1. **Withdrawal Denial of Service**: Users cannot withdraw their principal funds when oracle price is zero. The `execute_withdraw` function is callable by operators but affects user fund access. Transaction aborts with division by zero error, permanently blocking withdrawals until oracle price is updated.

2. **Vault Accounting Corruption**: When zero prices are used in `mul_with_oracle_price` operations during asset value updates, the vault calculates asset values as zero. This corrupts the `total_usd_value` and `share_ratio`, potentially leading to:
   - Incorrect share-to-asset conversions
   - Loss tracking failures
   - Fee miscalculations

3. **No Recovery Mechanism**: The vault has no fallback oracle or zero-price handling. Users and operators are stuck until external aggregator updates resolve the zero price.

### Likelihood Explanation

**Medium-High Likelihood**:

1. **Legitimate Aggregator States**: Switchboard aggregators legitimately initialize with zero values and remain at zero until receiving sufficient valid samples (`min_sample_size` threshold). This is not a theoretical edge case but a normal initialization state.

2. **Oracle Update Dependencies**: If oracle feeders fail to update or network conditions prevent timely updates, aggregators can return stale zero values within the `update_interval` window (typically 60 seconds), passing staleness checks while still being zero.

3. **No Preventive Validation**: The vault oracle performs zero validation checks on price values, unlike the protocol oracle's comprehensive range validation. The only check is timestamp-based staleness.

4. **Public Entry Points**: The vulnerability affects operator-callable functions (`execute_withdraw`, `update_principal_usd_value`, `update_usd_value`), but these are normal protocol operations that must function reliably.

### Recommendation

**Immediate Mitigations**:

1. Add zero-price validation in `get_asset_price`:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();
    
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);
    assert!(price_info.price > 0, ERR_INVALID_PRICE); // ADD THIS CHECK
    
    price_info.price
}
```

2. Add defensive check in `div_with_oracle_price`:

```move
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO_PRICE); // ADD THIS CHECK
    v1 * ORACLE_DECIMALS / v2
}
```

3. Add minimum effective price configuration per asset type, similar to the protocol oracle's `minimum_effective_price` field.

### Proof of Concept

**Scenario: Withdrawal DoS via Zero-Initialized Aggregator**

**Setup**:
1. Vault operator adds a new Switchboard aggregator for an asset using `add_switchboard_aggregator`
2. Aggregator is initialized with `current_result.result = decimal::zero()`
3. Aggregator has not yet received `min_sample_size` valid samples
4. User has a pending withdraw request

**Execution**:
1. Operator calls `execute_withdraw(vault, clock, oracle_config, request_id, max_amount)`
2. Function calls `get_normalized_asset_price(config, clock, asset_type)` which returns 0
3. Function calls `div_with_oracle_price(usd_value, 0)`
4. Division by zero occurs: `v1 * ORACLE_DECIMALS / 0`
5. **Transaction aborts**, withdrawal fails

**Result**: User funds are locked until aggregator receives valid price updates. No alternative withdrawal path exists.

**Alternative Scenario: Accounting Corruption via Zero Price**

**Execution**:
1. Operator calls `update_principal_usd_value(vault, clock, oracle_config)`
2. Function retrieves zero price from oracle
3. Function calls `mul_with_oracle_price(principal_balance, 0)`
4. Calculates `principal_usd_value = principal_balance * 0 / ORACLE_DECIMALS = 0`
5. Vault's `total_usd_value` becomes incorrect (near zero)
6. Share ratio becomes corrupted

**Result**: Vault accounting is corrupted, affecting all subsequent deposit/withdrawal calculations until corrected.

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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L190-220)
```text
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

**File:** volo-vault/sources/utils.move (L73-76)
```text
// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
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

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1145-1152)
```text
    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L38-41)
```text
        // check if the price is less than the minimum configuration value
        if (price < minimum_effective_price) {
            return false
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L193-197)
```text
        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_pro_test.move (L1213-1240)
```text
    #[test]
    #[expected_failure(abort_code = 2, location = oracle::oracle_pro)]
    public fun base_test_price0() {
        let _scenario = test_scenario::begin(OWNER);
        let scenario = &mut _scenario;
        let _clock = clock::create_for_testing(test_scenario::ctx(scenario));
        {
            global::init_protocol(scenario);
        };

        test_scenario::next_tx(scenario, OWNER);
        {
            let price_oracle = test_scenario::take_shared<PriceOracle>(scenario);
            let oracle_config = test_scenario::take_shared<OracleConfig>(scenario);

            let address_vec = config::get_vec_feeds(&oracle_config);
            let feed_id = *vector::borrow(&address_vec, 0);

            let time = 86400 * 1000;
            let expired_time =  time - 1000 * 40;
            std::debug::print(&expired_time);

            clock::increment_for_testing(&mut _clock, time);
            oracle_pro::update_single_price_for_testing(&_clock, &mut oracle_config, &mut price_oracle, 0, time, 0, time, feed_id);

            let (valid, price, decimal) = oracle::get_token_price(&_clock, &price_oracle, 0);

            std::debug::print(&decimal);
```
