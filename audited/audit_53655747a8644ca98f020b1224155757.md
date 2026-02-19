### Title
Oracle Aggregator Misconfiguration Causes Complete Vault DoS via Unreachable min_sample_size

### Summary
When the Switchboard aggregator authority sets `min_sample_size` higher than the available oracle count, the aggregator stops updating its `current_result` field, causing the oracle price to become permanently stale. This blocks all vault deposits, withdrawals, and operations that require price data, resulting in a complete denial of service until the vault admin switches to a different aggregator.

### Finding Description

The vulnerability exists in the aggregator configuration validation logic and its interaction with the vault's oracle price retrieval system.

**Root Cause**: The `aggregator_set_configs_action::run()` function only validates that `min_sample_size > 0` but does not verify that this value is achievable given the available oracle count. [1](#0-0) 

**Attack Path**:

1. **Configuration**: Authority calls `run()` with `min_sample_size = 10` when only 5 oracles are available.

2. **Update Blocking**: When oracles submit price updates, `compute_current_result()` filters valid updates and checks if there are sufficient samples. If the count is below `min_sample_size`, it returns `option::none()`. [2](#0-1) 

3. **Stale Result**: In `add_result()`, when `compute_current_result()` returns `None`, the aggregator's `current_result` field is NOT updated and retains its old timestamp. [3](#0-2) 

4. **Staleness Failure**: The vault's `get_current_price()` reads the stale `current_result` and enforces a staleness check that fails when `now - max_timestamp >= config.update_interval`. [4](#0-3) 

5. **Vault Operations Blocked**: All critical vault operations require oracle prices and thus fail:
   - Deposits call `update_free_principal_value()` which requires price data [5](#0-4) 
   
   - Withdrawals call `get_normalized_asset_price()` to calculate withdrawal amounts [6](#0-5) 
   
   - Asset value updates also require current prices [7](#0-6) 

### Impact Explanation

**Operational Impact**: Complete denial of service affecting all vault operations.

- **Deposit Blocking**: Users cannot execute pending deposit requests. All calls to `execute_deposit()` abort at the oracle price retrieval step, preventing users from depositing funds into the vault.

- **Withdrawal Blocking**: Users cannot execute pending withdrawal requests. All calls to `execute_withdraw()` abort when calculating the withdrawal amount using stale oracle prices, trapping user funds in the vault.

- **Operation Freezing**: Operators cannot start or complete vault operations (DeFi strategy executions) that require asset value updates, as these depend on current oracle prices.

- **Fund Lock**: While funds remain safe in the vault, they become inaccessible to users until the vault admin recognizes the issue and switches to a functional aggregator via `change_switchboard_aggregator()`. [8](#0-7) 

**Severity Justification**: HIGH - Complete operational shutdown of the vault with user funds temporarily inaccessible.

### Likelihood Explanation

**High Likelihood** - This can occur through misconfiguration or deliberate action:

- **Reachable Entry Point**: The `run()` function is a public entry function callable by the aggregator authority. [9](#0-8) 

- **Feasible Preconditions**: Only requires aggregator authority permissions (expected role) and the ability to set configuration parameters.

- **Realistic Scenarios**:
  - **Accidental Misconfiguration**: Authority mistakenly sets `min_sample_size` higher than available oracle count
  - **Oracle Dropout**: Initially sufficient oracles become unavailable (network issues, downtime), dropping below the configured threshold
  - **Malicious Authority**: Compromised or malicious authority deliberately misconfigures to DoS the vault

- **No Additional Constraints**: No economic cost or complex execution required beyond having authority permissions.

- **Detection**: May not be immediately obvious until users attempt deposits/withdrawals after the oracle result becomes stale.

### Recommendation

**Immediate Mitigation**:
1. Add validation in `aggregator_set_configs_action::validate()` to ensure `min_sample_size` is reasonable (e.g., warning if > MAX_RESULTS or adding oracle count tracking)
2. Implement monitoring to alert when `current_result` stops updating
3. Document operational procedures for vault admins to quickly switch aggregators in case of oracle issues

**Code-Level Fix**:

In `aggregator_set_configs_action.move`, add validation that `min_sample_size` does not exceed the practical maximum:

```move
// In validate() function after line 43:
assert!(min_sample_size <= MAX_RESULTS, EInvalidMinSampleSize);
// Where MAX_RESULTS = 16 from aggregator.move line 9
```

Additionally, consider adding a grace period or fallback mechanism in `get_current_price()` to allow slightly stale prices during oracle issues, or implement a circuit breaker that allows emergency operations when oracle data is unavailable.

**Test Cases**:
1. Test setting `min_sample_size = 10` with only 5 oracles submitting updates
2. Verify that `current_result` timestamp does not update
3. Confirm that vault operations abort with `ERR_PRICE_NOT_UPDATED` after staleness threshold
4. Test recovery via `change_switchboard_aggregator()`

### Proof of Concept

**Initial State**:
- Vault is operational with Switchboard aggregator configured
- Aggregator has 5 oracles providing price updates
- `update_interval` is set to 60 seconds

**Attack Steps**:

1. **Authority calls** `aggregator_set_configs_action::run()`:
   - `min_sample_size = 10` (higher than available 5 oracles)
   - Transaction succeeds - no validation failure

2. **Oracles submit updates**: 
   - 5 valid oracle updates are submitted via `add_result()`
   - `compute_current_result()` calculates `update_indices.length() = 5`
   - Check: `5 < 10` evaluates to `true`
   - Returns `option::none()`, `current_result` NOT updated

3. **Time passes**: 61+ seconds elapse, exceeding `update_interval`

4. **User attempts deposit**:
   - Calls `execute_deposit()` 
   - Internally calls `get_normalized_asset_price()`
   - Which calls `get_current_price()`
   - Reads stale `current_result.max_timestamp_ms` from 61+ seconds ago
   - Staleness check: `61000 >= 60000` 
   - **Result**: Transaction ABORTS with `ERR_PRICE_NOT_UPDATED`

5. **User attempts withdrawal**:
   - Calls `execute_withdraw()`
   - Same oracle price retrieval path fails
   - **Result**: Transaction ABORTS with `ERR_PRICE_NOT_UPDATED`

**Expected vs Actual**:
- **Expected**: Aggregator continues updating with 5 oracles, vault operations proceed normally
- **Actual**: Aggregator stops updating, all vault operations blocked indefinitely until admin intervention

**Success Condition**: All vault deposits, withdrawals, and operations consistently abort with `ERR_PRICE_NOT_UPDATED` until vault admin switches to a new aggregator.

### Citations

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L43-43)
```text
    assert!(min_sample_size > 0, EInvalidMinSampleSize);
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/actions/aggregator/aggregator_set_configs_action.move (L77-85)
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
```

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/schemas/aggregator.move (L252-256)
```text
    let mut current_result = compute_current_result(aggregator, now_ms);
    if (current_result.is_some()) {
        aggregator.current_result = current_result.extract();
        // todo: log the result
    };
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

**File:** volo-vault/sources/oracle.move (L198-220)
```text
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
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

**File:** volo-vault/sources/volo_vault.move (L839-839)
```text
    update_free_principal_value(self, config, clock);
```

**File:** volo-vault/sources/volo_vault.move (L1015-1022)
```text
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1146-1150)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
```
