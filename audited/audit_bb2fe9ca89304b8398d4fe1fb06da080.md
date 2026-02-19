### Title
Oracle Aggregator Can Be Changed Mid-Operation Causing Inconsistent Price Sources for Loss Tolerance Validation

### Summary
The `change_switchboard_aggregator()` function lacks vault status validation, allowing the oracle price source to be changed while the vault is in `VAULT_DURING_OPERATION_STATUS`. This causes operations to compare total USD values computed from different price sources (old aggregator at start, new aggregator at end), leading to artificial losses or gains that incorrectly consume or bypass the loss_tolerance mechanism.

### Finding Description

The `change_switchboard_aggregator()` function in `vault_manage` module only requires `AdminCap` and has no vault status check: [1](#0-0) 

This function directly calls the oracle config's implementation which immediately updates the aggregator address and price: [2](#0-1) 

During vault operations, the flow is as follows:

1. **Operation Start**: `start_op_with_bag()` sets vault status to `VAULT_DURING_OPERATION_STATUS` and captures the initial total USD value: [3](#0-2) [4](#0-3) 

2. **Mid-Operation**: Admin can call `change_switchboard_aggregator()` at any time, switching the price source for any asset type. The new aggregator's price is immediately stored in the oracle config.

3. **Operation End**: `end_op_value_update_with_bag()` recalculates total USD value using the **new** aggregator's prices and compares it to the initial value captured with the **old** aggregator: [5](#0-4) 

The asset value updates use `get_normalized_asset_price()` which reads from the oracle config's stored prices: [6](#0-5) [7](#0-6) 

**Root Cause**: The absence of vault status validation in `change_switchboard_aggregator()` allows oracle price sources to be modified during critical operation periods when price consistency is required for loss tolerance validation.

**Why Existing Protections Fail**: Unlike other admin functions such as `set_enabled()` which explicitly prevent changes during operations: [8](#0-7) 

The oracle aggregator change function has no such protection, creating an inconsistent security model.

### Impact Explanation

**Concrete Harm**:
- **Loss Tolerance Manipulation**: If aggregator prices differ (e.g., Aggregator A shows SUI = $10, Aggregator B shows SUI = $8), a vault with 1,000,000 SUI would show an artificial $2,000,000 loss purely from the price source change, consuming loss_tolerance budget without any actual value loss.
- **Loss Hiding**: Conversely, if the new aggregator shows higher prices, real operational losses can be masked, bypassing the loss_tolerance safety mechanism entirely.
- **Tolerance Exhaustion**: Accumulated artificial losses across multiple operations could exhaust the epoch's loss_tolerance limit, causing legitimate operations to fail.

**Protocol Damage**: The loss_tolerance per epoch is a critical invariant designed to limit operator risk. This vulnerability undermines that protection by allowing loss calculations to be based on inconsistent price sources.

**Affected Parties**: All vault shareholders are affected as the loss_tolerance mechanism protects their principal from excessive operational losses.

**Severity Justification**: HIGH - This directly compromises a critical security invariant (loss_tolerance correctness) without requiring any exploit complexity. The impact scales with vault TVL and price divergence between aggregators.

### Likelihood Explanation

**Entry Point**: The function is directly callable by any AdminCap holder through the public entry function in `vault_manage`.

**Attack Complexity**: Minimal - requires only a single function call during an active operation. This could occur:
- **Unintentionally**: Admin switching aggregators for operational reasons (e.g., oracle provider change, better price feed) without realizing an operation is in progress
- **Intentionally**: Admin deliberately timing the change to manipulate loss calculations

**Feasibility**: Highly feasible:
- No special preconditions beyond having AdminCap (which is expected for legitimate admin operations)
- Operations can run for extended periods during complex DeFi interactions
- No transaction ordering or timing precision required
- Works with any vault asset type that has multiple potential oracle aggregators

**Detection Constraints**: The `SwitchboardAggregatorChanged` event would be emitted, but correlating it with active operations requires off-chain monitoring. On-chain, there's no prevention mechanism.

**Probability**: HIGH - Given that:
1. Aggregator changes are legitimate operational needs
2. Operations can be long-running
3. No warning or status check exists
4. Both intentional and unintentional scenarios are plausible

### Recommendation

**Code-Level Mitigation**:

Add vault status validation to the `change_switchboard_aggregator()` function in `vault_manage` module. Modify the function to accept a vault reference and check its status:

```move
public fun change_switchboard_aggregator<PrincipalCoinType>(
    _: &AdminCap,
    vault: &Vault<PrincipalCoinType>,  // Add vault parameter
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    vault.assert_not_during_operation();  // Add status check
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
```

Alternatively, if aggregator changes should be allowed for assets not currently held in the vault, implement a more granular check that prevents changes only for asset types currently tracked in the vault's `asset_types` vector.

**Invariant Checks to Add**:
- `assert_not_during_operation()` before any oracle configuration changes that affect active vault assets
- Consider adding a similar check to `add_switchboard_aggregator()` and `remove_switchboard_aggregator()` for consistency

**Test Cases to Prevent Regression**:
1. Test that `change_switchboard_aggregator()` reverts when vault status is `VAULT_DURING_OPERATION_STATUS`
2. Test that changing aggregator between operations (when status is `VAULT_NORMAL_STATUS`) works correctly
3. Test that loss tolerance calculations remain accurate when aggregators are changed only between operations
4. Test the complete operation flow to ensure aggregator addresses remain constant from start to end of each operation

### Proof of Concept

**Initial State**:
- Vault holds 1,000,000 SUI tokens valued at 1,000,000,000,000 (with 9 decimals)
- Oracle Config has Aggregator A for SUI showing price = 10,000,000,000 ($10 with 9 decimals normalization)
- Vault status = `VAULT_NORMAL_STATUS`
- Loss tolerance = 10% (10,000 basis points)

**Transaction Sequence**:

1. **T0 - Operation Start**:
   - Operator calls `start_op_with_bag()` with vault
   - Vault status changes to `VAULT_DURING_OPERATION_STATUS`
   - `total_usd_value` captured = 1,000,000 SUI × $10 = $10,000,000 (in 9-decimal representation)

2. **T1 - Mid-Operation Aggregator Change**:
   - Admin calls `change_switchboard_aggregator(adminCap, oracleConfig, clock, "SUI", aggregatorB)`
   - Aggregator B shows SUI price = 8,000,000,000 ($8 with 9 decimals)
   - Oracle config's price for SUI is updated to $8
   - **Expected**: Transaction should revert with `ERR_VAULT_DURING_OPERATION`
   - **Actual**: Transaction succeeds, aggregator changed

3. **T2 - Operation End**:
   - Operator calls `update_free_principal_value()` which now uses Aggregator B's price ($8)
   - Operator calls `end_op_value_update_with_bag()`
   - `total_usd_value_after` calculated = 1,000,000 SUI × $8 = $8,000,000
   - Loss calculated = $10,000,000 - $8,000,000 = $2,000,000 (20% artificial loss)
   - Loss tolerance updated with $2,000,000 loss
   - **Expected**: No loss should be recorded (or only actual operational loss)
   - **Actual**: $2,000,000 artificial loss incorrectly deducted from loss tolerance

**Success Condition**: 
The artificial loss of $2,000,000 (20% of vault value) is recorded despite no actual value loss occurring, demonstrating successful manipulation of the loss_tolerance tracking mechanism through mid-operation oracle aggregator changes.

### Citations

**File:** volo-vault/sources/manage.move (L118-126)
```text
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
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

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L178-179)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
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
