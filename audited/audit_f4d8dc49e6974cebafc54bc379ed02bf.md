### Title
Inconsistent Price Feed Usage Due to Mid-Operation Oracle Aggregator Changes

### Summary
The oracle management functions in `manage.move` allow admins to add, remove, or change Switchboard aggregators without checking if any vault is currently in operation. This enables oracle price source changes between operation start and end, causing the value comparison logic to use inconsistent price feeds, leading to invalid loss calculations and potential loss tolerance bypass.

### Finding Description

The vulnerability exists in the oracle management functions that lack vault operation status checks: [1](#0-0) 

These admin functions can modify oracle aggregators at any time, including when a vault is mid-operation.

During vault operations, the value check mechanism relies on capturing USD values at two points:

**Operation Start** - captures baseline value: [2](#0-1) 

**Operation End** - captures final value and compares: [3](#0-2) 

Both calls to `get_total_usd_value` ultimately fetch prices from the shared `OracleConfig` through asset value update functions: [4](#0-3) 

The price is fetched from the oracle configuration: [5](#0-4) 

The oracle change functions directly modify the aggregator address and price without any coordination with vault operations: [6](#0-5) 

**Root Cause**: Unlike other admin functions that check vault status (e.g., `set_enabled`), the oracle management functions have no such protection: [7](#0-6) 

### Impact Explanation

**Security Integrity Impact - Loss Tolerance Bypass (Critical)**:
- The loss tolerance mechanism protects users from excessive losses per epoch
- By changing aggregators mid-operation, the before/after value comparison becomes meaningless
- Example: If an aggregator reporting $2/SUI is changed to one reporting $1/SUI, a vault with 100 SUI shows a $100 "loss" when no actual loss occurred
- Conversely, changing from $1/SUI to $2/SUI can hide a real $100 loss as a $100 "gain"
- This allows real trading losses to bypass the per-epoch loss tolerance checks

**Custody/Receipt Integrity Impact**:
- Share ratios calculated using inconsistent prices affect all users
- Deposits/withdrawals executed during affected periods receive incorrect share amounts
- The `get_share_ratio` function depends on `get_total_usd_value`: [8](#0-7) 

**Operational Impact**:
- Operations may falsely fail loss tolerance checks when prices are legitimately updated, causing DoS
- The shared `OracleConfig` affects all vaults simultaneously

### Likelihood Explanation

**High Likelihood**:

**Reachable Entry Point**: Admin functions are directly callable with `AdminCap`: [9](#0-8) 

**Feasible Preconditions**: 
- Only requires `AdminCap` - no malicious intent needed
- Can occur during legitimate oracle maintenance or aggregator upgrades
- Operations span multiple transactions with time gaps where oracle changes can occur
- Multiple vaults share one `OracleConfig`, increasing collision probability

**Execution Practicality**:
1. Operator calls `start_op_with_bag` (vault enters VAULT_DURING_OPERATION_STATUS)
2. Admin calls `change_switchboard_aggregator` for oracle maintenance (no status check prevents this)
3. Operator completes DeFi interactions
4. Operator calls asset value update functions (now using new aggregator)
5. Operator calls `end_op_value_update_with_bag` (compares values from different sources)

**Detection Constraints**: The issue is not easily detectable as oracle changes appear legitimate, and the inconsistency only manifests in the loss calculation logic.

### Recommendation

**Primary Fix**: Add vault operation status checks to oracle management functions:

```move
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    vault: &Vault<T>,  // Add vault parameter
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    vault.assert_not_during_operation();  // Add status check
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
```

Apply similar checks to `add_switchboard_aggregator` and `remove_switchboard_aggregator`.

**Alternative Fix**: If oracle changes must be allowed during operations, capture aggregator addresses/IDs at operation start and verify they haven't changed at operation end.

**Test Cases**:
1. Test that oracle changes revert when any vault is in VAULT_DURING_OPERATION_STATUS
2. Test that operations fail if oracle state changes mid-operation
3. Test multi-vault scenarios where one vault's operation blocks oracle changes

### Proof of Concept

**Initial State**:
- Vault has 100 SUI valued at $200 (using Aggregator A: $2/SUI)
- Loss tolerance: 10% per epoch ($20 maximum loss)

**Transaction Sequence**:

1. Operator starts operation:
   - Calls `start_op_with_bag`
   - `total_usd_value_before` = $200 (from Aggregator A)
   - Vault status = VAULT_DURING_OPERATION_STATUS

2. Admin changes oracle (no status check prevents this):
   - Calls `change_switchboard_aggregator` with Aggregator B ($1/SUI)
   - New aggregator is now active

3. Operator performs DeFi operations and updates asset values:
   - Calls adaptor functions which fetch prices from Aggregator B
   - 100 SUI now valued at $100

4. Operator ends operation:
   - Calls `end_op_value_update_with_bag`
   - `total_usd_value_after` = $100 (from Aggregator B)
   - Calculated loss = $200 - $100 = $100 (50%)
   - Loss tolerance check fails despite no actual loss occurring

**Expected Result**: Oracle changes should be blocked during operations, or operations should detect and handle oracle changes.

**Actual Result**: Operation value check uses inconsistent price feeds, producing invalid loss calculations that can bypass or falsely trigger loss tolerance limits.

### Citations

**File:** volo-vault/sources/manage.move (L99-126)
```text
public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}

public fun remove_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    asset_type: String,
) {
    oracle_config.remove_switchboard_aggregator(asset_type);
}

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

**File:** volo-vault/sources/operation.move (L178-193)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };
```

**File:** volo-vault/sources/operation.move (L353-363)
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
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-28)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
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

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```
