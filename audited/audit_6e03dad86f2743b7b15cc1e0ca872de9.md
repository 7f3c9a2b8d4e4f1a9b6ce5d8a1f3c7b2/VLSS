### Title
Oracle Configuration Change During Vault Operation Causes Incorrect Loss Calculation

### Summary
When the oracle configuration is changed via `change_switchboard_aggregator` between `start_op_with_bag` and `end_op_value_update_with_bag`, the vault uses different oracle price sources to calculate the "before" and "after" total USD values. This causes incorrect loss calculations that can bypass the loss tolerance mechanism, potentially allowing repeated losses to drain vault funds without triggering protection limits.

### Finding Description

The vulnerability exists in the three-step vault operation lifecycle:

**Step 1 - Operation Start:** [1](#0-0) 

At operation start, `get_total_usd_value` reads cached asset values from the vault's `assets_value` table. These cached values were populated by prior calls to update functions like `update_free_principal_value`, which query the oracle configuration at that time.

**Step 2 - Oracle Configuration Change:** [2](#0-1) 

The admin can change the oracle aggregator at any time without checking vault operation status. The underlying implementation immediately updates the oracle's price: [3](#0-2) 

**Step 3 - Operation End:**
After assets are returned, update functions are called again with the NEW oracle configuration: [4](#0-3) 

These update functions only check `assert_enabled`, which does NOT prevent updates during operations: [5](#0-4) 

Finally, `end_op_value_update_with_bag` reads the vault's total USD value using the NEW oracle prices: [6](#0-5) 

**Root Cause:**
The loss calculation compares values priced by different oracles (Oracle A before, Oracle B after), making the result meaningless. If Oracle B reports prices 10% higher than Oracle A, a real 5% loss would appear as a 5% gain, completely bypassing the loss tolerance check.

### Impact Explanation

**Direct Financial Impact:**
- **Loss Concealment**: An operator incurring real losses can have them hidden if the oracle price increases between operation start and end. For example, if $1M is lost but the oracle price increases 15%, the vault shows a $500K gain instead of a $1M loss.
- **Loss Tolerance Bypass**: The `loss_tolerance` mechanism (default 0.1% per epoch) is designed to limit losses. By using mismatched oracles, this protection is completely circumvented.
- **Cumulative Drainage**: Over multiple operations, hidden losses accumulate while the loss tolerance appears unused, allowing systematic fund drainage.

**Affected Parties:**
- All vault depositors whose funds are exposed to undetected losses
- Protocol integrity as the core risk management mechanism fails

**Severity Justification:**
This is CRITICAL because it undermines the fundamental loss protection mechanism. The vault's `loss_tolerance` is explicitly designed to prevent excessive losses per epoch, but this vulnerability makes it ineffective.

### Likelihood Explanation

**Attack Complexity:**
This vulnerability does NOT require a malicious admin. It can occur during legitimate operational scenarios:

1. **Legitimate Oracle Updates**: Admin switches to a better/more reliable price feed during normal operations
2. **Price Feed Maintenance**: Oracle provider deprecates an aggregator, requiring migration
3. **Emergency Response**: Admin responds to oracle manipulation by switching to backup feed

**Execution Practicality:**
The scenario requires only:
- Admin calls `change_switchboard_aggregator` (requires AdminCap)
- Timing: happens during any vault operation (operations can last minutes to hours)
- No sophisticated attack or coordination needed

**Feasibility:**
The `OracleConfig` is a shared object used by all vaults. There is no coordination mechanism between:
- Vault operation status (NORMAL vs DURING_OPERATION)
- Oracle configuration changes [7](#0-6) 

The OracleConfig has no vault_id tracking or operation status awareness, making this collision highly probable in production.

**Detection Difficulty:**
The vulnerability leaves no obvious trace - loss calculations appear normal, only the oracle source differs. Without careful monitoring of oracle changes correlated with operation timing, this goes undetected.

### Recommendation

**1. Add Vault Operation Status Check in Oracle Changes:**

Modify `change_switchboard_aggregator` to prevent changes while any vault is in DURING_OPERATION status. Since multiple vaults share one OracleConfig, implement either:

Option A - Time-locked Oracle Changes:
```
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    // Add pending change with time delay
    oracle_config.schedule_aggregator_change(clock, asset_type, aggregator, DELAY_MS);
}
```

Option B - Operation Registry:
Create a shared registry tracking active operations across all vaults, check it before oracle changes.

**2. Oracle Snapshot in Operation Context:**

Store the oracle aggregator addresses in `TxBagForCheckValueUpdate`:
```
public struct TxBagForCheckValueUpdate {
    vault_id: address,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    total_usd_value: u256,
    total_shares: u256,
    oracle_aggregators: Table<String, address>, // NEW: snapshot oracle sources
}
```

Verify in `end_op_value_update_with_bag` that the same aggregators are used for final valuation.

**3. Test Cases:**
Add test case simulating oracle change mid-operation, expecting either:
- Transaction abort if Option 1 implemented
- Same aggregator validation if Option 2 implemented

### Proof of Concept

**Initial State:**
- Vault has $10M total value (10M SUI @ $1/SUI from Oracle A)
- Oracle A: SUI = $1.00
- Oracle B: SUI = $1.15 (15% higher)

**Transaction Sequence:**

**TX1 - Update values with Oracle A:**
```
vault.update_free_principal_value(&oracle_config_A, &clock)
// assets_value[SUI] = 10M * $1.00 = $10M
```

**TX2 - Start Operation:**
```
start_op_with_bag(...)
// Captures total_usd_value = $10M (using Oracle A prices)
```

**TX3 - Operator Loses 5% of funds:**
```
// Operator trades poorly, vault now has 9.5M SUI
// Real loss: $500K
```

**TX4 - End Operation:**
```
end_op_with_bag(...)
// Returns assets
```

**TX5 - Admin Changes Oracle (legitimate upgrade):**
```
change_switchboard_aggregator(..., "SUI", oracle_B_aggregator)
// Oracle now reports SUI = $1.15
```

**TX6 - Update values with Oracle B:**
```
vault.update_free_principal_value(&oracle_config_B, &clock)
// assets_value[SUI] = 9.5M * $1.15 = $10.925M
```

**TX7 - Value Update Check:**
```
end_op_value_update_with_bag(...)
// total_usd_value_before = $10M (Oracle A)
// total_usd_value_after = $10.925M (Oracle B)
// loss = $10M - $10.925M = -$925K (appears as GAIN!)
```

**Expected Result:** Loss tolerance check should detect $500K loss and potentially revert or consume tolerance.

**Actual Result:** The vault shows a $925K gain, loss tolerance is not consumed, and the operator can continue making losses indefinitely while they appear hidden.

**Success Condition:** The `loss` variable in the `OperationValueUpdateChecked` event shows 0 (no loss detected) despite actual $500K loss.

### Citations

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

**File:** volo-vault/sources/oracle.move (L31-37)
```text
public struct OracleConfig has key, store {
    id: UID,
    version: u64,
    aggregators: Table<String, PriceInfo>,
    update_interval: u64,
    dex_slippage: u256, // Pool price and oracle price slippage parameter (used in adaptors related to DEX)
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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
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
