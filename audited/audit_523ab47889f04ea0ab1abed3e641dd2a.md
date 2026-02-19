### Title
Oracle Aggregator Change Creates Race Condition with Vault Operations Leading to Loss Tolerance Bypass

### Summary
The `change_switchboard_aggregator()` function allows admins to change price oracles without checking if any vault is mid-operation. This creates a race condition where vault operations capture "before" prices from one aggregator and calculate "after" prices from a different aggregator, causing false loss calculations that can either bypass loss tolerance limits (allowing unsafe operations) or trigger false DoS (blocking legitimate operations).

### Finding Description

The vulnerability exists in the interaction between oracle management and vault operations across multiple files:

**Root Cause**: The `change_switchboard_aggregator()` function in `vault_manage` module only requires `AdminCap` and does not coordinate with vault operation state: [1](#0-0) 

This function delegates to the oracle implementation which atomically updates the aggregator address and price within a single transaction: [2](#0-1) 

**The Race Condition Window**: Vault operations follow a three-phase model where price comparisons span multiple transactions:

**Phase 1** - Operation start captures the baseline USD value using current oracle prices: [3](#0-2) 

The captured `total_usd_value` is stored in `TxBagForCheckValueUpdate` and held by the operator across multiple transactions.

**Phase 3** - Operation completion recalculates USD value and compares with the baseline: [4](#0-3) 

If an admin changes the aggregator between Phase 1 and Phase 3, the comparison at line 361 uses prices from two different oracles, making the loss calculation meaningless.

**Impact on Loss Tolerance**: The calculated "loss" is fed into the tolerance enforcement mechanism: [5](#0-4) 

The accumulated loss is checked against a per-epoch limit. False losses from mixed prices corrupt this critical safety mechanism.

**Why Protections Fail**: 
- OracleConfig is a separate shared object from Vault
- No vault status check exists in `change_switchboard_aggregator()`
- No locking or coordination mechanism between oracle updates and vault operations
- Operations naturally span multiple blocks, creating a realistic timing window

### Impact Explanation

**Direct Security Integrity Impact - Loss Tolerance Bypass**:
- If the new aggregator has **higher prices** than the old one:
  - `total_usd_value_before` calculated with old (lower) prices
  - `total_usd_value_after` calculated with new (higher) prices
  - Real operational losses are masked by artificial price gains
  - Operations exceeding safe loss limits can complete without triggering `ERR_EXCEED_LOSS_LIMIT`
  - Vault users suffer unchecked losses beyond the configured 0.1% per-epoch tolerance
  
**Operational Impact - False Loss DoS**:
- If the new aggregator has **lower prices** than the old one:
  - `total_usd_value_before` calculated with old (higher) prices
  - `total_usd_value_after` calculated with new (lower) prices
  - System detects artificial "loss" that doesn't exist
  - Legitimate operations are blocked with `ERR_EXCEED_LOSS_LIMIT`
  - Vault enters DoS state where operations cannot complete

**Protocol Damage**:
- Loss tracking (`cur_epoch_loss`) becomes corrupted with false data
- Per-epoch loss limits lose meaning, violating critical invariant #3: "loss_tolerance per epoch; total_usd_value correctness"
- Trust in vault safety mechanisms is undermined

**Affected Parties**:
- All vault depositors whose funds are subject to loss tolerance violations
- Operators whose legitimate operations are blocked by false losses
- Protocol reputation when safety mechanisms fail

### Likelihood Explanation

**Reachable Entry Point**: Both flows are standard protocol operations:
- Operators routinely start/end vault operations for DeFi integrations
- Admins legitimately change aggregators when oracles malfunction, get deprecated, or need upgrades

**Feasible Preconditions**: No special setup required:
- Normal vault operations naturally span multiple blocks/transactions (borrow assets → execute DeFi strategy → return assets → update values)
- The timing window is measured in blocks, making the race condition highly probable
- No attacker capabilities needed beyond observing on-chain state

**Execution Practicality**: 
- Vault operations follow documented three-phase flow with natural delays
- Admin aggregator changes are single-transaction operations
- No Move language barriers prevent this scenario
- The vulnerability can occur accidentally (admin unaware of in-flight operations) or intentionally

**Economic Rationality**: 
- Zero attack cost for admins (legitimate capability)
- High impact if exploited during market volatility when aggregator changes are most likely
- MEV opportunity: attacker could monitor vault operations and coordinate with complicit admin
- Defensive scenario: legitimate admin action during oracle issues accidentally triggers the vulnerability

**Probability**: HIGH - Given that:
- Vault operations are frequent (daily DeFi rebalancing)
- Oracle updates occur periodically (oracle deprecations, upgrades, price feed issues)
- No protection mechanism exists
- The timing window is realistic (multi-block operation duration)

### Recommendation

**Immediate Fix**: Add vault operation status tracking to oracle changes:

1. **Track Active Operations**: Modify `OracleConfig` to maintain a registry of vaults currently in operation state:
```
// In oracle.move, add to OracleConfig struct:
active_vaults: Table<address, bool>
```

2. **Register/Unregister During Operations**: 
   - In `pre_vault_check()`: Register vault in `active_vaults` when entering `DURING_OPERATION` status
   - In `end_op_value_update_with_bag()`: Unregister vault when returning to `NORMAL` status

3. **Block Aggregator Changes During Operations**:
```
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    
    // NEW: Ensure no vault is mid-operation
    assert!(config.active_vaults.is_empty(), ERR_OPERATION_IN_PROGRESS);
    
    // ... existing code
}
```

**Alternative Fix**: Implement oracle versioning:
- Store oracle version in `TxBagForCheckValueUpdate` at operation start
- Validate same oracle version is used at operation end
- Abort if oracle changed during operation with clear error message

**Invariant Checks to Add**:
- Assert oracle config unchanged between operation phases
- Add event emission when aggregator changes to aid monitoring
- Implement cooldown period after aggregator change before operations can start

**Test Cases to Prevent Regression**:
1. Test: Start operation → Change aggregator → Complete operation → Should abort
2. Test: Change aggregator with no active operations → Should succeed
3. Test: Multiple vaults using same oracle, one in operation → Should block aggregator change
4. Test: False loss scenario with price decrease → Verify DoS prevention
5. Test: Loss bypass scenario with price increase → Verify safety enforcement

### Proof of Concept

**Initial State**:
- Vault configured with Aggregator A pricing SUI at $2.00
- Vault has 1000 SUI principal = $2000 USD value
- Loss tolerance set to 10 (0.1% per epoch = $2 max loss)

**Transaction Sequence**:

**T1 (Block N)**: Operator starts operation
```
start_op_with_bag(vault, ...)
// Captures: total_usd_value_before = $2000 (using Aggregator A @ $2.00)
// Vault status → DURING_OPERATION
```

**T2 (Block N+5)**: Admin changes aggregator (unaware of in-flight operation)
```
change_switchboard_aggregator(oracle_config, asset_type="SUI", new_aggregator_B)
// Aggregator B prices SUI at $2.50
// Oracle now returns $2.50 for SUI
```

**T3 (Block N+10)**: Operator returns assets
```
end_op_with_bag(vault, ...)
// Assets returned, now must update values
```

**T4 (Block N+12)**: Operator updates values and completes operation
```
update_free_principal_value(vault, oracle_config, clock)
// Now uses Aggregator B: 1000 SUI × $2.50 = $2500

end_op_value_update_with_bag(vault, tx_bag)
// total_usd_value_before = $2000 (Aggregator A)
// total_usd_value_after = $2500 (Aggregator B)
// Calculated loss = -$500 (FALSE - this is a gain from price change, not operational loss)
// Since after > before, no loss recorded
```

**Expected Result**: If actual operational loss was $50 (should trigger tolerance check), it would be hidden by the $500 artificial "gain" from the price change.

**Actual Result**: Operation completes successfully despite violating true loss tolerance, because the price comparison is corrupted by mixed aggregator sources.

**Success Condition**: The operation completes without triggering `ERR_EXCEED_LOSS_LIMIT` even though real operational losses exceeded the 0.1% tolerance limit, demonstrating the loss tolerance bypass vulnerability.

---

**Notes**:
- This vulnerability fundamentally violates the critical invariant: "loss_tolerance per epoch; total_usd_value correctness"
- The race condition is not hypothetical - it occurs naturally in the protocol's operational flow
- Both accidental (uncoordinated admin actions) and intentional (MEV/malicious) scenarios are realistic
- The fix requires coordination between the separate OracleConfig and Vault objects

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

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```
