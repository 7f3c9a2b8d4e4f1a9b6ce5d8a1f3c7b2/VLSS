### Title
Zero Slippage Configuration Causes Permanent DoS on Momentum Position Value Updates

### Summary
The `get_position_value()` function in the Momentum adaptor contains a flawed assertion that always fails when `dex_slippage` is set to 0, even when pool prices perfectly match oracle prices. This blocks vault operations from completing their value update phase, causing the vault to remain stuck in `VAULT_DURING_OPERATION_STATUS` and preventing all future operations.

### Finding Description

The root cause is in the price validation assertion logic: [1](#0-0) 

When `slippage = 0`, the right side of the comparison evaluates to:
- `DECIMAL * 0 / SLIPPAGE_BASE = 0`

Even when prices match perfectly (pool_price equals relative_price_from_oracle), the left side evaluates to:
- `pool_price.diff(relative_price_from_oracle) = 0` (absolute difference)
- `0 * DECIMAL / relative_price_from_oracle = 0`

The assertion becomes `0 < 0`, which is always false. The strict less-than operator `<` means zero difference cannot satisfy zero tolerance.

The `set_dex_slippage` function lacks validation to prevent setting slippage to zero: [2](#0-1) 

The public entry point also has no validation: [3](#0-2) 

During the three-phase operation lifecycle, after assets are returned via `end_op_with_bag`: [4](#0-3) 

The operator must call `update_momentum_position_value` which internally calls `get_position_value`: [5](#0-4) 

When the assertion fails, the value update cannot complete. The final `end_op_value_update_with_bag` function then fails its validation check: [6](#0-5) 

This check verifies all borrowed assets were updated: [7](#0-6) 

The vault remains stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all future operations which require normal status: [8](#0-7) 

### Impact Explanation

**Operational DoS**: Once `dex_slippage` is set to 0 and any operation involving Momentum positions is initiated, the vault becomes permanently stuck in operation mode. All subsequent operations are blocked because `pre_vault_check` requires normal status. Users cannot execute new deposits, withdrawals, or strategy operations until the admin changes the slippage configuration back to a non-zero value.

**Affected Parties**: All vault users are impacted. Operators cannot complete operations, depositors cannot execute requests, and the vault's operational continuity is compromised.

**Severity Justification**: Medium severity is appropriate because while this causes significant operational disruption (DoS), it:
1. Requires admin misconfiguration (setting slippage to 0)
2. Does not directly result in fund loss
3. Is reversible by admin action (changing slippage back)
4. Could occur accidentally through configuration error rather than malicious intent

### Likelihood Explanation

**Admin Configuration Error**: The vulnerability can be triggered through legitimate admin operations. An administrator might:
- Misunderstand the slippage units or semantics
- Accidentally set slippage to 0 when intending to set a different value
- Deliberately set to 0 believing it means "no tolerance" without understanding the assertion logic

**Attack Complexity**: Low. The sequence is straightforward:
1. Admin calls `set_dex_slippage(0)` 
2. Next operation involving Momentum positions fails at value update
3. Vault stuck until slippage is changed

**Feasibility**: High. No special preconditions are needed beyond admin access, which is a normal operational role (not a compromise). The lack of input validation makes this misconfiguration possible.

**Detection**: The issue becomes immediately apparent when operations fail, but the vault may already be stuck by then, requiring emergency admin intervention.

### Recommendation

**1. Add Input Validation**: Implement a minimum slippage check in `set_dex_slippage`:

```move
public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();
    assert!(dex_slippage > 0, ERR_INVALID_DEX_SLIPPAGE); // Add this check
    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
```

Add corresponding error constant:
```move
const ERR_INVALID_DEX_SLIPPAGE: u64 = 2_006;
```

**2. Alternative Fix**: If zero slippage must be supported, change the assertion logic to use `<=` instead of `<`:

```move
assert!(
    (pool_price.diff(relative_price_from_oracle) * DECIMAL / relative_price_from_oracle) <= (DECIMAL * slippage / SLIPPAGE_BASE),
    ERR_INVALID_POOL_PRICE,
);
```

**3. Test Cases**: Add test to verify slippage validation:

```move
#[test]
#[expected_failure(abort_code = ERR_INVALID_DEX_SLIPPAGE)]
public fun test_set_dex_slippage_zero_fails() {
    // Test that setting slippage to 0 aborts
    vault_manage::set_dex_slippage(&admin_cap, &mut oracle_config, 0);
}
```

### Proof of Concept

**Initial State**:
- Vault has Momentum positions as borrowed assets
- Oracle feeds are functioning normally with accurate prices
- Default `dex_slippage` is 100 (1%)

**Exploitation Steps**:

1. **Admin sets slippage to zero**:
   - Transaction: `vault_manage::set_dex_slippage(&admin_cap, &mut oracle_config, 0)`
   - Result: `oracle_config.dex_slippage` = 0
   - No assertion failure (no validation exists)

2. **Operator starts vault operation**:
   - Transaction: `operation::start_op_with_bag()` borrows Momentum positions
   - Result: Vault status = `VAULT_DURING_OPERATION_STATUS`, assets borrowed successfully

3. **Operator returns assets**:
   - Transaction: `operation::end_op_with_bag()` returns positions
   - Result: Assets returned, `value_update_enabled` = true, waiting for value updates

4. **Operator attempts value update** (THIS FAILS):
   - Transaction: `momentum_adaptor::update_momentum_position_value()`
   - Assertion at line 55-58 evaluates: `0 < 0` (even with perfect price match)
   - Result: Transaction aborts with `ERR_INVALID_POOL_PRICE`

5. **Cannot complete operation**:
   - Transaction: `operation::end_op_value_update_with_bag()` 
   - `check_op_value_update_record()` fails because Momentum asset not marked as updated
   - Result: Transaction aborts with `ERR_USD_VALUE_NOT_UPDATED`

**Expected vs Actual**:
- **Expected**: When prices match perfectly, value update should succeed even with zero slippage tolerance
- **Actual**: Assertion always fails due to strict `<` comparison with 0, causing permanent DoS

**Success Condition**: Vault remains stuck in `VAULT_DURING_OPERATION_STATUS`. Only recovery is admin changing `dex_slippage` back to non-zero value, then re-attempting the value update.

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L28-29)
```text
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L54-58)
```text
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/oracle.move (L117-122)
```text
public(package) fun set_dex_slippage(config: &mut OracleConfig, dex_slippage: u256) {
    config.check_version();

    config.dex_slippage = dex_slippage;
    emit(DexSlippageSet { dex_slippage })
}
```

**File:** volo-vault/sources/manage.move (L136-138)
```text
public fun set_dex_slippage(_: &AdminCap, oracle_config: &mut OracleConfig, dex_slippage: u256) {
    oracle_config.set_dex_slippage(dex_slippage);
}
```

**File:** volo-vault/sources/operation.move (L73-73)
```text
    vault.assert_normal();
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```
