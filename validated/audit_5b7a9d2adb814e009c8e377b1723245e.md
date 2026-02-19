# Audit Report

## Title
Vault Permanent DoS from Lack of Admin Emergency Override During Failed Operations

## Summary
The Volo vault system lacks an admin emergency override mechanism to recover from failed operations. When any borrowed asset's value update fails during an operation (due to oracle issues, slippage checks, or external protocol problems), the vault becomes permanently stuck in DURING_OPERATION status with no recovery path, causing complete DoS of all vault functions and locking all user funds indefinitely.

## Finding Description

The vulnerability stems from a critical design flaw in the vault's operation recovery mechanisms:

**Missing Validation at Asset Addition:**
When operators add DeFi assets via `add_new_defi_asset()`, there is no validation of the underlying asset state or pool health. [1](#0-0)  The function only checks version, enabled status, and asset type uniqueness.

**Mandatory Value Update During Operations:**
When assets are borrowed during operations, they are tracked in the operation value update record. [2](#0-1)  Before completing an operation, all borrowed assets must have their values updated and validated. [3](#0-2) 

**Value Update Can Fail:**
The value update for MomentumPosition performs a slippage check that aborts if the pool price deviates too far from oracle prices. [4](#0-3)  This can fail due to market volatility, oracle issues, or pool problems.

**Permanent Stuck State:**
The vault status can only return to NORMAL through successful completion of `end_op_value_update_with_bag()`. [5](#0-4)  If value updates fail, this line is never reached, leaving the vault permanently in DURING_OPERATION status.

**No Admin Recovery:**
The admin function `set_enabled()` explicitly prevents status changes while the vault is in DURING_OPERATION status. [6](#0-5)  There is no emergency override mechanism for admins to force reset the vault status.

**All Operations Blocked:**
Once stuck, the vault cannot process new operations because `pre_vault_check()` requires NORMAL status. [7](#0-6)  Similarly, `remove_defi_asset_support()` also requires NORMAL status. [8](#0-7) 

## Impact Explanation

**Severity: HIGH**

Once the vault enters this stuck state, it results in complete protocol DoS:
- All vault operations (deposits, withdrawals, asset management) permanently blocked
- User funds (principal, shares, DeFi positions) locked indefinitely
- Admin cannot disable vault for emergency maintenance
- No recovery mechanism exists - the vault remains permanently inoperable

The entire vault's total USD value becomes inaccessible, potentially affecting millions of dollars and all vault participants.

## Likelihood Explanation

**Likelihood: MEDIUM**

While the specific scenario mentioned (sqrt_price = 0) is unlikely, there are multiple realistic failure modes:

1. **Oracle Issues:** Oracle misconfiguration, staleness, or temporary unavailability
2. **Market Volatility:** Legitimate slippage check failures during extreme market conditions
3. **External Protocol Issues:** Bugs or upgrades in Momentum, Cetus, Navi, or Suilend protocols affecting existing positions
4. **Arithmetic Edge Cases:** Overflow, underflow, or division by zero in complex value calculations

Given that:
- Vaults execute operations frequently over their lifetime
- Each operation depends on multiple external systems (oracles, DEX protocols)
- Complex calculation chains have multiple failure points
- No error recovery exists

The probability of encountering at least one failure scenario over time is significant.

## Recommendation

Implement an admin emergency override mechanism:

```move
public(package) fun admin_force_reset_operation<PrincipalCoinType>(
    _: &AdminCap,
    self: &mut Vault<PrincipalCoinType>,
) {
    self.check_version();
    // Allow admin to force reset stuck operations
    self.set_status(VAULT_NORMAL_STATUS);
    self.clear_op_value_update_record();
    emit(EmergencyOperationReset { vault_id: self.vault_id() });
}
```

Additionally, add validation when adding DeFi assets to check pool health/initialization state, and implement circuit breakers or fallback mechanisms for value update failures.

## Proof of Concept

A test demonstrating this would:
1. Add a MomentumPosition to vault
2. Start an operation borrowing the position
3. Configure oracle or pool state to cause slippage check failure
4. Attempt to complete operation - fails at `check_op_value_update_record`
5. Verify vault stuck in DURING_OPERATION status
6. Attempt admin recovery via `set_vault_enabled` - fails with ERR_VAULT_DURING_OPERATION
7. Confirm vault permanently inoperable

The vulnerability is valid because the lack of admin recovery for failed operations, combined with multiple realistic failure scenarios and no upfront validation, creates a permanent DoS risk for the entire vault system.

### Citations

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

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```

**File:** volo-vault/sources/volo_vault.move (L1390-1395)
```text
public(package) fun remove_defi_asset_support<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
): AssetType {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
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

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```
