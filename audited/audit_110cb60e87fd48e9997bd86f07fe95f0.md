### Title
Cross-Vault Dependency Causes Cascading DoS When Receipt Vault is Disabled

### Summary
When a vault holds a Receipt pointing to another vault (receipt_vault), disabling the receipt_vault prevents the holding vault from completing operations, causing a complete DoS of deposits and withdrawals. The overly restrictive `assert_normal()` check in `update_receipt_value()` requires the receipt_vault to be in NORMAL status even though the function only reads valuation data.

### Finding Description

The vulnerability exists in the `update_receipt_value()` function which is called during Phase 3 of vault operations to update the USD value of Receipt assets: [1](#0-0) 

At line 29, the function calls `receipt_vault.assert_normal()` which enforces that the receipt_vault must have `status == VAULT_NORMAL_STATUS (0)`: [2](#0-1) 

The vault status values are: [3](#0-2) 

When a vault is disabled by the admin via `set_vault_enabled(false)`, its status becomes `VAULT_DISABLED_STATUS (2)`: [4](#0-3) 

During vault operations, when assets are borrowed, they must have their values updated before the operation can complete. The `check_op_value_update_record()` function enforces this requirement: [5](#0-4) 

This check is called in `end_op_value_update_with_bag()` at line 354: [6](#0-5) 

**Execution Flow:**
1. Vault A holds a Receipt asset pointing to Vault B
2. Admin disables Vault B (status becomes 2)
3. Vault A operator starts an operation that borrows the Receipt asset
4. Vault A status becomes `VAULT_DURING_OPERATION_STATUS (1)` at line 74: [7](#0-6) 

5. Operator attempts to call `update_receipt_value()` to update the Receipt's value
6. Function aborts at line 29 because Vault B status is 2, not 0
7. Operator cannot complete `check_op_value_update_record()`, operation remains incomplete
8. Vault A remains stuck with status = 1

**Why This is Problematic:**

The `update_receipt_value()` function only reads data from receipt_vault (share ratio, pending deposits, claimable principal) and does not modify it: [8](#0-7) 

Unlike other adaptors (Navi, Cetus, Suilend, Momentum) which only check the status of the vault being updated, the receipt_adaptor uniquely checks the status of an external dependency (receipt_vault). This creates a cross-vault dependency that can cascade failures.

### Impact Explanation

**Concrete Harm:**
When Vault A is stuck in `VAULT_DURING_OPERATION_STATUS`, all user operations are blocked:

- Users cannot submit deposit requests (requires `assert_normal()` at line 716): [9](#0-8) 

- Users cannot submit withdrawal requests (requires `assert_normal()` at line 905): [10](#0-9) 

- The vault cannot be disabled to prevent further operations (enforced at line 523): [11](#0-10) 

**Who is Affected:**
- All depositors in Vault A have their funds locked
- New users cannot deposit
- Existing users cannot withdraw
- The admin faces a forced choice: keep a potentially compromised Vault B enabled, or leave Vault A DoS'd

**Severity Justification:**
This is a Medium severity issue because:
1. Complete operational DoS of a vault
2. Funds are locked (though not lost)
3. Creates unintended dependencies between vaults
4. No automated recovery mechanism exists
5. Affects all users of the impacted vault

### Likelihood Explanation

**Preconditions:**
- Vault A holds a Receipt asset pointing to Vault B
- Admin disables Vault B
- Vault A has an operation in progress involving the Receipt

**Realistic Scenario:**
This is not a malicious exploit but a design flaw that manifests during legitimate operational scenarios:

1. **Emergency Response:** Admin discovers a critical vulnerability in Vault B and must disable it immediately to prevent exploitation
2. **Cascading Impact:** The admin may be unaware that Vault A holds receipts to Vault B
3. **Operational Conflict:** Vault A's ongoing operations fail, creating a cascading DoS
4. **Forced Dilemma:** Admin must choose between security (keep Vault B disabled) and availability (re-enable Vault B to unblock Vault A)

**Probability:**
Medium - While it requires admin action, cross-vault Receipt holdings are a designed feature for vault composition and diversification. As the protocol grows with multiple interconnected vaults, the likelihood of this scenario increases. Emergency vault disabling is a legitimate governance action that should not cascade to other vaults.

**Detection:**
Difficult to detect until it occurs, as there is no mechanism to track cross-vault dependencies or validate the impact of disabling a vault.

### Recommendation

**Code-Level Mitigation:**

Replace the overly restrictive `assert_normal()` check with `assert_enabled()` in `receipt_adaptor.move` line 29. Since the function only reads valuation data and does not modify the receipt_vault, it should allow reading even when the vault is in `VAULT_DURING_OPERATION_STATUS`:

```move
// Change from:
receipt_vault.assert_normal();

// To:
receipt_vault.assert_enabled();
```

Or remove the status check entirely, as the function performs read-only operations.

**Invariant Checks to Add:**

1. Add a dependency tracking system that records when vaults hold receipts to other vaults
2. Implement a pre-flight check in `set_enabled()` that validates no other vaults have pending operations involving receipts to the vault being disabled
3. Add an admin emergency function to force-reset operation status with proper multi-sig governance controls

**Test Cases:**

1. Test that `update_receipt_value()` succeeds when receipt_vault is in `VAULT_DURING_OPERATION_STATUS`
2. Test that disabling a vault does not prevent other vaults from updating receipt values pointing to it
3. Test the complete operation flow when receipt_vault status changes mid-operation
4. Test cascading scenarios where multiple vaults hold cross-references

### Proof of Concept

**Initial State:**
- Vault A (SUI vault) exists with normal operations
- Vault B (USDC vault) exists with normal operations  
- Vault A holds Receipt_X which represents shares in Vault B
- Receipt_X is registered as a DeFi asset in Vault A's asset bag

**Attack Sequence:**

1. **Admin disables Vault B:**
   ```
   vault_manage::set_vault_enabled(admin_cap, vault_b, false)
   // vault_b.status now = VAULT_DISABLED_STATUS (2)
   ```

2. **Operator starts operation on Vault A:**
   ```
   operation::start_op_with_bag(
       vault_a,
       operation,
       operator_cap,
       clock,
       defi_asset_ids: vector[0], // Receipt asset ID
       defi_asset_types: vector[type_name::get<Receipt>()],
       ...
   )
   // vault_a.status now = VAULT_DURING_OPERATION_STATUS (1)
   // Receipt_X is borrowed from vault_a
   ```

3. **Operator performs DeFi operations (succeeds)**

4. **Operator returns assets:**
   ```
   operation::end_op_with_bag(vault_a, ..., defi_assets_bag)
   // Receipt_X is returned to vault_a
   // vault_a.status still = 1 (waiting for value update)
   ```

5. **Operator attempts to update receipt value:**
   ```
   receipt_adaptor::update_receipt_value(
       vault_a,
       vault_b, // This vault is disabled (status=2)
       config,
       clock,
       receipt_asset_type
   )
   // ABORTS with ERR_VAULT_NOT_NORMAL at line 29
   ```

6. **Operator cannot complete operation:**
   ```
   operation::end_op_value_update_with_bag(vault_a, ...)
   // ABORTS at check_op_value_update_record() 
   // because Receipt value was not updated
   ```

**Expected vs Actual Result:**

- **Expected:** Vault A can read the valuation of its Receipt asset regardless of Vault B's operational status, since the valuation function only reads data
- **Actual:** Vault A's operation aborts and cannot be completed, leaving Vault A stuck in `VAULT_DURING_OPERATION_STATUS`

**Success Condition:**
Vault A remains stuck with status=1, all deposit/withdrawal operations for Vault A users fail with `ERR_VAULT_NOT_NORMAL`, and the only recovery is for the admin to re-enable Vault B (which may not be safe/desired).

### Notes

This vulnerability highlights a critical design flaw in cross-vault composability. The receipt_adaptor is the only adaptor that enforces status checks on external objects, creating implicit dependencies that are not tracked or validated at the protocol level. This violates the principle of fault isolation - disabling one vault should not cascade to DoS other vaults.

### Citations

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-36)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
    receipt_vault.assert_normal();

    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);

    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L41-76)
```text
public fun get_receipt_value<T>(
    vault: &Vault<T>,
    config: &OracleConfig,
    receipt: &Receipt,
    clock: &Clock,
): u256 {
    vault.assert_vault_receipt_matched(receipt);

    let share_ratio = vault.get_share_ratio(clock);

    let vault_receipt = vault.vault_receipt_info(receipt.receipt_id());
    let mut shares = vault_receipt.shares();

    // If the status is PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS, the share value part is 0
    if (vault_receipt.status() == PENDING_WITHDRAW_WITH_AUTO_TRANSFER_STATUS) {
        shares = shares - vault_receipt.pending_withdraw_shares();
    };

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );

    vault_share_value + pending_deposit_value + claimable_principal_value
}
```

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L715-717)
```text
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/sources/volo_vault.move (L904-906)
```text
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
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

**File:** volo-vault/sources/operation.move (L353-377)
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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
