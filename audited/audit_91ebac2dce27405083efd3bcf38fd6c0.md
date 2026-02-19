### Title
Vault Operations Permanently Locked Due to Suilend Module Version Incompatibility

### Summary
The volo-vault's suilend_adaptor lacks version compatibility checks when interacting with the external Suilend lending_market module. If Suilend upgrades their module and increments the version constant, the adaptor's calls to `compound_interest()` will fail with `EIncorrectVersion`, causing vault operations to become permanently stuck in `DURING_OPERATION` status with no recovery mechanism.

### Finding Description

The suilend_adaptor interacts with the deployed Suilend package to update position values during vault operations. The critical flow involves calling `compound_interest()` for each reserve: [1](#0-0) 

This function calls the Suilend lending_market module's `compound_interest()`, which contains a strict version check: [2](#0-1) 

The Suilend package is currently at version 7 and is deployed at a fixed address: [3](#0-2) 

**Root Cause:** When Suilend upgrades their module and increments `CURRENT_VERSION` (e.g., from 7 to 8), there is a critical window where:
1. The upgraded module is deployed with `CURRENT_VERSION = 8`
2. Existing LendingMarket objects still have `version = 7` (before migration)
3. The version check `assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion)` fails (7 ≠ 8)

**Why Protections Fail:** The vault operation flow requires value updates before completion: [4](#0-3) 

When the operation starts, the vault status is set to `DURING_OPERATION`. To complete, the operator must update all asset values and call `end_op_value_update_with_bag()`: [5](#0-4) 

If `update_suilend_position_value()` fails due to version mismatch, the vault cannot reach line 375 to reset status back to `NORMAL`. Even the AdminCap cannot recover because `set_enabled()` explicitly prevents status changes during operations: [6](#0-5) 

### Impact Explanation

**Direct Impact:** All vault operations involving Suilend positions become permanently locked until external resolution. The vault remains in `DURING_OPERATION_STATUS` indefinitely, preventing:
- Completion of in-progress operations
- Initiation of new operations (checked by `assert_normal()`)
- Deposit/withdrawal request processing
- Any vault rebalancing activities

**Who Is Affected:** All vault users with pending operations and all future users attempting operations. Funds remain custody-safe but operationally frozen.

**Severity Justification:** This is a critical operational DoS that requires external coordination (Suilend team migrating all LendingMarket objects) or protocol upgrade to resolve. The vault has no internal recovery mechanism despite having AdminCap capabilities.

### Likelihood Explanation

**Preconditions:** Suilend must upgrade their lending_market module package. This is not an attack but expected protocol evolution - Suilend is actively maintained and already at version 7, indicating multiple past upgrades.

**Execution:** The vulnerability triggers automatically when:
1. Suilend deploys upgraded module with incremented `CURRENT_VERSION`
2. Any vault operator attempts to update Suilend position values during operations
3. The `compound_interest()` version check fails

**Feasibility:** High probability due to:
- Suilend's active development history (7 versions indicate ongoing upgrades)
- Migration process requires calling `migrate()` on each LendingMarket object individually, creating time windows of incompatibility
- No version pinning or compatibility validation in the adaptor

**Complexity:** No attacker action required - occurs naturally during normal protocol operations when external dependency upgrades occur.

### Recommendation

**Immediate Mitigations:**

1. Add version compatibility checks in the suilend_adaptor before calling compound_interest:
```move
// In suilend_adaptor.move, add version validation
public fun validate_lending_market_version<ObligationType>(
    lending_market: &LendingMarket<ObligationType>,
) {
    // Check against expected version range or specific version
    assert!(lending_market.version() >= MIN_COMPATIBLE_VERSION, EIncompatibleVersion);
}
```

2. Implement emergency admin recovery function to reset vault status:
```move
// In volo_vault.move, add emergency reset
public fun emergency_reset_status<PrincipalCoinType>(
    _: &AdminCap,
    self: &mut Vault<PrincipalCoinType>,
) {
    self.status = VAULT_NORMAL_STATUS;
    self.clear_op_value_update_record();
}
```

3. Use try-catch or optional handling for version-checked operations to gracefully degrade:
```move
// Attempt compound_interest, but continue with stale values if version incompatible
// Add staleness warnings in position value calculation
```

4. Pin to specific Suilend package version or implement version negotiation protocol with fallback behavior.

### Proof of Concept

**Initial State:**
- Vault has Suilend positions (SuilendObligationOwnerCap in assets_bag)
- Suilend lending_market module is at version 7
- LendingMarket objects have version = 7

**Exploit Sequence:**

1. Suilend team upgrades lending_market module:
   - Deploy new package with `CURRENT_VERSION = 8`
   - Package upgrade is successful at address `0xf95b06141ed4a174f239417323bde3f209b972f5930d8521ea38a52aff3a6ddf`

2. Operator initiates vault operation:
   - Calls `start_op_with_bag()` - vault status → `DURING_OPERATION`
   - Borrows Suilend position from vault

3. Operator returns assets and attempts value update:
   - Calls `end_op_with_bag()` - assets returned successfully
   - Calls `update_suilend_position_value()` → calls `suilend_compound_interest()` → calls `lending_market.compound_interest()`

4. **Transaction aborts:**
   - `compound_interest()` checks: `assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion)`
   - LendingMarket object version = 7, CURRENT_VERSION = 8
   - Transaction aborts with error code 1 (EIncorrectVersion)

5. **Vault permanently stuck:**
   - Status remains `DURING_OPERATION`
   - Cannot complete operation (requires successful value update)
   - Cannot start new operations (`assert_normal()` fails)
   - AdminCap cannot call `set_enabled()` (asserts against `DURING_OPERATION` status)

**Expected Result:** Operation completes successfully, vault returns to NORMAL status

**Actual Result:** Transaction aborts, vault permanently stuck in DURING_OPERATION status until Suilend migrates the LendingMarket object to version 8 or vault code is upgraded with recovery mechanism.

### Citations

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L91-102)
```text
fun suilend_compound_interest<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
) {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());
    let reserve_array_indices = get_reserve_array_indicies(obligation);

    reserve_array_indices.do_ref!(|reserve_array_index| {
        lending_market.compound_interest(*reserve_array_index, clock);
    });
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L377-386)
```text
    public fun compound_interest<P>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);

        reserve.compound_interest(clock);
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/Move.toml (L20-23)
```text
[addresses]
sui = "0x2"
# suilend = "0x0"
suilend = "0xf95b06141ed4a174f239417323bde3f209b972f5930d8521ea38a52aff3a6ddf"
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

**File:** volo-vault/sources/operation.move (L354-377)
```text
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
