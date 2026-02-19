### Title
Vault Denial of Service via Operation Status Lock with No Admin Recovery

### Summary
The Volo vault can become permanently frozen in `VAULT_DURING_OPERATION_STATUS` if an operation fails to complete properly, with no admin recovery mechanism available. This is analogous to the LayerZero bridge freeze where an invalid packet blocks the queue - here, a failed operation leaves the vault in an unrecoverable state, blocking all user deposits, withdrawals, and subsequent operations indefinitely.

### Finding Description

The vulnerability maps to the LayerZero "queue poisoning" pattern where system state becomes permanently locked due to failed processing with no recovery mechanism.

**Root Cause:**

The vault transitions through a three-phase operation lifecycle controlled by status flags. When an operator starts a DeFi operation, the vault status changes from `VAULT_NORMAL_STATUS` (0) to `VAULT_DURING_OPERATION_STATUS` (1). [1](#0-0) 

The operation must complete by calling `end_op_value_update_with_bag`, which validates all borrowed assets were returned and values updated, then sets status back to `VAULT_NORMAL_STATUS`. [2](#0-1) 

**Critical Vulnerability:**

If `end_op_value_update_with_bag` fails any of its assertions, the transaction aborts but the vault remains in `DURING_OPERATION` status. The function has multiple failure points:

1. Asset return verification - asserts all borrowed DeFi assets (Navi, Cetus, Suilend, Momentum positions) were returned [3](#0-2) 

2. Value update verification - asserts all borrowed assets had their values updated [4](#0-3) 

3. Loss tolerance check - asserts operation loss doesn't exceed per-epoch limit [5](#0-4) 

4. Share verification - asserts total shares unchanged during operation [6](#0-5) 

**No Recovery Mechanism:**

The admin's `set_enabled` function explicitly blocks execution when vault is in `DURING_OPERATION` status: [7](#0-6) 

The `set_status` function that could directly change status is `public(package)` only and not exposed to `AdminCap`: [8](#0-7) 

**Operations Blocked:**

When vault is stuck in `DURING_OPERATION` status, all critical functions require `assert_normal()` and fail:
- User deposit requests [9](#0-8) 
- User withdraw requests [10](#0-9) 
- Deposit execution [11](#0-10) 
- Withdraw execution [12](#0-11) 
- Starting new operations [13](#0-12) 

### Impact Explanation

**Severity: Critical - Complete Vault Denial of Service**

Once the vault enters this stuck state:
- All user funds are locked - users cannot request or execute withdrawals
- No new deposits can be accepted, freezing vault growth
- Existing pending requests cannot be processed
- Operator cannot perform any recovery operations
- Admin cannot use `set_enabled` to recover due to the status check
- The vault is permanently frozen with no code-level recovery path

This represents a complete loss of availability for the vault, affecting all users and all deposited funds. Unlike temporary operational issues, this is a permanent freeze requiring contract upgrade or migration to resolve.

### Likelihood Explanation

**Likelihood: Medium-High - Realistic Operator Error Scenarios**

The vulnerability can be triggered through realistic operational errors, not requiring malicious intent or compromised keys:

1. **Operator forgets to return borrowed asset**: In complex multi-protocol operations involving Navi, Cetus, Suilend, and Momentum, operator code may fail to return one DeFi position before calling completion.

2. **Operator forgets value update call**: Each borrowed asset requires explicit value update. Missing one call leaves the operation incomplete.

3. **External DeFi protocol issues**: If Navi/Suilend/Cetus encounters issues preventing asset withdrawal, operator cannot return assets, blocking completion.

4. **Market volatility exceeds loss tolerance**: During high volatility, operation losses may exceed the per-epoch `loss_tolerance` (default 0.1%), causing assertion failure. [14](#0-13) 

5. **Oracle price fluctuations**: Between operation start and completion, oracle price changes can cause unexpected value calculations, triggering assertion failures.

These are operational realities, not theoretical edge cases. The multi-step, multi-protocol nature of vault operations increases error probability.

### Recommendation

**Add Emergency Admin Recovery Function:**

Add a new `AdminCap`-gated function in `manage.move` that can force vault status reset:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

Expose `set_status` to this emergency function or make status directly settable by admin in emergency scenarios.

**Alternative: Add Status Override to set_enabled:**

Modify `set_enabled` to allow admin override when vault is stuck:

```move
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
    force: bool, // New parameter for emergency override
) {
    self.check_version();
    if (!force) {
        assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
    };
    // ... rest of function
}
```

**Best Practice: Operation Retry Mechanism:**

Implement a time-based automatic status reset if operation doesn't complete within expected timeframe, preventing permanent locks from transient issues.

### Proof of Concept

**Step 1: Vault Initialization**
- Admin creates vault with `create_vault<SUI>`
- Vault status = `VAULT_NORMAL_STATUS` (0)
- Users deposit funds, vault has significant TVL

**Step 2: Operator Starts Operation**
- Operator calls `start_op_with_bag` to borrow Navi position for lending operations
- Vault status transitions to `VAULT_DURING_OPERATION_STATUS` (1)
- Navi AccountCap borrowed and added to `asset_types_borrowed` list

**Step 3: Operation Execution**
- Operator performs Navi lending operations using borrowed AccountCap
- Due to external Navi protocol issue, operator cannot properly close position
- OR operator code has bug and forgets to call Navi value update function

**Step 4: Failed Completion Attempt**
- Operator calls `end_op_with_bag` (succeeds - returns whatever assets possible)
- Operator calls `end_op_value_update_with_bag`
- Function checks: `assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED)` 
- OR: `vault.check_op_value_update_record()` fails with `ERR_USD_VALUE_NOT_UPDATED`
- Transaction aborts with error code 1_003 or 5_007
- **Vault remains in DURING_OPERATION status**

**Step 5: Permanent Lock Confirmed**
- User Alice tries to request withdrawal: `request_withdraw()` calls `assert_normal()` → fails with `ERR_VAULT_NOT_NORMAL` (5_022)
- User Bob tries to request deposit: `request_deposit()` calls `assert_normal()` → fails with `ERR_VAULT_NOT_NORMAL` (5_022)
- Operator tries to start new operation: `pre_vault_check()` calls `assert_normal()` → fails with `ERR_VAULT_NOT_NORMAL` (5_022)
- Admin tries recovery: `set_vault_enabled(false)` → fails with `ERR_VAULT_DURING_OPERATION` (5_025)

**Result:**
Vault permanently frozen. All user funds locked. No recovery mechanism exists without contract upgrade or emergency migration logic.

### Citations

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
```

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/sources/volo_vault.move (L533-541)
```text
public(package) fun set_status<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>, status: u8) {
    self.check_version();
    self.status = status;

    emit(VaultStatusChanged {
        vault_id: self.vault_id(),
        status: status,
    });
}
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

**File:** volo-vault/sources/volo_vault.move (L707-716)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L806-814)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L896-905)
```text
public(package) fun request_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    receipt_id: address,
    shares: u256,
    expected_amount: u64,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L994-1002)
```text
public(package) fun execute_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
): (Balance<PrincipalCoinType>, address) {
    self.check_version();
    self.assert_normal();
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

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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
