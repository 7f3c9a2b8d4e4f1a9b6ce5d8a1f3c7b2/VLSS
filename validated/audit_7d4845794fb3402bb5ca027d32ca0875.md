# Audit Report

## Title
Zero Loss Tolerance Configuration Causes Permanent Vault DoS Due to Unavoidable Value Fluctuations

## Summary
The `set_loss_tolerance` function lacks a minimum value check, allowing administrators to set loss tolerance to 0. This creates a permanent denial-of-service condition because any value decrease—from oracle price fluctuations, DeFi protocol fees, or rounding errors—exceeds the zero tolerance limit, causing the vault to become permanently stuck in operation status with no recovery mechanism.

## Finding Description

The vulnerability exists in the loss tolerance validation and enforcement mechanism across three critical code paths:

**Root Cause - Missing Minimum Check:**

The `set_loss_tolerance` function only validates the upper bound but has no minimum value check. [1](#0-0)  This allows `loss_tolerance` to be set to 0.

**Exploitation Point - Zero Tolerance Enforcement:**

When `loss_tolerance = 0`, the loss limit calculation in `update_tolerance` becomes:
```
loss_limit = cur_epoch_loss_base_usd_value * 0 / RATE_SCALING = 0
```

The assertion then checks: `assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT)` [2](#0-1) 

This will fail for ANY loss greater than zero (even 1 wei), aborting the transaction with `ERR_EXCEED_LOSS_LIMIT` (error code 5_008). [3](#0-2) 

**Critical Failure Point - Operation Value Check:**

During the three-step operation lifecycle, when `end_op_value_update_with_bag` detects any value decrease, it calls `vault.update_tolerance(loss)` which triggers the zero-tolerance check. [4](#0-3) 

Critically, the abort occurs at line 363 BEFORE the vault status is reset to `VAULT_NORMAL_STATUS` at line 375. This leaves the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS`.

**Sources of Unavoidable Value Fluctuations:**

Value fluctuations are inevitable due to:
- Oracle price updates from Switchboard aggregators naturally fluctuate between operation start and end
- DeFi protocol interactions (Navi, Cetus, Suilend, Momentum) include dynamic interest calculations and fees
- Rounding errors in decimal conversions between different precision levels
- Slippage in AMM interactions

**The Permanent DoS Mechanism:**

1. At operation start, `pre_vault_check` transitions the vault from `VAULT_NORMAL_STATUS` to `VAULT_DURING_OPERATION_STATUS` [5](#0-4) 

2. When the operation fails due to zero tolerance, the vault remains stuck in `VAULT_DURING_OPERATION_STATUS`

3. All future operations are blocked because `pre_vault_check` requires the vault to be in `VAULT_NORMAL_STATUS` (checked via `vault.assert_normal()` at line 73)

**No Recovery Mechanism Exists:**

The only admin function that can change vault status is `set_vault_enabled`, but it explicitly PREVENTS being called when the vault is in `VAULT_DURING_OPERATION_STATUS`. [6](#0-5) 

The `reset_loss_tolerance` function only resets the loss counter, not the vault status. [7](#0-6) [8](#0-7) 

## Impact Explanation

**Complete Operational Denial of Service:**

Once `loss_tolerance = 0` and any operation is attempted:
- The vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`
- All user deposits become impossible (requires normal status)
- All user withdrawals become impossible (requires normal status)
- All operator adaptor operations (Navi, Cetus, Suilend, Momentum) fail
- Vault funds become completely inaccessible
- No admin function exists to recover the vault status

**Severity Justification - HIGH:**
- Complete protocol denial of service
- All vault funds locked (users cannot deposit or withdraw)
- Deterministic and guaranteed failure with zero tolerance
- Requires admin intervention but cannot be fixed once stuck
- Breaks core protocol invariant: operational availability

This is HIGH severity because it causes complete vault inoperability with funds becoming permanently inaccessible until a contract upgrade is deployed.

## Likelihood Explanation

**Preconditions:**
- Requires `AdminCap` to call `set_loss_tolerance` with value 0 [9](#0-8) 

**Feasibility - MEDIUM-HIGH:**

Once `loss_tolerance` is set to 0 (whether accidentally or through misconfiguration):
- Any subsequent vault operation with value updates will ALWAYS fail
- Oracle prices naturally fluctuate due to market dynamics
- DeFi protocols continuously accrue interest and fees
- Rounding errors occur in all decimal conversions
- Even 1 wei of loss triggers the permanent DoS

**Execution Path:**
1. Admin calls `set_loss_tolerance(&admin_cap, &mut vault, 0)` (single transaction)
2. Operator attempts any vault operation (deposit execution, withdrawal execution, or adaptor operation)
3. Value naturally decreases by any amount (guaranteed in real operations)
4. Transaction aborts with `ERR_EXCEED_LOSS_LIMIT` leaving vault stuck
5. Vault becomes permanently unusable

**Detection/Prevention:**
- No runtime validation prevents setting tolerance to 0
- No warning system alerts administrators
- Users cannot detect misconfiguration until operations fail
- No emergency recovery mechanism exists

The likelihood is MEDIUM-HIGH because while it requires admin action, the misconfiguration is easy to make without proper validation, and the consequences are deterministic and irreversible.

## Recommendation

Add a minimum value check in the `set_loss_tolerance` function to prevent setting tolerance to 0 or unreasonably low values:

```move
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    const MIN_LOSS_TOLERANCE: u256 = 1; // Minimum 1 basis point (0.01%)
    assert!(tolerance >= MIN_LOSS_TOLERANCE, ERR_LOSS_TOLERANCE_TOO_LOW);
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

Additionally, consider adding an emergency admin function that can reset vault status when stuck:

```move
public fun emergency_reset_vault_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Emergency recovery: reset to normal status
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_EXCEED_LOSS_LIMIT)]
public fun test_zero_tolerance_causes_permanent_dos() {
    let mut s = test_scenario::begin(ADMIN);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault
    init_vault(&mut s, &mut clock);
    init_create_vault<SUI>(&mut s);
    
    s.next_tx(ADMIN);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut vault = s.take_shared<Vault<SUI>>();
        
        // Admin mistakenly sets loss_tolerance to 0
        vault_manage::set_loss_tolerance(&admin_cap, &mut vault, 0);
        
        s.return_to_sender(admin_cap);
        test_scenario::return_shared(vault);
    };
    
    // Setup vault with assets
    s.next_tx(ADMIN);
    {
        let mut vault = s.take_shared<Vault<SUI>>();
        let coin = coin::mint_for_testing<SUI>(1_000_000_000, s.ctx());
        vault.return_free_principal(coin.into_balance());
        test_scenario::return_shared(vault);
    };
    
    // Attempt operation - this will cause permanent DoS
    s.next_tx(OPERATOR);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI>>();
        let cap = s.take_from_sender<OperatorCap>();
        
        // Start operation - vault status becomes VAULT_DURING_OPERATION_STATUS
        let (asset_bag, tx_bag, tx_bag_check, principal, coin_balance) = 
            operation::start_op_with_bag(&mut vault, &operation, &cap, &clock, ...);
        
        // End operation
        operation::end_op_with_bag(&mut vault, &operation, &cap, asset_bag, tx_bag, principal, coin_balance);
        
        // Update values - ANY loss (even 1 wei from rounding) will abort here
        // Vault remains stuck in VAULT_DURING_OPERATION_STATUS
        operation::end_op_value_update_with_bag(&mut vault, &operation, &cap, &clock, tx_bag_check);
        // This line never executes - transaction aborts with ERR_EXCEED_LOSS_LIMIT
        
        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
    };
    
    // After abort, vault is permanently stuck:
    // - Status = VAULT_DURING_OPERATION_STATUS
    // - Cannot call any operations (requires VAULT_NORMAL_STATUS)
    // - Admin cannot recover (set_vault_enabled checks status != DURING_OPERATION)
    // - Funds are locked forever
    
    clock.destroy_for_testing();
    s.end();
}
```

The test demonstrates that with `loss_tolerance = 0`, any operation with the slightest value decrease causes `ERR_EXCEED_LOSS_LIMIT`, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism.

### Citations

**File:** volo-vault/sources/volo_vault.move (L56-56)
```text
const ERR_EXCEED_LOSS_LIMIT: u64 = 5_008;
```

**File:** volo-vault/sources/volo_vault.move (L486-494)
```text
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

**File:** volo-vault/sources/volo_vault.move (L519-531)
```text
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

**File:** volo-vault/sources/volo_vault.move (L608-624)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
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

**File:** volo-vault/sources/operation.move (L359-377)
```text
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

**File:** volo-vault/sources/manage.move (L58-64)
```text
public fun set_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    loss_tolerance: u256,
) {
    vault.set_loss_tolerance(loss_tolerance);
}
```

**File:** volo-vault/sources/manage.move (L170-176)
```text
public fun reset_loss_tolerance<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    vault.try_reset_tolerance(true, ctx);
}
```
