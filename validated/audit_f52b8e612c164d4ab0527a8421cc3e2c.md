# Audit Report

## Title
Unrestricted Public Access to Asset Value Update Functions During Vault Operations Enables Loss Tolerance Bypass

## Summary
All adaptor value update functions are declared as `public fun` without capability requirements, allowing any external caller to update asset valuations during vault operations while the vault is in `VAULT_DURING_OPERATION_STATUS`. These functions only enforce `assert_enabled()` rather than `assert_normal()`, permitting external interference with the operator's operation flow and creating opportunities to manipulate the timing of asset value snapshots used in loss tolerance calculations.

## Finding Description

**Root Cause - Insufficient Access Control:**

All adaptor update functions are declared as `public fun` without requiring operator capabilities:
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 
- [5](#0-4) 

These functions call `finish_update_asset_value()` which only enforces `assert_enabled()`: [6](#0-5) 

The `assert_enabled()` check only prevents calls when status is `VAULT_DISABLED_STATUS`, allowing both `VAULT_NORMAL_STATUS` and `VAULT_DURING_OPERATION_STATUS`: [7](#0-6) 

Compare with status constants showing DURING_OPERATION (1) is not blocked: [8](#0-7) 

**Operation Flow and Vulnerability Window:**

During operations, the vault status is set to `VAULT_DURING_OPERATION_STATUS`: [9](#0-8) 

The operator captures `total_usd_value_before` at operation start: [10](#0-9) 

`finish_update_asset_value` directly modifies the vault's `assets_value` table regardless of operation status: [11](#0-10) 

When operations complete, `end_op_value_update_with_bag` calculates `total_usd_value_after` using these asset values: [12](#0-11) 

The loss tolerance check validates using these values: [13](#0-12) 

## Impact Explanation

**Access Control Violation:**
External actors can interfere with operator-controlled operations by calling public update functions during the `VAULT_DURING_OPERATION_STATUS` window. This breaks the intended atomicity and control flow of vault operations.

**Loss Tolerance Bypass Potential:**
By controlling the timing of asset value updates, attackers can snapshot values when oracle prices or pool states temporarily show favorable valuations. While attackers cannot directly manipulate oracle prices (which come from trusted Switchboard feeds) or protocol states (from DEX/lending protocols), they can:
1. Monitor on-chain oracle price updates continuously
2. Front-run operator's value updates when prices temporarily spike
3. Force asset value snapshots at opportune moments
4. Make `total_usd_value_after` appear higher than if operator controlled timing
5. Cause actual losses to appear smaller in loss tolerance calculations

**Protocol Integrity Impact:**
- Operator's exclusive control over operation flow is compromised
- Asset valuation integrity during critical operation windows is violated
- Loss tolerance enforcement becomes unreliable due to external timing manipulation
- The security guarantee that operators control operation atomicity is broken

## Likelihood Explanation

**Trivial Execution:**
The attack requires only:
1. Monitoring vault status transitions (publicly observable on-chain state)
2. Access to shared objects (Vault, OracleConfig, Clock, Pool objects - all public)
3. Submitting a PTB transaction calling any public update function
4. No special capabilities, operator privileges, or complex setup required

**Attack Window:**
The vulnerability window exists during every vault operation from `start_op_with_bag` until `end_op_value_update_with_bag` completes, which occurs regularly as operators rebalance positions and manage DeFi integrations.

**Economic Considerations:**
- Attack cost: Single transaction gas fee (~0.01-0.1 SUI)
- Potential benefit: Can influence loss calculations to hide operational losses
- Timing opportunity exists within oracle update windows (1 minute intervals) where prices naturally fluctuate
- Success depends on favorable market conditions but opportunity recurs with every operation

## Recommendation

**Primary Fix - Restrict Access During Operations:**
Modify all public update functions to check vault status and prevent external calls during operations:

```move
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    vault.assert_normal(); // Add this check to all public update functions
    // ... rest of function
}
```

**Alternative Fix - Operator Capability Requirement:**
Add operator capability requirement to all update functions:

```move
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    _cap: &OperatorCap, // Require operator capability
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    // ... function body
}
```

## Proof of Concept

A POC would demonstrate:
1. Starting a vault operation (status → DURING_OPERATION)
2. External caller successfully calling `update_cetus_position_value` during operation
3. This call succeeding despite vault being in operation status
4. Asset values being updated by external caller
5. This affecting the final loss calculation in `end_op_value_update_with_bag`

The vulnerability is confirmed by the code structure where `assert_enabled()` explicitly allows `VAULT_DURING_OPERATION_STATUS`, and all update functions are declared as `public fun` without capability checks.

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-19)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-13)
```text
public fun update_navi_position_value<PrincipalCoinType>(
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-23)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-21)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-16)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
```

**File:** volo-vault/sources/volo_vault.move (L23-25)
```text
const VAULT_NORMAL_STATUS: u8 = 0;
const VAULT_DURING_OPERATION_STATUS: u8 = 1;
const VAULT_DISABLED_STATUS: u8 = 2;
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

**File:** volo-vault/sources/volo_vault.move (L645-647)
```text
public(package) fun assert_enabled<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() != VAULT_DISABLED_STATUS, ERR_VAULT_NOT_ENABLED);
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1181)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();
```

**File:** volo-vault/sources/volo_vault.move (L1183-1187)
```text
    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
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
