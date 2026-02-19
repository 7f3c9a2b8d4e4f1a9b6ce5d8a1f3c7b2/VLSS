### Title
Loss Tolerance Rounding Down Causes Permanent Vault Operation Deadlock

### Summary
The Volo vault's loss tolerance calculation uses integer division that rounds down, creating an analog to the external rounding vulnerability. When a vault has a small USD value (< 10,000 base units), any operational loss causes the `update_tolerance` check to fail, permanently locking the vault in `VAULT_DURING_OPERATION_STATUS` and blocking all user deposits and withdrawals.

### Finding Description

The external vulnerability involves sequential rounding operations that prevent a pool from reaching a terminal state. The same vulnerability class exists in Volo's vault operation completion flow.

**Root Cause Location:** [1](#0-0) 

The `update_tolerance` function calculates the maximum allowed loss with integer division that rounds down: [2](#0-1) 

When `cur_epoch_loss_base_usd_value * loss_tolerance < RATE_SCALING`, the loss limit rounds to zero.

**Exploit Path:**

1. At epoch start, the vault's base USD value is captured: [3](#0-2) 

2. Operator initiates operation, transitioning vault to `VAULT_DURING_OPERATION_STATUS`: [4](#0-3) 

3. During operation execution, minimal loss occurs (even 1 base unit from rounding, fees, or market fluctuations)

4. Operator attempts to complete operation via `end_op_value_update_with_bag`: [5](#0-4) 

5. The function calculates loss and calls `update_tolerance`: [6](#0-5) 

6. With `RATE_SCALING = 10_000` and default `loss_tolerance = 10`: [7](#0-6) 

If `cur_epoch_loss_base_usd_value = 999`, then `loss_limit = 999 * 10 / 10_000 = 0` (rounds down).

7. The assertion `loss_limit >= self.cur_epoch_loss` fails when any loss occurs, aborting with `ERR_EXCEED_LOSS_LIMIT`

8. The vault never reaches the status reset at line 375 of operation.move, remaining permanently stuck in `VAULT_DURING_OPERATION_STATUS`

9. All user operations fail because they require `VAULT_NORMAL_STATUS`: [8](#0-7) 

### Impact Explanation

**Critical Protocol Denial of Service:**

- Vault becomes permanently locked in operation status
- All user deposits and withdrawals are blocked (require `assert_normal()` checks)
- Funds remain trapped until admin intervention via vault disabling
- No attacker profit motive needed - occurs through normal operations
- Affects entire vault, not just single user

**Severity Justification:**
- Complete loss of vault availability
- User funds inaccessible indefinitely  
- Breaks core protocol invariant: operations must be completable
- No automatic recovery mechanism exists

### Likelihood Explanation

**High Likelihood - Multiple Realistic Scenarios:**

1. **Small Vault Balances:** For 9-decimal coins (SUI), 10,000 base units = 0.00001 SUI ≈ $0.00002. For 6-decimal coins (USDC), 10,000 base units = $0.01. Vaults naturally reach these levels during:
   - Initial deployment/testing phases
   - After large withdrawals leave dust
   - Vault wind-down operations
   - Normal operational variance

2. **Sequential Withdrawal Rounding:** The withdrawal flow has multiple rounding operations that can gradually reduce vault balance to dust: [9](#0-8) 

3. **DeFi Operation Losses:** Any DeFi strategy operation naturally incurs:
   - Protocol fees (rounded)
   - Slippage (rounded)  
   - Interest rate fluctuations (rounded)
   - Oracle price updates between operation start/end

4. **No Privileged Access Required:** Any operator performing normal duties can trigger this through standard operation flows

5. **No Prior Warning:** The rounding-to-zero occurs silently in the calculation step with no validation

### Recommendation

**Implement Rounding Protection in Loss Tolerance Calculation:**

Modify the `update_tolerance` function to use ceiling division or add a minimum threshold:

```move
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();
    
    self.cur_epoch_loss = self.cur_epoch_loss + loss;
    
    // Use ceiling division to prevent rounding to zero
    let numerator = self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256);
    let loss_limit = (numerator + (RATE_SCALING as u256) - 1) / (RATE_SCALING as u256);
    
    // Alternative: enforce minimum loss limit
    // let loss_limit = max(calculated_limit, 1);
    
    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**Additional Safeguards:**

1. Add minimum vault value check before allowing operations
2. Implement emergency admin function to force status reset with justification
3. Add pre-operation validation that `loss_limit > 0` when base value is small

### Proof of Concept

**Step-by-Step Exploit:**

1. **Initial State:**
   - Vault has `total_usd_value = 999` base units (< 10,000 threshold)
   - Oracle price = 1 * ORACLE_DECIMALS
   - Default `loss_tolerance = 10` (0.1%)
   - `RATE_SCALING = 10_000`

2. **Epoch Initialization:**
   - `try_reset_tolerance` sets `cur_epoch_loss_base_usd_value = 999`
   - `cur_epoch_loss = 0`

3. **Operator Starts Operation:**
   - Calls operation flow triggering `pre_vault_check`
   - Vault status changes: `VAULT_NORMAL_STATUS → VAULT_DURING_OPERATION_STATUS`

4. **Minimal Loss Occurs:**
   - DeFi operation incurs 1 base unit loss (fees, rounding, slippage)
   - `total_usd_value_after = 998`

5. **Operator Attempts Completion:**
   - Calls `end_op_value_update_with_bag`
   - Calculates: `loss = 999 - 998 = 1`
   - Invokes `update_tolerance(1)`

6. **Rounding Failure:**
   - `loss_limit = 999 * 10 / 10_000 = 9990 / 10_000 = 0` (integer division rounds down)
   - Assertion check: `assert!(0 >= 1)` → **FAILS**
   - Transaction aborts with `ERR_EXCEED_LOSS_LIMIT`

7. **Permanent Lock State:**
   - Vault remains in `VAULT_DURING_OPERATION_STATUS`
   - Status never resets to `VAULT_NORMAL_STATUS`
   - All user deposits call `assert_normal()` → fail
   - All user withdrawals call `assert_normal()` → fail
   - Vault funds inaccessible until admin manually disables vault

**Realistic Trigger Conditions:**
- Occurs naturally when vault balances drop below 10,000 base units through normal withdrawals
- Any operational loss (even 1 wei) triggers the deadlock
- No attacker intervention required
- Affects production vaults during low-liquidity periods or wind-down phases

### Citations

**File:** volo-vault/sources/volo_vault.move (L27-38)
```text
// For rates, 1 = 10_000, 1bp = 1
const RATE_SCALING: u64 = 10_000;

const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)

const DEFAULT_LOCKING_TIME_FOR_WITHDRAW: u64 = 12 * 3600 * 1_000; // 12 hours to withdraw after a deposit
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request

const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L1013-1023)
```text
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

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
