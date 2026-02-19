### Title
Permanent Fund Lockup and DoS Due to Missing Recovery Mechanism for Stuck Operations

### Summary
The Volo Vault system lacks an expiration mechanism for deposit requests and provides no admin recovery path when the vault becomes stuck in `VAULT_DURING_OPERATION_STATUS`. When operations fail to complete (due to loss tolerance violations, asset return failures, or operator errors), all pending deposit requests become permanently locked—users cannot cancel them, operators cannot execute them, and user funds remain trapped in the `deposit_coin_buffer` indefinitely. This constitutes a critical DoS vulnerability with direct fund lockup impact.

### Finding Description

**Root Cause:**

The `DepositRequest` struct has no expiration timestamp or cleanup mechanism. [1](#0-0) 

Deposit requests are stored indefinitely in `Table<u64, DepositRequest>` within the vault's `RequestBuffer` until either executed or cancelled. [2](#0-1) 

**Vulnerability Path:**

1. Users create deposit requests via `request_deposit()`, which requires the vault to be in `VAULT_NORMAL_STATUS`. Their coins are buffered in `deposit_coin_buffer` and a request record is added to the table. [3](#0-2) 

2. When operators start an operation, `pre_vault_check()` transitions the vault to `VAULT_DURING_OPERATION_STATUS`. [4](#0-3) 

3. The operation must complete via `end_op_value_update_with_bag()`, which has multiple assertion requirements that can fail:
   - All borrowed assets must be returned [5](#0-4) 
   - Loss tolerance must not be exceeded [6](#0-5) 
   - Total shares must match [7](#0-6) 

4. The loss tolerance check calls `update_tolerance()` which aborts if `loss_limit >= cur_epoch_loss` fails. [8](#0-7) 

5. If any assertion fails, the vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`, with no recovery mechanism.

**Why Protections Fail:**

- `cancel_deposit()` requires the vault to NOT be in `VAULT_DURING_OPERATION_STATUS`, blocking user cancellations when stuck. [9](#0-8) 

- `execute_deposit()` requires the vault to be in `VAULT_NORMAL_STATUS`, blocking operator execution when stuck. [10](#0-9) 

- The admin's `set_enabled()` function explicitly blocks operation when the vault is in `VAULT_DURING_OPERATION_STATUS`, preventing admin recovery. [11](#0-10) 

- The only function that can restore `VAULT_NORMAL_STATUS` is `end_op_value_update_with_bag()`, which requires successful completion with no assertion failures. [12](#0-11) 

- The internal `set_status()` function is `public(package)` visibility only, not accessible to admin for emergency recovery. [13](#0-12) 

### Impact Explanation

**Direct Fund Impact:**
User funds deposited via `request_deposit()` are held in the `deposit_coin_buffer` table and become permanently inaccessible when the vault is stuck. Users cannot withdraw these funds because cancellation is blocked. This affects ALL users who have pending deposit requests at the time the vault becomes stuck.

**Custody Integrity Violation:**
The protocol violates the fundamental custody invariant that users can retrieve their deposited funds. Once a user submits a deposit request, their coins are transferred to the vault's buffer, but they lose the ability to cancel if the vault enters an unrecoverable stuck state.

**Operational Impact:**
The entire vault becomes non-functional:
- No new deposit requests can be created (requires NORMAL status)
- Existing deposit requests cannot be executed or cancelled
- Withdrawal operations are also affected as the vault cannot process any user requests
- The vault's total TVL is effectively frozen

**Severity:** CRITICAL - This represents complete loss of user funds and protocol functionality with no recovery mechanism.

### Likelihood Explanation

**High Likelihood - Multiple Realistic Failure Scenarios:**

1. **Market-Driven Loss Tolerance Violations:**
   - The vault operates with a configurable loss tolerance (default 0.1% per epoch)
   - During market volatility, external DeFi protocol losses, or oracle price updates, the calculated loss can exceed this tolerance
   - The `update_tolerance()` assertion will cause `end_op_value_update_with_bag()` to abort
   - This is NOT an exploit—it's a legitimate market condition

2. **Asset Return Failures:**
   - External protocols (Cetus, Navi, Suilend, Momentum) may experience issues preventing proper asset withdrawal
   - Smart contract bugs in integrated protocols could prevent asset returns
   - The strict assertions checking asset return will cause the end operation to fail

3. **Operator Operational Errors:**
   - Operators may lose access to keys/infrastructure
   - Bugs in operator scripts could prevent proper operation completion
   - No timeout mechanism exists to handle abandoned operations

**No Attack Required:**
This vulnerability does not require malicious action. Normal market conditions, external protocol issues, or operational errors can trigger it. The issue is the LACK OF RECOVERY MECHANISM, not the failure itself.

**Preconditions:**
- Vault in normal operation with pending deposit requests
- Operator initiates standard operation flow
- Any of the completion assertions fail (common in volatile markets)

**Detection:**
Once stuck, the condition is permanent and easily detectable on-chain, but irreversible.

### Recommendation

**1. Add Emergency Admin Recovery Function:**

Add a new admin-gated function that can force status reset:

```move
public fun emergency_reset_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Allow emergency reset from any status
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
    emit(EmergencyStatusReset { vault_id: vault.vault_id() });
}
```

**2. Add Request Expiration Mechanism:**

Modify `DepositRequest` to include expiration:
- Add `expiry_time: u64` field to the struct
- In `cancel_deposit()`, allow cancellation if either locking time passed OR request expired
- Add periodic cleanup function for expired requests

**3. Add Operation Timeout:**

Implement a maximum operation duration:
- Track `operation_start_time` when entering DURING_OPERATION_STATUS
- Allow admin to force-complete operations that exceed timeout (e.g., 1 hour)
- Automatically process timeout in `end_op_value_update_with_bag()`

**4. Implement Graceful Loss Handling:**

Instead of aborting on loss tolerance violations, implement graduated responses:
- Warning threshold: emit event but continue
- Soft limit: pause new operations but allow completion
- Hard limit: only then abort
- Admin can adjust tolerance mid-operation for emergency recovery

**5. Add Circuit Breaker:**

Implement emergency pause that:
- Allows users to cancel requests regardless of vault status
- Prevents new operations but allows current operation cleanup
- Can be triggered by admin when issues detected

### Proof of Concept

**Initial State:**
- Vault deployed and in NORMAL status with sufficient free principal
- User1 and User2 have submitted deposit requests (request_id 0 and 1)
- Their coins (e.g., 1000 SUI each) are in deposit_coin_buffer
- Current vault USD value: $10,000

**Execution Steps:**

1. Operator calls `start_op_with_bag()` with valid parameters
   - Vault transitions to VAULT_DURING_OPERATION_STATUS
   - Operation begins normally

2. Market conditions change or external protocol issue occurs
   - External DeFi position loses 2% value ($200 loss)
   - Vault's loss_tolerance is 0.1% ($10 limit)

3. Operator attempts to complete via `end_op_value_update_with_bag()`
   - Function calculates: `total_usd_value_after = $9,800`
   - Loss = $200
   - `update_tolerance()` called with loss = $200
   - Assertion fails: `loss_limit ($10) >= cur_epoch_loss ($200)` = FALSE
   - Transaction aborts with ERR_EXCEED_LOSS_LIMIT

4. System now in stuck state:
   - Vault remains in VAULT_DURING_OPERATION_STATUS
   - User1 attempts `cancel_deposit(request_id: 0)` → Fails with ERR_VAULT_DURING_OPERATION
   - User2 attempts `cancel_deposit(request_id: 1)` → Fails with ERR_VAULT_DURING_OPERATION
   - Operator attempts `execute_deposit(request_id: 0)` → Fails with ERR_VAULT_NOT_NORMAL
   - Admin attempts `set_vault_enabled(enabled: true)` → Fails with ERR_VAULT_DURING_OPERATION

**Expected Result:**
Users should be able to cancel their requests or admin should be able to recover vault state.

**Actual Result:**
- Both users' 1000 SUI deposits permanently locked in deposit_coin_buffer
- Vault permanently non-functional
- No recovery mechanism exists
- Total user funds at risk: 2000 SUI + any other pending requests

**Success Condition for Exploit:**
The "stuck" condition is achieved, demonstrating that normal protocol operations (user cancellations, operator executions, admin interventions) all fail, proving the permanent DoS and fund lockup.

### Citations

**File:** volo-vault/sources/requests/deposit_request.move (L5-17)
```text
public struct DepositRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Deposit Info ---- //
    amount: u64, // Amount (of principal) to deposit
    expected_shares: u256, // Expected shares to get after deposit
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** volo-vault/sources/volo_vault.move (L132-140)
```text
public struct RequestBuffer<phantom T> has store {
    // ---- Deposit Request ---- //
    deposit_id_count: u64,
    deposit_requests: Table<u64, DepositRequest>,
    deposit_coin_buffer: Table<u64, Coin<T>>,
    // ---- Withdraw Request ---- //
    withdraw_id_count: u64,
    withdraw_requests: Table<u64, WithdrawRequest>,
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

**File:** volo-vault/sources/volo_vault.move (L707-757)
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
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == NORMAL_STATUS, ERR_WRONG_RECEIPT_STATUS);

    // Generate current request id
    let current_deposit_id = self.request_buffer.deposit_id_count;
    self.request_buffer.deposit_id_count = current_deposit_id + 1;

    // Deposit amount
    let amount = coin.value();

    // Generate the new deposit request and add it to the vault storage
    let new_request = deposit_request::new(
        current_deposit_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        amount,
        expected_shares,
        clock.timestamp_ms(),
    );
    self.request_buffer.deposit_requests.add(current_deposit_id, new_request);

    emit(DepositRequested {
        request_id: current_deposit_id,
        receipt_id: receipt_id,
        recipient: recipient,
        vault_id: self.id.to_address(),
        amount: amount,
        expected_shares: expected_shares,
    });

    // Temporary buffer the coins from user
    // Operator will retrieve this coin and execute the deposit
    self.request_buffer.deposit_coin_buffer.add(current_deposit_id, coin);

    vault_receipt.update_after_request_deposit(amount);

    current_deposit_id
}
```

**File:** volo-vault/sources/volo_vault.move (L761-769)
```text
public(package) fun cancel_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    request_id: u64,
    receipt_id: address,
    recipient: address,
): Coin<PrincipalCoinType> {
    self.check_version();
    self.assert_not_during_operation();
```

**File:** volo-vault/sources/volo_vault.move (L806-816)
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

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);
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

**File:** volo-vault/sources/operation.move (L319-351)
```text
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
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/operation.move (L366-366)
```text
    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);
```

**File:** volo-vault/sources/operation.move (L375-377)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
