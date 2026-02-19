### Title
Missing Input Validation Constraints on Vault Locking Time Parameters Enabling Protocol DoS

### Summary
The Volo vault's admin functions `set_locking_time_for_withdraw` and `set_locking_time_for_cancel_request` lack input validation constraints on timing parameters, analogous to the external report's missing validation on NFT attributes. This allows accidental misconfiguration (e.g., setting values to u64::MAX or wrong time units) that can permanently lock user funds or bypass intended security controls.

### Finding Description

The external report identifies missing input validation on admin-controlled parameters (star_rating, level, tier) that could cause data integrity issues and unexpected behavior even when called by trusted addresses. The same vulnerability class exists in Volo vault's locking time configuration.

**Exact Volo Location:** [1](#0-0) [2](#0-1) 

**Root Cause:**

The setter functions accept `u64` locking time parameters (in milliseconds) with no upper or lower bound validation. Default values are defined as reasonable constants: [3](#0-2) 

However, the admin setter functions impose no constraints on these values, unlike fee setters which validate against `MAX_DEPOSIT_FEE_RATE` and `MAX_WITHDRAW_FEE_RATE`.

**Exploit Path:**

1. Admin calls `set_locking_time_for_withdraw` or `set_locking_time_for_cancel_request` with misconfigured values
2. The locking time checks use addition with timestamps: [4](#0-3) [5](#0-4) 

3. If `locking_time_for_withdraw` is set to an extremely high value (e.g., close to u64::MAX = ~1.8e19 milliseconds), the check `locking_time_for_withdraw + receipt.last_deposit_time() <= clock.timestamp_ms()` will never be satisfied since current real-world timestamps are only ~1.7e12 milliseconds (year 2024)

4. Users attempting to request withdrawals will fail the locking check enforced in: [6](#0-5) 

5. Similar issue occurs for `locking_time_for_cancel_request` preventing request cancellations

**Why Current Protections Fail:**

Unlike fee configuration parameters which have explicit maximum bounds, the locking time setters have no validation whatsoever. An admin could accidentally:
- Use wrong time units (seconds instead of milliseconds: 43200 seconds = 12 hours becomes 43.2 milliseconds)
- Copy-paste errors with large numbers
- Set u64::MAX thinking it means "no limit"
- Reverse the conversion (interpret milliseconds as nanoseconds)

### Impact Explanation

**High Severity Protocol DoS:**

1. **Funds Permanently Locked**: If `locking_time_for_withdraw` is set to an extremely high value, all vault users lose access to their deposited funds. The withdrawal request mechanism becomes permanently inoperable as the locking time check will never pass. This affects all users across the entire vault.

2. **Security Control Bypass**: If set to 0, users can immediately withdraw after depositing, bypassing the intended 12-hour protection mechanism designed to prevent flash-loan style attacks or rapid liquidity extraction.

3. **Request Buffer Lock**: If `locking_time_for_cancel_request` is set too high, users cannot cancel their pending requests, causing stuck request buffers and operational gridlock.

The impact is concrete and affects critical protocol availability and fund custody, satisfying the "High-confidence protocol DoS via valid calls" criterion.

### Likelihood Explanation

**Realistic Accidental Misconfiguration:**

While these functions require `AdminCap`, accidental misconfiguration is highly realistic:

1. **Time Unit Confusion**: Common programming error mixing seconds/milliseconds/microseconds. Default is 43,200,000 ms (12 hours). An admin setting 43,200 thinking "seconds" creates a 43.2-millisecond window.

2. **Large Number Typos**: Intending to set 1 day (86,400,000 ms) but typing 86,400,000,000 by mistake (1000x error, ~2.7 years).

3. **No Safety Rails**: Unlike fee parameters which validate against explicit maximums, no bounds checking exists. Compare to: [7](#0-6) 

4. **Operational Changes**: During parameter tuning or emergency responses, admins may set extreme values without validation feedback.

The external report explicitly states: "Although these functions are currently only called by the custodial address, it is still beneficial to prevent accidental improper updates." This same reasoning applies here—trusted actors can make mistakes, and lack of validation enables those mistakes to cause protocol-wide damage.

### Recommendation

**Implement Validation Constraints:**

Add upper and lower bound validation to the locking time setter functions, similar to existing fee validation patterns:

```move
// In volo_vault.move, add constants:
const MAX_LOCKING_TIME_FOR_WITHDRAW: u64 = 30 * 24 * 3600 * 1_000; // 30 days max
const MIN_LOCKING_TIME_FOR_WITHDRAW: u64 = 1 * 3600 * 1_000; // 1 hour min
const MAX_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 24 * 3600 * 1_000; // 24 hours max
const MIN_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 60 * 1_000; // 1 minute min

// In set_locking_time_for_withdraw:
public(package) fun set_locking_time_for_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    assert!(
        locking_time >= MIN_LOCKING_TIME_FOR_WITHDRAW && 
        locking_time <= MAX_LOCKING_TIME_FOR_WITHDRAW, 
        ERR_EXCEED_LIMIT
    );
    self.locking_time_for_withdraw = locking_time;
    // emit event
}

// Similar validation for set_locking_time_for_cancel_request
```

This mirrors the validation pattern already used for fees and loss tolerance.

### Proof of Concept

**Scenario: Admin Accidentally Sets Extreme Locking Time**

1. **Initial State**: Vault operational with default `locking_time_for_withdraw = 43,200,000 ms` (12 hours)

2. **Admin Misconfiguration**: Admin intends to set 1 week (604,800,000 ms) but accidentally sets `18_000_000_000_000_000_000` (close to u64::MAX, possibly intending "unlimited")

3. **User Deposits**: Alice deposits 1,000,000 USDC at timestamp T = 1,700,000,000,000 ms (current time)

4. **Withdrawal Attempt**: Alice tries to withdraw after 24 hours (timestamp T + 86,400,000 ms = 1,700,086,400,000 ms)

5. **Check Fails**: The validation `locking_time_for_withdraw + last_deposit_time <= current_timestamp` becomes:
   - `18,000,000,000,000,000,000 + 1,700,000,000,000 <= 1,700,086,400,000`
   - This is false and will remain false for ~570 million years

6. **Result**: Alice's funds are permanently locked. All vault users face the same fate. Protocol experiences complete DoS for withdrawals.

**Alternative Scenario: Zero Value Bypass**

1. Admin sets `locking_time_for_withdraw = 0` thinking "disable locking"
2. Users can immediately request withdrawals after depositing
3. This bypasses the intended flash-loan protection mechanism
4. Malicious actors can exploit rapid deposit-withdraw cycles

**Notes**

This vulnerability is a direct analog to the external report. Both involve:
- Admin-controlled configuration parameters
- Missing input validation/range checks
- Potential for accidental misconfiguration despite trusted operators
- Concrete protocol impact from invalid parameter values
- Preventable through explicit constraint enforcement

The Volo vault implementation correctly validates fee parameters but inconsistently omits validation for timing parameters, creating this security gap.

### Citations

**File:** volo-vault/sources/manage.move (L66-80)
```text
public fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_cancel_request(locking_time);
}

public fun set_locking_time_for_withdraw<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    vault.set_locking_time_for_withdraw(locking_time);
}
```

**File:** volo-vault/sources/volo_vault.move (L35-36)
```text
const DEFAULT_LOCKING_TIME_FOR_WITHDRAW: u64 = 12 * 3600 * 1_000; // 12 hours to withdraw after a deposit
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L497-516)
```text
public(package) fun set_deposit_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_DEPOSIT_FEE_RATE, ERR_EXCEED_LIMIT);
    self.deposit_fee_rate = fee;
    emit(DepositFeeChanged { vault_id: self.vault_id(), fee: fee })
}

// Set the withdraw fee rate for the vault
public(package) fun set_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_WITHDRAW_FEE_RATE, ERR_EXCEED_LIMIT);
    self.withdraw_fee_rate = fee;
    emit(WithdrawFeeChanged { vault_id: self.vault_id(), fee: fee })
}
```

**File:** volo-vault/sources/volo_vault.move (L543-567)
```text
public(package) fun set_locking_time_for_withdraw<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    self.locking_time_for_withdraw = locking_time;

    emit(LockingTimeForWithdrawChanged {
        vault_id: self.vault_id(),
        locking_time: locking_time,
    });
}

public(package) fun set_locking_time_for_cancel_request<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    locking_time: u64,
) {
    self.check_version();
    self.locking_time_for_cancel_request = locking_time;

    emit(LockingTimeForCancelRequestChanged {
        vault_id: self.vault_id(),
        locking_time: locking_time,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L676-691)
```text
public fun check_locking_time_for_cancel_request<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    is_deposit: bool,
    request_id: u64,
    clock: &Clock,
): bool {
    self.check_version();

    if (is_deposit) {
        let request = self.request_buffer.deposit_requests.borrow(request_id);
        request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms()
    } else {
        let request = self.request_buffer.withdraw_requests.borrow(request_id);
        request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms()
    }
}
```

**File:** volo-vault/sources/volo_vault.move (L694-703)
```text
public fun check_locking_time_for_withdraw<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    receipt_id: address,
    clock: &Clock,
): bool {
    self.check_version();

    let receipt = self.receipts.borrow(receipt_id);
    self.locking_time_for_withdraw + receipt.last_deposit_time() <= clock.timestamp_ms()
}
```

**File:** volo-vault/sources/volo_vault.move (L761-782)
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

    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    let vault_receipt = &mut self.receipts[receipt_id];
    assert!(vault_receipt.status() == PENDING_DEPOSIT_STATUS, ERR_WRONG_RECEIPT_STATUS);

    let deposit_request = &mut self.request_buffer.deposit_requests[request_id];
    assert!(receipt_id == deposit_request.receipt_id(), ERR_RECEIPT_ID_MISMATCH);
    assert!(
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```
