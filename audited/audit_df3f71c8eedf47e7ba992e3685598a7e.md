### Title
Withdraw Fee Deduction After Slippage Check Breaks User Protection

### Summary
The `execute_withdraw()` function deducts withdrawal fees after performing the slippage protection check against `expected_amount`, causing users to receive less than their expected minimum amount. This breaks the fundamental slippage protection mechanism, as users consistently receive between 99.9% (default fee) to 95% (maximum fee) of their `expected_amount` despite the slippage check passing.

### Finding Description

The vulnerability exists in the withdrawal execution flow in `volo_vault.move`. When a user requests a withdrawal, they specify an `expected_amount` parameter as slippage protection: [1](#0-0) 

In `execute_withdraw()`, the flow is:

1. Calculate `amount_to_withdraw` based on shares and oracle price
2. Perform slippage check: `assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE)`
3. **Then deduct fees**: `fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING`
4. User receives: `amount_to_withdraw - fee_amount` [2](#0-1) 

The critical issue is that the slippage check at line 1029 validates the pre-fee amount, but users receive the post-fee amount shown in the event emission: [3](#0-2) 

The withdraw fee rate can be set up to 500 basis points (5%) with a default of 10 basis points (0.1%): [4](#0-3) [5](#0-4) 

In contrast, the deposit flow correctly handles fees by deducting them **before** the slippage check: [6](#0-5) 

### Impact Explanation

**Direct Fund Impact:**
- With default 10bp fee: Users receive 99.9% of `expected_amount` (0.1% less)
- With maximum 500bp fee: Users receive 95% of `expected_amount` (5% less)
- Affects every single withdrawal when fees > 0

**Concrete Example:**
- User requests withdrawal with `expected_amount = 1,000,000` tokens
- `amount_to_withdraw` calculated as 1,000,000
- Slippage check passes: `1,000,000 >= 1,000,000` ✓
- Fee deducted (at 10bp): `fee_amount = 1,000,000 * 10 / 10,000 = 100`
- User receives: `1,000,000 - 100 = 999,900` tokens
- **User expected minimum 1,000,000 but received 999,900**

**Who is Affected:**
All vault users performing withdrawals when fees are non-zero. The test suite masks this issue by setting fees to zero: [7](#0-6) 

### Likelihood Explanation

**Probability: 100% (Certain)**

This vulnerability triggers on every withdrawal execution in production:
- **Reachable Entry Point**: Users call `withdraw()` or `withdraw_with_auto_transfer()` through the public API
- **No Special Preconditions**: Only requires normal vault operation with non-zero fees (production default)
- **No Attack Complexity**: Natural user behavior, not an adversarial exploit
- **Economic Rationality**: N/A - users unknowingly lose funds on every withdrawal

The issue is not exploited maliciously but occurs as a design flaw affecting all legitimate users. Production vaults will have non-zero fees (default 10bp), making this guaranteed to impact users.

### Recommendation

**Fix 1: Calculate post-fee amount before slippage check**

Modify `execute_withdraw()` to calculate the post-fee amount first:

```move
// Calculate amount before fees
let amount_before_fee = vault_utils::div_with_oracle_price(...) as u64;

// Calculate fee
let fee_amount = amount_before_fee * self.withdraw_fee_rate / RATE_SCALING;
let amount_to_withdraw = amount_before_fee - fee_amount;

// Check slippage on POST-FEE amount
let expected_amount = withdraw_request.expected_amount();
assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

// Split the post-fee amount
let mut withdraw_balance = self.free_principal.split(amount_before_fee);
let fee_balance = withdraw_balance.split(fee_amount);
```

**Fix 2: Document that expected_amount should be pre-fee**

If the current behavior is intentional (slippage on pre-fee amount), clearly document this and update user interfaces to calculate `expected_amount` as pre-fee, so users set appropriate expectations.

**Required Test Cases:**
1. Test withdrawal with non-zero fees and verify user receives `>= expected_amount` after fees
2. Test with maximum fee (500bp) to ensure slippage protection holds
3. Add integration test that doesn't set fees to 0

### Proof of Concept

**Initial State:**
- Vault with 1,000,000 tokens
- User has 1,000,000 shares (1:1 ratio)
- Withdraw fee rate: 10bp (0.1%)
- Oracle price: $1 per token

**Transaction Steps:**

1. User calls `withdraw_with_auto_transfer()`:
   - `shares = 1,000,000`
   - `expected_amount = 1,000,000` (expecting minimum 1M tokens)

2. Operator calls `execute_withdraw()`:
   - `amount_to_withdraw` = 1,000,000 (calculated from shares)
   - Slippage check: `1,000,000 >= 1,000,000` ✓ PASSES
   - Fee calculation: `1,000,000 * 10 / 10,000 = 100`
   - User receives: `1,000,000 - 100 = 999,900`

**Expected Result:** User receives ≥ 1,000,000 tokens (their minimum expected amount)

**Actual Result:** User receives 999,900 tokens (100 tokens less than expected minimum)

**Success Condition:** Slippage protection is broken - user received less than `expected_amount` despite assertion passing.

### Citations

**File:** volo-vault/sources/requests/withdraw_request.move (L14-14)
```text
    expected_amount: u64, // Expected amount to get after withdraw
```

**File:** volo-vault/sources/volo_vault.move (L30-33)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L507-516)
```text
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

**File:** volo-vault/sources/volo_vault.move (L830-850)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1024-1042)
```text
    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

    // Decrease the share in vault and receipt
    self.total_shares = self.total_shares - shares_to_withdraw;

    // Split balances from the vault
    assert!(amount_to_withdraw <= self.free_principal.value(), ERR_NO_FREE_PRINCIPAL);
    let mut withdraw_balance = self.free_principal.split(amount_to_withdraw);

    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1044-1051)
```text
    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
    });
```

**File:** volo-vault/tests/init_vault.move (L54-60)
```text
        let mut vault = s.take_shared<Vault<PrincipalCoinType>>();
        vault.set_deposit_fee(0);
        vault.set_withdraw_fee(0);
        vault.set_locking_time_for_withdraw(12 * 3600 * 1_000);
        vault.set_locking_time_for_cancel_request(0);
        test_scenario::return_shared(vault);
    };
```
