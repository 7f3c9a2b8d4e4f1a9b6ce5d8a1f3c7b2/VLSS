### Title
Withdrawal Fee Front-Running Attack via Pre-Fee Slippage Check

### Summary
The vault's withdrawal execution applies the slippage protection check (`expected_amount`) against the pre-fee withdrawal amount, but the withdrawal fee is deducted afterward. This allows admins to front-run withdrawal executions by increasing the `withdraw_fee_rate` from 0.1% to the maximum 5%, extracting up to 4.9% more funds than users expected without triggering the slippage check.

### Finding Description

The vulnerability exists in the `execute_withdraw` function flow where the slippage protection is applied before fee deduction: [1](#0-0) 

**Root Cause:**
Lines 1014-1022 calculate `amount_to_withdraw` based on shares and current oracle prices (before any fee). Line 1029 validates this pre-fee amount against `expected_amount` from the user's request. Only after this check passes do lines 1040-1042 calculate and deduct the withdrawal fee using the current `withdraw_fee_rate`. [2](#0-1) 

The `WithdrawRequest` struct stores only `expected_amount`, not the expected fee rate, meaning there's no record of what fee the user anticipated when creating the request.

**Why Existing Protections Fail:**
The admin can change the fee rate at any time via: [3](#0-2) [4](#0-3) 

The fee change is capped at 500 bps (5%) but can occur between user request and operator execution. Since the slippage check compares against the pre-fee amount, increasing the fee from the default 10 bps to 500 bps doesn't cause the transaction to revert.

**Contrast with Deposit Protection (Works Correctly):**
For deposits, the fee is deducted before share calculation and the slippage check: [5](#0-4) 

Here, the fee is split off at line 835, shares are calculated from the post-fee USD value at line 844, and the check at line 849 validates shares after fee deduction. This correctly protects users.

### Impact Explanation

**Direct Fund Impact:**
- Users lose up to 4.9% of their withdrawal amount (difference between 0.1% default fee and 5% maximum fee)
- For a 1000 SUI withdrawal: user expects ~999 SUI but receives only 950 SUI, losing 49 SUI (~$98 USD at $2/SUI)
- This scales linearly with withdrawal size—large withdrawals suffer proportionally larger losses

**Who is Affected:**
All users with pending withdrawal requests are vulnerable. The attack is most profitable against large withdrawals.

**Severity Justification:**
HIGH severity because:
1. Direct theft of user funds (up to 4.9% of withdrawal)
2. No technical barriers to execution
3. Affects core vault functionality
4. Users have no way to protect themselves once request is submitted

### Likelihood Explanation

**Attacker Capabilities:**
Requires only AdminCap, which is a trusted role. However, this vulnerability enables the admin to extract unexpected value from users silently, representing a trust boundary violation even for privileged roles.

**Attack Complexity:**
Trivial execution path:
1. Monitor pending withdrawal requests in `vault.request_buffer.withdraw_requests`
2. Call `vault_manage::set_withdraw_fee(&AdminCap, &mut vault, 500)` before operator execution
3. Operator executes withdrawal as normal
4. Admin retrieves collected fees via `vault_manage::retrieve_deposit_withdraw_fee`

**Feasibility Conditions:**
- Requires admin control (trusted role compromise or malicious admin)
- No oracle manipulation or external dependencies needed
- Works on any pending withdrawal request
- Execution completes in single transaction

**Economic Rationality:**
Profitable for any withdrawal above transaction costs. For a 10,000 SUI withdrawal, admin extracts 490 SUI with zero technical cost.

**Detection/Operational Constraints:**
Fee changes emit `WithdrawFeeChanged` event but users cannot react after submitting requests. No technical detection prevents the attack.

### Recommendation

**Code-Level Mitigation:**
Modify the withdrawal execution to either:

**Option 1 (Preferred):** Apply slippage check to post-fee amount
```
// After line 1042 (after fee deduction), add:
let actual_amount_received = withdraw_balance.value();
assert!(actual_amount_received >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
```

**Option 2:** Store the fee rate in WithdrawRequest and validate it hasn't increased:
```
// In withdraw_request.move, add field:
expected_fee_rate: u64

// In execute_withdraw, before line 1040, add:
assert!(self.withdraw_fee_rate <= withdraw_request.expected_fee_rate(), ERR_FEE_INCREASED);
```

**Invariant Checks to Add:**
- Add test cases verifying that fee increases between request and execution cause withdrawal to fail or receive expected amount
- Document that `expected_amount` should represent post-fee expectations

**Test Cases:**
```
test_withdraw_fee_increase_attack() {
    // 1. User requests withdrawal with expected_amount assuming 0.1% fee
    // 2. Admin increases fee to 5%
    // 3. Execute withdrawal
    // 4. Assert transaction reverts OR user receives >= expected_amount
}
```

### Proof of Concept

**Initial State:**
- User has 1000 shares in vault
- Share ratio: 1 share = 1 USD
- SUI price: 2 USD/SUI
- Current `withdraw_fee_rate`: 10 bps (0.1%)

**Transaction Sequence:**

**Tx 1 - User requests withdrawal:**
```
user_entry::withdraw(
    vault,
    shares: 1_000_000_000,
    expected_amount: 499_000_000, // User expects 499.5 SUI after 0.1% fee
    receipt,
    clock,
    ctx
)
```
Request stored with `expected_amount = 499_000_000 SUI`

**Tx 2 - Admin front-runs execution:**
```
vault_manage::set_withdraw_fee(
    admin_cap,
    vault,
    500 // Increase to 5% (maximum)
)
```

**Tx 3 - Operator executes withdrawal:**
```
operation::execute_withdraw(
    operation,
    operator_cap,
    vault,
    reward_manager,
    clock,
    config,
    request_id: 0,
    max_amount_received: 500_000_000,
    ctx
)
```

**Expected Result:** User receives ~499.5 SUI (after 0.1% fee)

**Actual Result:**
- Line 1014-1022: `amount_to_withdraw = 500_000_000 SUI` (pre-fee)
- Line 1029: Check `500_000_000 >= 499_000_000` ✅ PASSES
- Line 1040: `fee_amount = 500_000_000 * 500 / 10000 = 25_000_000 SUI` (5% fee)
- User receives: `500_000_000 - 25_000_000 = 475_000_000 SUI`

**Success Condition:** 
User receives only 475 SUI instead of expected 499.5 SUI, losing 24.5 SUI (4.9% of withdrawal). Admin successfully extracted 24 SUI more than user anticipated.

### Citations

**File:** volo-vault/sources/volo_vault.move (L508-516)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1012-1042)
```text
    let shares_to_withdraw = withdraw_request.shares();
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

**File:** volo-vault/sources/requests/withdraw_request.move (L5-17)
```text
public struct WithdrawRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Withdraw Info ---- //
    shares: u256, // Shares to withdraw
    expected_amount: u64, // Expected amount to get after withdraw
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** volo-vault/sources/manage.move (L50-56)
```text
public fun set_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    withdraw_fee: u64,
) {
    vault.set_withdraw_fee(withdraw_fee);
}
```
