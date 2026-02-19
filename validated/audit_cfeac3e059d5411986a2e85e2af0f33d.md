# Audit Report

## Title
Withdraw Fee Rate Changes Between Request and Execution Allow Unexpected Fee Deduction Beyond User's Expected Amount

## Summary
The `expected_amount` slippage protection parameter in withdrawal requests validates the pre-fee withdrawal amount instead of the post-fee amount users actually receive. When admins change the `withdraw_fee_rate` between `request_withdraw()` and `execute_withdraw()`, users pay significantly higher fees than anticipated, with no protection mechanism to prevent this. Users can lose up to 4.9% of their withdrawal amount beyond their expectations.

## Finding Description

The vulnerability stems from a Time-Of-Check-Time-Of-Use (TOCTOU) flaw in the withdrawal flow where the slippage protection checks the wrong value.

**Request Creation:** When users create withdrawal requests via `user_entry::withdraw()`, they specify an `expected_amount` parameter intended to protect against slippage [1](#0-0) . This value is stored in the WithdrawRequest struct [2](#0-1)  but the current `withdraw_fee_rate` is NOT locked or stored with the request [3](#0-2) .

**Fee Rate Changes:** Admins can change the `withdraw_fee_rate` at any time using `vault_manage::set_withdraw_fee()` [4](#0-3) , which updates the vault's fee rate with no checks on pending requests [5](#0-4) . The fee can be increased up to MAX_WITHDRAW_FEE_RATE of 500 basis points (5%) [6](#0-5) .

**Broken Slippage Protection:** During execution, the critical flaw occurs in the order of operations. The `expected_amount` is validated against `amount_to_withdraw` (the gross amount before fee deduction) [7](#0-6) . Only AFTER this check passes does the protocol calculate and deduct fees using the CURRENT `withdraw_fee_rate` [8](#0-7) .

This breaks the security guarantee that `expected_amount` protects users' net receipt. Users calculate `expected_amount` based on the fee rate at request time, but receive an amount based on the fee rate at execution time, with no validation of the post-fee amount.

## Impact Explanation

**Direct Financial Loss:** Users suffer unexpected loss of funds when fee rates increase between request creation and execution. The worst-case scenario involves:

- User creates request when `withdraw_fee_rate = 10` (0.1%)  
- User sets `expected_amount` expecting to receive 99.9% of withdrawal value
- Admin increases `withdraw_fee_rate` to `500` (5% maximum)
- During execution, slippage check passes (gross amount ≥ expected_amount)
- User receives only 95% instead of expected 99.9%
- **Unexpected loss: 4.9% of withdrawal amount**

**Quantified Example:**
For a 10,000 USDC withdrawal:
- Expected to receive: 9,990 USDC (0.1% fee)
- Actually receives: 9,500 USDC (5% fee)  
- Unexpected loss: **490 USDC**

**System-Wide Impact:** All users with pending withdrawal requests are vulnerable whenever admin fee adjustments occur. This fundamentally breaks the user expectation that the `expected_amount` parameter provides slippage protection for their net receipt.

## Likelihood Explanation

**High Probability of Occurrence:**

The vulnerability manifests through normal protocol operations without requiring any exploitation:

1. Users create withdrawal requests (routine user action)
2. Requests remain in the buffer awaiting execution (common during operational cycles)
3. Admin adjusts fees for legitimate protocol management reasons (expected governance action)
4. Operator executes pending requests using the updated fee rate (standard operation)

**No Special Preconditions Required:**
- Fee adjustments are normal governance actions for protocol sustainability
- Withdrawal requests commonly pending during market volatility or operational processing delays  
- No time restrictions prevent fee changes from affecting pending requests
- Users have no visibility into fee rate changes before their request executes
- No warning or protection mechanism exists

This is not an attack scenario but a design flaw in the slippage protection mechanism that occurs during routine protocol operations.

## Recommendation

**Lock Fee Rate at Request Time:**

Modify the WithdrawRequest struct to store the fee rate at request creation:

```move
public struct WithdrawRequest has copy, drop, store {
    // ... existing fields ...
    locked_fee_rate: u64, // Fee rate locked at request time
}
```

Update `request_withdraw()` to store the current fee rate:

```move
let new_request = withdraw_request::new(
    current_request_id,
    receipt_id,
    recipient,
    self.id.to_address(),
    shares,
    expected_amount,
    clock.timestamp_ms(),
    self.withdraw_fee_rate, // Lock current fee rate
);
```

Update `execute_withdraw()` to use the locked fee rate:

```move
// Use locked fee rate from request instead of current vault rate
let fee_amount = amount_to_withdraw * withdraw_request.locked_fee_rate() / RATE_SCALING;
```

**Alternative Solution:**

Validate the post-fee amount against expected_amount:

```move
// Calculate fee first
let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
let net_amount = amount_to_withdraw - fee_amount;

// Check slippage on NET amount user receives
assert!(net_amount >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
```

## Proof of Concept

```move
#[test]
public fun test_fee_rate_change_causes_unexpected_loss() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with 0.1% fee
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    // User deposits and gets shares
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        user_entry::deposit(&mut vault, &mut reward_manager, coin, 1_000_000_000, 
                           2_000_000_000, option::none(), &clock, s.ctx());
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Execute deposit
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault.execute_deposit(&clock, &config, 0, 2_000_000_000);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // User requests withdraw expecting 999_000_000 (0.1% fee)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut receipt = s.take_from_sender<Receipt>();
        clock::set_for_testing(&mut clock, 1000 + 12 * 3600_000);
        
        // User expects to receive 999_000_000 after 0.1% fee
        user_entry::withdraw(&mut vault, 2_000_000_000, 999_000_000, 
                            &mut receipt, &clock, s.ctx());
        test_scenario::return_shared(vault);
        s.return_to_sender(receipt);
    };
    
    // Admin increases fee to 5% (500 basis points)
    s.next_tx(OWNER);
    {
        let admin_cap = s.take_from_sender<AdminCap>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        vault_manage::set_withdraw_fee(&admin_cap, &mut vault, 500); // 5%
        test_scenario::return_shared(vault);
        s.return_to_sender(admin_cap);
    };
    
    // Execute withdraw - slippage check passes but user gets much less
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        
        let (withdraw_balance, _) = vault.execute_withdraw(&clock, &config, 0, 1_100_000_000);
        
        // User receives only 950_000_000 (5% fee) instead of expected 999_000_000 (0.1% fee)
        // Unexpected loss: 49_000_000 (4.9%)
        assert!(withdraw_balance.value() == 950_000_000); // Proves the vulnerability
        
        transfer::public_transfer(withdraw_balance.into_coin(s.ctx()), OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability represents a fundamental design flaw in how slippage protection interacts with mutable protocol parameters. While the admin's ability to change fees is an expected and necessary governance function, the implementation fails to protect users who have already committed to withdrawals based on the original fee structure.

The key insight is that `expected_amount` was intended as user protection against adverse conditions (like price slippage), but because it validates the pre-fee amount rather than the post-fee amount, it provides no protection against fee rate changes. This is a mis-scoped privilege issue where the admin's fee adjustment authority retroactively affects users who already made informed decisions.

The vulnerability requires no malicious intent and occurs through normal protocol operations, making it a high-likelihood scenario that should be addressed to maintain user trust and protocol fairness.

### Citations

**File:** volo-vault/sources/user_entry.move (L124-148)
```text
public fun withdraw<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    shares: u256,
    expected_amount: u64,
    receipt: &mut Receipt,
    clock: &Clock,
    _ctx: &mut TxContext,
): u64 {
    vault.assert_vault_receipt_matched(receipt);
    assert!(
        vault.check_locking_time_for_withdraw(receipt.receipt_id(), clock),
        ERR_WITHDRAW_LOCKED,
    );
    assert!(shares > 0, ERR_INVALID_AMOUNT);

    let request_id = vault.request_withdraw(
        clock,
        receipt.receipt_id(),
        shares,
        expected_amount,
        address::from_u256(0),
    );

    request_id
}
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

**File:** volo-vault/sources/volo_vault.move (L27-33)
```text
// For rates, 1 = 10_000, 1bp = 1
const RATE_SCALING: u64 = 10_000;

const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

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

**File:** volo-vault/sources/volo_vault.move (L917-926)
```text
    let new_request = withdraw_request::new(
        current_request_id,
        receipt_id,
        recipient,
        self.id.to_address(),
        shares,
        expected_amount,
        clock.timestamp_ms(),
    );
    self.request_buffer.withdraw_requests.add(current_request_id, new_request);
```

**File:** volo-vault/sources/volo_vault.move (L1024-1030)
```text
    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1039-1042)
```text
    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
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
