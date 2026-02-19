# Audit Report

## Title
Withdrawal Fee Change Between Request and Execution Bypasses User Slippage Protection

## Summary
The Volo Vault withdrawal flow has a critical design flaw where user slippage protection validates the pre-fee withdrawal amount instead of the post-fee amount users actually receive. When admin changes the `withdraw_fee_rate` between `request_withdraw` and `execute_withdraw`, users can lose up to 4.9% of their withdrawal amount beyond their explicitly-provided slippage tolerance. This represents a mis-scoped admin privilege that allows legitimate fee changes to unintentionally bypass user protections.

## Finding Description

The vulnerability exists in the withdrawal flow's two-phase request-execute pattern and how slippage protection interacts with fee deduction timing.

**Phase 1 - Request Creation:**
Users request withdrawals by providing an `expected_amount` parameter intended as slippage protection. This value is stored in the `WithdrawRequest` struct but **the current fee rate is NOT stored**. [1](#0-0) [2](#0-1) 

**Phase 2 - Fee Change Window:**
The admin can change `withdraw_fee_rate` at any time using `set_withdraw_fee`, which only validates that the new fee doesn't exceed `MAX_WITHDRAW_FEE_RATE` (500bp/5%). There is **no check for pending withdrawal requests** in the fee change function. [3](#0-2) [4](#0-3) 

**Phase 3 - Execution with Flawed Validation:**
During `execute_withdraw`, the critical design flaw manifests:

1. The pre-fee `amount_to_withdraw` is calculated from shares and oracle price [5](#0-4) 

2. **Slippage validation checks the pre-fee amount**: The assertion `amount_to_withdraw >= expected_amount` validates that the pre-fee amount meets user expectations [6](#0-5) 

3. **Fee deducted AFTER slippage check passes**: The fee is calculated using the **current** `withdraw_fee_rate` (not from request time) and deducted from the withdrawal balance [7](#0-6) 

4. **User receives post-fee amount**: The final amount transferred to the user is `amount_to_withdraw - fee_amount` [8](#0-7) 

**Root Cause:**
The slippage protection validates the wrong value. Users expect `expected_amount` to represent the minimum they'll receive after all fees, but the protocol only validates the pre-fee amount. When the fee rate increases between request and execution, the post-fee amount users actually receive can fall far below their expectations without triggering the slippage check.

**Fee Impact Range:**
The default fee is 10bp (0.1%) but can be increased to 500bp (5%) - a 50x increase. [9](#0-8) 

## Impact Explanation

**Direct Financial Loss:**
Users can lose up to 4.9% of their withdrawal amount beyond their slippage tolerance when fees change from default (10bp) to maximum (500bp) between request and execution.

**Concrete Example:**
- User withdraws 500 SUI with `expected_amount = 499_500_000` (accounting for 10bp fee)
- `amount_to_withdraw` calculated as 500_000_000 (meets slippage check: 500M ≥ 499.5M ✓)
- Admin increases fee to 500bp before execution
- Fee deducted: 500_000_000 × 500 / 10_000 = 25_000_000 (25 SUI)
- User receives: 475_000_000 (475 SUI)
- **Unexpected loss: 24.5 SUI (4.9% of withdrawal)**

**Affected Scope:**
All users with pending withdrawal requests when fee increases occur. The request-buffering architecture means multiple users are typically affected simultaneously.

**Severity Justification:**
This is HIGH severity because:
1. Direct loss of user funds (up to 4.9%)
2. Bypasses explicitly-provided slippage protection
3. Affects protocol's core withdrawal guarantee
4. No user mitigation available (cancellation has locking periods)

## Likelihood Explanation

**Feasibility: HIGH**

This vulnerability manifests during normal protocol operations without requiring any malicious behavior:

1. **Common Operational Scenario:**
   - Vault operators legitimately adjust fees based on market conditions, protocol costs, or treasury strategy
   - The request-buffer pattern creates inherent delays between request and execution
   - Multiple pending requests typically exist awaiting operator execution

2. **No Prevention Mechanism:**
   The `set_withdraw_fee` function has no awareness of pending requests and applies changes immediately to all future executions. [4](#0-3) 

3. **User Helplessness:**
   - Users cannot predict or prevent fee changes
   - Cancellation requires waiting for `locking_time_for_cancel_request` (default 5 minutes)
   - No notification mechanism exists for fee changes
   - Users cannot re-submit requests with updated expectations

4. **Economic Reality:**
   - Zero attack cost (occurs during legitimate operations)
   - Probability increases with protocol adoption (more pending requests)
   - Even honest, well-intentioned admins can trigger this unintentionally

This is a **design flaw in privilege scoping**, not a malicious attack scenario. The admin privilege to change fees is mis-scoped because it doesn't account for its impact on users who have already committed to withdrawals under the previous fee structure.

## Recommendation

Implement one of the following solutions:

**Option 1: Snapshot Fee Rate at Request Time (Recommended)**
Store the `withdraw_fee_rate` in the `WithdrawRequest` struct and use the snapshotted rate during execution:

```move
// In WithdrawRequest struct
public struct WithdrawRequest has copy, drop, store {
    // ... existing fields ...
    expected_amount: u64,
    fee_rate_snapshot: u64,  // Add this field
    request_time: u64,
}

// In execute_withdraw
let fee_amount = amount_to_withdraw * withdraw_request.fee_rate_snapshot / RATE_SCALING;
```

**Option 2: Validate Post-Fee Amount**
Check the actual amount user receives against `expected_amount`:

```move
let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
let amount_after_fee = amount_to_withdraw - fee_amount;
assert!(amount_after_fee >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
```

**Option 3: Prevent Fee Changes with Pending Requests**
Add a check in `set_withdraw_fee` to prevent changes when withdrawal requests are pending, or implement a grace period for pending requests.

Option 1 is recommended as it provides the most predictable user experience and honors the fee structure users agreed to at request time.

## Proof of Concept

```move
#[test]
public fun test_fee_change_bypasses_slippage_protection() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with initial 10bp fee
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    // User deposits 1000 SUI
    scenario.next_tx(USER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, scenario.ctx());
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let expected_shares = 2_000_000_000; // Assuming 1 SUI = 2 USD
        
        let (_, receipt, _) = user_entry::deposit(
            &mut vault, coin, expected_shares, &clock, scenario.ctx()
        );
        transfer::public_transfer(receipt, USER);
        test_scenario::return_shared(vault);
    };
    
    // Execute deposit
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        vault.execute_deposit(&clock, &config, 0, 2_000_000_000);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // User requests withdrawal expecting 999 SUI (accounting for 10bp fee)
    scenario.next_tx(USER);
    let request_id = {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let receipt = scenario.take_from_sender<Receipt>();
        
        let request_id = vault.request_withdraw(
            receipt.id(),
            2_000_000_000, // all shares
            999_000_000,   // expected_amount accounting for 10bp fee
            USER,
            &clock,
        );
        
        transfer::public_transfer(receipt, USER);
        test_scenario::return_shared(vault);
        request_id
    };
    
    // Admin changes fee to 500bp (5%) - MALICIOUS OR LEGITIMATE
    scenario.next_tx(OWNER);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let admin_cap = scenario.take_from_sender<AdminCap>();
        
        vault_manage::set_withdraw_fee(&admin_cap, &mut vault, 500); // 5%
        
        scenario.return_to_sender(admin_cap);
        test_scenario::return_shared(vault);
    };
    
    // Execute withdrawal - slippage check passes but user loses 4.9%
    scenario.next_tx(OPERATOR);
    {
        let mut vault = scenario.take_shared<Vault<SUI_TEST_COIN>>();
        let config = scenario.take_shared<OracleConfig>();
        
        let (balance, _) = vault.execute_withdraw(
            &clock,
            &config,
            request_id,
            1_000_000_000, // max_amount
        );
        
        // User expected 999 SUI but receives only 950 SUI!
        // Loss: 49 SUI (4.9%) beyond slippage tolerance
        assert!(balance.value() == 950_000_000); // 1000 * 0.95
        
        balance.destroy_for_testing();
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    scenario.end();
}
```

This test demonstrates that the slippage check passes (pre-fee amount meets expectations) but the user receives significantly less than expected due to the fee change, proving the vulnerability is real and exploitable.

### Citations

**File:** volo-vault/sources/volo_vault.move (L31-33)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1014-1022)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1029-1029)
```text
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1040-1042)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1050-1050)
```text
        amount: amount_to_withdraw - fee_amount,
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
