### Title
Arithmetic Overflow in Deposit/Withdraw Fee Calculation Blocks Large Transactions

### Summary
The vault's deposit and withdraw fee calculations use unsafe u64 arithmetic that overflows for large transaction amounts, causing legitimate large deposits and withdrawals to fail. Despite the fee rate being capped at 5% (MAX_DEPOSIT_FEE_RATE = 500), deposits exceeding approximately 36.89 million SUI will trigger arithmetic overflow and abort. This creates a practical ceiling on transaction sizes that prevents institutional-scale usage of the protocol.

### Finding Description

The `set_deposit_fee()` function correctly validates that the fee rate does not exceed MAX_DEPOSIT_FEE_RATE: [1](#0-0) 

However, the fee calculation in `execute_deposit()` uses unsafe u64 arithmetic: [2](#0-1) 

The multiplication `coin_amount * self.deposit_fee_rate` occurs before division by RATE_SCALING. Since all values are u64 type, this multiplication can overflow when:
- coin_amount > u64::MAX / deposit_fee_rate
- With maximum fee (500): coin_amount > 36,893,488,147,419,103 base units (≈36.89 million SUI)

The `coin_amount` is a u64 value obtained from the deposit request: [3](#0-2) 

The identical vulnerability exists in `execute_withdraw()` for withdrawal fee calculations: [4](#0-3) 

In contrast, the liquid staking module correctly uses u128 widening to prevent overflow: [5](#0-4) 

When overflow occurs, the Move VM aborts the transaction, preventing the deposit or withdrawal from completing.

### Impact Explanation

**Operational Denial of Service:**
- Deposits exceeding ~36.89 million SUI (with 5% fee) cannot be processed
- Withdrawals of similar magnitude are similarly blocked
- Lower fee rates increase the threshold proportionally (e.g., 184.47 million SUI at 1% fee)

**Who is Affected:**
- Institutional investors attempting large deposits
- Whale users with significant holdings
- Protocol scalability for high-value operations

**Severity Justification:**
Given that major DeFi protocols regularly handle deposits in the tens or hundreds of millions USD, and that 36.89 million SUI represents approximately 0.369% of the 10 billion SUI total supply, this threshold is realistically reachable. The vulnerability blocks core protocol functionality (deposits/withdrawals) for legitimate large-scale users without any fund theft or loss—purely operational disruption.

### Likelihood Explanation

**Reachability:**
The vulnerable code path is reached through normal deposit/withdrawal flows accessible to any user via `execute_deposit()` and `execute_withdraw()`.

**Preconditions:**
- User attempts to deposit or withdraw an amount exceeding the overflow threshold
- No special permissions or attack setup required
- Happens naturally when large holders use the protocol

**Execution Practicality:**
Overflow is deterministic and unavoidable once the threshold is exceeded. The calculation happens during normal execution—no complex attack sequence needed.

**Economic Reality:**
With SUI having a market presence and institutional adoption, deposits of 30-50 million SUI are entirely feasible for:
- Treasury operations
- Liquidity pool migrations  
- Institutional vault allocations
- Large individual holders

The likelihood increases as the protocol gains adoption and total value locked (TVL) grows.

### Recommendation

**Code-Level Fix:**
Replace unsafe u64 arithmetic with u128 widening pattern already used in the liquid staking module:

```move
// In execute_deposit (line 830):
let deposit_fee = (((coin_amount as u128) * (self.deposit_fee_rate as u128)) / (RATE_SCALING as u128)) as u64;

// In execute_withdraw (line 1040):
let fee_amount = (((amount_to_withdraw as u128) * (self.withdraw_fee_rate as u128)) / (RATE_SCALING as u128)) as u64;
```

**Additional Safeguards:**
1. Add explicit assertions to verify the final fee amount fits in u64 before casting
2. Consider adding maximum transaction size constants if protocol design requires limits
3. Add integration tests with large deposit amounts (e.g., 50M, 100M, 1B SUI) to verify fee calculations succeed

**Test Cases:**
```move
#[test]
public fun test_large_deposit_with_max_fee() {
    // Test deposit of 50 million SUI with 5% fee
    // Should complete without overflow
}

#[test]
public fun test_large_withdraw_with_max_fee() {
    // Test withdrawal of 50 million SUI with 5% fee  
    // Should complete without overflow
}
```

### Proof of Concept

**Initial State:**
1. Vault initialized with deposit_fee_rate = 500 (5%)
2. User has Receipt with sufficient shares for large withdrawal
3. User prepares deposit of 40,000,000 SUI (40 million SUI = 40,000,000,000,000,000 base units)

**Transaction Steps:**

For Deposit:
1. User calls `request_deposit()` with 40,000,000 SUI
2. Request created successfully
3. Operator calls `execute_deposit()` for the request
4. Fee calculation attempts: `40,000,000,000,000,000 * 500 / 10,000`
5. Multiplication step: `40,000,000,000,000,000 * 500 = 20,000,000,000,000,000,000`
6. This exceeds u64::MAX (18,446,744,073,709,551,615)

**Expected Result:**
Transaction completes with 2,000,000 SUI (5%) collected as fee

**Actual Result:**
Transaction aborts with arithmetic overflow error during fee calculation at line 830

**Success Condition:**
The deposit fails to execute despite having valid request, sufficient funds, and within slippage tolerance—solely due to fee calculation overflow.

### Citations

**File:** volo-vault/sources/volo_vault.move (L497-505)
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
```

**File:** volo-vault/sources/volo_vault.move (L830-830)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/volo_vault.move (L1040-1040)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/requests/deposit_request.move (L64-66)
```text
public fun amount(self: &DepositRequest): u64 {
    self.amount
}
```

**File:** liquid_staking/sources/fee_config.move (L80-80)
```text
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
```
