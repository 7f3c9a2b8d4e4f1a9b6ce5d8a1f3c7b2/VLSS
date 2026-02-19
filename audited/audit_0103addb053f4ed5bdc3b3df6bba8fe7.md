### Title
Flash Loan Fee Bypass via Integer Division Rounding with Multiple Small Loans

### Summary
The flash loan fee calculation uses integer division that rounds down, allowing attackers to avoid fees entirely by taking many small loans instead of one large loan. When the minimum loan amount (`min`) is configured too low, attackers can exploit rounding errors to achieve near-zero or completely zero fees, causing direct loss of protocol revenue intended for suppliers and treasury.

### Finding Description

The vulnerability exists in the `loan()` function where flash loan fees are calculated using integer division: [1](#0-0) 

The fee calculation divides by `FlashLoanMultiple()` which returns 10000: [2](#0-1) 

When `_loan_amount * rate_to_supplier < 10000` or `_loan_amount * rate_to_treasury < 10000`, the division rounds down to zero, resulting in no fees charged. The `min` parameter that should prevent this can be configured to very low values including zero: [3](#0-2) 

The protocol allows multiple flash loans in a single transaction with independent receipts: [4](#0-3) 

The minimum loan amount check exists but is insufficient when configured too low: [5](#0-4) 

### Impact Explanation

**Direct Fund Impact**: The protocol loses 100% of flash loan fee revenue when exploited. With typical configurations (rate_to_supplier=16, rate_to_treasury=4), any loan amount below 625 tokens results in zero fees for both supplier and treasury.

**Quantified Loss**: For an effective loan of 1,000,000 tokens:
- Normal fee: (1,000,000 × 16 + 1,000,000 × 4) / 10000 = 2,000 tokens
- Exploited fee (1,603 loans of 624 tokens each): 0 tokens total
- Protocol loss: 2,000 tokens (100% fee avoidance)

**Affected Parties**: 
- Suppliers lose expected flash loan fee income that should increase their supply index
- Treasury loses its share of flash loan fees
- Protocol loses revenue on potentially large flash loan volumes

The severity is MEDIUM because while the impact is direct fund loss, it only affects flash loan fees (not principal), and the loss is proportional to flash loan usage volume.

### Likelihood Explanation

**Attacker Capabilities**: Any untrusted user can call public flash loan functions without special permissions.

**Attack Complexity**: Very low - attacker simply calls flash loan functions multiple times with small amounts instead of once with a large amount.

**Feasibility Conditions**:
- Configuration must have `min` set below the rounding threshold (confirmed possible with min=0 in tests)
- No gas cost constraints prevent multiple flash loans per transaction on Sui
- Attack works within normal protocol operations

**Economic Rationality**: Highly profitable - gas costs on Sui are relatively low compared to percentage-based flash loan fees. For any substantial flash loan amount (hundreds of thousands to millions of tokens), the fee savings significantly exceed gas costs.

**Detection**: Difficult to prevent without code changes, as each individual small flash loan appears legitimate.

Likelihood is HIGH - the attack is trivially executable when minimum loan amounts are configured too low.

### Recommendation

**Immediate Fix**: Implement a minimum fee threshold to prevent zero-fee loans:

```move
// In loan() function, after calculating fees:
let min_fee_per_loan = 1; // or appropriate minimum based on token decimals
if (to_supplier == 0 && to_treasury == 0 && _loan_amount > 0) {
    abort error::fee_too_low()
};
```

**Better Solution**: Use a minimum effective fee rate check:

```move
// Ensure minimum loan amount enforces meaningful fees
fun verify_config(cfg: &AssetConfig) {
    assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
    assert!(cfg.min < cfg.max, error::invalid_amount());
    
    // NEW: Ensure min amount produces at least 1 unit of total fees
    let min_fee_check = cfg.min * (cfg.rate_to_supplier + cfg.rate_to_treasury);
    assert!(min_fee_check >= constants::FlashLoanMultiple(), error::min_amount_too_low());
}
```

**Test Cases**: Add regression tests verifying:
1. Flash loans with amounts below fee threshold are rejected
2. Multiple small flash loans cannot bypass fees that a single large loan would pay
3. Configuration validation prevents setting `min` values that enable fee bypass

### Proof of Concept

**Initial State**:
- Flash loan configured with rate_to_supplier=16, rate_to_treasury=4, min=0, max=100000000
- Pool has sufficient liquidity (e.g., 10,000,000 tokens)

**Attack Sequence**:

Transaction 1 - Attacker wants to effectively borrow 1,000,000 tokens:
```
For i = 1 to 1603:
  1. Call flash_loan_with_ctx(config, pool, 624, ctx)
  2. Receive 624 tokens with receipt showing fee_to_supplier=0, fee_to_treasury=0
  3. Use borrowed tokens for arbitrage/other operations
  4. Repay 624 tokens (original amount + 0 fees)
  
Total borrowed: 1,603 × 624 = 1,000,272 tokens
Total fees paid: 0 tokens
```

**Expected Result** (without vulnerability):
- Fee should be: (1,000,272 × 16 + 1,000,272 × 4) / 10000 ≈ 2,005 tokens

**Actual Result** (with vulnerability):
- Fee charged: 0 tokens (each 624-token loan: 624×16/10000=0, 624×4/10000=0)

**Success Condition**: 
- Attacker completes flash loans totaling over 1 million tokens
- Zero fees paid to suppliers and treasury
- Protocol fee revenue loss of 2,005 tokens (100% fee avoidance)

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L149-149)
```text
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L152-153)
```text
        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L16-16)
```text
    public fun FlashLoanMultiple(): u64 {10000}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/base_tests.move (L82-93)
```text
            manage::create_flash_loan_asset<SUI_TEST>(
                &storage_admin_cap,
                &mut flash_loan_config,
                &storage,
                &pool,
                0,
                16, // 0.2% * 80% = 0.0016 -> 0.0016 * 10000 = 16
                4, // 0.2% * 20% = 0.0004 -> 0.0004 * 10000 = 4
                100000_000000000, // 100k
                0, // 1
                test_scenario::ctx(scenario)
            );
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-545)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }

    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }
```
