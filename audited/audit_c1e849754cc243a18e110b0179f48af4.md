### Title
Flash Loan Fee Rounding to Zero for Small Loan Amounts

### Summary
The flash loan fee calculation uses integer division that causes both fees to round down to zero when `loan_amount * rate < FlashLoanMultiple()` (10000). With the default configuration allowing minimum loan amounts of 0 and standard rates of 16-20 basis points, users can take flash loans up to 624 units without paying any fees, completely bypassing the protocol's fee collection mechanism and depriving suppliers and treasury of their entitled compensation.

### Finding Description

The flash loan fee calculation occurs in the `loan` function where fees are computed using integer division: [1](#0-0) 

The constant `FlashLoanMultiple()` returns 10000: [2](#0-1) 

**Root Cause**: Integer division truncates when the numerator is less than the denominator. For any loan where `loan_amount * rate < 10000`, the fee calculation produces zero.

**Why Protections Fail**:

1. The minimum loan amount check only validates against a configured minimum: [3](#0-2) 

2. The default configuration sets this minimum to 0, allowing arbitrarily small loans: [4](#0-3) 

3. The configuration verification only checks that rate sum is less than FlashLoanMultiple and min < max, without enforcing minimum fee collection: [5](#0-4) 

**Mathematical Analysis**:
With default rates (rate_to_supplier=16, rate_to_treasury=4):
- For `fee_to_supplier = 0`: requires `loan_amount * 16 < 10000` → `loan_amount < 625`
- For `fee_to_treasury = 0`: requires `loan_amount * 4 < 10000` → `loan_amount < 2500`
- Both fees are zero when `loan_amount < 625`

Even with maximum theoretical rates approaching 9999, a loan_amount of 1 would still produce zero fees due to integer truncation (1 * 9999 / 10000 = 0).

### Impact Explanation

**Direct Financial Impact**:
- **Fee Under-Collection**: The protocol fails to collect flash loan fees that are essential to its economic model
- **Supplier Loss**: Liquidity suppliers who provide capital for flash loans receive no compensation for loans < 625 units (with default rates)
- **Treasury Loss**: The protocol treasury receives no fees from these small flash loans

**Quantified Impact**:
- With default rates (16 supplier + 4 treasury = 0.20% total), loans up to 624 units pay zero fees
- For SUI with 9 decimals, this means loans up to 0.000000624 SUI pay no fees
- For USDC with 6 decimals, this means loans up to 0.000624 USDC pay no fees
- While individual amounts are small, this can be exploited repeatedly or as part of larger strategies

**Affected Parties**:
1. Liquidity suppliers expecting flash loan fee compensation
2. Protocol treasury expecting flash loan revenue
3. Protocol economic sustainability

**Severity Justification**: HIGH
- Breaks a core invariant: fee collection for protocol services
- Allows complete fee bypass for certain loan amounts
- Undermines the flash loan economic model
- Easy to exploit with no special privileges required

### Likelihood Explanation

**Reachable Entry Point**: 
Public flash loan functions are directly callable by any user: [6](#0-5) 

**Feasible Preconditions**:
- Default protocol configuration (min=0) enables this vulnerability immediately
- No special privileges or setup required
- Works with any asset configured for flash loans

**Execution Practicality**:
- Trivial to exploit: simply call flash loan function with amount < 625 (for default rates)
- Test cases demonstrate zero-amount flash loans work without failure: [7](#0-6) 

**Economic Rationality**:
While individual small loans may seem economically insignificant:
1. Can be used for gas-free testing and experimentation
2. Can be incorporated into complex multi-step transactions
3. Can be executed repeatedly to exploit small arbitrage opportunities
4. Demonstrates broken fee collection mechanism that could affect larger amounts if rates are adjusted
5. No cost to attacker beyond gas fees

**Attack Complexity**: TRIVIAL
- Single transaction
- No special timing or state requirements
- Works immediately with default configuration

### Recommendation

**Primary Fix**: Implement minimum fee enforcement in the `loan` function:

```move
public(friend) fun loan<CoinType>(...) {
    // ... existing validation ...
    
    let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
    let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();
    
    // NEW: Enforce minimum total fee
    assert!(to_supplier + to_treasury > 0 || _loan_amount == 0, error::insufficient_fee());
    
    // ... rest of function ...
}
```

**Alternative Approaches**:

1. **Set Minimum Loan Amount**: Configure `min` to ensure fees are always non-zero:
   - For rate=16: set min ≥ 625 
   - For rate=4: set min ≥ 2500
   - Generally: `min = ceil(10000 / min(rate_to_supplier, rate_to_treasury))`

2. **Implement Minimum Absolute Fee**: Add a minimum fee in absolute terms that applies regardless of loan size

3. **Enhanced Config Validation**: Update `verify_config` to check that min guarantees non-zero fees:

```move
fun verify_config(cfg: &AssetConfig) {
    assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
    assert!(cfg.min < cfg.max, error::invalid_amount());
    // NEW: Ensure minimum loan produces non-zero fees
    let min_rate = if (cfg.rate_to_supplier < cfg.rate_to_treasury) cfg.rate_to_supplier else cfg.rate_to_treasury;
    if (min_rate > 0) {
        assert!(cfg.min * min_rate >= constants::FlashLoanMultiple(), error::insufficient_min_for_fees());
    };
}
```

**Test Cases to Add**:
1. Test that flash loans at the minimum amount always produce non-zero fees
2. Test that flash loans just below the fee threshold are rejected
3. Test with various rate configurations to ensure minimum fee is enforced
4. Add fuzzing tests for different loan amounts and rate combinations

### Proof of Concept

**Initial State**:
- Protocol initialized with default configuration
- Flash loan config: rate_to_supplier=16, rate_to_treasury=4, min=0, max=100000
- Pool has sufficient liquidity (e.g., 1,000,000 SUI deposited)

**Exploit Steps**:

1. **Attacker calls flash loan with small amount**:
   ```
   loan_amount = 624 // Just below threshold where fees become non-zero
   flash_loan_with_ctx<SUI_TEST>(config, pool, 624, ctx)
   ```

2. **Fee Calculation** (flash_loan.move:152-153):
   ```
   fee_to_supplier = 624 * 16 / 10000 = 9984 / 10000 = 0
   fee_to_treasury = 624 * 4 / 10000 = 2496 / 10000 = 0
   ```

3. **Receipt Generated**:
   - amount: 624
   - fee_to_supplier: 0
   - fee_to_treasury: 0

4. **Attacker Uses Borrowed Funds**:
   - Can perform any operations with the 624 units
   - No fee obligation

5. **Attacker Repays** (flash_loan.move:194-198):
   ```
   Required repayment = amount + fee_to_supplier + fee_to_treasury = 624 + 0 + 0 = 624
   Attacker returns exactly 624 units
   ```

6. **Verification Check Passes**:
   - `repay_amount >= amount + fee_to_supplier + fee_to_treasury`
   - 624 >= 624 ✓

**Expected Result**: 
Attacker should pay fees totaling 0.20% of loan (approximately 1.25 units)

**Actual Result**: 
Attacker pays zero fees, successfully completing flash loan without any fee payment

**Success Condition**: 
Transaction succeeds with `fee_to_supplier = 0` and `fee_to_treasury = 0` in the FlashRepay event, confirmed by receipt values and zero fee deposit to treasury.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L141-173)
```text
    public(friend) fun loan<CoinType>(config: &Config, _pool: &mut Pool<CoinType>, _user: address, _loan_amount: u64): (Balance<CoinType>, Receipt<CoinType>) {
        version_verification(config);
        let str_type = type_name::into_string(type_name::get<CoinType>());
        assert!(table::contains(&config.support_assets, *ascii::as_bytes(&str_type)), error::reserve_not_found());
        let asset_id = table::borrow(&config.support_assets, *ascii::as_bytes(&str_type));
        let cfg = table::borrow(&config.assets, *asset_id);

        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());

        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();

        let _balance = pool::withdraw_balance(_pool, _loan_amount, _user);
        
        let _receipt = Receipt<CoinType> {
            user: _user,
            asset: *asset_id,
            amount: _loan_amount,
            pool: pool_id,
            fee_to_supplier: to_supplier,
            fee_to_treasury: to_treasury,
        };

        emit(FlashLoan {
            sender: _user,
            asset: *asset_id,
            amount: _loan_amount,
        });

        (_balance, _receipt)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L290-293)
```text
    fun verify_config(cfg: &AssetConfig) {
        assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
        assert!(cfg.min < cfg.max, error::invalid_amount());
    }
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

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/flash_loan_tests.move (L741-743)
```text
                let (loan_balance, receipt) = lending::flash_loan_with_ctx<USDC_TEST>(&flash_loan_config, &mut usdc_pool, 0, test_scenario::ctx(&mut user_b_scenario));
                let this_balance = loan_balance;
                let _excess_balance = lending::flash_repay_with_ctx<USDC_TEST>(&test_clock, &mut storage, &mut usdc_pool, receipt, this_balance, test_scenario::ctx(&mut user_b_scenario));
```
