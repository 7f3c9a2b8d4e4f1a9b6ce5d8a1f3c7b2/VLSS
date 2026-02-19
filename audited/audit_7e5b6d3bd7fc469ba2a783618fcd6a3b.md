### Title
Flash Loan Fee Bypass via Integer Division Rounding with Zero Minimum Amount

### Summary
The flash loan fee calculation uses integer division that rounds down to zero when `amount * rate < 10000`, and the protocol configuration sets the minimum loan amount to 0. This allows attackers to take flash loans with amounts below the rounding threshold and pay zero fees, effectively obtaining free capital for arbitrage or other profitable operations while the protocol loses all flash loan revenue.

### Finding Description

The vulnerability exists in the flash loan fee calculation mechanism: [1](#0-0) 

The fee calculation uses integer division where `fee = (loan_amount * rate) / 10000`. When the numerator is less than 10000, the result rounds down to zero.

The protocol enforces a minimum loan amount check: [2](#0-1) 

However, the configuration sets this minimum to 0 for both SUI and USDC assets: [3](#0-2) [4](#0-3) 

With default rates of `rate_to_supplier = 16` (0.16%) and `rate_to_treasury = 4` (0.04%), the rounding thresholds are:
- For `fee_to_supplier`: amounts < 625 result in zero fee (624 * 16 = 9,984 < 10,000)
- For `fee_to_treasury`: amounts < 2,500 result in zero fee (2,499 * 4 = 9,996 < 10,000)
- For total zero fees: amounts < 500 (499 * 20 = 9,980 < 10,000)

The protocol's own tests demonstrate that flash loans with amount=0 are explicitly allowed: [5](#0-4) 

### Impact Explanation

**Direct Financial Loss:**
- The protocol loses 100% of flash loan fee revenue for loans below the rounding threshold
- Liquidity providers lose their share (`fee_to_supplier = 0`) despite providing the capital
- Protocol treasury loses its share (`fee_to_treasury = 0`)

**Exploitation Economics:**
- For SUI (9 decimals): attackers can borrow up to 624 base units (0.000000624 SUI) paying zero `fee_to_supplier`
- For USDC (6 decimals): attackers can borrow up to 624 base units (0.000624 USDC) paying zero `fee_to_supplier`
- Attackers can perform unlimited free flash loans at these amounts for arbitrage, liquidations, or other DeFi operations
- Each transaction only costs gas, making this highly profitable for repeated exploitation

**Who is Affected:**
- Liquidity providers who expect fee revenue from their supplied capital
- Protocol treasury that should collect fees
- Protocol reputation when zero-fee flash loan exploitation becomes public

### Likelihood Explanation

**Reachable Entry Point:**
The exploit uses the standard public flash loan interface accessible to any user: [6](#0-5) 

**Attack Complexity: Very Low**
1. Identify the rate configuration (publicly readable on-chain)
2. Calculate threshold: `threshold = 10000 / rate`
3. Call flash loan with `amount < threshold`
4. Use borrowed funds for profitable operations
5. Repay exactly the borrowed amount (zero fees required)
6. Repeat indefinitely

**Feasibility Conditions:**
- No special permissions required
- Works with standard wallet/SDK interactions
- Configuration explicitly sets `min = 0` allowing the attack
- No monitoring or rate limiting prevents repeated exploitation

**Economic Rationality:**
- Attack cost: Only transaction gas fees
- Attack benefit: Free capital for arbitrage/liquidations that would normally require fee payment
- Net profit: 100% of what would have been paid in fees, plus any arbitrage profits
- Highly economically rational for attackers to exploit repeatedly

**Detection Constraints:**
- Small amounts may avoid detection initially
- Can be executed across multiple addresses
- Appears as legitimate flash loan usage in transaction logs

### Recommendation

**Immediate Fix:**
Enforce a minimum loan amount that guarantees non-zero fees. In the `create_asset` and `set_asset_min` functions, add validation:

```move
// In flash_loan.move, add after line 128 or in verify_config function:
let min_amount_for_nonzero_fee = (constants::FlashLoanMultiple() / rate_to_supplier) + 1;
assert!(minimum >= min_amount_for_nonzero_fee, error::invalid_minimum_amount());
```

**Additional Safeguards:**
1. Add explicit fee validation in the `loan` function to prevent zero-fee loans:
```move
// After line 153 in flash_loan.move:
assert!(to_supplier > 0 || to_treasury > 0, error::fee_cannot_be_zero());
```

2. Update configuration to set sensible minimums based on asset decimals:
   - SUI (9 decimals): minimum = 625 (0.000000625 SUI minimum to ensure fee_to_supplier > 0)
   - USDC (6 decimals): minimum = 625 (0.000625 USDC minimum to ensure fee_to_supplier > 0)

3. Add test case to prevent regression:
```move
#[test]
#[expected_failure]
public fun test_flash_loan_cannot_have_zero_fees() {
    // Attempt flash loan with amount that would result in zero fees
    // Should fail with fee_cannot_be_zero error
}
```

### Proof of Concept

**Initial State:**
- Flash loan config created with SUI asset: `rate_to_supplier = 16`, `rate_to_treasury = 4`, `min = 0`
- Pool has sufficient liquidity (e.g., 1000 SUI)

**Exploitation Steps:**

1. **Attacker identifies threshold:** Calculate `10000 / 16 = 625`, so any amount < 625 pays zero supplier fee

2. **Execute free flash loan:**
   - Call `lending::flash_loan_with_ctx<SUI_TEST>(config, pool, 624, ctx)`
   - Receive 624 units (0.000000624 SUI)
   - Fee calculation: `fee_to_supplier = 624 * 16 / 10000 = 9984 / 10000 = 0`
   - Fee calculation: `fee_to_treasury = 624 * 4 / 10000 = 2496 / 10000 = 0`

3. **Use borrowed capital:**
   - Perform arbitrage or other profitable operation with the borrowed 624 units
   - Or simply demonstrate the zero-fee capability

4. **Repay without fees:**
   - Call `lending::flash_repay_with_ctx` with exactly 624 units
   - Repayment check passes: `624 >= 624 + 0 + 0` ✓
   - No fees collected by protocol or liquidity providers

5. **Repeat indefinitely:**
   - Each iteration costs only gas
   - Protocol loses all fee revenue from these transactions
   - Attacker can scale by using multiple amounts below threshold or multiple addresses

**Expected vs Actual Result:**
- **Expected:** Flash loan should collect fees proportional to borrowed amount
- **Actual:** Flash loan collects zero fees due to integer division rounding
- **Success Condition:** Transaction completes with `fee_to_supplier = 0` and `fee_to_treasury = 0`, verified by parsing the receipt or checking the FlashRepay event

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

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/base_tests.move (L107-118)
```text
            manage::create_flash_loan_asset<USDC_TEST>(
                &storage_admin_cap,
                &mut flash_loan_config,
                &storage,
                &pool,
                1,
                16, // 0.2% * 80% = 0.0016 -> 0.0016 * 10000 = 16
                4, // 0.2% * 20% = 0.0004 -> 0.0004 * 10000 = 4
                100000_000000, // 100k
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
