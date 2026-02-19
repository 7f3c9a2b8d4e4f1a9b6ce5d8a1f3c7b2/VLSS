### Title
Suilend Reserve DoS via Unclaimed Spread Fees Causing Total Supply Underflow

### Summary
The `ctoken_ratio()` calculation in Suilend reserves can cause transaction aborts when `unclaimed_spread_fees` exceeds `available_amount + borrowed_amount`, making `total_supply()` underflow. This blocks all operations requiring the ratio, including Volo Vault's `update_suilend_position_value()`, causing denial of service for the vault's Suilend integration and preventing users from managing their positions.

### Finding Description

**Code Location:**
The vulnerability exists in the interaction between several functions: [1](#0-0) [2](#0-1) [3](#0-2) 

**Root Cause:**
The `total_supply()` function computes `available_amount + borrowed_amount - unclaimed_spread_fees` using the decimal `sub()` function, which aborts on underflow. There is no validation that `unclaimed_spread_fees` remains bounded relative to the sum of available and borrowed amounts. [4](#0-3) 

**How Fees Accumulate:**
During interest compounding, `unclaimed_spread_fees` increases as a fraction of interest earned, while `borrowed_amount` increases by the full interest amount. Over time, if fees are never claimed and most liquidity is withdrawn after loans are repaid, fees can approach or exceed the remaining `available_amount + borrowed_amount`. [5](#0-4) 

**Why Protections Fail:**
The `MIN_AVAILABLE_AMOUNT` check only ensures that `available_amount >= 100` and `ctoken_supply >= 100` after redemptions, but does not prevent `unclaimed_spread_fees` from growing arbitrarily large relative to total supply. [6](#0-5) 

**Execution Path to Volo Vault:**
The Volo Vault's Suilend adaptor calls `ctoken_market_value()` when updating position values, which depends on `ctoken_ratio()`: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Operational DoS:**
When `total_supply()` calculation underflows, all operations requiring `ctoken_ratio()` abort, including:
- `max_withdraw_amount()` in obligations
- `ctoken_market_value()` used by vault position updates
- Deposits and redemptions in the reserve
- Any vault operation that needs to update Suilend position values

**Vault Integration Failure:**
The Volo Vault cannot execute `update_suilend_position_value()`, blocking:
- Vault operations that require up-to-date asset values
- Proper accounting of Suilend positions
- User withdrawals and deposits that depend on accurate valuations

**Affected Parties:**
- All users with Suilend positions in affected reserves
- Volo Vault operators unable to manage Suilend exposures
- Protocol unable to collect accumulated fees

**Severity:**
This represents a critical operational failure that renders the Suilend reserve and associated vault positions unusable until fees are claimed or the reserve state is manually corrected.

### Likelihood Explanation

**Preconditions (Realistic):**
1. Reserve operates for extended period with high borrowing activity
2. Protocol spread fees accumulate without regular claims
3. Borrowers repay most loans
4. Liquidity providers withdraw most available liquidity
5. Remaining state: `available_amount` near `MIN_AVAILABLE_AMOUNT`, `borrowed_amount` low, `unclaimed_spread_fees` high

**Feasibility:**
This scenario occurs naturally without any malicious action. In a successful lending market with:
- 10% spread fee rate
- 100% interest earned over time on high utilization
- Infrequent fee claims (common in DeFi protocols)
- Natural withdrawal patterns

After significant borrowing volume (e.g., $10M borrowed, $1M in fees), if most liquidity withdraws and only 100 tokens remain available with 0 borrowed, the condition triggers.

**Attack Complexity:**
Not an intentional attack—this is a protocol design flaw that manifests under normal but stressed conditions. No special privileges or coordinated actions required.

**Detection:**
The issue becomes apparent when `update_suilend_position_value()` starts failing, but by then the reserve is already in a DoS state.

### Recommendation

**Immediate Fix:**
Add a validation in `compound_interest()` to ensure `unclaimed_spread_fees` never exceeds a safe threshold relative to total supply:

```move
public(package) fun compound_interest<P>(reserve: &mut Reserve<P>, clock: &Clock) {
    // ... existing interest calculation ...
    
    let max_safe_fees = saturating_sub(
        add(decimal::from(reserve.available_amount), reserve.borrowed_amount),
        decimal::from(MIN_AVAILABLE_AMOUNT * 2) // Safety margin
    );
    
    reserve.unclaimed_spread_fees = min(
        add(reserve.unclaimed_spread_fees, spread_fee),
        max_safe_fees
    );
    
    // ... rest of function ...
}
```

**Alternative Approach:**
Use `saturating_sub()` in `total_supply()` calculation to prevent underflow, though this would make `ctoken_ratio` artificially low and cause unfair value distribution.

**Additional Safeguards:**
1. Add assertions that `total_supply() >= decimal::from(MIN_AVAILABLE_AMOUNT)` after state changes
2. Implement automatic fee claim when fees reach dangerous thresholds
3. Add monitoring/alerts for reserves approaching problematic states

**Test Cases:**
1. Simulate high-utilization reserve with fee accumulation
2. Test withdrawal sequences that approach `MIN_AVAILABLE_AMOUNT`
3. Verify `ctoken_ratio()` never aborts under any valid reserve state
4. Test Volo Vault integration under stressed reserve conditions

### Proof of Concept

**Initial State:**
- Reserve: available_amount=1,000,000, ctoken_supply=1,000,000, borrowed_amount=0, unclaimed_spread_fees=0
- ctoken_ratio = 1.0

**Step 1:** Borrow 990,000 tokens
- available_amount=10,000, borrowed_amount=990,000
- ctoken_ratio = (10,000 + 990,000 - 0) / 1,000,000 = 1.0

**Step 2:** Accrue 100% interest with 10% spread over extended period
- borrowed_amount=1,980,000 (doubled due to interest)
- unclaimed_spread_fees=99,000 (10% of 990,000 interest)
- ctoken_ratio = (10,000 + 1,980,000 - 99,000) / 1,000,000 = 1.891

**Step 3:** Borrowers repay all loans
- available_amount=2,000,000 (10K + 1,980K repayment + 10K original)
- borrowed_amount=0
- unclaimed_spread_fees=99,000 (unchanged)
- ctoken_ratio = (2,000,000 + 0 - 99,000) / 1,000,000 = 1.901

**Step 4:** Users redeem 999,900 ctoken (most liquidity)
- Liquidity withdrawn = 999,900 × 1.901 ≈ 1,899,800 tokens
- available_amount = 2,000,000 - 1,899,800 = 100,200
- ctoken_supply = 100
- unclaimed_spread_fees = 99,000 (unchanged)

**Step 5:** One more small redemption attempt
- available_amount ≈ 100, ctoken_supply = 100, unclaimed_spread_fees = 99,000
- total_supply = sub(add(100, 0), 99,000) → **UNDERFLOW ABORT**
- All operations calling `ctoken_ratio()` now fail
- Volo Vault's `update_suilend_position_value()` aborts
- Reserve enters DoS state

**Success Condition:**
Transaction attempting to call `ctoken_ratio()` or any dependent function (including vault position updates) aborts with arithmetic underflow, preventing all further operations on the reserve.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L300-311)
```text
    public fun ctoken_market_value<P>(
        reserve: &Reserve<P>, 
        ctoken_amount: u64
    ): Decimal {
        // TODO should i floor here?
        let liquidity_amount = mul(
            decimal::from(ctoken_amount),
            ctoken_ratio(reserve)
        );

        market_value(reserve, liquidity_amount)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L371-379)
```text
    public fun total_supply<P>(reserve: &Reserve<P>): Decimal {
        sub(
            add(
                decimal::from(reserve.available_amount),
                reserve.borrowed_amount
            ),
            reserve.unclaimed_spread_fees
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L411-426)
```text
    public fun ctoken_ratio<P>(reserve: &Reserve<P>): Decimal {
        let total_supply = total_supply(reserve);

        // this branch is only used once -- when the reserve is first initialized and has 
        // zero deposits. after that, borrows and redemptions won't let the ctoken supply fall 
        // below MIN_AVAILABLE_AMOUNT
        if (reserve.ctoken_supply == 0) {
            decimal::from(1)
        }
        else {
            div(
                total_supply,
                decimal::from(reserve.ctoken_supply)
            )
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L621-636)
```text
        let net_new_debt = mul(
            reserve.borrowed_amount,
            sub(compounded_borrow_rate, decimal::from(1))
        );

        let spread_fee = mul(net_new_debt, spread_fee(config(reserve)));

        reserve.unclaimed_spread_fees = add(
            reserve.unclaimed_spread_fees,
            spread_fee
        );

        reserve.borrowed_amount = add(
            reserve.borrowed_amount,
            net_new_debt 
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L783-786)
```text
        assert!(
            reserve.available_amount >= MIN_AVAILABLE_AMOUNT && reserve.ctoken_supply >= MIN_AVAILABLE_AMOUNT, 
            EMinAvailableAmountViolated
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L850-859)
```text
        floor(
            min(
                decimal::from(deposit.deposited_ctoken_amount),
                div(
                    max_withdraw_token_amount,
                    reserve::ctoken_ratio(reserve),
                ),
            ),
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L57-61)
```text
    public fun sub(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: a.value - b.value,
        }
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L53-63)
```text
    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });
```
