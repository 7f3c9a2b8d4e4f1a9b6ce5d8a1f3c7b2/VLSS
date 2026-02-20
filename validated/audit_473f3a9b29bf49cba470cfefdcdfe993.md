# Audit Report

## Title
Suilend Reserve DoS via Unclaimed Spread Fees Causing Total Supply Underflow

## Summary
The Suilend reserve's `total_supply()` calculation can underflow when `unclaimed_spread_fees` exceeds `available_amount + borrowed_amount`, causing all operations requiring `ctoken_ratio()` to abort with arithmetic underflow. This blocks Volo Vault's `update_suilend_position_value()` function, creating a denial of service for vault operations that depend on accurate Suilend position valuations.

## Finding Description

The vulnerability exists in Suilend reserve's accounting logic that Volo Vault integrates with for position management.

**Root Cause:**

The `total_supply()` function performs an unchecked subtraction that can underflow: [1](#0-0) 

This uses the decimal `sub()` function which performs direct subtraction without underflow protection: [2](#0-1) 

**How Fees Accumulate:**

During interest compounding, spread fees accumulate while borrowed amounts increase: [3](#0-2) 

The problem occurs when:
1. Significant fees accumulate over time (e.g., 200,000 tokens in `unclaimed_spread_fees`)
2. Borrowers repay loans (reducing `borrowed_amount` to 0)
3. Liquidity providers withdraw funds (reducing `available_amount` to `MIN_AVAILABLE_AMOUNT = 100`)
4. Result: `100 + 0 - 200,000` causes arithmetic underflow in Move, aborting the transaction

**Why Protections Fail:**

The `MIN_AVAILABLE_AMOUNT` constant only prevents `available_amount` from dropping below 100: [4](#0-3) 

This check is enforced during redemptions: [5](#0-4) 

Fee claiming is limited by available funds: [6](#0-5) 

When `available_amount = MIN_AVAILABLE_AMOUNT = 100`, the claimable fees become `min(unclaimed_spread_fees, 100 - 100) = 0`, meaning NO fees can be claimed to reduce `unclaimed_spread_fees`.

**Impact on Volo Vault:**

The Volo Vault's Suilend adaptor calls `ctoken_market_value()` to update position values: [7](#0-6) 

This function depends on `ctoken_ratio()`: [8](#0-7) 

Which calls the vulnerable `total_supply()`: [9](#0-8) 

Additionally, both deposit and redeem operations call `ctoken_ratio()` before state updates: [10](#0-9) [11](#0-10) 

The obligation's `max_withdraw_amount()` is also affected: [12](#0-11) 

## Impact Explanation

**Critical Operational DoS:**

Once the underflow condition is reached (`available_amount + borrowed_amount < unclaimed_spread_fees`), ALL operations requiring `ctoken_ratio()` become permanently unusable:

1. **Volo Vault Operations**: Cannot execute `update_suilend_position_value()`, blocking any vault operation requiring up-to-date Suilend asset valuations
2. **Reserve Operations**: All deposits, withdrawals, and borrows from the affected Suilend reserve abort with arithmetic underflow
3. **Obligation Management**: Cannot calculate withdrawal limits or manage positions
4. **Fee Collection**: Protocol cannot access accumulated fees when reserve is at minimum liquidity (claimable amount = 0)

**Affected Parties:**
- Volo Vault users unable to withdraw or manage positions dependent on Suilend valuations
- Suilend reserve users completely locked out of their deposited funds
- Protocol unable to collect legitimately earned spread fees

This represents a critical failure of the integration between Volo Vault and Suilend that makes both systems unusable for the affected reserve until external liquidity is added.

## Likelihood Explanation

**Realistic Preconditions:**

The scenario requires only a sequence of normal DeFi operations:
1. Reserve operates with high borrowing activity (common in successful lending markets)
2. Spread fees accumulate over time (10% spread fee rate is typical)
3. Protocol doesn't claim fees frequently (common operational pattern in DeFi)
4. Borrowers repay loans (normal market behavior during low utilization)
5. Liquidity providers withdraw funds (normal during market downturns or low yields)

**Feasibility Example:**

Consider a reserve starting with $10M borrowed at 20% APR over 6 months:
- Interest accrued: $1M
- Spread fees (10%): $100K accumulated in `unclaimed_spread_fees`
- After full repayment and liquidity withdrawal: `available_amount = 100`, `borrowed_amount = 0`
- Calculation: `100 + 0 < 100,000` → DoS triggered on next `ctoken_ratio()` call

**No Malicious Action Required:**

This is not an attack but a design flaw that manifests under stressed but realistic market conditions. The state emerges naturally from:
- Successful lending activity (high volume → high fees accumulation)
- Normal market cycles (high utilization period → mass repayment → mass withdrawal)
- Typical operational patterns (infrequent fee claiming to save gas costs)

The vulnerability can occur in any Suilend reserve integrated with Volo Vault during normal market fluctuations.

## Recommendation

Add an invariant check that prevents the reserve from reaching a state where `unclaimed_spread_fees > available_amount + borrowed_amount`:

**Option 1**: Add check in withdrawal/redemption operations:
```move
public(package) fun redeem_ctokens<P, T>(
    reserve: &mut Reserve<P>, 
    ctokens: Balance<CToken<P, T>>
): LiquidityRequest<P, T> {
    // Add check before allowing redemption
    let post_redemption_available = reserve.available_amount - liquidity_amount;
    assert!(
        add(
            decimal::from(post_redemption_available),
            reserve.borrowed_amount
        ) >= reserve.unclaimed_spread_fees,
        EInsufficientLiquidityForFees
    );
    // ... rest of function
}
```

**Option 2**: Use `saturating_sub` in `total_supply()` calculation:
```move
public fun total_supply<P>(reserve: &Reserve<P>): Decimal {
    saturating_sub(
        add(
            decimal::from(reserve.available_amount),
            reserve.borrowed_amount
        ),
        reserve.unclaimed_spread_fees
    )
}
```

**Option 3**: Force fee claiming before reserve liquidity drops too low:
```move
// In redeem_ctokens, before allowing withdrawal
if (reserve.unclaimed_spread_fees > decimal::from(0)) {
    // Auto-claim fees if possible
    if (reserve.available_amount > MIN_AVAILABLE_AMOUNT) {
        claim_spread_fees_internal(reserve);
    }
}
```

The recommended approach is **Option 1** as it prevents the invalid state from occurring while maintaining predictable accounting behavior.

## Proof of Concept

```move
#[test]
fun test_reserve_dos_via_unclaimed_fees() {
    // Setup: Create reserve with high borrowing activity
    let reserve = create_test_reserve();
    
    // Step 1: Simulate high borrowing activity accumulating fees
    // Assume $10M borrowed at 20% APR for 6 months → ~$100K in spread fees
    reserve.unclaimed_spread_fees = decimal::from(100_000);
    reserve.borrowed_amount = decimal::from(10_000_000);
    reserve.available_amount = 5_000_000;
    
    // Step 2: All borrowers repay their loans
    reserve.borrowed_amount = decimal::from(0);
    reserve.available_amount = 10_000_000;
    
    // Step 3: Liquidity providers withdraw almost all funds
    // Withdrawals continue until hitting MIN_AVAILABLE_AMOUNT
    reserve.available_amount = 100; // MIN_AVAILABLE_AMOUNT
    
    // Step 4: Attempt to call ctoken_ratio() - this will abort with underflow
    // because: total_supply() = 100 + 0 - 100,000 = -99,900 (UNDERFLOW)
    let ratio = reserve::ctoken_ratio(&reserve); // ABORTS HERE
    
    // Step 5: Volo Vault cannot update position value
    vault::update_suilend_position_value(); // ABORTS - cannot get ctoken_ratio
    
    // Reserve is now completely bricked until external liquidity added
}
```

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L50-50)
```text
    const MIN_AVAILABLE_AMOUNT: u64 = 100; 
```

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L626-631)
```text
        let spread_fee = mul(net_new_debt, spread_fee(config(reserve)));

        reserve.unclaimed_spread_fees = add(
            reserve.unclaimed_spread_fees,
            spread_fee
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L706-710)
```text
        if (reserve.available_amount >= MIN_AVAILABLE_AMOUNT) {
            let claimable_spread_fees = floor(min(
                reserve.unclaimed_spread_fees,
                decimal::from(reserve.available_amount - MIN_AVAILABLE_AMOUNT)
            ));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L734-743)
```text
    public(package) fun deposit_liquidity_and_mint_ctokens<P, T>(
        reserve: &mut Reserve<P>, 
        liquidity: Balance<T>, 
    ): Balance<CToken<P, T>> {
        let ctoken_ratio = ctoken_ratio(reserve);

        let new_ctokens = floor(div(
            decimal::from(balance::value(&liquidity)),
            ctoken_ratio
        ));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L770-778)
```text
    public(package) fun redeem_ctokens<P, T>(
        reserve: &mut Reserve<P>, 
        ctokens: Balance<CToken<P, T>>
    ): LiquidityRequest<P, T> {
        let ctoken_ratio = ctoken_ratio(reserve);
        let liquidity_amount = floor(mul(
            decimal::from(balance::value(&ctokens)),
            ctoken_ratio
        ));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L783-786)
```text
        assert!(
            reserve.available_amount >= MIN_AVAILABLE_AMOUNT && reserve.ctoken_supply >= MIN_AVAILABLE_AMOUNT, 
            EMinAvailableAmountViolated
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L57-61)
```text
    public fun sub(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: a.value - b.value,
        }
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L58-62)
```text
        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L822-859)
```text
    public(package) fun max_withdraw_amount<P>(
        obligation: &Obligation<P>,
        reserve: &Reserve<P>,
    ): u64 {
        let deposit_index = find_deposit_index(obligation, reserve);
        assert!(deposit_index < vector::length(&obligation.deposits), EDepositNotFound);

        let deposit = vector::borrow(&obligation.deposits, deposit_index);

        if (
            open_ltv(config(reserve)) == decimal::from(0) || vector::length(&obligation.borrows) == 0
        ) {
            return deposit.deposited_ctoken_amount
        };

        let max_withdraw_value = div(
            saturating_sub(
                obligation.allowed_borrow_value_usd,
                obligation.weighted_borrowed_value_upper_bound_usd,
            ),
            open_ltv(config(reserve)),
        );

        let max_withdraw_token_amount = reserve::usd_to_token_amount_upper_bound(
            reserve,
            max_withdraw_value,
        );

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
