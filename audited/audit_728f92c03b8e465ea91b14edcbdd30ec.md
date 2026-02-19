### Title
Integer Division in Price Parsing Can Result in Zero Price, Enabling Unlimited Borrowing Without Liquidation Risk

### Summary
The `parse_price_to_decimal()` function in the Suilend oracle module performs integer division that can round down to zero when processing Pyth price feeds with large negative exponents relative to small price magnitudes. When an asset's price is incorrectly calculated as zero, borrowed amounts of that asset are excluded from debt calculations, preventing liquidation and allowing attackers to over-borrow without risk while corrupting vault USD valuations.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The `parse_price_to_decimal()` function converts Pyth prices by dividing `price_mag` by `pow(10, exponent_magnitude)` using the Decimal type's `div()` operation. The Decimal implementation uses fixed-point arithmetic with WAD = 1e18 precision: [2](#0-1) 

The division formula is: `result.value = (a.value * WAD) / b.value`

For `parse_price_to_decimal()` with negative exponent:
- `a.value = price_mag * 1e18`
- `b.value = pow(10, expo_magnitude) * 1e18`
- `result.value = (price_mag * 1e18 * 1e18) / (pow(10, expo_magnitude) * 1e18) = (price_mag * 1e18) / pow(10, expo_magnitude)`

**Critical Threshold:** When `price_mag * 1e18 < pow(10, expo_magnitude)`, integer division rounds to zero.

**Example:** With `expo = -20` and `price_mag = 50`:
- `50 * 1e18 < 1e20`
- Result: `(50 * 1e18) / 1e20 = 0` (integer division)

**Why Existing Protections Fail:**

1. The price validation only checks for `Option::is_some()`, not for zero values: [3](#0-2) 

2. There is no minimum price threshold check in the oracle parsing logic.

**Execution Path:**

1. Reserve is created/updated with a price that rounds to zero [4](#0-3) 

2. When obligation is refreshed, market values are calculated using the zero price: [5](#0-4) 

3. For borrowed assets with zero price, `weighted_borrowed_value_usd` excludes this debt

4. Liquidation check compares zero debt against collateral: [6](#0-5) 

5. Vault valuation in Suilend adaptor undercounts debt: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**

1. **Hidden Debt:** Borrowed assets with zero price have `market_value = 0`, making them invisible to the obligation health calculations. The `weighted_borrowed_value_usd` excludes this debt entirely.

2. **Liquidation Bypass:** Since `is_liquidatable()` checks if `weighted_borrowed_value_usd > unhealthy_borrow_value_usd`, obligations with zero-priced borrows can never be liquidated for those positions, even when severely undercollateralized.

3. **Unlimited Borrowing:** The `max_borrow_amount()` calculation relies on `weighted_borrowed_value_upper_bound_usd`, which also excludes zero-priced debt. Attackers can borrow unlimited amounts without affecting their borrowing capacity.

4. **Vault Mispricing:** The Suilend adaptor calculates net position value as `total_deposited_value_usd - total_borrowed_value_usd`. Zero-priced debt inflates the reported position value, corrupting the vault's `total_usd_value` calculations and potentially allowing withdrawals that shouldn't be permitted.

**Who Is Affected:**
- All depositors in the lending market (their collateral can be drained)
- Vault shareholders (inflated valuations lead to incorrect share pricing)
- Protocol solvency (bad debt accumulation)

**Severity Justification:** High impact (complete liquidation bypass, fund drainage) with Low-Medium likelihood (requires specific asset parameters) = Medium overall severity.

### Likelihood Explanation

**Attacker Capabilities:**
Standard untrusted user with ability to deposit collateral and borrow assets from whitelisted reserves.

**Required Preconditions:**

1. **Asset Configuration:** A reserve must be added with a Pyth price feed having parameters where `price_mag < pow(10, expo_magnitude - 18)`. This occurs when:
   - Assets with large negative exponents (expo ≤ -20)
   - Combined with small price magnitudes
   - Examples: tokens with many decimal places, micro-cap tokens with unusual Pyth configurations

2. **Asset Whitelisting:** The vulnerable asset must be whitelisted and available for borrowing in the lending market.

**Feasibility Analysis:**

While mainstream crypto assets (BTC, ETH, SOL) use standard Pyth configurations (expo -8 to -12) that don't trigger this issue, edge cases exist:

- Newly listed tokens with unusual decimal configurations
- Assets from protocols with non-standard Pyth feed setups  
- Test environments or misconfigured price feeds
- Future assets with parameters that happen to cross the threshold

The vulnerability is latent because:
- No validation prevents zero prices from being stored
- No runtime checks detect zero market values
- The impact is silent until exploitation occurs

**Probability:** Low-Medium. While unlikely with current well-configured assets, the complete absence of safeguards makes this exploitable if any vulnerable asset is added, either accidentally or in the future.

### Recommendation

**Immediate Mitigation:**

Add a zero-price validation check in `parse_price_to_decimal()`:

```move
fun parse_price_to_decimal(price: Price): Decimal {
    let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
    let expo = price::get_expo(&price);

    let result = if (i64::get_is_negative(&expo)) {
        div(
            decimal::from(price_mag),
            decimal::from(std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))),
        )
    } else {
        mul(
            decimal::from(price_mag),
            decimal::from(std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))),
        )
    };
    
    // Critical: Ensure price is non-zero
    assert!(decimal::gt(result, decimal::from(0)), EPriceIsZero);
    result
}
```

**Additional Safeguards:**

1. Add minimum price threshold checks in reserve creation/update functions
2. Add assertions in market value calculations to detect zero prices
3. Implement circuit breakers that pause operations when zero prices are detected
4. Add reserve-level validation that rejects price feeds with extreme parameters

**Test Cases:**

1. Test with expo=-20, price_mag=50 (should revert)
2. Test with expo=-25, price_mag=1000 (should revert)
3. Test boundary conditions around the division threshold
4. Test that legitimate micro-cap tokens (expo=-8, price_mag=1) still work correctly
5. Integration test attempting to borrow with zero-priced asset (should fail after fix)

### Proof of Concept

**Initial State:**
1. Suilend lending market with standard reserves (USDC as collateral)
2. Admin adds a new reserve with Pyth price feed configured with expo=-20
3. The asset's current Pyth price has price_mag=50

**Exploitation Steps:**

1. **Setup Phase:**
   - Attacker deposits 1000 USDC as collateral
   - Pyth price feed for vulnerable asset updates with price_mag=50, expo=-20

2. **Price Calculation (Vulnerable):**
   - `parse_price_to_decimal()` computes: `(50 * 1e18) / 1e20 = 0`
   - Reserve stores price = Decimal { value: 0 }
   - Passes `option::is_some()` check ✓

3. **Borrow Execution:**
   - Attacker borrows 1,000,000 units of vulnerable asset
   - `market_value = reserve::market_value(reserve, 1000000) = mul(Decimal{value:0}, decimal::from(1000000)) = Decimal{value:0}`

4. **Obligation Refresh:**
   - `weighted_borrowed_value_usd = 0` (debt is invisible)
   - `is_liquidatable()` returns `false` (0 < any_collateral_value)
   - Obligation appears healthy despite massive undercollateralization

5. **Vault Integration Impact:**
   - Suilend adaptor calculates: `total_borrowed_value_usd = 0`
   - Vault shows inflated position value
   - `finish_update_asset_value()` stores incorrect USD value

**Expected vs Actual:**
- **Expected:** Borrow counted in debt, liquidatable when health factor drops
- **Actual:** Zero debt value, unlimited borrowing, no liquidation possible

**Success Condition:** Attacker maintains borrowed position indefinitely without liquidation risk, draining protocol over time as they withdraw the borrowed assets.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-70)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let expo = price::get_expo(&price);

        if (i64::get_is_negative(&expo)) {
            div(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))),
            )
        } else {
            mul(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))),
            )
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L77-81)
```text
    public fun div(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: (a.value * WAD) / b.value,
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L167-168)
```text
        let (mut price_decimal, smoothed_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-593)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
        reserve.price_last_update_timestamp_s = clock::timestamp_ms(clock) / 1000;
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L245-260)
```text
            let market_value = reserve::market_value(borrow_reserve, borrow.borrowed_amount);
            let market_value_upper_bound = reserve::market_value_upper_bound(
                borrow_reserve,
                borrow.borrowed_amount,
            );

            borrow.market_value = market_value;
            unweighted_borrowed_value_usd = add(unweighted_borrowed_value_usd, market_value);
            weighted_borrowed_value_usd =
                add(
                    weighted_borrowed_value_usd,
                    mul(
                        market_value,
                        borrow_weight(config(borrow_reserve)),
                    ),
                );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L794-796)
```text
    public fun is_liquidatable<P>(obligation: &Obligation<P>): bool {
        gt(obligation.weighted_borrowed_value_usd, obligation.unhealthy_borrow_value_usd)
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L77-82)
```text
        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
```
