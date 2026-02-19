### Title
Missing Confidence Interval Validation for Pyth EMA Price Leading to Unreliable Price Bounds

### Summary
The Suilend oracle integration validates the confidence interval for Pyth's spot price but completely omits confidence validation for the EMA (Exponential Moving Average) price, despite Pyth providing confidence data for both. The unvalidated EMA price is used in price bound calculations that affect critical protocol operations including health factor assessments, liquidation eligibility, and borrow/deposit limits, potentially causing incorrect liquidations and limit bypasses during high volatility periods.

### Finding Description

The vulnerability exists in the `get_pyth_price_and_identifier()` function where the EMA price is extracted and returned without any confidence interval or staleness validation. [1](#0-0) 

The spot price undergoes rigorous validation:
- Confidence interval check ensuring confidence is less than 10% of price magnitude [2](#0-1) 

- Staleness check ensuring price is not older than 60 seconds [3](#0-2) 

However, the EMA price is always returned regardless of its confidence interval or staleness, appearing in all three return paths: [4](#0-3) 

The unvalidated EMA price is stored as `smoothed_price` in the Reserve: [5](#0-4) 

This smoothed price is then used to calculate price bounds: [6](#0-5) 

These bounds are used in critical calculations:

1. **Health factor calculations** - The lower bound affects allowed borrow values: [7](#0-6) 

2. **Weighted borrow value** - The upper bound affects liquidation eligibility: [8](#0-7) 

3. **Borrow limits** - Used to enforce USD-denominated borrow caps: [9](#0-8) 

4. **Deposit limits** - Used to enforce USD-denominated deposit caps: [10](#0-9) 

### Impact Explanation

**Direct Fund Impact via Incorrect Liquidations:**
During high volatility, Pyth's EMA confidence intervals can widen significantly. If an unreliable EMA price with wide confidence is used:

1. **False Liquidations**: If EMA is unreliably low, `price_lower_bound` decreases, reducing `allowed_borrow_value_usd`. Healthy positions may appear underwater and get liquidated, causing users to lose their liquidation bonus (typically 5-10% of collateral value).

2. **Missed Liquidations**: If EMA is unreliably high, `price_upper_bound` increases, inflating `weighted_borrowed_value_upper_bound_usd`. Underwater positions may appear healthy, delaying liquidations and accumulating bad debt for the protocol.

3. **Limit Bypass**: Unreliable EMA affects deposit and borrow limit calculations based on USD values, potentially allowing deposits or borrows beyond intended caps or incorrectly restricting valid operations.

The Volo vault uses Suilend positions through the adaptor, meaning these miscalculations directly affect vault asset valuations: [11](#0-10) 

### Likelihood Explanation

**High Likelihood During Normal Operations:**

1. **No Attacker Needed**: This vulnerability manifests during natural market volatility when Pyth's EMA confidence intervals widen. It does not require any attacker action.

2. **Realistic Preconditions**: 
   - Market volatility causes Pyth oracle confidence intervals to widen
   - This is a normal occurrence during price discovery, low liquidity periods, or market stress
   - Affects all users with Suilend positions, not just specific attackers

3. **Execution Practicality**:
   - Triggered automatically when prices are updated during volatile periods
   - No special capabilities required
   - Normal protocol operations (refreshing prices, calculating health factors) execute the vulnerable code path

4. **Detection Difficulty**: The protocol cannot detect when EMA confidence is too wide since it never checks this value, unlike the spot price where invalid confidence returns `None`.

### Recommendation

**Implement EMA Confidence and Staleness Validation:**

Modify `get_pyth_price_and_identifier()` to validate the EMA price's confidence interval and staleness similar to the spot price:

```move
public fun get_pyth_price_and_identifier(
    price_info_obj: &PriceInfoObject,
    clock: &Clock,
): (Option<Decimal>, Option<Decimal>, PriceIdentifier) {
    let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
    let price_feed = price_info::get_price_feed(&price_info);
    let price_identifier = price_feed::get_price_identifier(price_feed);

    // Validate EMA price
    let ema_price_raw = price_feed::get_ema_price(price_feed);
    let ema_price_mag = i64::get_magnitude_if_positive(&price::get_price(&ema_price_raw));
    let ema_conf = price::get_conf(&ema_price_raw);
    
    let ema_price = if (ema_conf * MIN_CONFIDENCE_RATIO > ema_price_mag) {
        option::none()
    } else {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (cur_time_s > price::get_timestamp(&ema_price_raw) && 
            cur_time_s - price::get_timestamp(&ema_price_raw) > MAX_STALENESS_SECONDS) {
            option::none()
        } else {
            option::some(parse_price_to_decimal(ema_price_raw))
        }
    };

    // Validate spot price (existing logic)
    let price = price_feed::get_price(price_feed);
    // ... existing validation ...
    
    (spot_price_option, ema_price, price_identifier)
}
```

**Update Reserve Price Handling:**

Modify `update_price()` and `create_reserve()` to handle cases where EMA price validation fails:

- Fall back to spot price for bounds if EMA is invalid
- Or return error if both spot and EMA fail validation
- Document the fallback behavior clearly

**Add Test Cases:**

1. Test with high EMA confidence intervals (>10% of price)
2. Test with stale EMA timestamps
3. Test that price bounds correctly handle missing EMA data
4. Test health factor calculations with only spot price available

### Proof of Concept

**Initial State:**
- User has a Suilend obligation with deposits and borrows
- Market experiences high volatility
- Pyth oracle's EMA confidence interval widens to 15% (exceeds MIN_CONFIDENCE_RATIO of 10%)
- Spot price confidence remains valid at 5%

**Exploitation Sequence:**

1. **Price Update**: Protocol calls `refresh_reserve_price()` which invokes `update_price()` on the reserve
   
2. **Oracle Query**: `get_pyth_price_and_identifier()` is called:
   - Spot price: $100, confidence: $5 (5%) → VALID, returned in Option
   - EMA price: $95, confidence: $14.25 (15%) → Should be INVALID but is returned anyway

3. **Price Bounds Calculation**:
   - `price_lower_bound` = min($100, $95) = $95
   - Should be just $100 if EMA were properly rejected

4. **Health Factor Impact**: User's obligation is refreshed:
   - Deposit: 10,000 tokens valued at lower bound
   - `allowed_borrow_value_usd` = 10,000 × $95 × 0.8 (LTV) = $760,000
   - Should be: 10,000 × $100 × 0.8 = $800,000
   - **Result**: User's borrowing power is incorrectly reduced by $40,000

5. **False Liquidation**: If user has borrowed $780,000:
   - With unreliable EMA: $780,000 > $760,000 → Position appears unhealthy → LIQUIDATED
   - With proper validation: $780,000 < $800,000 → Position is healthy → SAFE

**Expected vs Actual:**
- **Expected**: EMA with 15% confidence is rejected, only spot price ($100) is used for bounds
- **Actual**: EMA with 15% confidence is accepted, creates artificially low price bound ($95), causes incorrect liquidation

**Success Condition**: User's healthy position is incorrectly liquidated due to unvalidated wide-confidence EMA price being used in health calculations.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L19-52)
```text
    public fun get_pyth_price_and_identifier(
        price_info_obj: &PriceInfoObject,
        clock: &Clock,
    ): (Option<Decimal>, Decimal, PriceIdentifier) {
        let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
        let price_feed = price_info::get_price_feed(&price_info);
        let price_identifier = price_feed::get_price_identifier(price_feed);

        let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));

        let price = price_feed::get_price(price_feed);
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let conf = price::get_conf(&price);

        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };

        // check current sui time against pythnet publish time. there can be some issues that arise because the
        // timestamps are from different sources and may get out of sync, but that's why we have a fallback oracle
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };

        let spot_price = parse_price_to_decimal(price);
        (option::some(spot_price), ema_price, price_identifier)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L253-259)
```text
    public fun price_lower_bound<P>(reserve: &Reserve<P>): Decimal {
        min(reserve.price, reserve.smoothed_price)
    }

    public fun price_upper_bound<P>(reserve: &Reserve<P>): Decimal {
        max(reserve.price, reserve.smoothed_price)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L469-477)
```text
                // usd borrow limit
                usd_to_token_amount_lower_bound(
                    reserve,
                    saturating_sub(
                        decimal::from(borrow_limit_usd(config(reserve))),
                        market_value_upper_bound(reserve, reserve.borrowed_amount)
                    )
                )
            )
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-592)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
        reserve.price_last_update_timestamp_s = clock::timestamp_ms(clock) / 1000;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L754-758)
```text
        let total_supply_usd = market_value_upper_bound(reserve, total_supply);
        assert!(
            le(total_supply_usd, decimal::from(deposit_limit_usd(config(reserve)))), 
            EDepositLimitExceeded
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L197-211)
```text
            let market_value_lower_bound = reserve::ctoken_market_value_lower_bound(
                deposit_reserve,
                deposit.deposited_ctoken_amount,
            );

            deposit.market_value = market_value;
            deposited_value_usd = add(deposited_value_usd, market_value);
            allowed_borrow_value_usd =
                add(
                    allowed_borrow_value_usd,
                    mul(
                        market_value_lower_bound,
                        open_ltv(config(deposit_reserve)),
                    ),
                );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L246-268)
```text
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
            weighted_borrowed_value_upper_bound_usd =
                add(
                    weighted_borrowed_value_upper_bound_usd,
                    mul(
                        market_value_upper_bound,
                        borrow_weight(config(borrow_reserve)),
                    ),
                );
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L42-89)
```text
public(package) fun parse_suilend_obligation<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &LendingMarket<ObligationType>,
    clock: &Clock,
): u256 {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());

    let mut total_deposited_value_usd = 0;
    let mut total_borrowed_value_usd = 0;
    let reserves = lending_market.reserves();

    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```
