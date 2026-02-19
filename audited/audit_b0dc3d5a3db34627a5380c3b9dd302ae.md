### Title
Unvalidated Pyth EMA Price Enables Collateral Over-Withdrawal in Suilend Positions

### Summary
The Pyth EMA price is stored and used in Suilend reserve price bounds without any staleness or confidence validation, while the spot price has strict checks. When the EMA becomes stale and deviates significantly from spot price, attackers can exploit `price_lower_bound` calculations to withdraw excessive collateral from Suilend obligations, creating undercollateralized positions and bad debt that affects Volo vault holdings.

### Finding Description

**Root Cause:**

The `get_pyth_price_and_identifier()` function retrieves the Pyth EMA price without any validation checks, unlike the spot price which undergoes confidence interval and staleness validation. [1](#0-0) 

The spot price has strict validation that can cause it to return `None`: [2](#0-1) 

However, the EMA price is **always** returned regardless of whether the spot price passes validation. This unvalidated EMA is then stored as `smoothed_price` in the reserve: [3](#0-2) 

**Vulnerable Execution Path:**

The unvalidated EMA is used to compute price bounds: [4](#0-3) 

These bounds are then used in `usd_to_token_amount_upper_bound()`, which calculates maximum withdrawable token amounts: [5](#0-4) 

This function is called during obligation withdrawal calculations: [6](#0-5) 

The vulnerability is exploitable through the public `withdraw_ctokens()` function, which any holder of an `ObligationOwnerCap` can call: [7](#0-6) 

**Volo Vault Exposure:**

Volo vault operators borrow Suilend `ObligationOwnerCap` objects during operations and can directly call Suilend's withdrawal functions. The vault's Suilend positions are stored as borrowed DeFi assets: [8](#0-7) 

### Impact Explanation

**Direct Financial Harm:**

When the EMA is stale and significantly lower than the current spot price:
- Spot price: $100 (passes validation)
- Stale EMA: $50 (no validation)
- `price_lower_bound` = min($100, $50) = $50

For a $1,000 USD withdrawal limit:
- **Correct calculation**: $1,000 / $100 = 10 tokens
- **Exploited calculation**: $1,000 / $50 = 20 tokens
- **Result**: 2x over-withdrawal of collateral

**Affected Parties:**

1. **Volo Vault:** Operators with borrowed Suilend ObligationOwnerCaps can over-withdraw collateral, leaving vault positions undercollateralized
2. **Suilend Protocol:** Creates systemic bad debt as positions become insolvent
3. **All Suilend Users:** Bad debt affects protocol health and reserve ratios
4. **Volo Depositors:** Vault total value decreases due to Suilend position losses

**Severity Justification:**

This is CRITICAL because:
- Allows direct theft/extraction of excess collateral
- Bypasses fundamental lending protocol health checks
- Creates cascading insolvency risk across the protocol
- Can occur naturally during high volatility periods when EMAs lag significantly
- Affects all Suilend integrations including Volo vault positions

### Likelihood Explanation

**Attack Complexity: LOW**

The attacker simply needs:
1. Access to a Suilend ObligationOwnerCap (obtained through normal lending operations or Volo vault operator role)
2. Wait for or identify when EMA becomes stale/divergent from spot price
3. Call standard Suilend withdrawal functions with `amount = U64_MAX` to maximize extraction

**Feasibility Conditions:**

EMA staleness/divergence occurs naturally in multiple scenarios:
- **High volatility periods**: EMAs lag behind rapid spot price movements by design
- **Oracle update delays**: Pyth network congestion or temporary outages
- **Market manipulation**: Flash crashes or pumps that EMAs don't quickly reflect
- **Natural EMA characteristics**: EMAs are smoothed averages that inherently lag spot prices

**Detection Difficulty:**

The vulnerability is difficult to detect because:
- Withdrawals appear as legitimate operations
- No on-chain validation errors occur
- EMA divergence may be temporary and seem reasonable
- Operators have legitimate access to ObligationOwnerCaps during vault operations

**Probability Assessment: HIGH**

Given that:
- EMA divergence from spot price happens regularly in volatile markets
- The vulnerability affects ALL Suilend positions system-wide
- No additional manipulation is required beyond timing
- Both malicious operators and external Suilend users can exploit it

### Recommendation

**Immediate Fix:**

Add staleness and confidence validation for EMA prices in `get_pyth_price_and_identifier()`:

1. Query EMA timestamp and confidence from Pyth oracle
2. Apply the same validation checks used for spot price:
   - Confidence interval check: `ema_conf * MIN_CONFIDENCE_RATIO <= ema_price_mag`
   - Staleness check: `current_time - ema_timestamp <= MAX_STALENESS_SECONDS`
3. If EMA fails validation, either:
   - Return `option::none()` for EMA as well
   - Fall back to spot price for both bounds
   - Use a conservative bounds calculation

**Code-Level Mitigation:**

```move
// In oracles.move, line 27, add EMA validation:
let ema_price_obj = price_feed::get_ema_price(price_feed);
let ema_price_mag = i64::get_magnitude_if_positive(&price::get_price(&ema_price_obj));
let ema_conf = price::get_conf(&ema_price_obj);
let ema_timestamp = price::get_timestamp(&ema_price_obj);

// Validate EMA confidence
if (ema_conf * MIN_CONFIDENCE_RATIO > ema_price_mag) {
    // Use spot price as fallback for bounds
    return (option::none(), parse_price_to_decimal(price), price_identifier)
};

// Validate EMA staleness
if (cur_time_s > ema_timestamp && cur_time_s - ema_timestamp > MAX_STALENESS_SECONDS) {
    // Use spot price as fallback for bounds
    return (option::none(), parse_price_to_decimal(price), price_identifier)
};

let ema_price = parse_price_to_decimal(ema_price_obj);
```

**Additional Safeguards:**

1. **Maximum divergence check**: Enforce that `|spot - ema| / spot <= MAX_DIVERGENCE_PERCENT` (e.g., 10%)
2. **Price bounds tightening**: Use min/max with safety margins to reduce exploitation window
3. **Rate limiting enhancement**: Add stricter limits during periods of high price volatility
4. **Monitoring**: Alert when EMA divergence exceeds thresholds

**Test Cases:**

1. Test withdrawal when EMA is stale (>60s old) but spot is fresh
2. Test withdrawal when EMA has low confidence but spot has high confidence
3. Test withdrawal when EMA and spot diverge by >20%
4. Verify that price bounds calculations use validated prices only
5. Verify fallback behavior when EMA validation fails

### Proof of Concept

**Initial State:**
- Suilend reserve for Asset X configured with Pyth oracle
- Current market price: $100 per token
- Attacker has Suilend obligation with $10,000 collateral deposited
- Health factor: 1.5 (healthy position)

**Attack Sequence:**

1. **Price Update Phase:**
   - Market undergoes rapid volatility
   - Spot price stabilizes at $100 (passes validation)
   - EMA lags at $50 (stale, but no validation occurs)
   - Reserve price update called: `lending_market::refresh_reserve_price()`
   - Result: `reserve.price = $100`, `reserve.smoothed_price = $50`

2. **Exploitation Phase:**
   - Attacker (or Volo operator with borrowed ObligationOwnerCap) calls:
     ```
     lending_market::withdraw_ctokens<P, T>(
       lending_market,
       reserve_array_index,
       obligation_owner_cap,
       clock,
       U64_MAX,  // Request maximum withdrawal
       ctx
     )
     ```

3. **Calculation Phase:**
   - `max_withdraw_amount()` calculates allowed withdrawal
   - Obligation has $5,000 USD excess collateral capacity
   - Calls `usd_to_token_amount_upper_bound(reserve, $5,000)`
   - Uses `price_lower_bound` = min($100, $50) = $50
   - **Expected result**: $5,000 / $100 = 50 tokens
   - **Actual result**: $5,000 / $50 = 100 tokens

4. **Outcome:**
   - Attacker withdraws 100 tokens (worth $10,000)
   - Should have only withdrawn 50 tokens (worth $5,000)
   - Position now has $5,000 excess withdrawal
   - Obligation becomes undercollateralized
   - Remaining depositors/vault positions absorb the bad debt

**Success Condition:**

The attack succeeds when:
- Withdrawn token amount > (allowed_usd_value / actual_spot_price)
- Position becomes undercollateralized despite passing health checks
- Protocol bad debt increases by the excess withdrawal value

**Notes**

This vulnerability exists in the Suilend dependency code that Volo vault integrates with. While Volo's own adaptor code (`suilend_adaptor.move`) only reads position values using spot prices and doesn't directly trigger the vulnerable withdrawal calculations, Volo is still affected because:

1. **Direct Operator Exploitation**: Volo operators who borrow Suilend ObligationOwnerCaps during vault operations have direct access to call `lending_market::withdraw_ctokens()` and can exploit this vulnerability intentionally or accidentally.

2. **Indirect Systemic Risk**: Any Suilend user (not just Volo) can exploit this to create bad debt in the Suilend protocol, which directly impacts the health and value of all Suilend positions, including those held by Volo vaults.

3. **Position Value Degradation**: When bad debt accumulates in Suilend, the vault's Suilend position values decrease, affecting total vault value and depositor returns.

The vulnerability should be fixed in the Suilend dependency to protect all integrators including Volo. The EMA validation issue violates the critical invariant that "Oracle & Valuation" systems must have proper staleness checks and bounds validation.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L27-27)
```text
        let ema_price = parse_price_to_decimal(price_feed::get_ema_price(price_feed));
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L33-48)
```text
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
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L253-255)
```text
    public fun price_lower_bound<P>(reserve: &Reserve<P>): Decimal {
        min(reserve.price, reserve.smoothed_price)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L353-364)
```text
    public fun usd_to_token_amount_upper_bound<P>(
        reserve: &Reserve<P>, 
        usd_amount: Decimal
    ): Decimal {
        div(
            mul(
                decimal::from(std::u64::pow(10, reserve.mint_decimals)),
                usd_amount
            ),
            price_lower_bound(reserve)
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-591)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L845-848)
```text
        let max_withdraw_token_amount = reserve::usd_to_token_amount_upper_bound(
            reserve,
            max_withdraw_value,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L467-492)
```text
    public fun withdraw_ctokens<P, T>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        obligation_owner_cap: &ObligationOwnerCap<P>,
        clock: &Clock,
        mut amount: u64,
        ctx: &mut TxContext,
    ): Coin<CToken<P, T>> {
        let lending_market_id = object::id_address(lending_market);
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
        assert!(amount > 0, ETooSmall);

        let obligation = object_table::borrow_mut(
            &mut lending_market.obligations,
            obligation_owner_cap.obligation_id,
        );

        let exist_stale_oracles = obligation::refresh<P>(obligation, &mut lending_market.reserves, clock);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        assert!(reserve::coin_type(reserve) == type_name::get<T>(), EWrongType);

        if (amount == U64_MAX) {
            amount =
                max_withdraw_amount<P>(lending_market.rate_limiter, obligation, reserve, clock);
        };
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L29-34)
```text
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );
```
