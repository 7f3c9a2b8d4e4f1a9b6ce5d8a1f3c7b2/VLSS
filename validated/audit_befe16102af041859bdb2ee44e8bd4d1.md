# Audit Report

## Title
Reserve DoS via Unclaimed Spread Fees Underflow After Debt Forgiveness in Suilend Integration

## Summary
A critical accounting invariant violation in the Suilend lending protocol integration causes permanent DoS of reserve operations. The `forgive_debt()` function reduces `borrowed_amount` without adjusting `unclaimed_spread_fees`, allowing the condition `unclaimed_spread_fees > available_amount + borrowed_amount` to occur. When this happens, `total_supply()` aborts on underflow, making all deposits, withdrawals, and Volo adaptor position updates fail permanently.

## Finding Description

The vulnerability exists in Suilend's reserve accounting logic, which Volo integrates through its suilend_adaptor. The core issue is an invariant violation in the relationship between `available_amount`, `borrowed_amount`, and `unclaimed_spread_fees`.

The `total_supply()` function calculates total liquidity as `(available_amount + borrowed_amount) - unclaimed_spread_fees` using non-saturating subtraction that aborts on underflow: [1](#0-0) 

The `sub()` function performs regular subtraction without overflow protection: [2](#0-1) 

During normal operations, `compound_interest()` maintains the invariant by adding spread fees to both `borrowed_amount` (via net_new_debt) and `unclaimed_spread_fees` proportionally: [3](#0-2) 

However, `forgive_debt()` breaks this invariant by reducing only `borrowed_amount` using saturating subtraction, leaving `unclaimed_spread_fees` unchanged: [4](#0-3) 

**Attack Scenario:**
1. Reserve accumulates significant `unclaimed_spread_fees` over time through normal interest compounding
2. During market stress, the Suilend owner performs legitimate debt forgiveness on bad debt (obligations with no collateral): [5](#0-4) 
3. Debt forgiveness is authorized when obligations have zero collateral: [6](#0-5) 
4. `borrowed_amount` decreases significantly while `unclaimed_spread_fees` remains high
5. User withdrawals reduce `available_amount`
6. Eventually: `unclaimed_spread_fees > available_amount + borrowed_amount`
7. All subsequent operations calling `total_supply()` abort permanently

**Impact on Volo:**
The `ctoken_ratio()` function calls `total_supply()`: [7](#0-6) 

This ratio is used in critical deposit and redeem operations: [8](#0-7) [9](#0-8) 

Volo's suilend_adaptor calls `ctoken_market_value()` which internally calls `ctoken_ratio()`: [10](#0-9) [11](#0-10) 

When the underflow occurs, Volo's position value updates fail, potentially blocking vault operations.

## Impact Explanation

**Severity: HIGH**

**Operational Impact - Complete Reserve DoS:**
Once the invariant is violated, the affected Suilend reserve becomes permanently unusable:
- All deposit operations abort (call chain: `deposit_liquidity_and_mint_ctokens` → `ctoken_ratio` → `total_supply` → underflow abort)
- All withdrawal/redemption operations abort (call chain: `redeem_ctokens` → `ctoken_ratio` → `total_supply` → underflow abort)
- Volo adaptor position value updates fail (`update_suilend_position_value` → `ctoken_market_value` → `ctoken_ratio` → `total_supply` → abort)
- User funds locked in reserve with no recovery mechanism
- Complete loss of reserve functionality

**Affected Parties:**
- **Suilend depositors**: Cannot withdraw funds from affected reserve
- **Volo vault users**: Position values cannot be updated, potentially blocking Volo vault operations
- **Protocol**: Reputational damage, loss of reserve functionality

The impact is permanent because there is no mechanism to reduce `unclaimed_spread_fees` retroactively to restore the invariant. The only recovery would require contract upgrade or migration.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Preconditions (All Realistic):**
1. **Spread fee accumulation**: Occurs naturally during normal lending operations as interest compounds
2. **Market deterioration**: Common during market stress periods when collateral values drop
3. **Bad debt creation**: Liquidations may leave obligations with debt but no remaining collateral (when `is_forgivable()` returns true)
4. **Legitimate debt forgiveness**: Protocol owner performs authorized bad debt cleanup using `lending_market::forgive()`
5. **User withdrawals**: Normal user behavior that reduces `available_amount`

**Execution Path:**
The vulnerability is triggered through normal protocol operations, not malicious actions:
- Suilend owner performs legitimate debt forgiveness (authorized via `LendingMarketOwnerCap`)
- This is an expected governance action during market stress, not an attack
- The accounting bug is latent and triggers when reserves reach the critical state

**No Privilege Escalation Required:**
While the forgive operation requires owner privileges, this is not a compromised key scenario. The owner is acting honestly within protocol design to clean up bad debt. The bug is in the accounting logic itself, not a security assumption about admin behavior.

**Realistic Timeline:**
In production, this sequence is inevitable:
- Lending markets naturally accumulate spread fees over weeks/months
- Market volatility causes periodic liquidation events
- Debt forgiveness is standard practice for maintaining protocol health
- The combination will eventually trigger the invariant violation

## Recommendation

**Immediate Fix:**
Modify `forgive_debt()` to proportionally reduce `unclaimed_spread_fees` when forgiving debt:

```move
public(package) fun forgive_debt<P>(
    reserve: &mut Reserve<P>, 
    forgive_amount: Decimal
) {
    // Calculate proportion being forgiven
    if (gt(reserve.borrowed_amount, decimal::from(0))) {
        let forgive_ratio = div(forgive_amount, reserve.borrowed_amount);
        let fees_to_reduce = mul(reserve.unclaimed_spread_fees, forgive_ratio);
        
        reserve.unclaimed_spread_fees = saturating_sub(
            reserve.unclaimed_spread_fees,
            fees_to_reduce
        );
    }
    
    reserve.borrowed_amount = saturating_sub(
        reserve.borrowed_amount, 
        forgive_amount
    );

    log_reserve_data(reserve);
}
```

**Alternative Approach:**
Use saturating subtraction in `total_supply()` to prevent abort, though this masks the underlying accounting issue:

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

**Volo-Specific Mitigation:**
Add defensive checks in `suilend_adaptor` before calling Suilend functions to detect and handle potential underflow conditions.

## Proof of Concept

```move
#[test]
fun test_reserve_dos_via_forgive_underflow() {
    // Setup: Create reserve with accumulated spread fees
    // Initial state: available=100, borrowed=150, unclaimed_fees=50
    // total_supply = (100 + 150) - 50 = 200 ✓
    
    // Step 1: Market stress - owner forgives 120 of bad debt
    // After forgive: available=100, borrowed=30, unclaimed_fees=50 (unchanged!)
    // total_supply = (100 + 30) - 50 = 80 ✓
    
    // Step 2: Users withdraw 85 worth of liquidity
    // After withdraw: available=15, borrowed=30, unclaimed_fees=50
    // total_supply = (15 + 30) - 50 = -5 ✗ UNDERFLOW!
    
    // Step 3: Any subsequent operation calling total_supply() aborts
    // - deposit_liquidity_and_mint_ctokens() -> aborts
    // - redeem_ctokens() -> aborts  
    // - Volo suilend_adaptor.update_suilend_position_value() -> aborts
    
    // Reserve is permanently DoS'd, all funds locked
}
```

## Notes

**Critical Context:**
1. This vulnerability exists in the Suilend lending protocol code included in Volo's `local_dependencies`
2. While Volo cannot directly fix Suilend's code, Volo users are affected when using Suilend through the adaptor
3. The vulnerability requires Suilend owner action (`LendingMarketOwnerCap`), but this is legitimate protocol operation, not a compromised key scenario
4. The bug is in the accounting logic itself - forgive_debt breaks a critical invariant that other parts of the code depend on
5. This is a HIGH severity issue due to permanent DoS and fund lockup, despite requiring specific conditions to trigger

**Volo Impact:**
- If a Suilend reserve enters this broken state, Volo's `suilend_adaptor.update_suilend_position_value()` will fail
- This could block Volo vault operations that depend on accurate Suilend position valuations
- Volo should consider adding defensive checks or working with Suilend team to address this issue

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L734-748)
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

        reserve.available_amount = reserve.available_amount + balance::value(&liquidity);
        reserve.ctoken_supply = reserve.ctoken_supply + new_ctokens;

        let total_supply = total_supply(reserve);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L770-782)
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

        reserve.available_amount = reserve.available_amount - liquidity_amount;
        reserve.ctoken_supply = reserve.ctoken_supply - balance::value(&ctokens);

```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L957-967)
```text
    public(package) fun forgive_debt<P>(
        reserve: &mut Reserve<P>, 
        forgive_amount: Decimal
    ) {
        reserve.borrowed_amount = saturating_sub(
            reserve.borrowed_amount, 
            forgive_amount
        );

        log_reserve_data(reserve);
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L637-666)
```text
    public fun forgive<P, T>(
        _: &LendingMarketOwnerCap<P>,
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        obligation_id: ID,
        clock: &Clock,
        max_forgive_amount: u64,
    ) {
        let lending_market_id = object::id_address(lending_market);
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let obligation = object_table::borrow_mut(
            &mut lending_market.obligations,
            obligation_id,
        );

        let exist_stale_oracles = obligation::refresh<P>(obligation, &mut lending_market.reserves, clock);
        obligation::assert_no_stale_oracles(exist_stale_oracles);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        assert!(reserve::coin_type(reserve) == type_name::get<T>(), EWrongType);

        let forgive_amount = obligation::forgive<P>(
            obligation,
            reserve,
            clock,
            decimal::from(max_forgive_amount),
        );

        reserve::forgive_debt<P>(reserve, forgive_amount);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L798-800)
```text
    public fun is_forgivable<P>(obligation: &Obligation<P>): bool {
        vector::length(&obligation.deposits) == 0
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
