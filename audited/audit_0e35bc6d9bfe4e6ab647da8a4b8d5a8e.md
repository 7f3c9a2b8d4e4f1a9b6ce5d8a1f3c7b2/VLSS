### Title
Self-Liquidation Allows Users to Avoid 90% of Liquidation Penalties

### Summary
The `base_liquidation_call()` function does not prevent users from self-liquidating by setting `executor = liquidate_user`. This allows unhealthy borrowers to act as their own liquidators, capturing the liquidation bonus meant for external parties and reducing their penalty from the full bonus amount to only the treasury portion—a 90% reduction in liquidation costs.

### Finding Description

The vulnerability exists in the `base_liquidation_call()` function which accepts separate `executor` and `liquidate_user` parameters without validating that they must be different addresses. [1](#0-0) 

The function allows the `executor` to deposit debt balance and receive the liquidated collateral plus bonus: [2](#0-1) 

The only validations performed are in `execute_liquidate()` which checks that the liquidated user has loans, has collateral, and is unhealthy—but never validates that executor ≠ liquidate_user: [3](#0-2) 

The `validate_liquidate()` function only checks coin types and amounts, with no address validation: [4](#0-3) 

The liquidation calculation splits the bonus between executor and treasury based on the `treasury_factor`: [5](#0-4) 

With typical parameters (5% liquidation bonus, 10% treasury factor), the executor receives 4.5% while treasury receives 0.5%. In self-liquidation, the user captures the 4.5% executor bonus themselves.

### Impact Explanation

**Quantified Impact:**
With standard protocol parameters (5% liquidation bonus, 10% treasury factor):
- Normal liquidation: User loses 5% of liquidated collateral value (4.5% to liquidator + 0.5% to treasury)
- Self-liquidation: User loses only 0.5% to treasury
- **Penalty reduction: 90%**

**Concrete Harm:**
1. **Economic Loss to Protocol**: Liquidation penalties are designed to discourage risky borrowing and compensate the protocol/liquidators. Self-liquidation allows users to retain 90% of what should be lost.

2. **Undermined Incentive Structure**: External liquidators lose motivation to monitor positions since users can front-run them with self-liquidations, keeping the bonus themselves.

3. **Systemic Risk**: If users know they can avoid penalties through self-liquidation, they may take on more risk, increasing protocol insolvency risk during market downturns.

**Affected Parties:**
- Protocol treasury: Loses 90% of expected liquidation revenue
- External liquidators: Lose liquidation opportunities and rewards
- Protocol stability: Reduced deterrent against risky borrowing behavior

**Severity Justification:** HIGH - This directly subverts a core security mechanism (liquidation penalties) with measurable economic impact and is trivially exploitable by any user.

### Likelihood Explanation

**Attacker Capabilities:**
Any user with an unhealthy position can execute this attack. No special privileges, knowledge, or resources required beyond:
1. Having a lending position that becomes unhealthy (health factor < 1)
2. Access to enough debt tokens to perform the liquidation (which they can obtain through normal means)

**Attack Complexity:** 
Extremely low. The attack simply requires calling the liquidation functions with the attacker's own address as both executor and liquidate_user: [6](#0-5) 

**Feasibility Conditions:**
- User position becomes unhealthy (common during market volatility)
- User has access to debt tokens (can borrow from other protocols, use flash loans, or use their own funds)
- No special timing or MEV requirements

**Economic Rationality:**
Highly rational for any user facing liquidation. Example with $1000 liquidation:
- Normal liquidation loss: $50 (5%)
- Self-liquidation loss: $5 (0.5%)
- **Savings: $45 per liquidation event**

For larger positions (e.g., $100,000), savings would be $4,500—a massive incentive.

**Probability:** VERY HIGH - Every rational user facing liquidation would attempt this to minimize losses.

### Recommendation

**Code-Level Mitigation:**
Add an explicit check in `base_liquidation_call()` to prevent self-liquidation:

```move
fun base_liquidation_call<DebtCoinType, CollateralCoinType>(
    clock: &Clock,
    oracle: &PriceOracle,
    storage: &mut Storage,
    debt_asset: u8,
    debt_pool: &mut Pool<DebtCoinType>,
    debt_balance: Balance<DebtCoinType>,
    collateral_asset: u8,
    collateral_pool: &mut Pool<CollateralCoinType>,
    executor: address,
    liquidate_user: address
): (Balance<DebtCoinType>, Balance<CollateralCoinType>) {
    storage::when_not_paused(storage);
    storage::version_verification(storage);
    
    // ADD THIS CHECK:
    assert!(executor != liquidate_user, error::self_liquidation_not_allowed());
    
    // ... rest of function
}
```

**Invariant Check:**
Enforce that `executor ≠ liquidate_user` in all liquidation flows.

**Test Cases:**
1. Test that self-liquidation attempt reverts with appropriate error
2. Test that normal external liquidation still works correctly
3. Test edge cases with AccountCap-based liquidations to ensure the check applies to all entry points

### Proof of Concept

**Initial State:**
- User has 1000 USDC collateral deposited
- User has 700 USDC debt
- Market moves, user's health factor drops below 1.0 (becomes unhealthy)
- Liquidation parameters: 35% liquidation ratio, 5% bonus, 10% treasury factor

**Self-Liquidation Steps:**

1. **User prepares debt tokens**: User obtains 245 USDC (35% of 700) through any means (own funds, flash loan, borrow from another protocol)

2. **User calls liquidation as executor**: User invokes:
```
liquidation<USDC, USDC>(
    clock,
    oracle,
    storage,
    debt_asset: USDC_ID,
    debt_pool,
    debt_coin: 245 USDC,
    collateral_asset: USDC_ID,
    collateral_pool,
    liquidate_user: USER_ADDRESS,  // User's own address
    liquidate_amount: 245,
    ctx
)
```

3. **Execution flow**: 
   - Function calls `base_liquidation_call()` with `executor = USER_ADDRESS` and `liquidate_user = USER_ADDRESS`
   - No check prevents this
   - Liquidation proceeds normally

**Expected vs Actual Result:**

**Expected (with protection):** Transaction should revert with "self-liquidation not allowed" error

**Actual (current vulnerable state):**
- User provides: 245 USDC debt payment
- User receives back: 245 USDC collateral + 11.025 USDC bonus (4.5% of 245) = 256.025 USDC
- Treasury receives: 1.225 USDC (0.5% of 245)
- User's position updated: 
  - Collateral reduced by 257.25 USDC (245 + 11.025 + 1.225)
  - Debt reduced by 245 USDC
- **Net effect**: User spent 245, received 256.025, lost 257.25 from position = net loss of only 1.225 USDC (0.5%) instead of 12.25 USDC (5%)

**Success Condition:** User successfully self-liquidates and reduces penalty from 5% to 0.5%, keeping the 4.5% executor bonus that should have gone to an external liquidator.

### Notes

The vulnerability is present in all liquidation entry points that ultimately call `base_liquidation_call()`, including the `liquidation()` and `liquidation_non_entry()` friend functions. The issue fundamentally stems from treating the executor and liquidated user as independent parties without enforcing that constraint.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L361-372)
```text
        let (_excess_balance, _bonus_balance) = base_liquidation_call(
            clock,
            oracle,
            storage,
            debt_asset,
            debt_pool,
            debt_balance,
            collateral_asset,
            collateral_pool,
            sender,
            liquidate_user
        );
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L408-419)
```text
    fun base_liquidation_call<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_balance: Balance<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        executor: address,
        liquidate_user: address
    ): (Balance<DebtCoinType>, Balance<CollateralCoinType>) {
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L424-447)
```text
        pool::deposit_balance(debt_pool, debt_balance, executor);

        let normal_debt_amount = pool::normal_amount(debt_pool, debt_amount);
        let (
            normal_obtainable_amount,
            normal_excess_amount,
            normal_treasury_amount
        ) = logic::execute_liquidate<DebtCoinType, CollateralCoinType>(
            clock,
            oracle,
            storage,
            liquidate_user,
            collateral_asset,
            debt_asset,
            (normal_debt_amount as u256)
        );

        // The treasury balance
        let treasury_amount = pool::unnormal_amount(collateral_pool, (normal_treasury_amount as u64));
        pool::deposit_treasury(collateral_pool, treasury_amount);

        // The total collateral balance = collateral + bonus
        let obtainable_amount = pool::unnormal_amount(collateral_pool, (normal_obtainable_amount as u64));
        let obtainable_balance = pool::withdraw_balance(collateral_pool, obtainable_amount, executor);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L203-212)
```text
        assert!(is_loan(storage, debt_asset, user), error::user_have_no_loan());
        // check if the user's liquidated assets are collateralized
        assert!(is_collateral(storage, collateral_asset, user), error::user_have_no_collateral());

        update_state_of_all(clock, storage);

        validation::validate_liquidate<CoinType, CollateralCoinType>(storage, debt_asset, collateral_asset, amount);

        // Check the health factor of the user
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L614-622)
```text
        let total_bonus_value = ray_math::ray_mul(liquidable_value, liquidation_bonus);
        let treasury_value = ray_math::ray_mul(total_bonus_value, treasury_factor);
        let executor_bonus_value = total_bonus_value - treasury_value;

        let total_liquidable_amount_in_collateral = calculator::calculate_amount(clock, oracle, liquidable_value, collateral_asset_oracle_id);
        let total_liquidable_amount_in_debt = calculator::calculate_amount(clock, oracle, liquidable_value, debt_asset_oracle_id);
        let executor_bonus_amount_in_collateral = calculator::calculate_amount(clock, oracle, executor_bonus_value, collateral_asset_oracle_id);
        let treasury_amount_in_collateral = calculator::calculate_amount(clock, oracle, treasury_value, collateral_asset_oracle_id);
        let executor_excess_repayment_amount = calculator::calculate_amount(clock, oracle, excess_value, debt_asset_oracle_id);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L81-85)
```text
    public fun validate_liquidate<LoanCointype, CollateralCoinType>(storage: &mut Storage, debt_asset: u8, collateral_asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<LoanCointype>()) == storage::get_coin_type(storage, debt_asset), error::invalid_coin_type());
        assert!(type_name::into_string(type_name::get<CollateralCoinType>()) == storage::get_coin_type(storage, collateral_asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount())
    }
```
