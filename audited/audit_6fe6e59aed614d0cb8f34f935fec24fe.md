### Title
Missing Pool Liquidity Validation in Liquidation Causes Denial of Service

### Summary
The `base_liquidation_call` function attempts to withdraw collateral from pools without validating available liquidity beforehand. When collateral pools are heavily borrowed by other users, liquidations fail with generic abort errors, causing denial of service on the liquidation mechanism even when liquidations are otherwise valid. This prevents timely liquidation of unhealthy positions and can lead to bad debt accumulation.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The liquidation validation function lacks pool liquidity checks that exist in other withdrawal operations.

The liquidation flow proceeds as follows:
1. `logic::execute_liquidate` calculates liquidation amounts based on the user's **accounting balance** in Storage [2](#0-1) 

2. Line 226 decreases the liquidated user's supply_balance in Storage (accounting only) [3](#0-2) 

3. Lines 447 and 451 attempt to withdraw **physical tokens** from pools [1](#0-0) 

The critical flaw: `validate_liquidate` only checks coin types and non-zero amounts [4](#0-3) 

In contrast, `validate_withdraw` explicitly checks pool liquidity: `assert!(scale_supply_balance >= scale_borrow_balance + amount, error::insufficient_balance())` [5](#0-4) 

**Why Protections Fail:**
The `pool::withdraw_balance` function uses `balance::split` which aborts on insufficient balance [6](#0-5) . However, this abort happens AFTER:
- All state updates in Storage
- Gas consumption for liquidation calculations
- No early liquidity check

**Execution Path:**
In a lending protocol, when User A deposits 100 tokens and User B borrows 80, the pool has only 20 physical tokens remaining while User A's supply_balance in Storage still shows 100. If User A becomes liquidatable for 50 tokens, line 447 will abort because the pool lacks sufficient liquidity.

### Impact Explanation

**Harm Caused:**
- **Liquidation DoS**: Valid liquidations fail when collateral pools are heavily utilized (>80% borrowed), which is common in efficient lending markets
- **Bad Debt Accumulation**: Unhealthy positions cannot be liquidated timely, allowing debt to grow beyond collateral value as prices move
- **Gas Waste**: Liquidators spend gas on failed transactions with no early failure indication
- **Protocol Insolvency Risk**: Accumulation of under-collateralized debt threatens protocol solvency

**Who Is Affected:**
- Liquidators waste gas on consistently failing liquidation attempts
- Protocol accumulates bad debt from unliquidatable positions
- Healthy users bear losses when protocol becomes insolvent

**Severity Justification:** High severity due to:
- Core protocol function (liquidations) can be blocked
- Common occurrence (high pool utilization is normal)
- Direct path to protocol insolvency
- No workaround available to liquidators

### Likelihood Explanation

**Attacker Capabilities:** No attacker needed - natural market conditions trigger this issue. Any user can borrow from pools, reducing available liquidity.

**Attack Complexity:** Trivial - occurs automatically when:
1. Pool utilization reaches >80% (standard in DeFi)
2. Any user becomes liquidatable
3. Liquidator attempts liquidation

**Feasibility Conditions:**
- Reachable via public `liquidation` and `liquidation_non_entry` functions [7](#0-6) 
- No special permissions required
- Normal DeFi usage patterns cause high pool utilization
- Common in bull markets when borrowing demand is high

**Probability:** HIGH - This will occur repeatedly during normal protocol operation when pools are efficiently utilized.

### Recommendation

**Code-Level Mitigation:**
Add liquidity validation to `validate_liquidate` matching the check in `validate_withdraw`:

```move
public fun validate_liquidate<LoanCointype, CollateralCoinType>(
    storage: &mut Storage, 
    debt_asset: u8, 
    collateral_asset: u8, 
    amount: u256,
    liquidation_collateral_amount: u256  // Add parameter
) {
    // Existing checks...
    assert!(type_name::into_string(type_name::get<LoanCointype>()) == storage::get_coin_type(storage, debt_asset), error::invalid_coin_type());
    assert!(type_name::into_string(type_name::get<CollateralCoinType>()) == storage::get_coin_type(storage, collateral_asset), error::invalid_coin_type());
    assert!(amount != 0, error::invalid_amount());
    
    // Add liquidity check for collateral pool
    let (collateral_supply, collateral_borrow) = storage::get_total_supply(storage, collateral_asset);
    let (collateral_supply_index, collateral_borrow_index) = storage::get_index(storage, collateral_asset);
    let scale_collateral_supply = ray_math::ray_mul(collateral_supply, collateral_supply_index);
    let scale_collateral_borrow = ray_math::ray_mul(collateral_borrow, collateral_borrow_index);
    
    assert!(scale_collateral_supply >= scale_collateral_borrow + liquidation_collateral_amount, 
            error::insufficient_balance());
}
```

**Invariant Checks:**
- Pool available liquidity >= liquidation collateral + bonus + treasury amounts
- Early validation prevents wasted gas and provides clear error messages

**Test Cases:**
1. Test liquidation when collateral pool is 90% utilized - should fail with clear error
2. Test liquidation when collateral pool has sufficient liquidity - should succeed
3. Test liquidation amount calculation includes bonus and treasury in liquidity check

### Proof of Concept

**Required Initial State:**
1. Pool has total supply of 1000 tokens (User A deposits 1000)
2. User B borrows 900 tokens (90% utilization)
3. Pool now has 100 physical tokens available
4. User A's position becomes unhealthy (debt value > collateral value * liquidation threshold)

**Transaction Steps:**
1. Liquidator calls `liquidation` function to liquidate 200 tokens worth of User A's collateral
2. `execute_liquidate` calculates: liquidation amount = 200, bonus = 10, total = 210 tokens needed
3. Function validates User A is unhealthy ✓
4. Function updates Storage balances (decreases User A's supply by 210) ✓
5. Line 447 attempts `pool::withdraw_balance(collateral_pool, 210, executor)`
6. `balance::split` aborts because pool only has 100 tokens available ✗

**Expected vs Actual:**
- **Expected**: Early validation catches insufficient liquidity with clear error before state changes
- **Actual**: Transaction aborts at line 447 with generic abort after consuming gas and updating state (which then reverts)

**Atomicity Answer:** 
Line 447 (collateral withdrawal) executes first and fails if collateral_pool has insufficient funds. Line 451 (excess debt withdrawal) executes second and would fail if debt_pool lacks funds. Sui Move's transaction model ensures atomicity - all state changes revert on abort. However, gas is still consumed and liquidators receive no advance warning of failure.

**Notes**

This vulnerability stems from an inconsistency in validation patterns across the protocol. While `validate_withdraw` and `validate_borrow` both check available pool liquidity before attempting operations, `validate_liquidate` omits this critical check. The issue is exacerbated because liquidations typically need to move larger amounts (including bonuses and penalties) compared to normal withdrawals, making liquidity exhaustion more likely during liquidation scenarios.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L345-405)
```text
    public(friend) fun liquidation<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_coin: Coin<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        liquidate_user: address,
        liquidate_amount: u64,
        ctx: &mut TxContext
    ): (Balance<CollateralCoinType>, Balance<DebtCoinType>) {
        let sender = tx_context::sender(ctx);
        let debt_balance = utils::split_coin_to_balance(debt_coin, liquidate_amount, ctx);

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

        (_bonus_balance, _excess_balance)
    }

    public(friend) fun liquidation_non_entry<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_balance: Balance<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        liquidate_user: address,
        ctx: &mut TxContext
    ): (Balance<CollateralCoinType>, Balance<DebtCoinType>) {
        let sender = tx_context::sender(ctx);

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

        (_bonus_balance, _excess_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L447-451)
```text
        let obtainable_balance = pool::withdraw_balance(collateral_pool, obtainable_amount, executor);

        // The excess balance
        let excess_amount = pool::unnormal_amount(debt_pool, (normal_excess_amount as u64));
        let excess_balance = pool::withdraw_balance(debt_pool, excess_amount, executor);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L193-239)
```text
    public(friend) fun execute_liquidate<CoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        user: address,
        collateral_asset: u8,
        debt_asset: u8,
        amount: u256
    ): (u256, u256, u256) {
        // check if the user has loan on this asset
        assert!(is_loan(storage, debt_asset, user), error::user_have_no_loan());
        // check if the user's liquidated assets are collateralized
        assert!(is_collateral(storage, collateral_asset, user), error::user_have_no_collateral());

        update_state_of_all(clock, storage);

        validation::validate_liquidate<CoinType, CollateralCoinType>(storage, debt_asset, collateral_asset, amount);

        // Check the health factor of the user
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());

        let (
            liquidable_amount_in_collateral,
            liquidable_amount_in_debt,
            executor_bonus_amount,
            treasury_amount,
            executor_excess_amount,
            is_max_loan_value,
        ) = calculate_liquidation(clock, storage, oracle, user, collateral_asset, debt_asset, amount);

        // Reduce the liquidated user's loan assets
        decrease_borrow_balance(storage, debt_asset, user, liquidable_amount_in_debt);
        // Reduce the liquidated user's supply assets
        decrease_supply_balance(storage, collateral_asset, user, liquidable_amount_in_collateral + executor_bonus_amount + treasury_amount);

        if (is_max_loan_value) {
            storage::remove_user_loans(storage, debt_asset, user);
        };

        update_interest_rate(storage, collateral_asset);
        update_interest_rate(storage, debt_asset);

        emit_state_updated_event(storage, collateral_asset, user);
        emit_state_updated_event(storage, debt_asset, user);

        (liquidable_amount_in_collateral + executor_bonus_amount, executor_excess_amount, treasury_amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L45-45)
```text
        assert!(scale_supply_balance >= scale_borrow_balance + amount, error::insufficient_balance())
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L81-85)
```text
    public fun validate_liquidate<LoanCointype, CollateralCoinType>(storage: &mut Storage, debt_asset: u8, collateral_asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<LoanCointype>()) == storage::get_coin_type(storage, debt_asset), error::invalid_coin_type());
        assert!(type_name::into_string(type_name::get<CollateralCoinType>()) == storage::get_coin_type(storage, collateral_asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L125-140)
```text
    public(friend) fun withdraw_balance<CoinType>(pool: &mut Pool<CoinType>, amount: u64, user: address): Balance<CoinType> {
        if (amount == 0) {
            let _zero = balance::zero<CoinType>();
            return _zero
        };

        let _balance = balance::split(&mut pool.balance, amount);
        emit(PoolWithdraw {
            sender: user,
            recipient: user,
            amount: amount,
            pool: type_name::into_string(type_name::get<CoinType>()),
        });

        return _balance
    }
```
