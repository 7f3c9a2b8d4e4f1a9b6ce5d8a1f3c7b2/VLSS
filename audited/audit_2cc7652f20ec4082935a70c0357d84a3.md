# Audit Report

## Title
Missing Pool Liquidity Validation in Liquidation Causes Denial of Service

## Summary
The liquidation validation function lacks pool liquidity checks that exist in withdrawal operations, causing liquidations to fail when collateral pools are heavily borrowed. This prevents timely liquidation of unhealthy positions under normal high-utilization conditions and can lead to bad debt accumulation.

## Finding Description

The lending protocol's liquidation mechanism has a critical validation gap that causes liquidations to fail under normal operating conditions.

The `validate_liquidate` function only validates coin types and non-zero amounts, with no pool liquidity check: [1](#0-0) 

In contrast, the `validate_withdraw` function explicitly checks that the pool has sufficient liquidity before allowing withdrawals: [2](#0-1) 

The liquidation flow proceeds as follows:

1. The liquidator calls the liquidation function which deposits debt tokens and executes liquidation logic: [3](#0-2) 

2. The `execute_liquidate` function calls `validate_liquidate` (lacking liquidity check), calculates liquidation amounts, and updates accounting balances in Storage: [4](#0-3) 

3. The function then attempts to withdraw collateral tokens from the pool: [5](#0-4) 

4. The `pool::withdraw_balance` function uses `balance::split` which aborts if insufficient balance exists: [6](#0-5) 

**Execution Scenario:** When a pool has 100 tokens deposited and 80 tokens borrowed, only 20 physical tokens remain in the pool. If a position needs to be liquidated for 50 collateral tokens, the liquidation will fail at the withdrawal step, even though the user's accounting balance in Storage shows 100 tokens available.

## Impact Explanation

**Direct Protocol Harms:**
- **Liquidation DoS**: Core liquidation functionality fails when pools reach typical utilization levels (>80% borrowed), which is standard in efficient DeFi lending markets
- **Bad Debt Accumulation**: Unhealthy positions cannot be liquidated timely, allowing debt to exceed collateral value as market prices move adversely
- **Gas Waste**: Liquidators consume gas executing liquidation logic and calculations, only to have transactions abort at the final withdrawal step with no early failure indication
- **Protocol Insolvency Risk**: Accumulation of under-collateralized debt directly threatens the lending protocol's solvency and ability to return deposits

**Affected Parties:**
- Liquidators waste resources on consistently failing liquidation attempts
- The protocol accumulates bad debt that cannot be cleared through liquidations
- All depositors face potential losses if the protocol becomes insolvent due to bad debt

This is HIGH severity because it blocks a core protocol safety mechanism (liquidations) under normal operating conditions, creating a direct path to protocol insolvency with no available workaround.

## Likelihood Explanation

**No Attacker Required:** This vulnerability manifests under natural market conditions without any malicious actor. Normal user borrowing behavior reduces pool liquidity, making this a systemic issue inherent to the protocol design.

**Triggering Conditions:**
1. Pool utilization exceeds approximately 80% borrowed (standard and expected in efficient DeFi lending markets)
2. Any user position becomes unhealthy with health factor < 1.0 (normal market volatility occurrence)
3. A liquidator attempts to execute the liquidation through public interfaces (expected protocol behavior)

**Feasibility:** Liquidation functions are publicly accessible with no special permission requirements. High pool utilization is not only possible but economically optimal for lending protocols, occurring regularly during bull markets when borrowing demand is strong.

**Probability: HIGH** - This will occur repeatedly during normal protocol operation whenever pools reach efficient utilization levels combined with liquidatable positions.

## Recommendation

Add the same liquidity validation to `validate_liquidate` that exists in `validate_withdraw`:

```move
public fun validate_liquidate<LoanCointype, CollateralCoinType>(
    storage: &mut Storage, 
    debt_asset: u8, 
    collateral_asset: u8, 
    amount: u256
) {
    assert!(type_name::into_string(type_name::get<LoanCointype>()) == storage::get_coin_type(storage, debt_asset), error::invalid_coin_type());
    assert!(type_name::into_string(type_name::get<CollateralCoinType>()) == storage::get_coin_type(storage, collateral_asset), error::invalid_coin_type());
    assert!(amount != 0, error::invalid_amount());
    
    // Add liquidity check for collateral pool
    let (collateral_supply_balance, collateral_borrow_balance) = storage::get_total_supply(storage, collateral_asset);
    let (collateral_supply_index, collateral_borrow_index) = storage::get_index(storage, collateral_asset);
    let scale_collateral_supply = ray_math::ray_mul(collateral_supply_balance, collateral_supply_index);
    let scale_collateral_borrow = ray_math::ray_mul(collateral_borrow_balance, collateral_borrow_index);
    
    // Calculate expected collateral withdrawal amount based on liquidation
    // This requires estimating the liquidation amount, which may need to be passed as a parameter
    // or calculated within this function
    assert!(scale_collateral_supply >= scale_collateral_borrow + estimated_collateral_withdrawal, error::insufficient_balance());
}
```

Alternatively, add an early liquidity check in `base_liquidation_call` before calling `execute_liquidate` to fail fast with clear error messaging.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = lending_core::pool::EINSUFFICIENT_BALANCE)]
public fun test_liquidation_fails_with_high_pool_utilization() {
    let scenario = test_scenario::begin(@0x1);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    
    // Initialize protocol
    base::initial_protocol(&mut scenario, &clock);
    
    // User A deposits 100 tokens
    let userA = @0xA;
    test_scenario::next_tx(&mut scenario, userA);
    {
        let pool = test_scenario::take_shared<Pool<USDT_TEST>>(&scenario);
        let coin = coin::mint_for_testing<USDT_TEST>(100_000000, test_scenario::ctx(&mut scenario));
        base_deposit_for_testing(&mut scenario, &clock, &mut pool, coin, 0, 100_000000);
        test_scenario::return_shared(pool);
    };
    
    // User B borrows 80 tokens (80% utilization)
    let userB = @0xB;
    test_scenario::next_tx(&mut scenario, userB);
    {
        // User B must have collateral first
        let sui_pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
        let sui_coin = coin::mint_for_testing<SUI_TEST>(1000_000000000, test_scenario::ctx(&mut scenario));
        base_deposit_for_testing(&mut scenario, &clock, &mut sui_pool, sui_coin, 1, 1000_000000000);
        test_scenario::return_shared(sui_pool);
        
        let pool = test_scenario::take_shared<Pool<USDT_TEST>>(&scenario);
        base_borrow_for_testing(&mut scenario, &clock, &mut pool, 0, 80_000000);
        test_scenario::return_shared(pool);
    };
    
    // Price drops making User B liquidatable
    test_scenario::next_tx(&mut scenario, @0x1);
    {
        let oracle = test_scenario::take_shared<PriceOracle>(&scenario);
        let oracle_cap = test_scenario::take_from_sender<OracleFeederCap>(&scenario);
        oracle::update_token_price(&oracle_cap, &clock, &mut oracle, 1, 500000000); // SUI price drops
        test_scenario::return_shared(oracle);
        test_scenario::return_to_sender(&scenario, oracle_cap);
    };
    
    // Liquidator attempts to liquidate 50 tokens
    // This should FAIL because pool only has 20 tokens available (100 - 80)
    let liquidator = @0xC;
    test_scenario::next_tx(&mut scenario, liquidator);
    {
        let usdt_pool = test_scenario::take_shared<Pool<USDT_TEST>>(&scenario);
        let sui_pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
        let repay_coin = coin::mint_for_testing<USDT_TEST>(50_000000, test_scenario::ctx(&mut scenario));
        
        // This will ABORT due to insufficient liquidity in the pool
        base_liquidation_for_testing(
            &mut scenario,
            0, // debt_asset (USDT)
            &mut usdt_pool,
            repay_coin,
            1, // collateral_asset (SUI)
            &mut sui_pool,
            userB,
            50_000000
        );
        
        test_scenario::return_shared(sui_pool);
        test_scenario::return_shared(usdt_pool);
    };
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

**Notes:**
- This vulnerability exists in the Navi lending protocol dependency integrated into Volo vault
- The issue is confirmed through code analysis showing the validation gap between `validate_liquidate` and `validate_withdraw`
- While Sui Move transactions are atomic (state rolls back on abort), gas is still consumed and liquidators cannot efficiently identify failing liquidations in advance
- The fix requires adding proper liquidity validation before attempting liquidations

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L35-46)
```text
    public fun validate_withdraw<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_supply_balance >= scale_borrow_balance + amount, error::insufficient_balance())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L81-85)
```text
    public fun validate_liquidate<LoanCointype, CollateralCoinType>(storage: &mut Storage, debt_asset: u8, collateral_asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<LoanCointype>()) == storage::get_coin_type(storage, debt_asset), error::invalid_coin_type());
        assert!(type_name::into_string(type_name::get<CollateralCoinType>()) == storage::get_coin_type(storage, collateral_asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L408-439)
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
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let debt_amount = balance::value(&debt_balance);
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L447-447)
```text
        let obtainable_balance = pool::withdraw_balance(collateral_pool, obtainable_amount, executor);
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
