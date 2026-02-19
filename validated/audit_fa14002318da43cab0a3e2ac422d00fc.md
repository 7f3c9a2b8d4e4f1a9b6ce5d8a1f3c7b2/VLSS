# Audit Report

## Title
MIN_AVAILABLE_AMOUNT Invariant Violation and DoS via rebalance_staker() Desynchronization

## Summary
The `rebalance_staker()` function withdraws all liquidity from the reserve's actual balance and stakes it, but critically fails to update the reserve's accounting field `reserve.available_amount`. This creates a dangerous desynchronization where MIN_AVAILABLE_AMOUNT invariant checks pass on the accounting level while the actual balance becomes zero, causing all subsequent borrow and redeem operations to fail.

## Finding Description

The protocol maintains two separate tracking mechanisms for reserve liquidity:
- `reserve.available_amount`: A `u64` accounting field in the Reserve struct used for invariant checks [1](#0-0) 
- `balances.available_amount`: The actual `Balance<T>` stored in a dynamic field [2](#0-1) 

Throughout the codebase, these two fields are kept synchronized. For example, when depositing liquidity, both fields are updated [3](#0-2) , and when borrowing, the accounting field is decreased before the actual balance is withdrawn [4](#0-3) .

However, the `rebalance_staker()` function breaks this invariant. The function withdraws ALL available balance from the actual Balance [5](#0-4)  and stakes it, but nowhere in the function is `reserve.available_amount` updated [6](#0-5) .

The MIN_AVAILABLE_AMOUNT constant is defined to prevent rounding attacks [7](#0-6) , and all invariant enforcement checks use the accounting field `reserve.available_amount` [8](#0-7) [9](#0-8) .

However, when fulfilling liquidity requests, the actual balance is used [10](#0-9) .

The function is publicly accessible with no access control [11](#0-10) .

**Attack Scenario:**
1. Reserve has 10,000 SUI with both `reserve.available_amount = 10000` and `balances.available_amount = Balance(10000)`
2. Anyone calls the public `rebalance_staker()` function
3. All 10,000 SUI is withdrawn from `balances.available_amount` and staked, but `reserve.available_amount` remains 10000
4. User attempts to borrow 5,000 SUI via `lending_market::borrow()` [12](#0-11) 
5. The MIN_AVAILABLE_AMOUNT check passes because it checks the stale `reserve.available_amount` value
6. `fulfill_liquidity_request` attempts to split 5,000 from `balances.available_amount` which is now empty
7. Transaction fails with arithmetic underflow error

Critically, the standard borrow and redeem flows do NOT automatically call `unstake_sui_from_staker` [12](#0-11) [13](#0-12) , causing guaranteed transaction failures.

## Impact Explanation

**Invariant Violation:** The MIN_AVAILABLE_AMOUNT invariant's purpose is to ensure 100 tokens physically remain in the reserve to prevent rounding attacks. After `rebalance_staker()`, the accounting shows sufficient balance while the actual balance is zero, completely negating the protection.

**Denial of Service:** All users attempting to borrow or redeem SUI after rebalancing will face transaction failures. The `unstake_sui_from_staker()` function exists as a separate public function [14](#0-13) , but it is not integrated into the standard borrow/redeem transaction flows, creating an unexpected and undocumented two-step requirement.

**Protocol Integrity:** The desynchronization between accounting and actual balance represents a fundamental break in protocol invariants that could cascade to other issues including incorrect interest calculations, reserve status reporting, and liquidity assessments.

## Likelihood Explanation

**High Likelihood:**

1. **Public Access:** The function has no access control - any user can trigger this state at any time
2. **Expected Usage:** The function is designed to maximize staking rewards, incentivizing frequent calls
3. **Simple Trigger:** Requires only a single public function call
4. **No Prerequisites:** No special state or permissions required beyond staker initialization
5. **Immediate Impact:** The desynchronization occurs instantly and affects all subsequent operations until manually resolved

## Recommendation

The `rebalance_staker()` function must update `reserve.available_amount` to reflect the withdrawal. The fix should:

1. Store the withdrawn amount before staking
2. Decrease `reserve.available_amount` by the withdrawn amount after line 841
3. Ensure MIN_AVAILABLE_AMOUNT is respected

Example fix (pseudo-code):
```move
public(package) fun rebalance_staker<P>(
    reserve: &mut Reserve<P>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext
) {
    // ... existing code ...
    let sui = balance::withdraw_all(&mut balances.available_amount);
    let withdrawn_amount = balance::value(&sui);
    
    // UPDATE ACCOUNTING FIELD
    reserve.available_amount = reserve.available_amount - withdrawn_amount;
    
    // ... rest of function ...
}
```

Additionally, consider either:
- Integrating `unstake_sui_from_staker` automatically into the borrow/redeem flows
- Enforcing a minimum balance that cannot be staked
- Adding clear documentation about the manual unstaking requirement

## Proof of Concept

```move
#[test]
fun test_rebalance_staker_desync_causes_borrow_dos() {
    // Setup lending market with SUI reserve containing 10,000 SUI
    let (lending_market, reserve_index) = setup_lending_market_with_sui_reserve(10000);
    
    // Initialize staker for the reserve
    init_staker_for_reserve(&mut lending_market, reserve_index);
    
    // Verify initial state: reserve.available_amount = 10000, balances.available_amount = 10000
    assert!(get_reserve_available_amount(&lending_market, reserve_index) == 10000, 0);
    
    // Call rebalance_staker - this stakes all SUI
    rebalance_staker(&mut lending_market, reserve_index, &mut system_state, &mut ctx);
    
    // BUG: reserve.available_amount still shows 10000, but actual balance is 0
    assert!(get_reserve_available_amount(&lending_market, reserve_index) == 10000, 1); // Accounting shows 10000
    assert!(get_actual_balance(&lending_market, reserve_index) == 0, 2); // Actual balance is 0
    
    // User attempts to borrow 5000 SUI
    // MIN_AVAILABLE_AMOUNT check passes because it checks reserve.available_amount (10000)
    // But fulfill_liquidity_request tries to split from empty balance -> FAILS
    let result = borrow(&mut lending_market, reserve_index, &obligation_cap, &clock, 5000, &mut ctx);
    
    // Transaction fails with arithmetic error when trying to split from empty balance
    assert!(is_error(result), 3); // Proves DoS
}
```

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L50-50)
```text
    const MIN_AVAILABLE_AMOUNT: u64 = 100; 
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L70-70)
```text
        available_amount: u64,
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L102-102)
```text
        available_amount: Balance<T>,
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L745-766)
```text
        reserve.available_amount = reserve.available_amount + balance::value(&liquidity);
        reserve.ctoken_supply = reserve.ctoken_supply + new_ctokens;

        let total_supply = total_supply(reserve);
        assert!(
            le(total_supply, decimal::from(deposit_limit(config(reserve)))), 
            EDepositLimitExceeded
        );

        let total_supply_usd = market_value_upper_bound(reserve, total_supply);
        assert!(
            le(total_supply_usd, decimal::from(deposit_limit_usd(config(reserve)))), 
            EDepositLimitExceeded
        );

        log_reserve_data(reserve);
        let balances: &mut Balances<P, T> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );

        balance::join(&mut balances.available_amount, liquidity);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L784-784)
```text
            reserve.available_amount >= MIN_AVAILABLE_AMOUNT && reserve.ctoken_supply >= MIN_AVAILABLE_AMOUNT, 
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L813-813)
```text
        let mut liquidity = balance::split(&mut balances.available_amount, amount);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L831-867)
```text
    public(package) fun rebalance_staker<P>(
        reserve: &mut Reserve<P>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        assert!(dynamic_field::exists_(&reserve.id, StakerKey {}), EStakerNotInitialized);
        let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );
        let sui = balance::withdraw_all(&mut balances.available_amount);

        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});

        staker::deposit(staker, sui);
        staker::rebalance(staker, system_state, ctx);

        let fees = staker::claim_fees(staker, system_state, ctx);
        if (balance::value(&fees) > 0) {
            event::emit(ClaimStakingRewardsEvent {
                lending_market_id: object::id_to_address(&reserve.lending_market_id),
                coin_type: reserve.coin_type,
                reserve_id: object::uid_to_address(&reserve.id),
                amount: balance::value(&fees),
            });

            let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
                &mut reserve.id,
                BalanceKey {}
            );

            balance::join(&mut balances.fees, fees);
        }
        else {
            balance::destroy_zero(fees);
        };
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L909-909)
```text
        reserve.available_amount = reserve.available_amount - borrow_amount_with_fees;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L927-927)
```text
            reserve.available_amount >= MIN_AVAILABLE_AMOUNT && reserve.ctoken_supply >= MIN_AVAILABLE_AMOUNT,
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L264-282)
```text
    public fun redeem_ctokens_and_withdraw_liquidity<P, T>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
        ctokens: Coin<CToken<P, T>>,
        rate_limiter_exemption: Option<RateLimiterExemption<P, T>>,
        ctx: &mut TxContext,
    ): Coin<T> {
        let liquidity_request = redeem_ctokens_and_withdraw_liquidity_request(
            lending_market,
            reserve_array_index,
            clock,
            ctokens,
            rate_limiter_exemption,
            ctx,
        );

        fulfill_liquidity_request(lending_market, reserve_array_index, liquidity_request, ctx)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L357-374)
```text
    public fun borrow<P, T>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        obligation_owner_cap: &ObligationOwnerCap<P>,
        clock: &Clock,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<T> {
        let liquidity_request = borrow_request<P, T>(
            lending_market,
            reserve_array_index,
            obligation_owner_cap,
            clock,
            amount,
        );

        fulfill_liquidity_request(lending_market, reserve_array_index, liquidity_request, ctx)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L791-803)
```text
    public fun rebalance_staker<P>(
        lending_market: &mut LendingMarket<P>,
        sui_reserve_array_index: u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, sui_reserve_array_index);
        assert!(reserve::coin_type(reserve) == type_name::get<SUI>(), EWrongType);

        reserve::rebalance_staker<P>(reserve, system_state, ctx);
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L805-820)
```text
    public fun unstake_sui_from_staker<P>(
        lending_market: &mut LendingMarket<P>,
        sui_reserve_array_index: u64,
        liquidity_request: &LiquidityRequest<P, SUI>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, sui_reserve_array_index);
        if (reserve::coin_type(reserve) != type_name::get<SUI>()) {
            return
        };

        reserve::unstake_sui_from_staker<P, SUI>(reserve, liquidity_request, system_state, ctx);
    }
```
