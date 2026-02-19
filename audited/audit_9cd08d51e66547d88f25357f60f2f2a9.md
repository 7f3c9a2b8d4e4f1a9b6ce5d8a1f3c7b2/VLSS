### Title
Suilend Staker DoS Due to Unchecked LST Balance in `unstake_n_sui()`

### Summary
The `unstake_n_sui()` function calculates `lst_to_redeem` based on the current LST exchange rate without validating that the staker has sufficient LST balance before attempting to split. When LST loses value (e.g., due to validator slashing), withdrawal requests can require more LST tokens than available, causing a panic that renders the lending market's SUI borrowing functionality inoperable.

### Finding Description

**Location**: [1](#0-0) 

**Root Cause**: The function calculates the required LST redemption amount using ceiling division at [2](#0-1)  but performs no validation before attempting to split this amount from `lst_balance` at [3](#0-2) .

The formula `lst_to_redeem = ceil((sui_amount_out * total_lst_supply) / total_sui_supply)` assumes the staker has sufficient LST. However, when `total_sui_supply` decreases due to validator slashing, the same amount of SUI requires proportionally more LST to redeem. If `sui_amount_out > total_sui_supply`, then `lst_to_redeem` will exceed `total_lst_supply`, causing the split operation to panic.

**Execution Path**:
1. User calls public function [4](#0-3)  to create a borrow request
2. System calls [5](#0-4)  to unstake SUI from staker
3. This triggers [6](#0-5)  which calculates withdrawal amount
4. Reserve calls [7](#0-6)  with the needed amount
5. Withdraw calls [1](#0-0)  which panics

**Why Existing Protections Fail**: The invariant check at [8](#0-7)  only exists in `claim_fees()`, not in `withdraw()`, and occurs AFTER the unstaking attempt, meaning the panic happens before any validation.

### Impact Explanation

**Operational Impact - Critical DoS**: When validator slashing occurs and reduces the LST value below liabilities, all SUI borrow operations requiring unstaking will fail with a panic. This completely disables the lending market's ability to provide SUI liquidity to borrowers.

**Concrete Scenario**:
- Staker has 100 LST worth 105 SUI initially, with 100 SUI in liabilities
- Validator slashing reduces the LST value to 90 SUI (15 SUI loss)
- User attempts to borrow 95 SUI
- Calculation: `lst_to_redeem = ceil((95 * 100) / 90) = 106 LST`
- Staker only has 100 LST available
- Transaction panics, user cannot borrow

**Affected Parties**: All users attempting to borrow SUI from the Suilend lending market when the staker cannot fulfill unstaking requests. The entire SUI lending functionality becomes inoperable until the deficit is manually resolved.

**Severity Justification**: This is a HIGH severity issue because it causes complete denial of service for a core protocol function (SUI lending) under realistic market conditions (validator slashing), affecting all protocol users.

### Likelihood Explanation

**Reachable Entry Points**: Public functions [9](#0-8)  and [10](#0-9)  are accessible to any user with an obligation.

**Feasible Preconditions**: 
- Validator slashing is a standard blockchain mechanism on Sui for penalizing misbehaving validators
- The staker's delegation to SUILEND_VALIDATOR at [11](#0-10)  exposes it to slashing risk
- No special attacker capabilities required - normal market conditions trigger the issue

**Execution Practicality**: Users perform normal borrow operations through standard lending market functions. No exploitation beyond routine protocol usage is needed.

**Probability**: MEDIUM-HIGH. Validator slashing events occur periodically on proof-of-stake networks. Once slashing reduces LST value below liabilities, the condition persists until manually resolved, and every borrow attempt triggers the DoS.

### Recommendation

**Immediate Fix**: Add balance validation before the split operation in `unstake_n_sui()`:

```move
fun unstake_n_sui<P: drop>(
    staker: &mut Staker<P>,
    system_state: &mut SuiSystemState,
    sui_amount_out: u64,
    ctx: &mut TxContext,
) {
    if (sui_amount_out == 0) {
        return
    };

    let total_sui_supply = (staker.liquid_staking_info.total_sui_supply() as u128);
    let total_lst_supply = (staker.liquid_staking_info.total_lst_supply() as u128);

    let lst_to_redeem =
        ((sui_amount_out as u128) * total_lst_supply + total_sui_supply - 1) / total_sui_supply;
    
    // ADD THIS CHECK
    let available_lst = balance::value(&staker.lst_balance);
    assert!(
        (lst_to_redeem as u64) <= available_lst,
        EInsufficientLstBalance
    );
    
    let lst = balance::split(&mut staker.lst_balance, (lst_to_redeem as u64));
    // ... rest of function
}
```

**Additional Safeguards**:
1. Add pre-validation in `withdraw()` at [7](#0-6)  to check `withdraw_amount <= total_sui_supply()`
2. Implement graceful degradation that returns available SUI rather than panicking
3. Add monitoring for the invariant `total_sui_supply() >= liabilities` with automatic circuit breaker

**Test Cases**:
1. Test unstaking with slashed validator reducing LST value by 10-20%
2. Test withdrawal requests exceeding available LST capacity
3. Test recovery path after slashing events restore operations

### Proof of Concept

**Initial State**:
- Staker initialized with LST protocol instance
- 100 LST tokens staked (total_lst_supply = 100)
- Initial value: 105 SUI (total_sui_supply = 105)
- Liabilities: 100 SUI
- Liquid balance (sui_balance): 0 SUI

**Transaction Sequence**:

**Step 1 - Validator Slashing Event**:
- Sui network slashes validator at [11](#0-10) 
- Staked SUI reduced from 105 to 90 SUI (15 SUI penalty)
- Post-slashing: total_sui_supply = 90, total_lst_supply = 100, lst_balance = 100 LST

**Step 2 - User Borrows SUI**:
- User calls `borrow_request<P, SUI>(lending_market, reserve_index, obligation_cap, clock, 95)`
- Creates LiquidityRequest for 95 SUI

**Step 3 - Attempt to Fulfill Request**:
- System calls `unstake_sui_from_staker<P>(lending_market, reserve_index, &liquidity_request, system_state, ctx)`
- Reserve calculates: withdraw_amount = 95 - 0 = 95 SUI
- Calls `staker::withdraw(staker, 95, system_state, ctx)`

**Step 4 - Panic Occurs**:
- In withdraw: unstake_amount = 95 - 0 = 95
- Calls `unstake_n_sui(system_state, 95, ctx)`
- Calculates: `lst_to_redeem = ceil((95 * 100 + 90 - 1) / 90) = ceil(9589 / 90) = ceil(106.54) = 107`
- Attempts: `balance::split(&mut staker.lst_balance, 107)`
- **PANIC**: Insufficient balance (has 100 LST, needs 107 LST)

**Expected Result**: Transaction should either succeed or fail gracefully with an error code

**Actual Result**: Transaction aborts with panic, rendering all future SUI borrow operations inoperable until manual intervention

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L16-17)
```text
    const SUILEND_VALIDATOR: address =
        @0xce8e537664ba5d1d5a6a857b17bd142097138706281882be6805e17065ecde89;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L80-97)
```text
    public(package) fun withdraw<P: drop>(
        staker: &mut Staker<P>,
        withdraw_amount: u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ): Balance<SUI> {
        staker.liquid_staking_info.refresh(system_state, ctx);

        if (withdraw_amount > staker.sui_balance.value()) {
            let unstake_amount = withdraw_amount - staker.sui_balance.value();
            staker.unstake_n_sui(system_state, unstake_amount, ctx);
        };

        let sui = staker.sui_balance.split(withdraw_amount);
        staker.liabilities = staker.liabilities - sui.value();

        sui
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L154-154)
```text
        assert!(staker.total_sui_supply() >= staker.liabilities, EInvariantViolation);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L163-189)
```text
    fun unstake_n_sui<P: drop>(
        staker: &mut Staker<P>,
        system_state: &mut SuiSystemState,
        sui_amount_out: u64,
        ctx: &mut TxContext,
    ) {
        if (sui_amount_out == 0) {
            return
        };

        let total_sui_supply = (staker.liquid_staking_info.total_sui_supply() as u128);
        let total_lst_supply = (staker.liquid_staking_info.total_lst_supply() as u128);

        // ceil lst redemption amount
        let lst_to_redeem =
            ((sui_amount_out as u128) * total_lst_supply + total_sui_supply - 1) / total_sui_supply;
        let lst = balance::split(&mut staker.lst_balance, (lst_to_redeem as u64));

        let sui = liquid_staking::redeem(
            &mut staker.liquid_staking_info,
            coin::from_balance(lst, ctx),
            system_state,
            ctx,
        );

        staker.sui_balance.join(sui.into_balance());
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L389-448)
```text
    public fun borrow_request<P, T>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        obligation_owner_cap: &ObligationOwnerCap<P>,
        clock: &Clock,
        mut amount: u64,
    ): LiquidityRequest<P, T> {
        let lending_market_id = object::id_address(lending_market);
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
        assert!(amount > 0, ETooSmall);

        let obligation = object_table::borrow_mut(
            &mut lending_market.obligations,
            obligation_owner_cap.obligation_id,
        );

        let exist_stale_oracles = obligation::refresh<P>(obligation, &mut lending_market.reserves, clock);
        obligation::assert_no_stale_oracles(exist_stale_oracles);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        assert!(reserve::coin_type(reserve) == type_name::get<T>(), EWrongType);

        reserve::compound_interest(reserve, clock);
        reserve::assert_price_is_fresh(reserve, clock);

        if (amount == U64_MAX) {
            amount = max_borrow_amount<P>(lending_market.rate_limiter, obligation, reserve, clock);
            assert!(amount > 0, ETooSmall);
        };

        let liquidity_request = reserve::borrow_liquidity<P, T>(reserve, amount);
        obligation::borrow<P>(
            obligation,
            reserve,
            clock,
            reserve::liquidity_request_amount(&liquidity_request),
        );

        let borrow_value = reserve::market_value_upper_bound(
            reserve,
            decimal::from(reserve::liquidity_request_amount(&liquidity_request)),
        );
        rate_limiter::process_qty(
            &mut lending_market.rate_limiter,
            clock::timestamp_ms(clock) / 1000,
            borrow_value,
        );

        event::emit(BorrowEvent {
            lending_market_id,
            coin_type: type_name::get<T>(),
            reserve_id: object::id_address(reserve),
            obligation_id: object::id_address(obligation),
            liquidity_amount: reserve::liquidity_request_amount(&liquidity_request),
            origination_fee_amount: reserve::liquidity_request_fee(&liquidity_request),
        });

        obligation::zero_out_rewards_if_looped(obligation, &mut lending_market.reserves, clock);
        liquidity_request
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L869-899)
```text
    public(package) fun unstake_sui_from_staker<P, T>(
        reserve: &mut Reserve<P>,
        liquidity_request: &LiquidityRequest<P, T>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        assert!(reserve.coin_type == type_name::get<SUI>() && type_name::get<T>() == type_name::get<SUI>(), EWrongType);
        if (!dynamic_field::exists_(&reserve.id, StakerKey {})) {
            return
        };

        let balances: &Balances<P, SUI> = dynamic_field::borrow(&reserve.id, BalanceKey {});
        if (liquidity_request.amount <= balance::value(&balances.available_amount)) {
            return
        };
        let withdraw_amount = liquidity_request.amount - balance::value(&balances.available_amount);

        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});
        let sui = staker::withdraw(
            staker,
            withdraw_amount, 
            system_state, 
            ctx
        );

        let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );
        balance::join(&mut balances.available_amount, sui);
    }
```
