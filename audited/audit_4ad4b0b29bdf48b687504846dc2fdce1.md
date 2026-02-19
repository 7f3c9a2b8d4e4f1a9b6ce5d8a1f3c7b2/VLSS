# Audit Report

## Title
Suilend Staker DoS Due to Unchecked LST Balance in `unstake_n_sui()`

## Summary
The `unstake_n_sui()` function in Suilend's staker module calculates the required LST redemption amount using ceiling division but fails to validate that sufficient LST balance exists before attempting to split. When validator slashing reduces LST value below the staker's liabilities, withdrawal requests trigger a panic that completely disables SUI borrowing functionality in Suilend lending markets, indirectly affecting Volo vault users who hold Suilend positions.

## Finding Description

The vulnerability exists in the `unstake_n_sui()` function which is called during SUI withdrawal operations from the Suilend staker. [1](#0-0) 

The root cause is a two-part failure:

1. **Unchecked LST calculation**: The function calculates `lst_to_redeem` using ceiling division [2](#0-1)  but performs no balance validation before attempting to split this amount. [3](#0-2) 

2. **Missing invariant check in withdrawal path**: The critical invariant check `assert!(staker.total_sui_supply() >= staker.liabilities, EInvariantViolation)` only exists in `claim_fees()` [4](#0-3)  but is absent from the `withdraw()` function. [5](#0-4) 

**Execution Flow:**
1. User calls public borrow functions [6](#0-5)  or [7](#0-6) 
2. System calls `unstake_sui_from_staker()` [8](#0-7)  to unstake SUI from the staker
3. This triggers `reserve::unstake_sui_from_staker()` [9](#0-8)  which calculates the withdrawal amount
4. Reserve calls `staker::withdraw()` [10](#0-9)  with the needed amount
5. Withdraw calls `unstake_n_sui()` which panics at the split operation

**Why It Breaks:**
When validator slashing reduces `total_sui_supply`, the exchange rate worsens. The formula `lst_to_redeem = ceil((sui_amount_out * total_lst_supply) / total_sui_supply)` requires proportionally more LST to redeem the same SUI amount. If the staker's liabilities exceed the actual SUI value of its LST holdings, `lst_to_redeem` can exceed the available `lst_balance`, causing `balance::split()` to panic.

The staker is delegated to SUILEND_VALIDATOR [11](#0-10)  exposing it to slashing risk.

## Impact Explanation

**HIGH SEVERITY** - This vulnerability causes complete denial of service for SUI borrowing functionality in Suilend lending markets under realistic conditions.

**Direct Impact on Suilend:**
When the staker becomes undercollateralized due to validator slashing, ALL borrow operations requiring SUI unstaking will abort, rendering the lending market's SUI liquidity provision completely inoperable until manual intervention resolves the deficit.

**Indirect Impact on Volo Protocol:**
Volo vaults integrate with Suilend through the suilend_adaptor [12](#0-11)  holding Suilend `ObligationOwnerCap` objects as DeFi assets. When Suilend's SUI reserve encounters this DoS:
- Volo users with Suilend obligations cannot properly manage their positions
- New SUI borrows fail for all Suilend users
- Liquidations requiring SUI borrows may fail
- Multi-protocol strategies involving Suilend positions become unreliable

**Concrete Scenario:**
- Staker: 100 LST worth 105 SUI, 100 SUI liabilities
- Validator slashing reduces value to 90 SUI (15 SUI loss)
- User borrows 95 SUI: `lst_to_redeem = ceil(95 * 100 / 90) = 106 LST`
- Staker has only 100 LST → transaction panics

## Likelihood Explanation

**MEDIUM-HIGH** likelihood due to:

1. **Realistic Preconditions:** Validator slashing is a standard proof-of-stake mechanism on Sui for penalizing misbehaving validators. No attacker capabilities required beyond normal protocol usage.

2. **Reachable Entry Points:** Public functions are accessible to any user with a Suilend obligation for normal borrowing operations.

3. **Persistent Condition:** Once slashing reduces LST value below liabilities, the condition persists until manually resolved, and every borrow attempt triggers the DoS.

4. **Probability:** Validator slashing events occur periodically on PoS networks. Given the staker's exposure through delegation, this scenario will eventually occur during normal protocol operations.

## Recommendation

Add balance validation before attempting to split LST tokens in `unstake_n_sui()`:

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
    
    // ADD VALIDATION HERE
    let available_lst = balance::value(&staker.lst_balance);
    assert!(
        (lst_to_redeem as u64) <= available_lst, 
        EInsufficientLstBalance
    );
    
    let lst = balance::split(&mut staker.lst_balance, (lst_to_redeem as u64));
    // ... rest of function
}
```

Additionally, add the invariant check to the `withdraw()` function:

```move
public(package) fun withdraw<P: drop>(
    staker: &mut Staker<P>,
    withdraw_amount: u64,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext,
): Balance<SUI> {
    staker.liquid_staking_info.refresh(system_state, ctx);
    
    // ADD INVARIANT CHECK HERE
    assert!(
        staker.total_sui_supply() >= staker.liabilities, 
        EInvariantViolation
    );

    if (withdraw_amount > staker.sui_balance.value()) {
        let unstake_amount = withdraw_amount - staker.sui_balance.value();
        staker.unstake_n_sui(system_state, unstake_amount, ctx);
    };

    let sui = staker.sui_balance.split(withdraw_amount);
    staker.liabilities = staker.liabilities - sui.value();

    sui
}
```

## Proof of Concept

A test demonstrating this vulnerability would require:
1. Creating a Suilend lending market with a staker
2. Depositing SUI to create liabilities
3. Simulating validator slashing by reducing the LST exchange rate
4. Attempting to borrow SUI that requires unstaking
5. Observing the transaction panic

The test would verify that when `total_sui_supply < liabilities`, any unstake operation requiring more LST than available causes a panic, completely blocking SUI borrowing functionality.

**Notes:**
- This vulnerability exists in Suilend protocol code included as a Volo dependency
- It is explicitly in-scope per the audit specification
- While remediation must occur in Suilend code, Volo users are indirectly affected through the suilend_adaptor integration
- The issue represents a systemic risk to any protocol integrating with Suilend's staking mechanism

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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L1-118)
```text
module volo_vault::suilend_adaptor;

use std::ascii::String;
use sui::clock::Clock;
use suilend::lending_market::{LendingMarket, ObligationOwnerCap as SuilendObligationOwnerCap};
use suilend::obligation::{Obligation};
use suilend::reserve::{Self};
use volo_vault::vault::Vault;

const DECIMAL: u256 = 1_000_000_000;

// @dev Need to update the price of the reserve before calling this function
//      Update function: lending_market::refresh_reserve_price
//          public fun refresh_reserve_price<P>(
//              lending_market: &mut LendingMarket<P>,
//              reserve_array_index: u64,
//              clock: &Clock,
//              price_info: &PriceInfoObject,
//           )

// Obligation type is type of suilend lending_market
// e.g. Obligation<suilend::main_market>
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}

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

fun suilend_compound_interest<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
) {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());
    let reserve_array_indices = get_reserve_array_indicies(obligation);

    reserve_array_indices.do_ref!(|reserve_array_index| {
        lending_market.compound_interest(*reserve_array_index, clock);
    });
}

fun get_reserve_array_indicies<ObligationType>(
    obligation: &Obligation<ObligationType>,
): vector<u64> {
    let mut array_indices = vector::empty<u64>();

    obligation.deposits().do_ref!(|deposit| {
        vector::push_back(&mut array_indices, deposit.reserve_array_index());
    });

    obligation.borrows().do_ref!(|borrow| {
        vector::push_back(&mut array_indices, borrow.reserve_array_index());
    });

    array_indices
}
```
