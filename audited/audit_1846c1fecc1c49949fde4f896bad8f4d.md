# Audit Report

## Title
Division by Zero DoS in Flash Loan Repayment When No Depositors Exist

## Summary
The flash loan repayment mechanism unconditionally attempts to distribute supplier fees through division by `total_supply`, causing transaction abortion when no depositors exist in the lending protocol. This creates a complete DoS condition for flash loan functionality during initial asset deployment or after full user withdrawal, as pool liquidity exists independently from depositor balances.

## Finding Description

The vulnerability exists at the intersection of flash loan repayment and supplier fee distribution logic. The `cumulate_to_supply_index()` function performs unchecked division by `total_supply` when distributing flash loan fees to suppliers. [1](#0-0) 

The division operation uses `ray_div()` which explicitly asserts the divisor is non-zero, causing a panic with error code 1103 when `total_supply == 0`. [2](#0-1) 

Flash loan repayment unconditionally calls this fee distribution function regardless of whether suppliers exist. [3](#0-2) 

The root cause is architectural: Pool balance (flash loan liquidity source) is independent from Storage `total_supply` (depositor balance tracking). Pools can receive initial funding through direct balance deposits without updating `total_supply`. [4](#0-3) 

When reserves are initialized, `total_supply` starts at zero and only increases through user deposits via the lending protocol. [5](#0-4) 

Flash loan issuance validates loan bounds and pool liquidity but does not verify depositor existence. [6](#0-5) 

## Impact Explanation

**Operational DoS Impact:**
- Flash loan repayment becomes completely non-functional for any asset where `total_supply = 0`
- All flash loan repayment transactions abort with error 1103
- Condition persists until at least one user makes a deposit to the lending protocol
- Affects protocol usability during critical periods (new asset launches, market stress causing full withdrawals)

**Affected Parties:**
- Flash loan users who cannot complete their transactions
- Protocol operators losing flash loan fee revenue
- Potential loss of funds if users cannot repay within the same transaction context

**Severity Justification:** 
High severity due to complete functional DoS affecting a core protocol feature under realistic operational conditions without requiring adversarial action.

## Likelihood Explanation

**Reachable Entry Points:**
Flash loan functions are publicly accessible through `lending::flash_loan_with_ctx()` and `lending::flash_repay_with_ctx()`. [7](#0-6) 

**Feasible Preconditions:**
1. Pool has liquidity (admin-funded or residual from previous activity)
2. No current depositors exist (`total_supply = 0`)
3. Occurs naturally during:
   - Initial protocol deployment when pools are pre-funded before lending activity begins
   - Post-market-stress scenarios where all users fully withdraw
   - New asset launches with pool liquidity but no immediate depositor adoption

**Execution Practicality:**
- Requires no special permissions or setup
- Standard flash loan workflow: loan → logic → repay
- Transaction aborts at repayment with deterministic error 1103
- No economic attack cost beyond standard flash loan parameters

## Recommendation

Add a zero-check guard in `cumulate_to_supply_index()` before performing division:

```move
public(friend) fun cumulate_to_supply_index(storage: &mut Storage, asset: u8, amount: u256) {
    let (total_supply, _) = storage::get_total_supply(storage, asset);
    
    // Guard against division by zero when no depositors exist
    if (total_supply == 0) {
        return
    };
    
    let (supply_index, borrow_index) = storage::get_index(storage, asset);
    let last_update_at = storage::get_last_update_timestamp(storage, asset);
    
    let result = ray_math::ray_mul(
        ray_math::ray_div(amount, total_supply) + ray_math::ray(),
        supply_index,
    );
    
    storage::update_state(storage, asset, borrow_index, result, last_update_at, 0);
    emit_state_updated_event(storage, asset, @0x0);
}
```

Alternative: Accumulate fees to treasury when no suppliers exist, rather than attempting distribution.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = 1103)] // RAY_MATH_DIVISION_BY_ZERO
public fun test_flash_loan_dos_with_zero_depositors() {
    let scenario = test_scenario::begin(OWNER);
    let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    
    // Initialize protocol with pool but NO deposits
    initialize_protocol_with_empty_storage(&mut scenario, &clock);
    
    test_scenario::next_tx(&mut scenario, USER);
    {
        let config = test_scenario::take_shared<FlashLoanConfig>(&scenario);
        let pool = test_scenario::take_shared<Pool<SUI_TEST>>(&scenario);
        let storage = test_scenario::take_shared<Storage>(&scenario);
        
        // Admin funds pool directly (bypasses storage total_supply update)
        fund_pool_directly(&mut pool, 1000_000000000);
        
        // Verify precondition: pool has liquidity but total_supply = 0
        let (pool_balance, _, _) = pool::get_pool_info(&pool);
        assert!(pool_balance > 0, 0);
        let (total_supply, _) = storage::get_total_supply(&mut storage, 0);
        assert!(total_supply == 0, 0);
        
        // Flash loan succeeds (only checks pool balance)
        let amount = 100_000000000;
        let (loan_balance, receipt) = lending::flash_loan_with_ctx<SUI_TEST>(
            &config, &mut pool, amount, test_scenario::ctx(&mut scenario)
        );
        
        // Add fees for repayment
        let (_, _, _, _, fee_supplier, fee_treasury) = flash_loan::parsed_receipt(&receipt);
        let fee_coin = coin::mint_for_testing<SUI_TEST>(fee_supplier + fee_treasury, test_scenario::ctx(&mut scenario));
        balance::join(&mut loan_balance, coin::into_balance(fee_coin));
        
        // Repayment ABORTS at cumulate_to_supply_index with error 1103
        let _excess = lending::flash_repay_with_ctx<SUI_TEST>(
            &clock, &mut storage, &mut pool, receipt, loan_balance, test_scenario::ctx(&mut scenario)
        );
        
        test_scenario::return_shared(storage);
        test_scenario::return_shared(pool);
        test_scenario::return_shared(config);
    };
    
    clock::destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

**Notes:**
- This vulnerability affects the Navi Protocol lending integration used by Volo Vault
- The issue resides in a dependency (`local_dependencies/protocol/lending_core`) that is within the audit scope
- While not directly in Volo's core vault logic, it impacts any Volo operations utilizing Navi flash loans
- The vulnerability is deterministic and reproducible under documented preconditions
- Fix should be applied at the protocol level to protect all integrators

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L300-315)
```text
    public(friend) fun cumulate_to_supply_index(storage: &mut Storage, asset: u8, amount: u256) {
        //next liquidity index is calculated this way: `((amount / totalLiquidity) + 1) * liquidityIndex`
        //division `amount / totalLiquidity` done in ray for precision

        let (total_supply, _) = storage::get_total_supply(storage, asset);
        let (supply_index, borrow_index) = storage::get_index(storage, asset);
        let last_update_at = storage::get_last_update_timestamp(storage, asset);

        let result = ray_math::ray_mul(
            ray_math::ray_div(amount, total_supply) + ray_math::ray(), // (amount / totalSupply) + 1
            supply_index,
        );

        storage::update_state(storage, asset, borrow_index, result, last_update_at, 0);
        emit_state_updated_event(storage, asset, @0x0);
    }
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L85-86)
```text
    public fun ray_div(a: u256, b: u256): u256 {
        assert!(b != 0, RAY_MATH_DIVISION_BY_ZERO);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L148-155)
```text
        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());

        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();

        let _balance = pool::withdraw_balance(_pool, _loan_amount, _user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L175-191)
```text
    public(friend) fun repay<CoinType>(clock: &Clock, storage: &mut Storage, _pool: &mut Pool<CoinType>, _receipt: Receipt<CoinType>, _user: address, _repay_balance: Balance<CoinType>): Balance<CoinType> {
        let Receipt {user, asset, amount, pool, fee_to_supplier, fee_to_treasury} = _receipt;
        assert!(user == _user, error::invalid_user());
        assert!(pool == object::uid_to_address(pool::uid(_pool)), error::invalid_pool());

        // handler logic
        {
            logic::update_state_of_all(clock, storage);
            let asset_id = get_storage_asset_id_from_coin_type(storage, type_name::into_string(type_name::get<CoinType>()));

            let normal_amount = pool::normal_amount(_pool, fee_to_supplier);
            let (supply_index, _) = storage::get_index(storage, asset_id);
            let scaled_fee_to_supplier = ray_math::ray_div((normal_amount as u256), supply_index);

            logic::cumulate_to_supply_index(storage, asset_id, scaled_fee_to_supplier);
            logic::update_interest_rate(storage, asset_id);
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L100-109)
```text
    public(friend) fun deposit_balance<CoinType>(pool: &mut Pool<CoinType>, deposit_balance: Balance<CoinType>, user: address) {
        let balance_value = balance::value(&deposit_balance);
        balance::join(&mut pool.balance, deposit_balance);

        emit(PoolDeposit {
            sender: user,
            amount: balance_value,
            pool: type_name::into_string(type_name::get<CoinType>())
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L206-209)
```text
            supply_balance: TokenBalance {
                user_state: table::new<address, u256>(ctx),
                total_supply: 0,
            },
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-549)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }

    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }

    public fun flash_repay_with_ctx<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, receipt: FlashLoanReceipt<CoinType>, repay_balance: Balance<CoinType>, ctx: &mut TxContext): Balance<CoinType> {
        base_flash_repay<CoinType>(clock, storage, pool, receipt, tx_context::sender(ctx), repay_balance)
    }
```
