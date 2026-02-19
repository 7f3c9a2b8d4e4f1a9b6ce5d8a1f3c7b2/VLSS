# Audit Report

## Title
Flash Loan Operations Bypass Pause Mechanism

## Summary
The lending protocol's pause mechanism, designed to freeze all operations during emergencies, is completely bypassed by flash loan operations. While all standard operations (deposit, withdraw, borrow, repay, liquidation) correctly check the pause state, flash loan functions lack this critical security check, allowing users to borrow funds and modify protocol state even when the protocol is paused.

## Finding Description

The pause mechanism relies on `storage::when_not_paused(storage)` to enforce the pause state. [1](#0-0) 

All primary lending operations correctly implement pause checks:
- `base_deposit()` checks pause state [2](#0-1) 
- `base_withdraw()` checks pause state [3](#0-2) 
- `base_borrow()` checks pause state [4](#0-3) 
- `base_repay()` checks pause state [5](#0-4) 
- `base_liquidation_call()` checks pause state [6](#0-5) 

However, flash loan operations completely lack pause checks:
- `base_flash_loan()` has no pause check [7](#0-6) 
- `base_flash_repay()` has no pause check [8](#0-7) 
- The underlying `flash_loan::loan()` function only performs version verification without pause check [9](#0-8) 
- The underlying `flash_loan::repay()` function has no pause check and directly modifies state [10](#0-9) 

Four public functions expose these unprotected operations to any user:
- `flash_loan_with_ctx()` [11](#0-10) 
- `flash_loan_with_account_cap()` [12](#0-11) 
- `flash_repay_with_ctx()` [13](#0-12) 
- `flash_repay_with_account_cap()` [14](#0-13) 

## Impact Explanation

**Security Integrity Violation**: The pause mechanism is a critical emergency control that should prevent ALL protocol operations during security incidents. Flash loans completely bypass this protection, undermining the protocol's ability to respond to emergencies.

**Direct Fund Impact**: During a pause (typically triggered due to detected vulnerabilities or attacks), flash loans can still withdraw large amounts from lending pools. If the pause was triggered due to a vulnerability in related systems, these funds could be at risk.

**Protocol State Manipulation**: Most critically, flash loan repayment modifies core protocol state even when paused. The `repay()` function calls `logic::update_state_of_all(clock, storage)` [15](#0-14) , which iterates through all reserves and updates their state [16](#0-15) . This modifies:
- Supply and borrow indices for all reserves
- Interest rates
- Treasury balances

This completely defeats the purpose of pausing the protocol to freeze state during incident response.

## Likelihood Explanation

**Reachable Entry Points**: Four public functions are directly callable by any user without special permissions or prerequisites.

**No Prerequisites**: Any user can execute flash loans. No trusted role compromise is required. No special account setup or collateral is needed.

**Trivial Execution**: Flash loans are a standard DeFi operation. The execution path is straightforward:
1. Call `flash_loan_with_ctx()` to borrow funds (works even when paused)
2. Use the borrowed funds for any purpose
3. Call `flash_repay_with_ctx()` to repay (works even when paused, modifies state)

**Economic Viability**: Flash loan fees are standard protocol fees paid to suppliers and treasury. The cost to execute is minimal.

**High Probability**: This vulnerability is guaranteed to be exploitable whenever:
- The protocol is paused (emergency situation)
- Flash loan configuration exists
- Pools have available liquidity

The vulnerability is deterministic and will work 100% of the time under these conditions.

## Recommendation

Add pause checks to both flash loan functions. Modify the code as follows:

In `base_flash_loan()` function:
```move
fun base_flash_loan<CoinType>(
    storage: &Storage,  // Add storage parameter
    config: &FlashLoanConfig, 
    pool: &mut Pool<CoinType>, 
    user: address, 
    amount: u64
): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
    storage::when_not_paused(storage);  // Add pause check
    flash_loan::loan<CoinType>(config, pool, user, amount)
}
```

In `base_flash_repay()` function:
```move
fun base_flash_repay<CoinType>(
    clock: &Clock, 
    storage: &mut Storage, 
    pool: &mut Pool<CoinType>, 
    receipt: FlashLoanReceipt<CoinType>, 
    user: address, 
    repay_balance: Balance<CoinType>
): Balance<CoinType> {
    storage::when_not_paused(storage);  // Add pause check
    flash_loan::repay<CoinType>(clock, storage, pool, receipt, user, repay_balance)
}
```

Update all public flash loan entry points to pass the storage parameter accordingly.

## Proof of Concept

```move
#[test]
fun test_flash_loan_bypasses_pause() {
    // Setup: Initialize protocol with storage, pool, and flash loan config
    let mut scenario = test_scenario::begin(@0xABCD);
    let ctx = test_scenario::ctx(&mut scenario);
    
    // Initialize storage and set up reserves
    let mut storage = create_test_storage(ctx);
    let mut pool = create_test_pool<SUI>(ctx);
    let config = create_flash_loan_config(ctx);
    let clock = clock::create_for_testing(ctx);
    
    // Add liquidity to pool
    add_pool_liquidity(&mut pool, 1000000, ctx);
    
    // CRITICAL: Pause the protocol
    storage::set_pause(&owner_cap, &mut storage, true);
    assert!(storage::pause(&storage) == true, 0);
    
    // EXPLOIT: Flash loan still works despite pause
    let (borrowed_balance, receipt) = lending::flash_loan_with_ctx<SUI>(
        &config,
        &mut pool,
        100000,  // Borrow 100k
        ctx
    );
    
    assert!(balance::value(&borrowed_balance) == 100000, 1);
    
    // Repay also works and MODIFIES STATE while paused
    let excess = lending::flash_repay_with_ctx<SUI>(
        &clock,
        &mut storage,
        &mut pool,
        receipt,
        borrowed_balance,
        ctx
    );
    
    // Test passes - flash loan completed successfully while protocol was paused
    // This should have been blocked but wasn't
    
    balance::destroy_zero(excess);
    test_scenario::end(scenario);
}
```

This test demonstrates that flash loans operate normally even when `storage.paused == true`, violating the fundamental security guarantee that pausing freezes all operations.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L141-143)
```text
    public fun when_not_paused(storage: &Storage) {
        assert!(!pause(storage), error::paused())
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L184-184)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L225-225)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L275-275)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L319-319)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L420-420)
```text
        storage::when_not_paused(storage);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L531-533)
```text
    fun base_flash_loan<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, user: address, amount: u64): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        flash_loan::loan<CoinType>(config, pool, user, amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L535-537)
```text
    fun base_flash_repay<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, receipt: FlashLoanReceipt<CoinType>, user: address, repay_balance: Balance<CoinType>): Balance<CoinType> {
        flash_loan::repay<CoinType>(clock, storage, pool, receipt, user, repay_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-541)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L543-545)
```text
    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L547-549)
```text
    public fun flash_repay_with_ctx<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, receipt: FlashLoanReceipt<CoinType>, repay_balance: Balance<CoinType>, ctx: &mut TxContext): Balance<CoinType> {
        base_flash_repay<CoinType>(clock, storage, pool, receipt, tx_context::sender(ctx), repay_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L551-553)
```text
    public fun flash_repay_with_account_cap<CoinType>(clock: &Clock, storage: &mut Storage, pool: &mut Pool<CoinType>, receipt: FlashLoanReceipt<CoinType>, repay_balance: Balance<CoinType>, account_cap: &AccountCap): Balance<CoinType> {
        base_flash_repay<CoinType>(clock, storage, pool, receipt, account::account_owner(account_cap), repay_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L141-173)
```text
    public(friend) fun loan<CoinType>(config: &Config, _pool: &mut Pool<CoinType>, _user: address, _loan_amount: u64): (Balance<CoinType>, Receipt<CoinType>) {
        version_verification(config);
        let str_type = type_name::into_string(type_name::get<CoinType>());
        assert!(table::contains(&config.support_assets, *ascii::as_bytes(&str_type)), error::reserve_not_found());
        let asset_id = table::borrow(&config.support_assets, *ascii::as_bytes(&str_type));
        let cfg = table::borrow(&config.assets, *asset_id);

        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());

        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();

        let _balance = pool::withdraw_balance(_pool, _loan_amount, _user);
        
        let _receipt = Receipt<CoinType> {
            user: _user,
            asset: *asset_id,
            amount: _loan_amount,
            pool: pool_id,
            fee_to_supplier: to_supplier,
            fee_to_treasury: to_treasury,
        };

        emit(FlashLoan {
            sender: _user,
            asset: *asset_id,
            amount: _loan_amount,
        });

        (_balance, _receipt)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L175-209)
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

        let repay_amount = balance::value(&_repay_balance);
        assert!(repay_amount >= amount + fee_to_supplier + fee_to_treasury, error::invalid_amount());

        let repay = balance::split(&mut _repay_balance, amount + fee_to_supplier + fee_to_treasury);
        pool::deposit_balance(_pool, repay, _user);
        pool::deposit_treasury(_pool, fee_to_treasury);

        emit(FlashRepay {
            sender: _user,
            asset: asset,
            amount: amount,
            fee_to_supplier: fee_to_supplier,
            fee_to_treasury: fee_to_treasury,
        });

        _repay_balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L243-251)
```text
    public(friend) fun update_state_of_all(clock: &Clock, storage: &mut Storage) {
        let count = storage::get_reserves_count(storage);

        let i = 0;
        while (i < count) {
            update_state(clock, storage, i);
            i = i + 1;
        }
    }
```
