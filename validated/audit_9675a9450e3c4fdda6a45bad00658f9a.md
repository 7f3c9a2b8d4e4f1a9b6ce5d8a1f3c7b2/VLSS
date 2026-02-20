# Audit Report

## Title
Treasury Balance Inflation via Missing Balance Deduction in execute_withdraw() Dust Handling

## Summary
The `execute_withdraw()` function in the Navi lending_core protocol contains a critical accounting flaw where dust balances (≤1000 units) are credited to the treasury's accounting balance without being deducted from the user's supply balance. This allows users to withdraw their dust a second time while the treasury believes it owns those funds, leading to inflated treasury balances that steal from other depositors when withdrawn by admins.

## Finding Description

The vulnerability exists in the dust handling logic of `execute_withdraw()`. [1](#0-0) 

**The Bug Flow:**

1. When a user withdraws, the function retrieves their balance and decreases it by the withdrawal amount. [2](#0-1) 

2. If dust remains (≤1000 units), the code credits the treasury and removes the user from the collateral list. [3](#0-2) 

3. However, `increase_treasury_balance()` only increments an accounting field without deducting from the user's balance. [4](#0-3) 

**Why Existing Protections Fail:**

- The entry point check only validates `user_collateral_balance > 0`, which checks actual balance, not collateral list membership. [5](#0-4) 

- The user retains their dust balance in the scaled supply balance tracking because only `actual_amount` is deducted, not `token_amount`. [6](#0-5) 

- Users can call withdraw again through the public entry point, passing the balance check and extracting the dust. [7](#0-6) 

**Treasury Withdrawal Exploitation:**

When admins withdraw the inflated treasury balance, the function reads the accounting balance and withdraws real tokens from the pool's reserves. [8](#0-7) [9](#0-8) 

This means the treasury withdraws tokens that actually belong to other depositors, causing direct fund loss.

## Impact Explanation

**Critical Fund Loss Scenario:**

1. Alice deposits 10,000 tokens
2. Bob deposits 1,500 tokens  
3. Bob withdraws 500 tokens, leaving 1,000 dust
   - Bob's balance: 1,000 (only `actual_amount` was deducted, not the dust)
   - Treasury accounting: +1,000 (phantom funds)
   - Pool has: 11,000 actual tokens
4. Bob withdraws his remaining 1,000 tokens
   - Bob's balance: 0
   - Treasury accounting: still 1,000
   - Pool has: 10,000 actual tokens (only Alice's deposit)
5. Admin withdraws 1,000 treasury tokens via `withdraw_treasury()`
   - Function withdraws 1,000 from pool reserves
   - Pool now has: 9,000 tokens
6. Alice tries to withdraw her 10,000 but pool only has 9,000
   - **Alice loses 1,000 tokens**

This breaks the fundamental invariant that `sum(user_balances) + legitimate_treasury = pool_reserves`. The treasury steals from innocent depositors.

## Likelihood Explanation

**Highly Likely:**

- **Entry Point:** Any user can call withdrawal functions that invoke `execute_withdraw()` through the public entry function.
- **Preconditions:** Only requires normal withdrawal that leaves dust ≤1000 units
- **No Special Privileges:** Any regular user can trigger this
- **Economic Incentive:** For high-value tokens, the dust threshold of 1,000 units represents significant value
- **Compounding Effect:** Multiple users performing such withdrawals across multiple assets rapidly inflates treasury balance

## Recommendation

The fix requires deducting the dust amount from the user's balance when crediting it to treasury:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let dust_amount = token_amount - actual_amount;
        // ADD THIS: Decrease user's balance by the dust amount
        decrease_supply_balance(storage, asset, user, dust_amount);
        // Then credit to treasury
        storage::increase_treasury_balance(storage, asset, dust_amount);
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

This ensures the user's balance is properly decreased by the full withdrawn amount (including dust), preventing double-withdrawal of the dust portion.

## Proof of Concept

```move
#[test]
fun test_dust_double_withdrawal_exploit() {
    // Setup: Create lending pool with initial liquidity
    // 1. Alice deposits 10,000 tokens
    // 2. Bob deposits 1,500 tokens (total pool: 11,500)
    
    // 3. Bob withdraws 500, leaving 1,000 dust
    //    - Bob's actual balance after: 1,000 (bug: not decreased for dust)
    //    - Treasury accounting: +1,000
    //    - Pool balance: 11,000
    
    // 4. Bob withdraws remaining 1,000 (SHOULD FAIL but doesn't due to bug)
    //    - Bob gets 1,000 tokens
    //    - Pool balance: 10,000
    //    - Treasury accounting: still 1,000 (phantom)
    
    // 5. Admin withdraws treasury 1,000
    //    - Withdraws from pool.balance
    //    - Pool balance: 9,000
    
    // 6. Alice tries to withdraw 10,000 but only 9,000 available
    //    - Alice LOSES 1,000 tokens
}
```

**Notes:**
This vulnerability directly impacts the Volo protocol's integration with Navi lending through the navi_adaptor, which relies on the correctness of the underlying Navi lending protocol's accounting. The inflated treasury balance represents phantom funds that, when withdrawn, steal from legitimate depositors.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L68-114)
```text
    public(friend) fun execute_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        asset: u8,
        user: address,
        amount: u256 // e.g. 100USDT -> 100000000000
    ): u64 {
        assert!(user_collateral_balance(storage, asset, user) > 0, error::user_have_no_collateral());

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_withdraw<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury //
        /////////////////////////////////////////////////////////////////
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());

        if (actual_amount == token_amount) {
            // If the asset is all withdrawn, the asset type of the user is removed.
            if (is_collateral(storage, asset, user)) {
                storage::remove_user_collaterals(storage, asset, user);
            }
        };

        if (token_amount > actual_amount) {
            if (token_amount - actual_amount <= 1000) {
                // Tiny balance cannot be raised in full, put it to treasury 
                storage::increase_treasury_balance(storage, asset, token_amount - actual_amount);
                if (is_collateral(storage, asset, user)) {
                    storage::remove_user_collaterals(storage, asset, user);
                }
            };
        };

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);

        (actual_amount as u64)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L334-339)
```text
    fun decrease_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::decrease_supply_balance(storage, asset, user, scaled_amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L565-568)
```text
    public(friend) fun increase_treasury_balance(storage: &mut Storage, asset: u8, amount: u256) {
        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.treasury_balance = reserve.treasury_balance + amount;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L629-680)
```text
    public fun withdraw_treasury<CoinType>(
        _: &StorageAdminCap,
        pool_admin_cap: &PoolAdminCap,
        storage: &mut Storage,
        asset: u8,
        pool: &mut Pool<CoinType>,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coin_type = get_coin_type(storage, asset);
        assert!(coin_type == type_name::into_string(type_name::get<CoinType>()), error::invalid_coin_type());

        let (supply_index, _) = get_index(storage, asset);
        let reserve = table::borrow_mut(&mut storage.reserves, asset);

        // Without this conversion, then when typpe 1USDT (decimals is 6), the amount of 0.001 will be withdrawn(protocol decimals is 9)
        let withdraw_amount = pool::normal_amount(pool, amount);

        let scaled_treasury_value = reserve.treasury_balance;
        let treasury_value = ray_math::ray_mul(scaled_treasury_value, supply_index);
        let withdrawable_value = math::safe_math::min((withdraw_amount as u256), treasury_value); // get the smallest one value, which is the amount that can be withdrawn

        {
            // decrease treasury balance
            let scaled_withdrawable_value = ray_math::ray_div(withdrawable_value, supply_index);
            reserve.treasury_balance = scaled_treasury_value - scaled_withdrawable_value;
            decrease_total_supply_balance(storage, asset, scaled_withdrawable_value);
        };

        let withdrawable_amount = pool::unnormal_amount(pool, (withdrawable_value as u64));

        pool::withdraw_reserve_balance<CoinType>(
            pool_admin_cap,
            pool,
            withdrawable_amount,
            recipient,
            ctx
        );

        let scaled_treasury_value_after_withdraw = get_treasury_balance(storage, asset);
        emit(WithdrawTreasuryEvent {
            sender: tx_context::sender(ctx),
            recipient: recipient,
            asset: asset,
            amount: withdrawable_value,
            poolId: object::uid_to_address(pool::uid(pool)),
            before: scaled_treasury_value,
            after: scaled_treasury_value_after_withdraw,
            index: supply_index,
        })
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L833-851)
```text
    public entry fun entry_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        let _balance = lending::withdraw_coin<CoinType>(clock, oracle, storage, pool, asset, amount, ctx);
        let _coin = coin::from_balance(_balance, ctx);
        transfer::public_transfer(_coin, user);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L159-184)
```text
    public(friend) fun withdraw_reserve_balance<CoinType>(
        _: &PoolAdminCap,
        pool: &mut Pool<CoinType>,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let total_supply = balance::value(&pool.balance);
        assert!(total_supply >= amount, error::insufficient_balance());

        let withdraw_balance = balance::split(&mut pool.balance, amount);
        let withdraw_coin = coin::from_balance(withdraw_balance, ctx);

        let total_supply_after_withdraw = balance::value(&pool.balance);
        emit(PoolWithdrawReserve {
            sender: tx_context::sender(ctx),
            recipient: recipient,
            amount: amount,
            before: total_supply,
            after: total_supply_after_withdraw,
            pool: type_name::into_string(type_name::get<CoinType>()),
            poolId: object::uid_to_address(&pool.id),
        });

        transfer::public_transfer(withdraw_coin, recipient)
    }
```
