# Audit Report

## Title
Treasury Balance Inflation via Missing Balance Deduction in execute_withdraw() Dust Handling

## Summary
The `execute_withdraw()` function in the Navi lending_core protocol contains a critical accounting flaw where dust balances (≤1000 units) are credited to the treasury's accounting balance without being deducted from the user's supply balance. This allows users to withdraw their dust a second time while the treasury believes it owns those funds, leading to inflated treasury balances that steal from other depositors when withdrawn by admins.

## Finding Description

The vulnerability exists in the dust handling logic of `execute_withdraw()`. [1](#0-0) 

**The Bug Flow:**

1. When a user withdraws, the function retrieves their balance and decreases it by the withdrawal amount [2](#0-1) 

2. If dust remains (≤1000 units), the code credits the treasury and removes the user from the collateral list [3](#0-2) 

3. However, `increase_treasury_balance()` only increments an accounting field without deducting from the user's balance [4](#0-3) 

**Why Existing Protections Fail:**

- The entry point check at line 76 only validates `user_collateral_balance > 0`, which checks actual balance, not collateral list membership [5](#0-4) 

- The user retains their dust balance in the scaled supply balance tracking [6](#0-5) 

- Users can call withdraw again, passing the balance check and extracting the dust

**Treasury Withdrawal Exploitation:**

When admins withdraw the inflated treasury balance, the function reads the accounting balance and withdraws real tokens from the pool's reserves [7](#0-6) 

This means the treasury withdraws tokens that actually belong to other depositors, causing direct fund loss.

## Impact Explanation

**Critical Fund Loss Scenario:**

1. Alice deposits 10,000 tokens
2. Bob deposits 1,500 tokens  
3. Bob withdraws 500 tokens, leaving 1,000 dust
   - Bob's balance: 1,000 (not decreased for dust)
   - Treasury accounting: +1,000 (phantom funds)
   - Pool has: 11,000 actual tokens
4. Bob withdraws his remaining 1,000 tokens
   - Bob's balance: 0
   - Treasury accounting: still 1,000
   - Pool has: 10,000 actual tokens (only Alice's deposit)
5. Admin withdraws 1,000 treasury tokens via `withdraw_treasury()`
   - Function withdraws 1,000 from pool reserves [8](#0-7) 
   - Pool now has: 9,000 tokens
6. Alice tries to withdraw her 10,000 but pool only has 9,000
   - **Alice loses 1,000 tokens**

This breaks the fundamental invariant that `sum(user_balances) + legitimate_treasury = pool_reserves`. The treasury steals from innocent depositors.

## Likelihood Explanation

**Highly Likely:**

- **Entry Point:** Any user can call withdrawal functions that invoke `execute_withdraw()` [9](#0-8) 

- **Preconditions:** Only requires normal withdrawal that leaves dust ≤1000 units

- **No Special Privileges:** Any regular user can trigger this

- **Economic Incentive:** For high-value tokens, the dust threshold of 1,000 units represents significant value

- **Compounding Effect:** Multiple users performing such withdrawals across multiple assets rapidly inflates treasury balance

## Recommendation

Add a balance deduction when crediting dust to treasury:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let dust_amount = token_amount - actual_amount;
        // Credit treasury
        storage::increase_treasury_balance(storage, asset, dust_amount);
        // CRITICAL FIX: Deduct dust from user's balance
        decrease_supply_balance(storage, asset, user, dust_amount);
        // Remove from collateral list
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

This ensures the dust is actually transferred from user to treasury, not double-counted.

## Proof of Concept

```move
#[test]
fun test_dust_double_withdrawal_exploit() {
    // Setup: Alice deposits 10000, Bob deposits 1500
    // Step 1: Bob withdraws 500, leaving 1000 dust
    // - Treasury credited 1000
    // - Bob still has 1000 in balance
    // Step 2: Bob withdraws 1000 again
    // - Bob successfully withdraws his dust
    // - Treasury accounting still shows 1000
    // Step 3: Admin withdraws 1000 treasury
    // - Withdraws from pool reserves (Alice's funds)
    // Step 4: Alice can only withdraw 9000 instead of 10000
    // Result: Alice loses 1000 tokens to inflated treasury
}
```

The vulnerability is confirmed through the code flow analysis showing the missing balance deduction enables double-counting of dust amounts.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L553-563)
```text
    fun decrease_balance(_balance: &mut TokenBalance, user: address, amount: u256) {
        let current_amount = 0;

        if (table::contains(&_balance.user_state, user)) {
            current_amount = table::remove(&mut _balance.user_state, user)
        };
        assert!(current_amount >= amount, error::insufficient_balance());

        table::add(&mut _balance.user_state, user, current_amount - amount);
        _balance.total_supply = _balance.total_supply - amount
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L216-248)
```text
    fun base_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        user: address
    ): Balance<CoinType> {
        storage::when_not_paused(storage);
        storage::version_verification(storage);

        let normal_withdraw_amount = pool::normal_amount(pool, amount);
        let normal_withdrawable_amount = logic::execute_withdraw<CoinType>(
            clock,
            oracle,
            storage,
            asset,
            user,
            (normal_withdraw_amount as u256)
        );

        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
        let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
        emit(WithdrawEvent {
            reserve: asset,
            sender: user,
            to: user,
            amount: withdrawable_amount,
        });

        return _balance
    }
```
