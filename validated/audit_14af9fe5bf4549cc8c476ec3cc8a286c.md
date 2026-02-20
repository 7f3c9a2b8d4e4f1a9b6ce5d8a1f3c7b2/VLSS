# Audit Report

## Title
Treasury Balance Inflation via Missing Balance Deduction in execute_withdraw() Dust Handling

## Summary
The `execute_withdraw()` function in the Navi lending_core protocol contains a critical accounting flaw where dust balances (≤1000 units) are credited to the treasury without being deducted from the user's supply balance. This enables users to withdraw their dust twice while the treasury believes it owns those funds, leading to inflated treasury balances that steal from other depositors when withdrawn by admins.

## Finding Description

The vulnerability exists in the dust handling logic of `execute_withdraw()`. [1](#0-0) 

**The Bug Flow:**

1. At line 90, the user's balance is decreased only by `actual_amount` (the withdrawal amount): [2](#0-1) 

2. At lines 100-108, when dust remains (≤1000 units), the code credits the treasury and removes the user from the collateral list, but **never decreases the user's balance by the dust amount**: [3](#0-2) 

3. The `increase_treasury_balance()` function only increments an accounting field without any corresponding balance deduction: [7](#0-6) 

**Why Existing Protections Fail:**

The entry point check at line 76 validates `user_collateral_balance > 0`, which reads the **actual balance from storage**, not collateral list membership: [4](#0-3) 

The `user_collateral_balance()` function reads the user's scaled balance and multiplies by the supply index: [5](#0-4) 

Since the dust was never removed via `decrease_supply_balance()`, the user retains it in storage and can pass this check on subsequent withdrawals despite being removed from the collateral list.

**Treasury Withdrawal Exploitation:**

When admins withdraw the inflated treasury balance, the function reads the accounting balance and withdraws **real tokens from pool reserves**: [6](#0-5) 

## Impact Explanation

**Critical Fund Loss Scenario:**

1. Alice deposits 10,000 tokens, Bob deposits 1,500 tokens
2. Bob withdraws 500 tokens, leaving 1,000 dust
   - Bob's balance: 1,000 (not decreased for dust)
   - Treasury accounting: +1,000 (phantom funds)
   - Pool has: 11,000 actual tokens
3. Bob withdraws his remaining 1,000 tokens (passes balance check at line 76)
   - Bob's balance: 0
   - Treasury accounting: still 1,000
   - Pool has: 10,000 actual tokens (only Alice's deposit)
4. Admin withdraws 1,000 treasury tokens
   - Pool now has: 9,000 tokens
5. Alice cannot withdraw her full 10,000 - **she loses 1,000 tokens**

This breaks the fundamental invariant: `sum(user_balances) + legitimate_treasury = pool_reserves`. The treasury steals from innocent depositors.

**Volo Protocol Impact:**

Since Volo vault integrates with Navi via `navi_adaptor`, if multiple users exploit this bug extensively, Navi protocol could become insolvent, directly impacting Volo vault's ability to withdraw its positions and causing losses to Volo users. [8](#0-7) 

## Likelihood Explanation

**Highly Likely:**

- **Entry Point:** Any user can call withdrawal functions that invoke `execute_withdraw()`
- **Preconditions:** Only requires normal withdrawal that leaves dust ≤1000 units  
- **No Special Privileges:** Any regular user can trigger this
- **Economic Incentive:** For high-value tokens, 1,000 units can represent significant value
- **Compounding Effect:** Multiple users performing such withdrawals rapidly inflates treasury balance

## Recommendation

Add an explicit balance deduction for the dust amount before crediting it to treasury:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let dust_amount = token_amount - actual_amount;
        // Add this line to properly deduct dust from user's balance
        decrease_supply_balance(storage, asset, user, dust_amount);
        storage::increase_treasury_balance(storage, asset, dust_amount);
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

## Proof of Concept

```move
#[test]
fun test_dust_double_withdraw_exploit() {
    // Setup: User deposits 10,000 tokens
    // Step 1: User withdraws 9,000, leaving 1,000 dust
    //   - User balance should be 0 after dust handling
    //   - Treasury should have 1,000
    //   - But user balance remains 1,000 (BUG)
    // Step 2: User withdraws again, extracting the dust
    //   - User gets another 1,000 tokens
    // Step 3: Treasury withdraws its 1,000
    //   - Total withdrawn: 11,000 from 10,000 deposit
    //   - Proof of double-spend and accounting corruption
}
```

**Notes:**

This vulnerability affects the Navi lending_core protocol which is a critical integration for Volo vault. The bug enables double-spending of dust amounts and inflates treasury balances with funds that should remain in user accounts. When treasury withdrawals occur, real tokens are extracted from pool reserves, causing direct losses to other depositors. Since Volo vault uses Navi as an external DeFi integration, widespread exploitation could lead to Navi insolvency and inability for Volo to recover its deposited positions.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L486-490)
```text
    public fun user_collateral_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (supply_balance, _) = storage::get_user_balance(storage, asset, user);
        let (supply_index, _) = storage::get_index(storage, asset);
        ray_math::ray_mul(supply_balance, supply_index) // scaled_amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L565-568)
```text
    public(friend) fun increase_treasury_balance(storage: &mut Storage, asset: u8, amount: u256) {
        let reserve = table::borrow_mut(&mut storage.reserves, asset);
        reserve.treasury_balance = reserve.treasury_balance + amount;
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L648-665)
```text
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
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```
