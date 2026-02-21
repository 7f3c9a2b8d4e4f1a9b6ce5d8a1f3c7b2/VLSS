# Audit Report

## Title
Critical Double-Spend Vulnerability in execute_withdraw() Dust Handling with Accounting Mismatch

## Summary
The `execute_withdraw()` function in the Navi lending_core protocol contains a critical double-spend vulnerability where dust balances (≤1000 units) are transferred to treasury accounting without being deducted from users' supply balances. This allows users to withdraw the same dust twice while the treasury believes it owns those funds, leading to direct theft from other depositors. Additionally, a scaling bug compounds the issue by over-crediting the treasury.

## Finding Description

The vulnerability exists in the dust handling logic where two separate accounting bugs create a double-spend exploit path.

**Bug #1: Missing Balance Deduction**

When a withdrawal leaves dust (≤1000 units), the code credits the treasury but fails to deduct this amount from the user's supply balance. [1](#0-0) 

The execution flow is:
1. Line 90 decreases user balance by `actual_amount` (the amount withdrawn)
2. Lines 100-108 detect remaining dust and credit treasury via `increase_treasury_balance()`
3. However, the user's balance is NOT decreased by this dust amount
4. User retains the dust in their supply balance while treasury also claims ownership

**Bug #2: Incorrect Scaling**

The dust amount added to treasury is in actual tokens, but `treasury_balance` stores scaled values. This is evident from:
- Normal treasury accrual uses scaled amounts [2](#0-1) 
- Treasury withdrawal treats balance as scaled [3](#0-2) 
- But dust is added without scaling [4](#0-3) 

**Why Existing Protections Fail:**

The entry point validation only checks if user balance > 0, which the user still satisfies since their balance wasn't decreased. [5](#0-4) 

The balance calculation multiplies scaled balance by supply_index to get actual tokens, confirming users retain the dust. [6](#0-5) 

## Impact Explanation

**Critical Fund Loss Scenario:**

With supply_index = 1.5 (showing scaling impact):

1. User deposits 10,000 tokens (scaled: 6,667)
2. User withdraws 9,000 tokens leaving 1,000 dust:
   - User's balance decreased to 1,000 (scaled: 667)
   - Treasury credited with 1,000 (treated as scaled, but should be 667)
   - User's actual balance: still 1,000
3. User withdraws the 1,000 dust again (passes balance check)
4. Admin withdraws treasury: 1,000 * 1.5 = 1,500 tokens withdrawn
5. **Result**: User withdrew 10,000, treasury withdrew 1,500 = 11,500 total from 10,000 deposit
6. **1,500 tokens stolen from other depositors**

This breaks the fundamental invariant: `sum(user_balances) + treasury_balance = pool_reserves`

The scaling bug amplifies the theft by the supply_index multiplier, making high-interest markets especially vulnerable.

## Likelihood Explanation

**Highly Likely:**

- **Entry Point**: Any user can call public withdrawal functions [7](#0-6) 
- **Preconditions**: Only requires normal withdrawal leaving ≤1000 dust (extremely common)
- **No Special Privileges**: Regular user action
- **Economic Incentive**: For tokens with high value or high supply_index, the dust represents significant funds
- **Compounding Effect**: Multiple users across multiple assets rapidly drain the protocol
- **Undetectable**: Treasury accounting appears correct until withdrawal attempts fail

## Recommendation

Apply two fixes:

1. **Decrease user balance when transferring dust to treasury**:
```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let dust_amount = token_amount - actual_amount;
        // ADD THIS: Decrease user's balance by dust amount
        decrease_supply_balance(storage, asset, user, dust_amount);
        storage::increase_treasury_balance(storage, asset, dust_amount);
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

2. **Fix treasury scaling in increase_treasury_balance**:
```move
public(friend) fun increase_treasury_balance(storage: &mut Storage, asset: u8, amount: u256) {
    let (supply_index, _) = get_index(storage, asset);
    let scaled_amount = ray_math::ray_div(amount, supply_index);
    let reserve = table::borrow_mut(&mut storage.reserves, asset);
    reserve.treasury_balance = reserve.treasury_balance + scaled_amount;
}
```

Or alternatively, pass scaled amounts to `increase_treasury_balance` at the call site in `execute_withdraw()`.

## Proof of Concept

```move
#[test]
fun test_dust_double_spend_exploit() {
    let scenario = test_scenario::begin(OWNER);
    sup_global::init_protocol(&mut scenario);
    
    // Setup: User deposits 1500 tokens
    test_scenario::next_tx(&mut scenario, OWNER);
    {
        let storage = test_scenario::take_shared<Storage>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        
        logic::execute_deposit_for_testing<USDT_TEST>(&clock, &mut storage, ASSET_ID, OWNER, 1500);
        
        // First withdrawal: withdraw 500, leaving 1000 dust
        let withdrawn1 = logic::execute_withdraw<USDT_TEST>(&clock, &oracle, &mut storage, ASSET_ID, OWNER, 500);
        assert!(withdrawn1 == 500, 0);
        
        // Check user still has 1000 balance (BUG: not decreased by dust)
        let balance_after_first = logic::user_collateral_balance(&mut storage, ASSET_ID, OWNER);
        assert!(balance_after_first == 1000, 1);
        
        // Check treasury was credited with 1000
        let treasury_bal = storage::get_treasury_balance(&storage, ASSET_ID);
        assert!(treasury_bal == 1000, 2);
        
        // Second withdrawal: user withdraws the 1000 dust AGAIN
        let withdrawn2 = logic::execute_withdraw<USDT_TEST>(&clock, &oracle, &mut storage, ASSET_ID, OWNER, 1000);
        assert!(withdrawn2 == 1000, 3);
        
        // User withdrew 1500 total but treasury also has 1000
        // Pool deficit created - treasury steals from other depositors
        
        clock::destroy_for_testing(clock);
        test_scenario::return_shared(storage);
    };
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L76-76)
```text
        assert!(user_collateral_balance(storage, asset, user) > 0, error::user_have_no_collateral());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L100-108)
```text
        if (token_amount > actual_amount) {
            if (token_amount - actual_amount <= 1000) {
                // Tiny balance cannot be raised in full, put it to treasury 
                storage::increase_treasury_balance(storage, asset, token_amount - actual_amount);
                if (is_collateral(storage, asset, user)) {
                    storage::remove_user_collaterals(storage, asset, user);
                }
            };
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L283-285)
```text
        let scaled_treasury_amount = ray_math::ray_div(treasury_amount, new_supply_index);

        storage::update_state(storage, asset, new_borrow_index, new_supply_index, current_timestamp, scaled_treasury_amount);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L648-650)
```text
        let scaled_treasury_value = reserve.treasury_balance;
        let treasury_value = ray_math::ray_mul(scaled_treasury_value, supply_index);
        let withdrawable_value = math::safe_math::min((withdraw_amount as u256), treasury_value); // get the smallest one value, which is the amount that can be withdrawn
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L229-229)
```text
        let normal_withdrawable_amount = logic::execute_withdraw<CoinType>(
```
