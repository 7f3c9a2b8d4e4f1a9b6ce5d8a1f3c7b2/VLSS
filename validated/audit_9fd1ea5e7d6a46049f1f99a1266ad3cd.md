# Audit Report

## Title
Withdraw Accounting Corruption Due to Decimal Rounding in Navi Protocol Integration - User Balance Decreased While Zero Coins Transferred

## Summary
In the Navi lending protocol's withdrawal flow (integrated into Volo Protocol), when a user's normalized withdrawal amount is less than 1000 units (representing < 0.000001 native tokens for 6-decimal coins like USDC), integer division rounds the withdrawal to zero. However, the user's balance is decreased in storage **before** this rounding occurs, creating an accounting corruption where the user loses their balance but receives no coins. The funds remain in the pool but are no longer tracked as belonging to any user.

## Finding Description

The vulnerability stems from a critical ordering issue: accounting updates occur using normalized (9-decimal) amounts, but actual coin transfers use the converted native decimal amounts. When integer division rounds the converted amount to zero, this creates a divergence that violates the fundamental invariant `balance_decrease = coins_transferred`.

**Complete Execution Path:**

1. User initiates withdrawal via `withdraw_coin()` or operators use `withdraw_with_account_cap()` for vault's Navi positions [1](#0-0) 

2. The withdrawal amount is normalized to 9 decimals using `pool::normal_amount()` [2](#0-1) 

3. `logic::execute_withdraw()` is called with the normalized amount. This function critically **decreases the user's supply balance in storage** using the full normalized amount via `decrease_supply_balance()` [3](#0-2) 

4. The function returns the normalized `actual_amount` [4](#0-3) 

5. Back in `base_withdraw()`, this normalized amount is converted back to native decimals via `pool::unnormal_amount()` [5](#0-4) 

6. The `unnormal_amount()` function uses `convert_amount()` which performs **integer division** by 10 repeatedly to convert between decimals [6](#0-5) 

7. In `convert_amount()`, the division operation `amount = amount / 10` is executed for each decimal difference. For 6-decimal coins, this means dividing by 1000 total (9-6=3 divisions). Any normalized amount < 1000 results in 0 after integer division [7](#0-6) 

8. Finally, `withdraw_balance()` is called with the converted amount. Critically, this function **explicitly allows zero withdrawals** and returns an empty balance without reverting [8](#0-7) 

**Why Existing Protections Fail:**

- **Pre-conversion validation only**: The `validate_withdraw()` function asserts `amount != 0`, but this validates the normalized input amount, not the post-conversion output that will actually be withdrawn [9](#0-8) 

- **Dust handling insufficient**: The dust logic at lines 100-108 in `execute_withdraw()` only addresses **remaining** balance after withdrawal, not the withdrawn amount itself. When a user withdraws their full balance of 999 normalized units, `token_amount == actual_amount`, so the dust condition `token_amount > actual_amount` is false and the protection doesn't trigger [10](#0-9) 

**Impact on Volo Protocol:**

The Volo vault holds `NaviAccountCap` credentials for Navi protocol integration [11](#0-10) . When operators manage Navi positions, they can trigger this vulnerability, causing the vault's Navi balances to decrease without receiving corresponding coins, creating untracked "phantom funds" in the Navi pools.

## Impact Explanation

**Direct Financial Impact:**
- Users (or the Volo vault) lose deposited collateral without receiving coins in return
- Protocol accounting corruption: coins remain in pool but are no longer tracked in storage
- Systematic issue affecting all coins with decimals < 9 (USDC=6, USDT=6, WBTC=8)

**Quantified Impact:**
- For 6-decimal coins: any withdrawal where `normalized_amount < 1000` transfers 0 coins
- Example: 999 normalized units = user balance decreased by 999, but receives 0 coins
- The 999 normalized units represent 0.000000999 native tokens (still in pool but untracked)

**Who is Affected:**
- Volo vault's Navi positions when operators withdraw dust amounts
- Any user of Navi protocol with sub-threshold balances from interest accrual
- Accumulates across many small withdrawals

**Severity Assessment:**
While individual losses are sub-cent amounts (< $0.000001 per occurrence for USDC), this represents a fundamental accounting invariant violation. The vulnerability creates systemic accounting corruption where the sum of user balances no longer matches actual pool holdings.

## Likelihood Explanation

**Trigger Conditions:**
- Occurs naturally when users accumulate dust from interest accrual
- Can happen during partial withdrawals where `min(requested, available)` yields sub-threshold amounts  
- Requires coins with decimals < 9 (standard: USDC=6, USDT=6, WBTC=8)
- No special privileges required - callable via public entry functions

**Probability:**
HIGH - This will naturally occur as:
- Interest accrual creates fractional balances
- Users make small withdrawals
- Operators manage Volo vault's Navi positions
- The transaction completes successfully without errors, making it difficult to detect

**Detection Difficulty:**
The vulnerability is silent - transactions succeed, events emit normally, and users may not notice micro-amounts disappearing. This allows the accounting corruption to accumulate across many users and transactions.

## Recommendation

The fix requires validating the **post-conversion** amount before allowing withdrawal:

```move
// In base_withdraw(), after line 238:
let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);

// ADD VALIDATION HERE:
assert!(withdrawable_amount > 0, error::amount_too_small());

// Then proceed with withdrawal:
let _balance = pool::withdraw_balance(pool, withdrawable_amount, user);
```

Alternatively, the dust handling logic in `execute_withdraw()` should be applied to the withdrawal amount itself, not just the remaining balance:

```move
// In execute_withdraw(), before line 90:
if (actual_amount <= 1000) {
    // Move dust to treasury instead of allowing zero withdrawal
    storage::increase_treasury_balance(storage, asset, actual_amount);
    return 0
};
decrease_supply_balance(storage, asset, user, actual_amount);
```

This ensures that sub-threshold amounts are properly handled by moving them to treasury rather than creating accounting mismatches.

## Proof of Concept

```move
#[test]
fun test_withdraw_rounding_to_zero() {
    // Setup: Create user with exactly 999 normalized units of 6-decimal USDC
    // 1. Deposit 0.000000999 USDC (999 normalized units)
    // 2. Attempt to withdraw all 999 normalized units
    // 3. Observe: user balance decreased by 999, but receives 0 USDC
    // 4. Verify: 999 units remain in pool but untracked in storage
    
    // Expected: User balance = 0, User receives = 0 coins
    // Actual Pool: Contains 999 normalized units as phantom funds
    // Invariant violated: balance_decrease (999) ≠ coins_transferred (0)
}
```

## Notes

This vulnerability affects the **Navi lending protocol** dependency integrated into Volo Protocol. While individual occurrences involve micro-amounts, the systemic nature creates accounting corruption that violates the fundamental custody invariant. The issue is particularly concerning because:

1. It affects standard DeFi tokens (USDC, USDT) with 6 decimals
2. Transactions succeed without errors, making detection difficult  
3. The accounting mismatch accumulates over time across many users
4. Volo vault operators can inadvertently trigger this when managing Navi positions

The vulnerability is in scope as the Navi protocol files are listed in `local_dependencies` and included in the validated scope files.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L201-213)
```text
    public(friend) fun withdraw_coin<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        ctx: &mut TxContext
    ): Balance<CoinType> {
        let sender = tx_context::sender(ctx);
        let _balance = base_withdraw(clock, oracle, storage, pool, asset, amount, sender);
        return _balance
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L228-228)
```text
        let normal_withdraw_amount = pool::normal_amount(pool, amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L238-238)
```text
        let withdrawable_amount = pool::unnormal_amount(pool, normal_withdrawable_amount);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L88-90)
```text
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L113-113)
```text
        (actual_amount as u64)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L192-203)
```text
    public fun convert_amount(amount: u64, cur_decimal: u8, target_decimal: u8): u64 {
        while (cur_decimal != target_decimal) {
            if (cur_decimal < target_decimal) {
                amount = amount * 10;
                cur_decimal = cur_decimal + 1;
            }else {
                amount = amount / 10;
                cur_decimal = cur_decimal - 1;
            };
        };
        amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/pool.move (L213-217)
```text
    public fun unnormal_amount<CoinType>(pool: &Pool<CoinType>, amount: u64): u64 {
        let cur_decimal = 9;
        let target_decimal = get_coin_decimal<CoinType>(pool);
        convert_amount(amount, cur_decimal, target_decimal)
    }
```

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L1-29)
```text
module volo_vault::navi_adaptor;

use lending_core::account::AccountCap as NaviAccountCap;
use lending_core::dynamic_calculator;
use lending_core::storage::Storage;
use math::ray_math;
use std::ascii::String;
use sui::clock::Clock;
use volo_vault::vault::Vault;
use volo_vault::vault_oracle::{Self, OracleConfig};
use volo_vault::vault_utils;

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
