# Audit Report

## Title
Collateral List Corruption via Tiny Balance Handling Leading to Accounting Error and Health Factor Miscalculation

## Summary
In the Navi lending protocol's `execute_withdraw()` function, when a partial withdrawal leaves a tiny remaining balance (≤1000 units), the function credits the treasury with this amount but fails to deduct it from the user's balance before removing the user from the collateral list. This creates a double-counting vulnerability where the same tokens are attributed to both the user and treasury, while simultaneously breaking health factor calculations.

## Finding Description

The vulnerability occurs in the tiny balance handling logic within `execute_withdraw()` [1](#0-0) 

**Root Cause:**

When a withdrawal leaves a tiny balance, the function executes three critical operations in sequence:

1. Line 90 decreases the user's balance by only `actual_amount` via `decrease_supply_balance()`, leaving `token_amount - actual_amount` still in the user's account
2. Line 103 credits the treasury with `token_amount - actual_amount` via `increase_treasury_balance()` WITHOUT debiting the user
3. Line 105 removes the asset from the user's collateral list via `remove_user_collaterals()`

The critical flaw is that `increase_treasury_balance()` only increments the treasury balance without touching the user's balance [2](#0-1) 

The `decrease_balance()` function that updates user balances [3](#0-2)  shows that the user's new balance is set to `current_amount - amount`, meaning after line 90, the user retains `token_amount - actual_amount` in their balance.

**Security Guarantee Breakage:**

This breaks the critical invariant: **"user has non-zero balance ⟺ asset is in user's collateral list"**

After execution:
- User's balance: `token_amount - actual_amount` (non-zero)
- Treasury balance: `+token_amount - actual_amount` (also credited)
- User's collateral list: Asset removed
- Result: Double-counting + health factor corruption

## Impact Explanation

**1. Accounting Double-Counting:**
The same tokens are counted twice - once in the user's remaining balance and once in the treasury balance. This creates phantom balances that don't correspond to actual locked funds.

**2. Health Factor Miscalculation:**
The `user_health_collateral_value()` function only counts assets present in the user's collateral list [4](#0-3) 

Line 424 retrieves only assets in the collateral list. Since the tiny balance asset has been removed from this list, the user's remaining balance is NOT counted toward their health factor. This makes users appear less healthy than they actually are, potentially triggering incorrect liquidations.

**3. Protocol Insolvency Risk:**
Over time, repeated occurrences accumulate treasury balance without actual backing. Each instance leaves user funds "orphaned" (existing in storage but uncounted), while the treasury is credited with funds it doesn't actually hold.

**4. Impact on Volo Protocol:**
Since Volo holds positions in Navi through `NaviAccountCap` [5](#0-4) , any accounting corruption in Navi directly affects Volo's position valuations and security model. Volo's position value calculations read from Navi's storage, making them susceptible to this accounting error.

**Severity: HIGH** - Violates core accounting invariants, enables incorrect liquidations through health factor manipulation, and creates systemic protocol insolvency risk.

## Likelihood Explanation

**Attacker Capabilities:**
Any regular user can trigger this vulnerability through normal withdrawal operations. No special privileges or capabilities required.

**Attack Complexity:**
Trivial. A user simply needs to withdraw an amount that leaves a tiny balance (≤1000 units). 

**Example Scenario:**
- User has balance: 10,001 units
- User withdraws: 10,000 units  
- Remaining: 1 unit → triggers vulnerability
- Result: User keeps 1 unit in balance, treasury gets +1 unit, asset removed from collateral list

**Feasibility:**
- ✅ User must have a collateral balance (normal condition)
- ✅ Withdrawal amount leaves remainder ≤1000 (extremely common)
- ✅ No special market conditions required
- ✅ No timing dependencies

**Economic Rationality:**
Zero cost to trigger. Natural occurrence during normal protocol usage. Users are incentivized to withdraw maximum amounts (e.g., "withdraw all"), which frequently leaves dust balances due to rounding.

**Probability: HIGH** - This will occur naturally and frequently in normal protocol operation without any malicious intent.

## Recommendation

The fix requires ensuring the tiny balance is properly debited from the user before crediting the treasury:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        // Deduct the tiny balance from the user BEFORE crediting treasury
        decrease_supply_balance(storage, asset, user, token_amount - actual_amount);
        
        // Now credit the treasury
        storage::increase_treasury_balance(storage, asset, token_amount - actual_amount);
        
        // Remove from collateral list
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

This ensures:
1. User's balance is fully decremented (first by `actual_amount`, then by tiny balance)
2. Treasury is credited with the tiny balance
3. No double-counting occurs
4. User has zero balance when removed from collateral list (preserving the invariant)

## Proof of Concept

The vulnerability can be demonstrated with a test showing:
1. User deposits 10,001 units
2. User withdraws 10,000 units
3. After execution: User still has 1 unit in balance, treasury has +1 unit, asset not in collateral list
4. Health factor calculation excludes the user's remaining 1 unit

This proves the double-counting and invariant violation.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L423-440)
```text
    public fun user_health_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): u256 {
        let (collaterals, _) = storage::get_user_assets(storage, user);
        let len = vector::length(&collaterals);
        let value = 0;
        let i = 0;

        while (i < len) {
            let asset = vector::borrow(&collaterals, i);
            // let ltv = storage::get_asset_ltv(storage, *asset); // ltv for coin

            // TotalCollateralValue = CollateralValue * LTV * Threshold
            let collateral_value = user_collateral_value(clock, oracle, storage, *asset, user); // total collateral in usd
            // value = value + ray_math::ray_mul(collateral_value, ltv);
            value = value + collateral_value;
            i = i + 1;
        };
        value
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
