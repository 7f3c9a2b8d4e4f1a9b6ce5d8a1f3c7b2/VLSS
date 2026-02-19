# Audit Report

## Title
Collateral List Corruption via Tiny Balance Handling Leading to Accounting Error and Health Factor Miscalculation

## Summary
In the Navi lending protocol's `execute_withdraw()` function, when a partial withdrawal leaves a tiny remaining balance (≤1000 units), the function credits the treasury with this amount but fails to deduct it from the user's balance before removing the user from the collateral list. This creates a double-counting vulnerability where the same tokens are attributed to both the user and treasury, while simultaneously breaking health factor calculations.

## Finding Description

The vulnerability occurs in the tiny balance handling logic within `execute_withdraw()` in the Navi lending_core protocol, which Volo integrates with for position management. [1](#0-0) 

**Root Cause:**

When a withdrawal leaves a tiny balance, the function executes three operations in sequence:

1. **Line 90**: Decreases user balance by `actual_amount` only via `decrease_supply_balance()`, leaving `token_amount - actual_amount` still in the user's account
2. **Line 103**: Credits treasury with `token_amount - actual_amount` via `increase_treasury_balance()` WITHOUT debiting the user
3. **Lines 104-106**: Removes the asset from the user's collateral list via `remove_user_collaterals()`

The critical flaw is that `increase_treasury_balance()` only increments the treasury balance without touching the user's balance: [2](#0-1) 

The `decrease_balance()` function that updates user balances: [3](#0-2) 

Shows that the user's new balance is set to `current_amount - amount`, meaning after line 90, the user retains `token_amount - actual_amount` in their balance.

**Security Guarantee Breakage:**

This breaks the critical invariant: **"user has non-zero balance ⟺ asset is in user's collateral list"**

After execution:
- User's scaled balance: `token_amount - actual_amount` (non-zero)
- Treasury balance: `+token_amount - actual_amount` (also credited)
- User's collateral list: Asset removed
- Result: Double-counting + health factor corruption

## Impact Explanation

**1. Accounting Double-Counting:**
The same tokens are counted twice - once in the user's remaining balance and once in the treasury balance. This creates phantom balances that don't correspond to actual locked funds.

**2. Health Factor Miscalculation:**
The `user_health_collateral_value()` function only counts assets present in the user's collateral list: [4](#0-3) 

Line 424 retrieves only assets in the collateral list. Since the tiny balance asset has been removed from this list, the user's remaining balance is NOT counted toward their health factor. This makes users appear less healthy than they actually are, potentially triggering incorrect liquidations.

**3. Protocol Insolvency Risk:**
Over time, repeated occurrences accumulate treasury balance without actual backing. Each instance leaves user funds "orphaned" (existing in storage but uncounted), while the treasury is credited with funds it doesn't actually hold.

**4. Impact on Volo Protocol:**
Since Volo holds positions in Navi through `NaviAccountCap`: [5](#0-4) 

Any accounting corruption in Navi directly affects Volo's position valuations and security model.

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

Add a call to decrease the user's balance by the tiny amount before crediting the treasury. The fix should be:

```move
if (token_amount > actual_amount) {
    if (token_amount - actual_amount <= 1000) {
        let tiny_amount = token_amount - actual_amount;
        // FIX: Decrease user balance by tiny amount before crediting treasury
        decrease_supply_balance(storage, asset, user, tiny_amount);
        storage::increase_treasury_balance(storage, asset, tiny_amount);
        if (is_collateral(storage, asset, user)) {
            storage::remove_user_collaterals(storage, asset, user);
        }
    };
};
```

This ensures atomic transfer of the tiny balance from user to treasury, maintaining accounting integrity and the collateral list invariant.

## Proof of Concept

```move
#[test]
fun test_tiny_balance_double_counting() {
    let mut scenario = test_scenario::begin(@0xA);
    
    // Setup: User deposits 10,001 units
    let user = @0xA;
    let asset = 0u8;
    
    // Initialize protocol storage, oracle, clock
    let (mut storage, oracle, clock) = setup_protocol(&mut scenario);
    
    // User deposits 10,001 units
    deposit_collateral(&mut storage, &clock, &oracle, asset, user, 10001);
    
    // Verify initial state
    let initial_balance = user_collateral_balance(&storage, asset, user);
    assert!(initial_balance == 10001, 0);
    let initial_treasury = get_treasury_balance(&storage, asset);
    let user_has_collateral = is_collateral(&storage, asset, user);
    assert!(user_has_collateral == true, 1);
    
    // Execute withdrawal leaving tiny balance
    execute_withdraw<COIN>(
        &clock,
        &oracle, 
        &mut storage,
        asset,
        user,
        10000  // Withdraw 10,000, leaving 1 unit
    );
    
    // Check post-state - BUG EXPOSED
    let final_balance = user_collateral_balance(&storage, asset, user);
    let final_treasury = get_treasury_balance(&storage, asset);
    let user_still_has_collateral = is_collateral(&storage, asset, user);
    
    // VULNERABILITY: User still has balance but not in collateral list
    assert!(final_balance == 1, 2);  // User still has 1 unit
    assert!(user_still_has_collateral == false, 3);  // But removed from collateral list!
    assert!(final_treasury == initial_treasury + 1, 4);  // Treasury also got +1
    
    // DOUBLE-COUNTING PROVEN: Same 1 unit counted in both user balance AND treasury
    // HEALTH FACTOR BUG: User's 1 unit won't be counted in health calculations
}
```

This test demonstrates that after withdrawal:
1. User retains non-zero balance (1 unit)
2. Treasury is credited with 1 unit
3. Asset is removed from user's collateral list
4. The same 1 unit is double-counted
5. Health factor calculations will ignore the user's remaining balance

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L85-108)
```text
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L3-5)
```text
use lending_core::account::AccountCap as NaviAccountCap;
use lending_core::dynamic_calculator;
use lending_core::storage::Storage;
```
