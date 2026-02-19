### Title
Collateral List Corruption: Zero-Balance Assets Not Removed After Full Liquidation

### Summary
The `execute_liquidate()` function fails to remove collateral assets from a user's collateral list when the asset is fully liquidated (balance reaches zero). This causes the collateral list to accumulate "ghost" entries over time, leading to increased gas costs for health factor calculations and potential denial-of-service when the list grows too large.

### Finding Description

The vulnerability exists in the `execute_liquidate()` function where collateral balances are decreased but the asset is never removed from the user's collateral list, even when fully liquidated: [1](#0-0) 

The function only removes the debt asset from the loan list when `is_max_loan_value` is true, but provides no corresponding logic to remove the collateral asset from the collateral list when the supply balance becomes zero.

In contrast, the `execute_withdraw()` function correctly implements collateral removal when a balance reaches zero: [2](#0-1) 

The `execute_withdraw()` function even handles edge cases where tiny balances remain: [3](#0-2) 

The collateral list is stored in the `UserInfo` struct and managed through `update_user_collaterals()` and `remove_user_collaterals()` functions: [4](#0-3) [5](#0-4) 

### Impact Explanation

The accumulation of zero-balance collateral entries creates multiple operational impacts:

1. **Gas Cost Escalation**: Health factor calculations must iterate over all entries in the collateral list, including zero-balance ghost entries. The following functions are affected: [6](#0-5) [7](#0-6) [8](#0-7) 

2. **State Bloat**: Each user who experiences full collateral liquidations will permanently store increasing numbers of meaningless entries in their collateral vector.

3. **Denial of Service**: If a user accumulates enough ghost entries through repeated liquidations, health factor calculations could exceed transaction gas limits, preventing liquidation, borrowing, or withdrawal operations for that user.

4. **Attack Amplification**: An attacker can intentionally create positions with many small collaterals across different assets, trigger liquidations on all of them, and cause permanent gas cost increases for that account.

### Likelihood Explanation

This vulnerability has **HIGH** likelihood:

- **Reachable Entry Point**: The `execute_liquidate()` function is called through the normal liquidation flow accessible to any user via the public lending interface.

- **Automatic Trigger**: Every liquidation that fully consumes a collateral asset (which is common in severe undercollateralization scenarios) will trigger this issue without any special conditions.

- **No Prevention Mechanism**: There is no maximum limit on collateral list size, no cleanup mechanism, and no validation preventing ghost entries from accumulating: [9](#0-8) 

- **Economic Feasibility**: The attack costs only the normal liquidation transaction fees, with no special requirements or expensive setup.

### Recommendation

Add collateral removal logic to `execute_liquidate()` after decreasing the supply balance. The fix should mirror the pattern used in `execute_withdraw()`:

```move
// After line 226 in execute_liquidate():
decrease_supply_balance(storage, collateral_asset, user, liquidable_amount_in_collateral + executor_bonus_amount + treasury_amount);

// Add this check:
let remaining_collateral = user_collateral_balance(storage, collateral_asset, user);
if (remaining_collateral == 0 || remaining_collateral <= 1000) {
    if (is_collateral(storage, collateral_asset, user)) {
        storage::remove_user_collaterals(storage, collateral_asset, user);
    }
}
```

Additional recommendations:
1. Add regression tests that verify collateral list cleanup after full liquidation
2. Consider implementing a cleanup function that allows users to manually remove zero-balance entries from their collateral lists
3. Add invariant checks in test suites to verify collateral list entries always have non-zero balances

### Proof of Concept

**Initial State:**
- Alice deposits 10 ETH (collateral asset 1) and 5 BTC (collateral asset 2)
- Alice borrows 10,000 USDT (debt asset 0)
- Alice's collateral list: [1, 2] (ETH, BTC)

**Execution Steps:**
1. ETH price drops from $1800 to $1300, making Alice's position unhealthy
2. Liquidator calls `execute_liquidate()` with parameters:
   - collateral_asset: 1 (ETH)
   - debt_asset: 0 (USDT)
   - amount: sufficient to liquidate all 10 ETH
3. The function executes:
   - Decreases Alice's ETH supply balance to 0 at line 226
   - Removes USDT from loan list if fully repaid at lines 228-230
   - **MISSING**: No removal of ETH from collateral list

**Expected Result:**
- Alice's collateral list should be [2] (only BTC remains)
- Alice's ETH balance: 0

**Actual Result:**
- Alice's collateral list: [1, 2] (ETH remains as ghost entry)
- Alice's ETH balance: 0
- All future health calculations will iterate over ETH unnecessarily

**Success Condition:**
Call `storage::get_user_assets()` for Alice and observe that asset 1 (ETH) remains in the collateral vector despite having zero balance. Each subsequent health factor calculation will include this zero-balance asset in its iteration loops, increasing gas costs without affecting the calculation result.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L93-98)
```text
        if (actual_amount == token_amount) {
            // If the asset is all withdrawn, the asset type of the user is removed.
            if (is_collateral(storage, asset, user)) {
                storage::remove_user_collaterals(storage, asset, user);
            }
        };
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L224-230)
```text
        decrease_borrow_balance(storage, debt_asset, user, liquidable_amount_in_debt);
        // Reduce the liquidated user's supply assets
        decrease_supply_balance(storage, collateral_asset, user, liquidable_amount_in_collateral + executor_bonus_amount + treasury_amount);

        if (is_max_loan_value) {
            storage::remove_user_loans(storage, debt_asset, user);
        };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L393-417)
```text
    public fun dynamic_liquidation_threshold(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // Power by Erin
        let (collaterals, _) = storage::get_user_assets(storage, user);
        let len = vector::length(&collaterals);
        let i = 0;

        let collateral_value = 0;
        let collateral_health_value = 0;

        while (i < len) {
            let asset = vector::borrow(&collaterals, i);
            let (_, _, threshold) = storage::get_liquidation_factors(storage, *asset); // liquidation threshold for coin
            let user_collateral_value = user_collateral_value(clock, oracle, storage, *asset, user); // total collateral in usd

            collateral_health_value = collateral_health_value + ray_math::ray_mul(user_collateral_value, threshold);
            collateral_value = collateral_value + user_collateral_value;
            i = i + 1;
        };

        if (collateral_value > 0) {
            return ray_math::ray_div(collateral_health_value, collateral_value)
        };

        0
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L634-654)
```text
    public fun calculate_avg_ltv(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): u256 {
        let (collateral_assets, _) = storage::get_user_assets(storage, user);

        let i = 0;
        let total_value = 0;
        let total_value_in_ltv = 0;
        while (i < vector::length(&collateral_assets)) {
            let asset_id = vector::borrow(&collateral_assets, i);
            let ltv = storage::get_asset_ltv(storage, *asset_id);
            let user_collateral_value = user_collateral_value(clock, oracle, storage, *asset_id, user);
            total_value = total_value + user_collateral_value;
            total_value_in_ltv = total_value_in_ltv + ray_math::ray_mul(ltv, user_collateral_value);

            i = i + 1;
        };

        if (total_value > 0) {
            return ray_math::ray_div(total_value_in_ltv, total_value)
        };
        0
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L69-72)
```text
    struct UserInfo has store {
        collaterals: vector<u8>,
        loans: vector<u8>
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L603-619)
```text
    public(friend) fun update_user_collaterals(storage: &mut Storage, asset: u8, user: address) {
        if (!table::contains(&storage.user_info, user)) {
            let collaterals = vector::empty<u8>();
            vector::push_back(&mut collaterals, asset);

            let user_info = UserInfo {
                collaterals: collaterals,
                loans: vector::empty<u8>(),
            };
            table::add(&mut storage.user_info, user, user_info)
        } else {
            let user_info = table::borrow_mut(&mut storage.user_info, user);
            if (!vector::contains(&user_info.collaterals, &asset)) {
                vector::push_back(&mut user_info.collaterals, asset)
            }
        };
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L621-627)
```text
    public(friend) fun remove_user_collaterals(storage: &mut Storage, asset: u8, user: address) {
        let user_info = table::borrow_mut(&mut storage.user_info, user);
        let (exist, index) = vector::index_of(&user_info.collaterals, &asset);
        if (exist) {
            _ = vector::remove(&mut user_info.collaterals, index)
        }
    }
```
