# Audit Report

## Title
Collateral List Corruption: Zero-Balance Assets Not Removed After Full Liquidation

## Summary
The Navi lending protocol's `execute_liquidate()` function fails to remove fully liquidated collateral assets from a user's collateral tracking vector, creating permanent "ghost" entries that cause gas cost escalation and potential denial-of-service. This contrasts with `execute_withdraw()` which correctly implements cleanup logic.

## Finding Description

The vulnerability exists due to asymmetric collateral list management between withdrawal and liquidation operations.

When a user's collateral is fully liquidated, `execute_liquidate()` reduces the collateral balance to zero but never removes the asset from the user's collateral tracking vector [1](#0-0) . The function only removes the debt asset from the loans list when `is_max_loan_value` is true, but provides no corresponding cleanup for the collateral asset.

In contrast, `execute_withdraw()` implements proper cleanup by removing collateral assets when balance reaches zero [2](#0-1)  and even handles edge cases where tiny balances remain [3](#0-2) .

The collateral list is stored as a vector in the UserInfo struct [4](#0-3)  and returned directly without filtering by `get_user_assets()` [5](#0-4) .

The impact manifests during health factor calculations, which iterate through all collateral entries including ghost entries. Critical affected functions include `user_health_collateral_value()` [6](#0-5) , `dynamic_liquidation_threshold()` [7](#0-6) , `calculate_avg_ltv()` [8](#0-7) , and `calculate_avg_threshold()` [9](#0-8) . Each iteration performs oracle price lookups even for zero-balance entries.

## Impact Explanation

This vulnerability creates multiple measurable impacts:

1. **Gas Cost Escalation**: Every health factor check must iterate ghost entries and perform unnecessary oracle price lookups. For Volo vault users accessing Navi positions via the adaptor [10](#0-9) , this increases operational gas costs linearly with accumulated ghost entries.

2. **Permanent State Bloat**: Ghost entries persist forever in on-chain storage, bloating the UserInfo struct with meaningless data.

3. **Denial-of-Service Risk**: If a user accumulates sufficient ghost entries through repeated full liquidations across different collateral types, health factor calculations could exceed transaction gas limits, preventing critical operations like further liquidations, borrowing, or withdrawals.

4. **Attack Amplification**: An attacker can intentionally create positions with many small collateral deposits across different assets, allow them to be fully liquidated, and permanently increase gas costs for that account.

## Likelihood Explanation

This vulnerability has HIGH likelihood:

- **Reachable Entry Point**: The liquidation flow is accessible via public entry functions [11](#0-10)  that any user can call.

- **Automatic Trigger**: Every liquidation that fully consumes a collateral asset triggers this issue. Full liquidations are common during market volatility when positions become severely undercollateralized.

- **No Prevention Mechanism**: Code inspection confirms no maximum limit on collateral list size, no cleanup mechanism in the liquidation path, and no validation preventing ghost entry accumulation.

- **Economic Feasibility**: The issue is triggered during normal protocol operations with no additional cost beyond standard liquidation transaction fees.

## Recommendation

Add collateral cleanup logic to `execute_liquidate()` similar to `execute_withdraw()`:

```move
// After line 226 in execute_liquidate()
let remaining_collateral = user_collateral_balance(storage, collateral_asset, user);
if (remaining_collateral == 0 || remaining_collateral <= 1000) {
    if (remaining_collateral > 0) {
        storage::increase_treasury_balance(storage, collateral_asset, remaining_collateral);
    };
    if (is_collateral(storage, collateral_asset, user)) {
        storage::remove_user_collaterals(storage, collateral_asset, user);
    };
};
```

This ensures parity with withdrawal logic and prevents ghost entry accumulation.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize Navi lending storage with multiple reserves (USDT, USDC, ETH)
2. Create a user account and deposit collateral in all three assets
3. Have user borrow against collateral to create unhealthy position
4. Execute full liquidations on each collateral type sequentially
5. Verify that all three assets remain in the user's collaterals vector despite zero balances
6. Measure gas cost increase in subsequent health factor calculations
7. Demonstrate that the collaterals vector contains ghost entries that `execute_withdraw()` would have cleaned up

The test would confirm that the asymmetry between withdrawal and liquidation cleanup leads to permanent state corruption with measurable gas impact.

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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L656-676)
```text
    public fun calculate_avg_threshold(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): u256 {
        let (collateral_assets, _) = storage::get_user_assets(storage, user);

        let i = 0;
        let total_value = 0;
        let total_value_in_threshold = 0;
        while (i < vector::length(&collateral_assets)) {
            let asset_id = vector::borrow(&collateral_assets, i);
            let (_, _, threshold) = storage::get_liquidation_factors(storage, *asset_id);
            let user_collateral_value = user_collateral_value(clock, oracle, storage, *asset_id, user);
            total_value = total_value + user_collateral_value;
            total_value_in_threshold = total_value_in_threshold + ray_math::ray_mul(threshold, user_collateral_value);

            i = i + 1;
        };

        if (total_value > 0) {
            return ray_math::ray_div(total_value_in_threshold, total_value)
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L365-372)
```text
    public fun get_user_assets(storage: &Storage, user: address): (vector<u8>, vector<u8>){
        if (!table::contains(&storage.user_info, user)) {
            return (vector::empty<u8>(), vector::empty<u8>())
        };

        let user_info = table::borrow(&storage.user_info, user);
        (user_info.collaterals, user_info.loans)
    }
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L345-375)
```text
    public(friend) fun liquidation<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_coin: Coin<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        liquidate_user: address,
        liquidate_amount: u64,
        ctx: &mut TxContext
    ): (Balance<CollateralCoinType>, Balance<DebtCoinType>) {
        let sender = tx_context::sender(ctx);
        let debt_balance = utils::split_coin_to_balance(debt_coin, liquidate_amount, ctx);

        let (_excess_balance, _bonus_balance) = base_liquidation_call(
            clock,
            oracle,
            storage,
            debt_asset,
            debt_pool,
            debt_balance,
            collateral_asset,
            collateral_pool,
            sender,
            liquidate_user
        );

        (_bonus_balance, _excess_balance)
    }
```
