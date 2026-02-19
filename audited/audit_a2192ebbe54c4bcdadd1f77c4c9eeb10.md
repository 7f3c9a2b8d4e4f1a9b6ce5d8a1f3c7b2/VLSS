# Audit Report

## Title
Incorrect Effective Amount Calculation Due to Mixed Scaled Balance Precision in Incentive V2

## Summary
The Navi protocol's incentive V2 system, integrated into Volo vault operations, calculates user effective amounts using scaled balances (normalized by supply/borrow indices) without converting them to actual token amounts. This causes systematic reward miscalculation for users with both supply and borrow positions, as scaled balances with different denominators are arithmetically combined as if they had the same precision.

## Finding Description

The vulnerability exists in the incentive reward calculation flow where `update_reward()` retrieves user balances that are stored in scaled form. [1](#0-0) 

The protocol stores balances as scaled values where actual amounts are divided by their respective indices during deposit/borrow operations. [2](#0-1) 

The `storage::get_user_balance()` function returns these scaled balances directly from storage without any conversion. [3](#0-2) 

However, `calculate_user_effective_amount()` receives these scaled balances and performs arithmetic operations on them as if they were actual token balances. [4](#0-3) 

The function's implementation confirms it expects actual balances (note the comment stating "borrow_balance decimal is 9" referring to token decimals) but operates on scaled values: [5](#0-4) 

**The core issue:** scaled_supply has denominator supply_index while scaled_borrow has denominator borrow_index. When these indices diverge (supply_index = 1.0, borrow_index = 1.5), the arithmetic `scaled_supply - factor * scaled_borrow` produces incorrect results because it's mixing different denominators.

The correct approach is demonstrated in incentive V3, which converts scaled balances to actual balances using ray_mul with respective indices before performing calculations: [6](#0-5) 

Volo vault operations integrate with this incentive_v2 system: [7](#0-6) 

## Impact Explanation

**Direct Fund Impact - Reward Misallocation:**

When supply_index = 1.0e27 and borrow_index = 1.5e27:
- User with actual_supply = 10,000 tokens, actual_borrow = 5,000 tokens  
- Stored values: scaled_supply = 10,000, scaled_borrow = 3,333
- Current calculation: effective_amount = 10,000 - 3,333 = 6,667
- Correct calculation: effective_amount = 10,000 - 5,000 = 5,000
- Error: 33% overestimation

This causes:
1. Users with both supply/borrow positions receive **incorrect reward amounts** based on wrong effective balances
2. Error **compounds over time** as indices diverge further through natural interest accrual
3. Creates **unfair reward distribution** - some users over-rewarded at expense of others
4. Incentive pool **depletes faster** than intended if systematic over-rewarding occurs
5. Affects **all active incentive pools** using V2 across all assets

The severity is HIGH because this directly impacts fund distribution through the reward mechanism, affecting every user with both supply and borrow positions across all assets integrated with Volo vault operations.

## Likelihood Explanation

**Exploitation Conditions:**
- No special attacker capabilities required - affects all normal protocol users
- Occurs automatically whenever a user has both supply and borrow positions  
- Requires only that time passes for indices to diverge (happens naturally as interest accrues)

**Execution Practicality:**
- Triggered through standard protocol operations: deposit, borrow, and reward claims
- Entry point is public function `claim_reward()`
- No authorization bypass needed - it's a systematic logic bug
- Works on any asset where incentive pools are configured

**Economic Rationality:**
- Users naturally have both supply and borrow positions in lending protocols
- Indices diverge naturally over time as borrowers pay interest  
- Users claiming rewards perform expected protocol actions
- No extraordinary gas costs or capital required

**Probability:** CERTAIN - This vulnerability affects every reward calculation for users with both supply and borrow positions. It is not an edge case but a systematic error in the core incentive calculation logic that manifests in all normal operations.

## Recommendation

Convert scaled balances to actual balances before performing effective amount calculations, following the pattern used in incentive V3:

```move
fun update_reward(clock: &Clock, incentive: &mut Incentive, storage: &mut Storage, asset_id: u8, option: u8, user: address) {
    // ... existing code ...
    
    let (user_supply_balance, user_borrow_balance) = storage::get_user_balance(storage, asset_id, user);
    let (total_supply_balance, total_borrow_balance) = storage::get_total_supply(storage, asset_id);
    
    // ADD: Get indices and convert to actual balances
    let (supply_index, borrow_index) = storage::get_index(storage, asset_id);
    let user_supply_balance = ray_math::ray_mul(user_supply_balance, supply_index);
    let user_borrow_balance = ray_math::ray_mul(user_borrow_balance, borrow_index);
    let total_supply_balance = ray_math::ray_mul(total_supply_balance, supply_index);
    let total_borrow_balance = ray_math::ray_mul(total_borrow_balance, borrow_index);
    
    // Now use actual balances in calculations
    let user_effective_amount = calculate_user_effective_amount(option, user_supply_balance, user_borrow_balance, pool.factor);
    // ... rest of function ...
}
```

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a lending pool with supply_index = 1.0e27, borrow_index = 1.5e27
2. Creating a user with 10,000 supply and 5,000 borrow (stored as scaled: 10,000 and 3,333)
3. Calling `claim_reward()` 
4. Observing that effective_amount = 6,667 instead of correct 5,000
5. User receives 33% more rewards than deserved

The test would create this scenario and verify the incorrect reward calculation occurs due to the mixed scaled balance arithmetic.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L385-386)
```text
        let (user_supply_balance, user_borrow_balance) = storage::get_user_balance(storage, asset_id, user);
        let (total_supply_balance, total_borrow_balance) = storage::get_total_supply(storage, asset_id);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L398-398)
```text
            let user_effective_amount = calculate_user_effective_amount(option, user_supply_balance, user_borrow_balance, pool.factor);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L465-483)
```text
    public fun calculate_user_effective_amount(option: u8, supply_balance: u256, borrow_balance: u256, factor: u256): u256 {
        let tmp_balance = supply_balance;
        if (option == constants::option_type_borrow()) {
            supply_balance = borrow_balance;
            borrow_balance = tmp_balance;
        };

        // supply- Scoefficient*borrow
        // **After many verifications, the calculation method is ray_mul
        // factor is set to 1e27, and borrow_balance decimal is 9
        // the correct one is: ray_math::ray_mul(1000000000000000000000000000, 2_000000000) = 2_000000000
        // ray_math::ray_mul(800000000000000000000000000, 2_000000000) = 1_600000000
        let effective_borrow_balance = ray_math::ray_mul(factor, borrow_balance);
        if (supply_balance > effective_borrow_balance) {
            return supply_balance - effective_borrow_balance
        };

        0
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L323-346)
```text
    fun increase_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////////////////////////////////
        //                               get the current exchange rate                              //
        // the update_state function has been called before here, so it is the latest exchange rate //
        //////////////////////////////////////////////////////////////////////////////////////////////
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::increase_supply_balance(storage, asset, user, scaled_amount)
    }

    fun decrease_supply_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (supply_index, _) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, supply_index);

        storage::decrease_supply_balance(storage, asset, user, scaled_amount)
    }

    fun increase_borrow_balance(storage: &mut Storage, asset: u8, user: address, amount: u256) {
        let (_, borrow_index) = storage::get_index(storage, asset);
        let scaled_amount = ray_math::ray_div(amount, borrow_index);

        storage::increase_borrow_balance(storage, asset, user, scaled_amount)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/storage.move (L414-427)
```text
    public fun get_user_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256) {
        let reserve = table::borrow(&storage.reserves, asset);
        let supply_balance = 0;
        let borrow_balance = 0;

        if (table::contains(&reserve.supply_balance.user_state, user)) {
            supply_balance = *table::borrow(&reserve.supply_balance.user_state, user)
        };
        if (table::contains(&reserve.borrow_balance.user_state, user)) {
            borrow_balance = *table::borrow(&reserve.borrow_balance.user_state, user)
        };

        (supply_balance, borrow_balance)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L483-508)
```text
    public fun get_effective_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256, u256, u256) {
        // get the total supply and borrow
        let (total_supply, total_borrow) = storage::get_total_supply(storage, asset);
        let (user_supply, user_borrow) = storage::get_user_balance(storage, asset, user);
        let (supply_index, borrow_index) = storage::get_index(storage, asset);

        // calculate the total supply and borrow
        let total_supply = ray_math::ray_mul(total_supply, supply_index);
        let total_borrow = ray_math::ray_mul(total_borrow, borrow_index);
        let user_supply = ray_math::ray_mul(user_supply, supply_index);
        let user_borrow = ray_math::ray_mul(user_borrow, borrow_index);

        // calculate the user effective supply
        let user_effective_supply: u256 = 0;
        if (user_supply > user_borrow) {
            user_effective_supply = user_supply - user_borrow;
        };

        // calculate the user effective borrow
        let user_effective_borrow: u256 = 0;
        if (user_borrow > user_supply) {
            user_effective_borrow = user_borrow - user_supply;
        };

        (user_effective_supply, user_effective_borrow, total_supply, total_borrow)
    }
```

**File:** volo-vault/tests/operation/operation.test.move (L3229-3239)
```text
        let mut incentive_v2 = s.take_shared<IncentiveV2>();
        let mut incentive_v3 = s.take_shared<IncentiveV3>();
        incentive_v3::deposit_with_account_cap<SUI_TEST_COIN>(
            &clock,
            &mut storage,
            &mut sui_pool,
            0,
            split_to_deposit_balance.into_coin(s.ctx()),
            &mut incentive_v2,
            &mut incentive_v3,
            navi_account_cap,
```
