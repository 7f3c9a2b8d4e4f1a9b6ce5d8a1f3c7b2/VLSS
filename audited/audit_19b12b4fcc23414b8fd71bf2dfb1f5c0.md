### Title
Mathematical Inconsistency in Incentive v3 Reward Calculation Causes Systematic Reward Under-Distribution

### Summary
The incentive v3 reward system uses GROSS total balances (total_supply/total_borrow) to calculate the global reward index but NET effective balances (user_effective_supply/user_effective_borrow) to calculate individual user rewards. This mathematical inconsistency causes systematic under-distribution of rewards when users have offsetting supply and borrow positions in the same asset, with the shortfall accumulating undistributed in reward funds.

### Finding Description

The vulnerability exists in both the UI getter function and the core reward update logic: [1](#0-0) [2](#0-1) 

The root cause is in how balances are retrieved and used:

**Step 1: Balance Retrieval** - The `get_effective_balance()` function returns four values: [3](#0-2) 

The critical distinction:
- `total_supply` and `total_borrow` are GROSS totals (sum of all user balances with interest applied)
- `user_effective_supply` and `user_effective_borrow` are NET positions (supply minus borrow, or vice versa)

**Step 2: Global Index Calculation** - Uses GROSS totals as the denominator: [4](#0-3) 

**Step 3: User Reward Calculation** - Uses NET effective balances as the multiplier: [5](#0-4) 

**Why Protections Fail:**
The Volo lending protocol does NOT prevent users from supplying and borrowing the same asset, unlike Suilend. The validation logic only checks liquidity and caps, not position conflicts: [6](#0-5) 

### Impact Explanation

**Mathematical Proof:**
Consider supply rewards with rate R = 1000 tokens/day for asset SUI:
- User A: 100 SUI supply, 80 SUI borrow → effective_supply = 20
- User B: 100 SUI supply, 0 SUI borrow → effective_supply = 100  
- Total supply in pool: 200 SUI

Global index increase = 1000 / 200 = 5 per day

Actual rewards distributed:
- User A: 20 × 5 = 100 tokens/day
- User B: 100 × 5 = 500 tokens/day
- Total: 600 tokens/day

**Expected distribution: 1000 tokens/day → 40% shortfall!**

The missing 400 tokens/day corresponds to User A's borrowed portion (80 SUI) which is counted in the denominator (total_supply = 200) but not rewarded (effective_supply = 20).

**Concrete Impact:**
- **Direct Fund Impact**: Rewards systematically under-distributed by (Σ min(user_supply_i, user_borrow_i)) / total_supply percentage
- **Affected Parties**: All users with offsetting positions receive proportionally correct rewards relative to each other, but the absolute reward rate is lower than configured
- **Protocol Damage**: Unclaimed rewards accumulate in reward funds; administrators believe they're distributing X tokens/day when actual distribution is less
- **Severity Justification**: HIGH - Direct financial impact affecting core incentive mechanism; misalignment between configured and actual reward rates; no theft but systematic loss of intended rewards

### Likelihood Explanation

**Attacker Capabilities:** Not required - this is a passive bug affecting normal protocol operation, not an exploit.

**Triggering Conditions:**
1. User supplies asset X (e.g., 100 SUI)
2. User borrows same asset X (e.g., 80 SUI) - economically viable if using borrowed funds for external yield strategies
3. Reward rules configured for asset X (either supply or borrow rewards)

**Feasibility:** 
- No special privileges required - any user can supply and borrow
- No restriction in validation logic prevents same-asset positions
- Health factor checks can pass with sufficient other collateral
- Common scenario in DeFi where users maintain delta-neutral positions or use recursive leverage strategies

**Economic Rationality:**
Users naturally enter such positions when:
- Borrowing for external yield farming while maintaining exposure
- Creating leveraged positions (supply collateral → borrow same asset → re-supply)
- Maintaining liquidity positions while earning borrow rewards

**Detection:** The bug is not easily observable because:
- Individual user rewards appear proportionally correct relative to each other
- Only visible when comparing aggregate distributed rewards vs. configured emission rate
- Requires analyzing sum of all user effective balances vs. total pool balances

**Probability:** MEDIUM-HIGH - Will occur naturally as users adopt common DeFi position strategies; becomes more severe as more users have offsetting positions.

### Recommendation

**Code-Level Mitigation:**

Modify `get_effective_balance()` to calculate effective totals consistently:

```
public fun get_effective_balance(storage: &mut Storage, asset: u8, user: address): (u256, u256, u256, u256) {
    // ... existing code to get raw balances and indices ...
    
    // Calculate individual user effective balances (unchanged)
    let user_effective_supply: u256 = 0;
    if (user_supply > user_borrow) {
        user_effective_supply = user_supply - user_borrow;
    };
    
    let user_effective_borrow: u256 = 0;
    if (user_borrow > user_supply) {
        user_effective_borrow = user_borrow - user_supply;
    };
    
    // NEW: Calculate total effective balances for consistency
    let total_effective_supply = if (total_supply > total_borrow) {
        total_supply - total_borrow
    } else {
        0
    };
    
    let total_effective_borrow = if (total_borrow > total_supply) {
        total_borrow - total_supply
    } else {
        0
    };
    
    // Return effective totals instead of gross totals
    (user_effective_supply, user_effective_borrow, total_effective_supply, total_effective_borrow)
}
```

**Alternative (simpler):** Use gross balances for both calculations:
- Return gross user_supply and user_borrow (before netting)
- Update `calculate_user_reward` to use gross balances
- This rewards all supply/borrow activity, not just net positions

**Invariant Checks:**
- Add assertion: `Σ(all_user_effective_balances) == total_effective_balance` 
- Monitor ratio: `actual_distributed_rewards / configured_emission_rate ≈ 1.0`

**Test Cases:**
1. User with offsetting positions should receive rewards based on consistent balance treatment
2. Sum of all user rewards over time should equal total configured emission
3. Edge case: User with equal supply and borrow (effective = 0) should receive zero rewards
4. Multiple users with various offsetting positions - verify total distribution matches emission rate

### Proof of Concept

**Initial State:**
- Asset: SUI (asset_id = 0)
- Reward rule: Supply rewards at 1000 SUI/day
- Reward fund: Sufficient SUI tokens

**Transaction Sequence:**

1. **User A deposits 100 SUI**
   - Calls: `incentive_v3::entry_deposit<SUI>`
   - User A supply: 100 SUI, borrow: 0 SUI
   - Total supply: 100 SUI

2. **User A borrows 80 SUI** (using other collateral)
   - Calls: `incentive_v3::entry_borrow<SUI>`
   - User A supply: 100 SUI, borrow: 80 SUI
   - User A effective_supply: 20 SUI
   - Total supply: 100 SUI, total borrow: 80 SUI

3. **Wait 1 day**

4. **Calculate rewards:**
   - Expected from admin perspective: User A should earn ~1000 SUI (sole supplier)
   - Actual calculation:
     - Global index increase = 1000 / 100 = 10
     - User A reward = 20 × 10 = 200 SUI
   
**Expected Result:** User A receives 1000 SUI in rewards (100% of daily emission as sole participant)

**Actual Result:** User A receives 200 SUI in rewards (20% of daily emission due to net position)

**Success Condition:** Demonstrate that actual distributed rewards (200) < configured emission rate (1000), proving systematic under-distribution of 80%.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_ui/sources/incentive_v3.move (L30-39)
```text
            let (user_effective_supply, user_effective_borrow, total_supply, total_borrow) = incentive_v3::get_effective_balance(storage, asset, user);

            while (vector::length(&rules_keys) > 0) {
                let rule_key = vector::pop_back(&mut rules_keys);
                let rule = vec_map::get(rules, &rule_key);

                let (_, option, _, reward_coin_type, _, _, _, _, _, _) = incentive_v3::get_rule_info(rule);

                let global_index = calculate_global_index(clock, rule, total_supply, total_borrow);
                let user_total_reward = calculate_user_reward(rule, global_index, user, user_effective_supply, user_effective_borrow);
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L549-551)
```text
    fun update_reward_state_by_rule_and_balance(clock: &Clock, rule: &mut Rule, user: address, user_effective_supply: u256, user_effective_borrow: u256, total_supply: u256, total_borrow: u256) {
        let new_global_index = calculate_global_index(clock, rule, total_supply, total_borrow);
        let new_user_total_reward = calculate_user_reward(rule, new_global_index, user, user_effective_supply, user_effective_borrow);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L573-590)
```text
    fun calculate_global_index(clock: &Clock, rule: &Rule, total_supply: u256, total_borrow: u256): u256 {
        let total_balance = if (rule.option == constants::option_type_supply()) {
            total_supply
        } else if (rule.option == constants::option_type_borrow()) {
            total_borrow
        } else {
            abort 0
        };
        
        let now = clock::timestamp_ms(clock);
        let duration = now - rule.last_update_at;
        let index_increased = if (duration == 0 || total_balance == 0) {
            0
        } else {
            (rule.rate * (duration as u256)) / total_balance
        };
        rule.global_index + index_increased
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L592-603)
```text
    fun calculate_user_reward(rule: &Rule, global_index: u256, user: address, user_effective_supply: u256, user_effective_borrow: u256): u256 {
        let user_balance = if (rule.option == constants::option_type_supply()) {
            user_effective_supply
        } else if (rule.option == constants::option_type_borrow()) {
            user_effective_borrow
        } else {
            abort 0
        };
        let user_index_diff = global_index - get_user_index_by_rule(rule, user);
        let user_reward = get_user_total_rewards_by_rule(rule, user);
        user_reward + ray_math::ray_mul(user_balance, user_index_diff)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/validation.move (L56-74)
```text
    public fun validate_borrow<CoinType>(storage: &mut Storage, asset: u8, amount: u256) {
        assert!(type_name::into_string(type_name::get<CoinType>()) == storage::get_coin_type(storage, asset), error::invalid_coin_type());
        assert!(amount != 0, error::invalid_amount());

        // e.g. get the total lending and total collateral for this pool
        let (supply_balance, borrow_balance) = storage::get_total_supply(storage, asset);
        let (current_supply_index, current_borrow_index) = storage::get_index(storage, asset);

        let scale_supply_balance = ray_math::ray_mul(supply_balance, current_supply_index);
        let scale_borrow_balance = ray_math::ray_mul(borrow_balance, current_borrow_index);

        assert!(scale_borrow_balance + amount < scale_supply_balance, error::insufficient_balance());

        // get current borrowing ratio current_borrow_ratio
        let current_borrow_ratio = ray_math::ray_div(scale_borrow_balance + amount, scale_supply_balance);
        // e.g. borrow_ratio
        let borrow_ratio = storage::get_borrow_cap_ceiling_ratio(storage, asset);
        assert!(borrow_ratio >= current_borrow_ratio, error::exceeded_maximum_borrow_cap())
    }
```
