### Title
Stale Total Supply in Reward Index Calculation Leads to Inflated Reward Payouts

### Summary
The `calc_pool_update_rewards()` function in incentive v1 uses the current `total_supply` from storage to calculate reward index increases for the entire time period since `last_update_time`, even when `total_supply` has changed significantly during that period. Since incentive v1 operates independently from v2/v3 and is only updated when users claim rewards, long periods without claims allow the lending pool's `total_supply` to drift substantially, resulting in incorrect reward calculations that favor users who claim after supply decreases.

### Finding Description

The vulnerability exists in the `calc_pool_update_rewards()` function: [1](#0-0) 

The critical flaw is at line 251 where `get_total_supply()` retrieves the CURRENT total supply from the lending pool storage, and line 255 where this current value is used to calculate `index_increase` for the entire `time_diff` period: [2](#0-1) [3](#0-2) 

The `update_reward()` function is only called when users claim rewards: [4](#0-3) [5](#0-4) 

Critically, the production lending operations in incentive_v3 do NOT call incentive v1's update_reward: [6](#0-5) 

This creates a disconnect where the lending pool's `total_supply` changes through v3 operations, but v1's reward calculations remain stale until someone claims from the v1 system.

### Impact Explanation

**Direct Fund Impact - Reward Pool Drainage:**

When `total_supply` decreases significantly between updates (e.g., from 100,000 to 10,000 tokens), users who maintained their positions receive drastically inflated rewards. For example:
- Correct calculation: User with 10% stake over 40 days at 100K supply + 100% stake over 10 days at 10K supply = 140 reward tokens
- Actual calculation: (rate × 50 days) ÷ 10,000 current supply = 500 reward tokens (357% inflation)

The safety check in `base_claim_reward` prevents exceeding the total allocated rewards: [7](#0-6) 

However, this creates a race condition where early claimers receive inflated shares while later claimers find the pool depleted, receiving nothing despite being entitled to rewards. The reward pool is drained faster than intended, violating the designed emission schedule and creating unfair distribution.

### Likelihood Explanation

**High Likelihood - Natural Protocol Usage:**

The vulnerability requires no special attacker capabilities:
1. **Reachable Entry Point**: `claim_reward()` and `claim_reward_non_entry()` are public entry functions accessible to all users
2. **Feasible Preconditions**: Simply requires normal protocol usage where users perform lending operations through v3 (which don't update v1) while periods pass without v1 claims
3. **Low Complexity**: No manipulation required - the issue manifests naturally during periods of v3 activity without v1 claims
4. **Economic Rationality**: Users benefit by timing claims after observing `total_supply` decreases, with no cost beyond normal gas fees

The vulnerability is particularly severe because:
- Incentive v1 and v2/v3 are independent systems sharing only the storage layer
- All production lending operations go through v3, not v1
- There's no automatic mechanism to keep v1 rewards synchronized with v2/v3 operations
- Users can observe on-chain `total_supply` changes and time their v1 claims accordingly

### Recommendation

**Code-Level Mitigation:**

1. Track historical `total_supply` snapshots at each update, or implement time-weighted average supply calculations
2. Add a maximum `time_diff` threshold (e.g., 1 week) and cap `index_increase` proportionally to prevent extreme staleness
3. Consider deprecating incentive v1 entirely and migrating users to v2/v3 which have better update synchronization
4. If continuing v1, hook v1's `update_reward` into v3's entry functions similar to v2's test pattern: [8](#0-7) 

**Invariant Checks:**

Add assertions to verify:
- `time_diff` since last update doesn't exceed a reasonable threshold (e.g., 7 days)
- `total_supply` hasn't changed by more than X% since last update
- Rate of index increase is bounded within expected ranges

**Test Cases:**

Add regression tests covering:
- Scenario where `total_supply` drops 90% between updates
- Multiple users claiming after stale periods
- Verification that reward distribution matches intended emission schedule

### Proof of Concept

**Initial State:**
- Incentive v1 pool created with 1,000 reward tokens, 100-day duration (rate = 10 tokens/day)
- Lending pool has 100,000 tokens deposited (total_supply = 100,000)
- User A deposits 10,000 tokens (10% of pool)
- `last_update_time = T0`, `index_reward = 0`

**Transaction Sequence:**

1. **Days 1-40**: Users perform lending operations through incentive_v3 entry functions (deposit/withdraw/borrow/repay) - these update v2/v3 but NOT v1
2. **Day 40**: 90% of users withdraw through v3, new total_supply = 10,000
3. **Days 40-50**: No v1 claims occur, v1 remains stale
4. **Day 50**: User A calls `claim_reward()` on v1 system

**Expected Result:**
User A should receive: (10 tokens/day × 40 days × 10%) + (10 tokens/day × 10 days × 100%) = 40 + 100 = 140 tokens

**Actual Result:**
- `time_diff = 50 days`
- `total_supply = 10,000` (current value after withdrawals)
- `index_increase = (10 × 50) ÷ 10,000 = 0.05`
- User A receives: 0.05 × 10,000 = **500 tokens** (357% more than entitled)

**Success Condition:**
User A successfully claims 500 tokens. Subsequent claimers find the pool depleted faster than intended, with later claims failing the assertion at line 332 once distributed rewards approach the 1,000 token cap.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L184-222)
```text
    public(friend) fun update_reward(
        incentive: &mut Incentive,
        clock: &Clock,
        storage: &mut Storage,
        asset: u8,
        account: address
    ) {
        if (table::contains(&incentive.pools, asset)) {
            let current_timestamp = clock::timestamp_ms(clock);
            let (index_rewards, user_acc_rewards) = calc_pool_update_rewards(incentive, storage, current_timestamp, asset, account);
            
            let pool_info = table::borrow_mut(&mut incentive.pools, asset);
            pool_info.last_update_time = current_timestamp;

            let length = vector::length(&pool_info.coin_types);
            let i = 0;
            while(i < length) {
                let index_reward_new = *vector::borrow(&index_rewards, i);
                let user_acc_reward_new = *vector::borrow(&user_acc_rewards, i);

                let index_reward = vector::borrow_mut(&mut pool_info.index_rewards, i);
                *index_reward = index_reward_new;

                let index_rewards_paids = vector::borrow_mut(&mut pool_info.index_rewards_paids, i);
                if (table::contains(index_rewards_paids, account)) {
                    table::remove(index_rewards_paids, account);
                };
                table::add(index_rewards_paids, account, index_reward_new);

                let user_acc_rewards = vector::borrow_mut(&mut pool_info.user_acc_rewards, i);
                if (table::contains(user_acc_rewards, account)) {
                    table::remove(user_acc_rewards, account);
                };
                table::add(user_acc_rewards, account, user_acc_reward_new);

                i = i + 1;
            }
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L249-258)
```text
            if (start_time < end_time) {
                let time_diff = ((end_time - start_time) as u256);
                let (total_supply, _) = storage::get_total_supply(storage, asset);

                let index_increase = 0;
                if (total_supply > 0) {
                    index_increase = safe_math::mul(rate, time_diff) / total_supply;
                };
                index_reward = index_reward + index_increase;
            };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L310-311)
```text
    fun base_claim_reward<CoinType>(incentive: &mut Incentive, bal: &mut IncentiveBal<CoinType>, clock: &Clock, storage: &mut Storage, account: address): Balance<CoinType> {
        update_reward(incentive, clock, storage, bal.asset, account);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L332-332)
```text
        assert!(bal.distributed_amount + amount_to_pay <= total_supply, error::insufficient_balance());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L792-793)
```text
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L903-905)
```text
        incentive_v1::update_reward(incentive_v1, clock, storage, asset, tx_context::sender(ctx));
        update_reward_all(clock, incentive_v2, storage, asset, tx_context::sender(ctx));
        lending::deposit_coin<CoinType>(clock, storage, pool, asset, deposit_coin, amount, ctx);
```
