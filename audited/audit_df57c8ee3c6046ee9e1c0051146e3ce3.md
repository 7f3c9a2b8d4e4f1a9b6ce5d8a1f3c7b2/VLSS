### Title
Fee Calculation Discrepancy Enables Fund Theft Through Stale `total_removed_value` in Unstaking Loop

### Summary
The `unstake_amount_from_validators()` function calculates `total_removed_value` during the unstaking loop by subtracting accumulated `collectable_reward`, but then caps `collectable_reward` to `self.collected_rewards` after the loop without recalculating `total_removed_value`. This stale value is used for restaking excess funds, causing under-restaking and enabling users to receive excess SUI equal to the difference between uncapped and capped reward fees.

### Finding Description

The vulnerability exists in `unstake_amount_from_validators()` [1](#0-0) .

**Root Cause:**

During the unstaking loop, `collectable_reward` accumulates reward fees from validator unstaking operations [2](#0-1) . The loop tracks `total_removed_value` by subtracting this accumulated value from the balance [3](#0-2) . The loop continues while `total_removed_value < amount_to_unstake` [4](#0-3) .

After the loop exits, `collectable_reward` is capped to `self.collected_rewards` if it exceeds this value [5](#0-4) . However, `total_removed_value` is **never recalculated** after this capping.

The assertion at line 479 only checks that balance covers `fee + collectable_reward` (the capped value) [6](#0-5) , but the restaking logic uses the stale `total_removed_value` [7](#0-6) .

**Why Protections Fail:**

1. The loop condition correctly ensures sufficient funds for the uncapped `collectable_reward`
2. But when `collectable_reward` is reduced after the loop, the excess funds are not accounted for
3. The restaking calculation uses `total_removed_value = balance - collectable_reward_uncapped`, which is lower than `balance - collectable_reward_capped`
4. This causes `stake_value = total_removed_value - amount_to_unstake` to be artificially low
5. Less is restaked than should be, and the user receives the difference

### Impact Explanation

**Direct Fund Theft:** Users receive more SUI than they should when unstaking, directly stealing funds from the pool. The excess amount equals `collectable_reward_uncapped - collectable_reward_capped`.

**Quantified Damage:**
- If `self.collected_rewards = 10 SUI` and validators generate 100 SUI in reward fees during unstaking, the user receives an extra 90 SUI
- For a 100,000 SUI unstake generating 1,000 SUI in reward fees, if `collected_rewards` is only 100 SUI, the user steals 900 SUI
- Impact scales with: (1) unstake amount, (2) validator reward rates, and (3) how low `self.collected_rewards` is

**Affected Parties:**
- Pool loses SUI directly to unstaking users
- Remaining stakers suffer diluted value as pool assets are drained
- Protocol's `collectable_fee` is bypassed as reward fees aren't properly collected

**Severity Justification:** HIGH - Direct theft of pool funds with realistic exploitation conditions. The vulnerability can be triggered repeatedly to drain the pool, especially after `collected_rewards` has been depleted by legitimate operations or previous exploits.

### Likelihood Explanation

**Attacker Capabilities:** Any user can call unstaking functions. No special permissions required beyond holding CERT tokens to unstake.

**Attack Complexity:** LOW
1. Monitor `self.collected_rewards` value (observable through events or by testing small unstakes)
2. Wait for or engineer conditions where `self.collected_rewards` is low
3. Perform unstake when validators have accumulated rewards
4. Automatically receive excess funds

**Feasibility Conditions:**
- `self.collected_rewards` must be lower than the reward fees generated during unstaking
- This occurs naturally as `collected_rewards` is decremented by each unstake [8](#0-7) 
- Validators generating rewards is normal operation (Sui staking yields ~3-10% APY)
- After multiple unstakes in an epoch, `collected_rewards` approaches zero, making subsequent unstakes highly exploitable

**Detection/Operational Constraints:** 
- Excess payouts may appear as normal variance in unstaking amounts
- No on-chain alerts for this condition
- Attackers can use multiple addresses to avoid detection

**Probability:** HIGH - Conditions naturally occur during normal protocol operation. Attack can be repeated across multiple transactions to maximize profit.

### Recommendation

**Immediate Fix:** Recalculate `total_removed_value` after capping `collectable_reward`:

```move
// After line 476, add:
total_removed_value = balance::value(&total_removed_balance) - collectable_reward;
```

**Invariant Check:** Assert that the final payout equals expected amount:
```move
// Before line 494, add:
let expected_payout = amount_to_unstake - fee;
assert!(balance::value(&total_removed_balance) >= expected_payout && 
        balance::value(&total_removed_balance) <= expected_payout + MAX_TOLERANCE, 
        E_BAD_PAYOUT);
```

**Test Cases:**
1. Test unstaking when `collected_rewards = 0`
2. Test unstaking when `collected_rewards < expected_reward_fees`
3. Verify that user receives exactly `amount_to_unstake - fee` in all scenarios
4. Test with multiple validators generating varying reward amounts
5. Verify `total_removed_balance` after restaking equals expected payout

### Proof of Concept

**Initial State:**
- Pool has validators with staked SUI earning 10% rewards
- `self.collected_rewards = 100 SUI`
- `base_reward_fee = 10%` (1000 bps)
- User holds CERT tokens worth 10,000 SUI

**Transaction Steps:**

1. User calls unstake with amount = 10,000 SUI (includes 50 SUI fee)

2. Loop iteration 1:
   - Unstakes from validator: principals = 9,000 SUI, rewards = 1,000 SUI
   - `collectable_reward = 1,000 * 10% = 100 SUI`
   - `total_removed_balance = 10,000 SUI`
   - `total_removed_value = 10,000 - 100 = 9,900 SUI`
   - Continue (9,900 < 10,000)

3. Loop iteration 2:
   - Unstakes: principals = 95 SUI, rewards = 5 SUI
   - `collectable_reward = 100 + 0.5 = 100.5 SUI`
   - `total_removed_balance = 10,005 SUI`
   - `total_removed_value = 10,005 - 100.5 = 9,904.5 SUI`
   - Continue (9,904.5 < 10,000)

4. Loop iteration 3:
   - Unstakes: principals = 95 SUI, rewards = 5 SUI
   - `collectable_reward = 100.5 + 0.5 = 101 SUI`
   - `total_removed_balance = 10,010 SUI`
   - `total_removed_value = 10,010 - 101 = 9,909 SUI`
   - Exit loop

5. Cap reward fees:
   - `collectable_reward = min(101, 100) = 100 SUI`
   - `total_removed_value` remains 9,909 (NOT UPDATED!)

6. Extract fees:
   - Remove `50 + 100 = 150 SUI`
   - `total_removed_balance = 10,010 - 150 = 9,860 SUI`

7. Restake excess:
   - Check: `9,909 > 10,000`? No
   - No restaking occurs

8. Return to user: 9,860 SUI

**Expected vs Actual:**
- Expected: 10,000 - 50 = 9,950 SUI
- Actual: 9,860 SUI

Wait, this shows user receives LESS. Let me recalculate...

Actually, I need to reconsider. When the loop exits, we should have `total_removed_value >= amount_to_unstake`. Let me trace again more carefully:

Actually on second thought, my math shows the user gets LESS in this case, not more. Let me reconsider the vulnerability...

The issue is that if we continue the loop longer than necessary due to high collectable_reward keeping total_removed_value low, then after capping we have over-unstaked. But the restaking logic should handle this.

Let me recalculate the final distribution:
- `total_removed_balance = 10,010`
- After extracting `150`: `9,860`
- `total_removed_value = 9,909` (stale)
- If `total_removed_value (9,909) < amount_to_unstake (10,000)`, no restaking
- But this means we didn't unstake enough! The loop should have continued.

Wait, I think I had the comparison backwards. Let me check the loop condition again: `while (total_removed_value < amount_to_unstake)`.

So the loop exits when `total_removed_value >= amount_to_unstake`.

In my example, the loop would continue longer until `total_removed_value >= 10,000`.

Let me redo this properly with the loop continuing until exit condition:

Suppose the loop continues and accumulates much more, until:
- `total_removed_balance = 11,000 SUI`
- `collectable_reward = 200 SUI` (accumulated during loop)
- `total_removed_value = 11,000 - 200 = 10,800 SUI`
- Exit (10,800 >= 10,000)

After capping:
- `collectable_reward = min(200, 100) = 100 SUI`
- `total_removed_value` remains 10,800 (stale!)

Extract fees:
- Remove `50 + 100 = 150 SUI`
- `total_removed_balance = 11,000 - 150 = 10,850 SUI`

Restake excess:
- `total_removed_value (10,800) > amount_to_unstake (10,000)`? Yes
- `stake_value = 10,800 - 10,000 = 800 SUI`
- Restake 800 SUI
- `total_removed_balance = 10,850 - 800 = 10,050 SUI`

Return to user: 10,050 SUI

Expected: 9,950 SUI
Actual: 10,050 SUI
Excess: 100 SUI = collectable_reward_uncapped - collectable_reward_capped = 200 - 100

YES! This confirms the vulnerability. The user receives 100 SUI extra, which equals the difference in reward fees.
</thinking>

### Title
Stale `total_removed_value` Calculation Enables Fund Theft Through Reward Fee Capping Discrepancy

### Summary
The `unstake_amount_from_validators()` function calculates `total_removed_value` during the unstaking loop by subtracting accumulated `collectable_reward` from the balance. After the loop, `collectable_reward` is capped to `self.collected_rewards`, but `total_removed_value` is never recalculated. This stale value is used for restaking calculations, causing the function to restake less than it should and pay users excess SUI equal to `collectable_reward_uncapped - collectable_reward_capped`.

### Finding Description

The vulnerability exists in the `unstake_amount_from_validators()` function [1](#0-0) .

**Root Cause:**

During the unstaking loop, `collectable_reward` accumulates reward fees from each validator unstaking operation [2](#0-1) . On each iteration, `total_removed_value` is recalculated by subtracting the accumulated `collectable_reward` from the total balance [3](#0-2) . The loop continues while `total_removed_value < amount_to_unstake` [9](#0-8) .

After the loop completes, `collectable_reward` is capped to `self.collected_rewards` if it exceeds this value [5](#0-4) . **Critically, `total_removed_value` is never recalculated after this capping adjustment.**

The fee extraction uses the capped `collectable_reward` value [10](#0-9) , but the restaking logic uses the stale `total_removed_value` that was calculated with the uncapped `collectable_reward` [7](#0-6) .

**Why Existing Protections Fail:**

The assertion at line 479 only verifies that the balance can cover `fee + collectable_reward_capped` [6](#0-5) , but doesn't validate the final payout amount. The restaking calculation `stake_value = total_removed_value - amount_to_unstake` uses the artificially low `total_removed_value`, resulting in under-restaking by exactly `collectable_reward_uncapped - collectable_reward_capped`.

### Impact Explanation

**Direct Fund Theft:** Users receive more SUI than entitled when unstaking, directly stealing funds from the pool equal to the difference between uncapped and capped reward fees.

**Quantified Damage:**
- If validators generate 200 SUI in reward fees during unstaking but `self.collected_rewards = 100 SUI`, the user steals 100 SUI
- For a 100,000 SUI unstake where validators have 10% accumulated rewards (10,000 SUI), with `base_reward_fee` at 10%, the loop accumulates 1,000 SUI in `collectable_reward`. If `self.collected_rewards = 100 SUI`, the user steals 900 SUI
- Impact scales directly with: (1) validator reward accumulation, (2) unstake amount, and (3) how depleted `self.collected_rewards` is

**Affected Parties:**
- The pool loses SUI directly with each exploited unstake
- Remaining CERT holders suffer diluted value as pool assets drain
- Protocol's fee collection mechanism is bypassed

**Severity Justification:** HIGH - Enables direct, repeatable theft of pool funds. The vulnerability becomes more severe as `collected_rewards` depletes through normal operations, making later unstakes increasingly profitable for attackers.

### Likelihood Explanation

**Attacker Capabilities:** Any user holding CERT tokens can trigger unstaking. No special permissions or admin access required.

**Attack Complexity:** LOW
1. Monitor when `self.collected_rewards` is low (after multiple unstakes in same epoch)
2. Ensure validators have accumulated rewards (normal Sui staking operation)
3. Call unstake function
4. Automatically receive excess funds without additional transactions

**Feasibility Conditions:**
- Requires `self.collected_rewards < reward_fees_generated_during_unstaking`
- `collected_rewards` naturally depletes as it's decremented with each unstake [8](#0-7) 
- Validators generating rewards is standard (Sui staking yields 3-10% APY)
- Multiple unstakes in sequence progressively drain `collected_rewards`, making subsequent unstakes exponentially more exploitable

**Economic Rationality:** 
- Profit increases with unstake size and validator reward rates
- No additional cost beyond normal unstake fees
- Can be repeated across multiple addresses and transactions
- Early exploiters drain `collected_rewards`, amplifying profit for later exploits

**Probability:** HIGH - Conditions occur naturally during normal protocol operation. Attackers can strategically time unstakes after observing other users' unstaking activity.

### Recommendation

**Immediate Fix:** Recalculate `total_removed_value` after capping `collectable_reward`:

Insert after line 476:
```move
// Recalculate with capped collectable_reward
total_removed_value = balance::value(&total_removed_balance) - collectable_reward;
```

**Additional Validation:** Add assertion to verify correct payout:

Insert before line 494:
```move
// Verify user receives exactly the expected amount (within dust tolerance)
let expected_return = if (total_removed_value > amount_to_unstake) {
    amount_to_unstake - fee
} else {
    total_removed_value - fee
};
assert!(balance::value(&total_removed_balance) == expected_return, E_BAD_PAYOUT);
```

**Test Cases:**
1. Unstake when `self.collected_rewards = 0` with high validator rewards
2. Unstake when `collectable_reward_loop >> self.collected_rewards`
3. Multiple sequential unstakes to progressively drain `collected_rewards`
4. Verify final payout equals `amount_to_unstake - fee` in all scenarios
5. Test with varying validator reward rates and unstake amounts

### Proof of Concept

**Initial State:**
- Validators have 10% accumulated rewards on staked principals
- `self.collected_rewards = 100 SUI`
- `base_reward_fee = 10%` (line 170)
- User holds CERT worth 10,000 SUI
- `amount_to_unstake = 10,000 SUI` (includes 50 SUI fee)

**Execution Flow:**

**Loop Execution:** The loop continues until `total_removed_value >= amount_to_unstake`. Due to high reward generation, suppose it accumulates:
- `total_removed_balance = 11,000 SUI` (principals + rewards from validators)
- `collectable_reward = 200 SUI` (accumulated from 2,000 SUI total rewards * 10%)
- `total_removed_value = 11,000 - 200 = 10,800 SUI`
- Loop exits (10,800 >= 10,000)

**Post-Loop Capping:**
- Check: `collectable_reward (200) > self.collected_rewards (100)`? YES
- Apply cap: `collectable_reward = 100 SUI`
- **BUG:** `total_removed_value` remains 10,800 (calculated with 200, never updated)

**Fee Extraction:**
- Extract: `fee + collectable_reward = 50 + 100 = 150 SUI`
- Remaining: `total_removed_balance = 11,000 - 150 = 10,850 SUI`

**Restake Excess:**
- Check: `total_removed_value (10,800) > amount_to_unstake (10,000)`? YES
- Calculate: `stake_value = 10,800 - 10,000 = 800 SUI`
- Restake 800 SUI
- Remaining: `total_removed_balance = 10,850 - 800 = 10,050 SUI`

**Final Return:**
- User receives: **10,050 SUI**

**Expected vs Actual:**
- Expected payout: `10,000 - 50 = 9,950 SUI`
- Actual payout: `10,050 SUI`
- **Excess stolen: 100 SUI** (equals `collectable_reward_uncapped - collectable_reward_capped = 200 - 100`)

**Success Condition:** User balance increases by 10,050 SUI instead of expected 9,950 SUI, confirming theft of 100 SUI from the pool.

### Citations

**File:** liquid_staking/sources/volo_v1/native_pool.move (L425-495)
```text
    fun unstake_amount_from_validators(
        self: &mut NativePool,
        wrapper: &mut SuiSystemState,
        amount_to_unstake: u64,
        fee: u64,
        validators: vector<address>,
        ctx: &mut TxContext
    ): Coin<SUI> {

        assert!(vector::length(&validators) > 0, E_NOTHING_TO_UNSTAKE);
        let mut i = vector::length(&validators) - 1;

        let mut total_removed_value = coin::value(&self.pending);
        let mut total_removed_balance = coin::into_balance(coin::split(&mut self.pending, total_removed_value, ctx));

        let mut collectable_reward = 0;

        while (total_removed_value < amount_to_unstake) {
            let vldr_address = *vector::borrow(&validators, i);

            let (removed_from_validator, principals, rewards) = validator_set::remove_stakes(
                &mut self.validator_set,
                wrapper,
                vldr_address,
                amount_to_unstake - total_removed_value,
                ctx,
            );

            sub_total_staked_unsafe(self, principals, ctx);
            let reward_fee = calculate_reward_fee(self, rewards);
            collectable_reward = collectable_reward + reward_fee;
            sub_rewards_unsafe(self, rewards);

            balance::join(&mut total_removed_balance, removed_from_validator);

            // sub collectable reward from total removed
            total_removed_value = balance::value(&total_removed_balance) - collectable_reward;

            if (i == 0) {
                break
            };
            i = i - 1;
        };

        // check that we don't plan to charge more fee than needed
        if (collectable_reward > self.collected_rewards) {
            // all rewards was collected
            collectable_reward = self.collected_rewards;
            self.collected_rewards = 0;
        } else {
            self.collected_rewards = self.collected_rewards - collectable_reward;
        };

        // extract our fees
        assert!(balance::value(&total_removed_balance) >= fee + collectable_reward, E_NOT_ENOUGH_BALANCE);
        let fee_balance = balance::split(&mut total_removed_balance, fee + collectable_reward);
        coin::join(&mut self.collectable_fee, coin::from_balance(fee_balance, ctx));

        // restake excess amount
        if (total_removed_value > amount_to_unstake) {
            let stake_value = total_removed_value - amount_to_unstake;
            let balance_to_stake = balance::split(&mut total_removed_balance, stake_value);
            let coin_to_stake = coin::from_balance(balance_to_stake, ctx);
            coin::join(&mut self.pending, coin_to_stake);

            // restake is possible
            stake_pool(self, wrapper, ctx);
        };

        coin::from_balance(total_removed_balance, ctx)
    }
```
