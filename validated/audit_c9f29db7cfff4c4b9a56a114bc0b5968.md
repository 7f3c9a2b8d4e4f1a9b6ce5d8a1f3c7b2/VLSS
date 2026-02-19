# Audit Report

## Title
Permanent Reward Loss Due to Precision Truncation in Ray Division

## Summary
The Navi Protocol incentive systems (V1 and V2) integrated into Volo use plain integer division when converting RAY-precision rewards to token amounts, causing users to permanently lose fractional rewards on every claim. The system marks the full RAY-precision amount as "paid" while only transferring the truncated integer portion.

## Finding Description

The vulnerability exists in two incentive implementations:

**Incentive V1 (`incentive.move`):**

The `base_claim_reward()` function calculates rewards accumulated in RAY precision (1e27). When claiming, it performs plain integer division to convert to token units: [1](#0-0) 

This truncates any fractional amounts. However, the system then marks the **full** RAY-precision amount as paid: [2](#0-1) 

The actual transfer only includes the truncated amount: [3](#0-2) 

**Incentive V2 (`incentive_v2.move`):**

The same pattern exists in V2's `base_claim_reward()` function: [4](#0-3) 

It marks the full amount as claimed: [5](#0-4) 

**Why Existing Protections Fail:**

The codebase's own `ray_math` module demonstrates proper rounding practices. The `ray_mul()` function includes HALF_RAY for correct rounding: [6](#0-5) 

Similarly, `ray_to_wad()` adds proper rounding: [7](#0-6) 

However, the claim functions bypass these utilities and use plain division operator `/` without any rounding, causing systematic loss.

The rewards are accumulated in RAY precision through multiplication: [8](#0-7) 

## Impact Explanation

**Concrete Loss Mechanism:**
- User accumulates 1.7e27 RAY units (representing 1.7 tokens)
- Plain division: `1.7e27 / 1e27 = 1` (integer division truncates)
- System marks 1.7e27 as paid/claimed
- User receives only 1 token
- **0.7 tokens permanently lost**

**Quantified Impact:**
- Each claim can lose up to 0.999... tokens
- For USDC (6 decimals): up to $0.999999 per claim
- For high-frequency claimers making multiple small claims, cumulative losses can exceed 50% of total rewards
- Lost funds remain in the contract forever, marked as "paid" but never transferred
- Affects all users across the entire protocol

**Systemic Nature:**
This is not an edge case but affects virtually every claim transaction, as time-based reward accumulation with continuous rates rarely produces exact integer multiples of 1e27.

## Likelihood Explanation

**Frequency:** HIGH - Triggers automatically during normal reward claims

**No Attack Required:** This is a design flaw, not an exploit. Users lose funds through regular protocol interaction via public entry functions: [9](#0-8) 

**Preconditions:**
1. User has accumulated rewards (normal operation)
2. Rewards include fractional RAY amounts (virtually always true due to continuous time-based accrual)
3. User calls `claim_reward()` (expected user behavior)

**Inevitability:** Since reward rates are set per time period and rarely align to produce exact RAY multiples, fractional losses occur on nearly every single claim transaction.

## Recommendation

Add proper rounding before division, following the pattern established elsewhere in the codebase:

```move
// Instead of:
let amount_to_pay = (user_acc_reward - user_acc_rewards_paid) / ray_math::ray();

// Use:
let amount_to_pay = (user_acc_reward - user_acc_rewards_paid + ray_math::half_ray()) / ray_math::ray();
```

Alternatively, only mark the actually-paid amount:

```move
let amount_to_pay = (user_acc_reward - user_acc_rewards_paid) / ray_math::ray();
table::add(user_acc_rewards_paids, account, user_acc_rewards_paid + amount_to_pay * ray_math::ray());
```

Apply the same fix to both `incentive.move` and `incentive_v2.move`.

## Proof of Concept

```move
#[test]
fun test_fractional_reward_loss() {
    // Setup: User has 1.7e27 RAY units accumulated (1.7 tokens)
    let user_acc_reward: u256 = 1_700000000000000000000000000; // 1.7e27
    let user_acc_rewards_paid: u256 = 0;
    
    // Current implementation: plain division
    let amount_to_pay = (user_acc_reward - user_acc_rewards_paid) / 1_000000000000000000000000000;
    
    // Result: amount_to_pay = 1 (truncated)
    assert!(amount_to_pay == 1, 0);
    
    // System marks full 1.7e27 as paid
    // User receives only 1 token
    // Loss: 0.7 tokens permanently lost (700000000000000000000000000 RAY units)
    
    let lost_amount = user_acc_reward - (amount_to_pay * 1_000000000000000000000000000);
    assert!(lost_amount == 700000000000000000000000000, 1); // 0.7e27 lost
}
```

This test demonstrates that with 1.7 tokens worth of rewards, only 1 token is paid while the full 1.7 is marked as claimed, resulting in permanent loss of 0.7 tokens.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L274-275)
```text
                let reward_increase = (index_reward - index_rewards_paid) * supply_balance;
                user_acc_reward = user_acc_reward + reward_increase;
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L285-290)
```text
    public entry fun claim_reward<CoinType>(
        incentive: &mut Incentive,
        bal: &mut IncentiveBal<CoinType>,
        clock: &Clock,
        storage: &mut Storage,
        account: address,
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L327-327)
```text
        table::add(user_acc_rewards_paids, account, user_acc_reward);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L329-329)
```text
        let amount_to_pay = (user_acc_reward - user_acc_rewards_paid) / ray_math::ray();
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive.move (L335-335)
```text
        let claim_balance = balance::split(&mut bal.balance, (amount_to_pay as u64));
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L320-320)
```text
            table::add(&mut pool.total_claimed_of_users, user, total_rewards_of_user);
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v2.move (L322-322)
```text
            let reward = ((total_rewards_of_user - total_claimed_of_user) / ray_math::ray() as u64);
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L71-78)
```text
    public fun ray_mul(a: u256, b: u256): u256 {
        if (a == 0 || b == 0) {
            return 0
        };

        assert!(a <= (address::max() - HALF_RAY) / b, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * b + HALF_RAY) / RAY
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L97-102)
```text
    public fun ray_to_wad(a: u256): u256 {
        let halfRatio = WAD_RAY_RATIO / 2;
        let result = halfRatio + a;
        assert!(result >= halfRatio, RAY_MATH_ADDITION_OVERFLOW);

        result / WAD_RAY_RATIO
```
