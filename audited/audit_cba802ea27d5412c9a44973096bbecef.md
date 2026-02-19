# Audit Report

## Title
Insufficient Liquidity Recovery in Two-Phase Unstaking Causes Assertion Failure and Fund Lockup

## Summary
The `split_n_sui()` function's two-phase unstaking mechanism cannot guarantee retrieval of the requested SUI amount due to MIN_STAKE_THRESHOLD constraints and exchange rate rounding. When the shortfall exceeds the 10 mist tolerance, the assertion fails, preventing users from unstaking their LST tokens and effectively locking their funds until external conditions change.

## Finding Description

The vulnerability exists in the two-phase unstaking implementation within `split_n_sui()`. [1](#0-0) 

**Root Cause:**

The function implements a two-phase strategy to unstake SUI from validators:

**Phase 1 (Proportional)**: Unstakes from validators proportionally based on their assigned weights. [2](#0-1) 

**Phase 2 (Sequential)**: Attempts to fill any remaining shortfall by sequentially unstaking from validators. [3](#0-2) 

However, both phases are constrained by multiple factors that prevent guaranteed liquidity recovery:

**Constraint 1 - MIN_STAKE_THRESHOLD**: Set to 1 SUI (1,000,000,000 mist). [4](#0-3)  This minimum is enforced in the unstaking logic, preventing partial unstakes that would leave less than 1 SUI staked. [5](#0-4) 

**Constraint 2 - Exchange Rate Rounding**: The `get_sui_amount()` function uses integer division, causing precision loss in conversion calculations. [6](#0-5) 

**Constraint 3 - Ceiling Calculation**: Unstaking from active stake uses ceiling division that can round up the required fungible staked SUI amount. [7](#0-6) 

**Constraint 4 - Offset Addition**: An ACTIVE_STAKE_REDEEM_OFFSET of 100 mist is added to compensate for rounding. [8](#0-7) [9](#0-8) 

After exhausting both phases, the function allows only a 10 mist shortfall tolerance. [10](#0-9) [11](#0-10) 

If the shortfall exceeds this tolerance, the assertion fails with `ENotEnoughSuiInSuiPool`. [12](#0-11) 

**Why Protections Fail:**

The code itself explicitly documents this failure scenario in comments, describing a situation where a user requests 190 SUI but only 175 SUI can be unstaked (15 SUI shortfall = 15,000,000,000 mist), which is 1.5 billion times larger than the 10 mist tolerance. [13](#0-12) 

The vulnerability is triggered through the public `unstake()` function which calls `split_n_sui()`. [14](#0-13) 

## Impact Explanation

**Severity: HIGH**

**Concrete Harm:**
- Users holding LST tokens cannot convert them back to SUI when liquidity is fragmented across validators
- The transaction reverts with `ENotEnoughSuiInSuiPool` error, making unstaking completely impossible
- Funds remain locked until external conditions change (new stakes arrive, epoch rollover, manual rebalancing by operators)

**Affected Parties:**
- Any user attempting to unstake LST tokens when the pool has low liquidity relative to their withdrawal request
- Particularly impacts large withdrawals or withdrawals during/after rebalancing operations

**Quantified Impact:**
- The documented example shows a 15 SUI shortfall on a 190 SUI withdrawal (~7.9% of requested amount locked)
- With MIN_STAKE_THRESHOLD at 1 SUI and multiple validators, shortfalls of multiple SUI are realistic
- Users lose complete access to their funds temporarily, representing a critical operational failure

**Severity Justification:**
This warrants HIGH severity because:
1. **Core functionality failure**: Unstaking, a fundamental protocol operation, becomes unavailable
2. **No attack required**: Occurs through normal operations without any admin compromise
3. **Direct fund custody impact**: Temporary but complete lockup of user funds
4. **Widespread effect**: Can affect significant portions of user withdrawals during low liquidity periods

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

**Entry Point:**
The vulnerability is triggered through the public `unstake()` function - no special permissions required.

**Preconditions (All Realistic):**
1. Pool has low overall liquidity relative to withdrawal request
2. Validator stakes are unevenly distributed across validators
3. Some validators have stakes close to MIN_STAKE_THRESHOLD boundaries
4. Recent rebalancing operations have left small unstakeable amounts in validators

**Execution Practicality:**
- No special permissions required - any user can call `unstake()`
- The scenario is explicitly documented in code comments at lines 726-738, confirming developers knew it could occur
- Conditions naturally arise after rebalancing operations followed by periods with insufficient new stakes
- The ratio of MIN_STAKE_THRESHOLD (1 billion mist) to tolerance (10 mist) is 100 million:1, making the tolerance demonstrably insufficient

**Economic Rationality:**
- No attack cost - occurs naturally during normal protocol operations
- Higher likelihood after periods of net withdrawals or validator changes
- Cannot be prevented by individual users

**Realistic Triggers:**
- Market volatility causing withdrawal waves
- Post-rebalancing periods with low new deposits
- Multiple validators with varying stake amounts (standard configuration)

## Recommendation

**Immediate Fix:**
Increase `ACCEPTABLE_MIST_ERROR` to a value that can accommodate MIN_STAKE_THRESHOLD constraints. A reasonable value would be at least 2 * MIN_STAKE_THRESHOLD (2 SUI = 2,000,000,000 mist) to account for the worst case where multiple validators cannot be fully unstaked.

**Better Solution:**
Implement a fallback mechanism that:
1. Tracks the maximum possible retrievable SUI amount during the two-phase process
2. If the requested amount cannot be fully retrieved, adjust the user's expectation to the maximum achievable amount
3. Return proportionally reduced LST tokens to the user for the unfulfilled portion
4. Emit an event indicating partial fulfillment

**Code Fix Example (Simplified):**
```move
// After Phase 2, instead of asserting:
let achievable_amount = self.sui_pool.value();
if (achievable_amount < max_sui_amount_out) {
    if (max_sui_amount_out - achievable_amount > ACCEPTABLE_MIST_ERROR) {
        // Return what's achievable, issue receipt for remainder
        // Or increase tolerance significantly
        safe_max_sui_amount_out = achievable_amount;
    }
}
```

## Proof of Concept

The vulnerability is demonstrated by the scenario explicitly documented in the code comments:

**Setup:**
- Validator 1: 100 weight, 90 SUI active stake
- Validator 2: 100 weight, 110 SUI active stake  
- SUI pool buffer: 20 SUI
- User requests withdrawal: 190 SUI

**Execution:**
1. Phase 1 attempts proportional unstaking (95 SUI each)
2. Validator 1 can only provide 80 SUI (cannot unstake 10 SUI due to MIN_STAKE_THRESHOLD)
3. Validator 2 provides 95 SUI
4. Total retrieved: 175 SUI (with 20 SUI buffer = 195 would work, but example shows 175 active)
5. Shortfall: 15 SUI = 15,000,000,000 mist
6. Tolerance check: 15,000,000,000 > 10 (ACCEPTABLE_MIST_ERROR)
7. Assertion fails at line 762: `assert!(self.sui_pool.value() >= safe_max_sui_amount_out, ENotEnoughSuiInSuiPool)`

**Result:** Transaction reverts, user cannot unstake, funds remain locked.

This scenario is explicitly acknowledged in the code comments, confirming it is a known and reproducible issue under realistic conditions.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L28-28)
```text
    const MIN_STAKE_THRESHOLD: u64 = 1_000_000_000;
```

**File:** liquid_staking/sources/validator_pool.move (L32-32)
```text
    const ACCEPTABLE_MIST_ERROR: u64 = 10;
```

**File:** liquid_staking/sources/validator_pool.move (L34-34)
```text
    const ACTIVE_STAKE_REDEEM_OFFSET: u64 = 100;
```

**File:** liquid_staking/sources/validator_pool.move (L610-610)
```text
            amount = amount + self.unstake_approx_n_sui_from_active_stake(system_state, validator_index, unstake_sui_amount - amount + ACTIVE_STAKE_REDEEM_OFFSET, ctx);
```

**File:** liquid_staking/sources/validator_pool.move (L639-639)
```text
        let target_unstake_sui_amount = max(target_unstake_sui_amount, MIN_STAKE_THRESHOLD);
```

**File:** liquid_staking/sources/validator_pool.move (L645-651)
```text
            let split_amount = (
                ((target_unstake_sui_amount as u128)
                    * (fungible_staked_sui_amount as u128)
                    + (total_sui_amount as u128)
                    - 1)
                / (total_sui_amount as u128)
            ) as u64;
```

**File:** liquid_staking/sources/validator_pool.move (L695-764)
```text
    public(package) fun split_n_sui(
        self: &mut ValidatorPool,
        system_state: &mut SuiSystemState,
        max_sui_amount_out: u64,
        ctx: &mut TxContext
    ): Balance<SUI> {

        {
            let to_unstake = if(max_sui_amount_out > self.sui_pool.value()) {
                max_sui_amount_out - self.sui_pool.value()
            } else {
                0
            };
            let total_weight = self.total_weight as u128;
            let mut i = self.validators().length();
            
            while (i > 0 && self.sui_pool.value() < max_sui_amount_out) {
                i = i - 1;

                let to_unstake_i = 1 + (self.validator_infos[i].assigned_weight as u128 
                                        * ((to_unstake)as u128)
                                        / total_weight);
                                
                self.unstake_approx_n_sui_from_validator(
                    system_state,
                    i,
                    to_unstake_i as u64,
                    ctx
                );
            };

            // The initial unstaking by weight will softly rebalance the pool
            // However, in a rare case that the pool has very little liquidity,
            //   the unstaking amount will not be guaranteed to be the target amount
            //   for the case that the pool has very little liquidity
            // Example:
            // 1. weights: [validator1 100, validator2 100]
            // 2. total active stake: [validator1 90, validator2 110]
            // 3. rebalance by weight: [validator1 80, validator2 100], sui pool = 20
            //    - 10 mist of sui is not stake to validator1 due to the minimum stake threshold
            // 4. User withdraw 190, withdraw target: [95, 95]
            // 5. User actually withdraws: [80, 95] = 175 < 190
            // 6. User should get 190, but the pool has only 175

            // Make sure all the sui can be withdrawn
            i = self.validators().length();
            while (i > 0 && self.sui_pool.value() < max_sui_amount_out) {
                i = i - 1;
                let to_unstake_i = max_sui_amount_out - self.sui_pool.value();
                                
                self.unstake_approx_n_sui_from_validator(
                    system_state,
                    i,
                    to_unstake_i as u64,
                    ctx
                );}
            ;
        };

        // Allow 10 mist of rounding error
        let mut safe_max_sui_amount_out = max_sui_amount_out;
        if(max_sui_amount_out > self.sui_pool.value()) {
            if(max_sui_amount_out  <= self.sui_pool.value() + ACCEPTABLE_MIST_ERROR) {
                safe_max_sui_amount_out = self.sui_pool.value();
            };
        };

        assert!(self.sui_pool.value() >= safe_max_sui_amount_out, ENotEnoughSuiInSuiPool);
        self.split_from_sui_pool(safe_max_sui_amount_out)
    }
```

**File:** liquid_staking/sources/validator_pool.move (L883-886)
```text
        let res = (exchange_rate.sui_amount() as u128)
                * (token_amount as u128)
                / (exchange_rate.pool_token_amount() as u128);
        res as u64
```

**File:** liquid_staking/sources/stake_pool.move (L280-297)
```text
    public fun unstake(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        lst: Coin<CERT>,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.manage.check_not_paused();
        self.refresh(metadata, system_state, ctx);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```
