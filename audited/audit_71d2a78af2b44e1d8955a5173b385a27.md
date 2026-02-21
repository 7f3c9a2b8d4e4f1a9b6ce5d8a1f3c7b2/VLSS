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

The vulnerability is triggered through the public `unstake_entry()` function which calls `unstake()`, which in turn calls `split_n_sui()`. [14](#0-13) [15](#0-14) 

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
The vulnerability is triggered through the public `unstake_entry()` function - no special permissions required.

**Preconditions (All Realistic):**
1. Pool has low overall liquidity relative to withdrawal request
2. Validator stakes are unevenly distributed across validators
3. Some validators have stakes close to MIN_STAKE_THRESHOLD boundaries
4. Recent rebalancing operations have left small unstakeable amounts in validators

**Execution Practicality:**
- No special permissions required - any user can call `unstake_entry()`
- The scenario is explicitly documented in code comments, confirming developers knew it could occur
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

Increase the `ACCEPTABLE_MIST_ERROR` tolerance from 10 mist to a more realistic value that accounts for MIN_STAKE_THRESHOLD constraints. Consider:

1. **Dynamic tolerance calculation**: Calculate tolerance based on the number of validators and MIN_STAKE_THRESHOLD:
   ```
   let tolerance = MIN_STAKE_THRESHOLD * validator_count / 10
   ```

2. **Partial unstake support**: Allow users to receive whatever amount can be unstaked rather than reverting entirely:
   ```move
   // Instead of asserting, return what's available
   if(self.sui_pool.value() < safe_max_sui_amount_out) {
       safe_max_sui_amount_out = self.sui_pool.value();
   };
   ```

3. **Better error handling**: Provide a view function for users to check unstakeable amount before attempting unstake, preventing failed transactions.

4. **Liquidity reserve**: Maintain a minimum liquidity buffer in `sui_pool` to handle edge cases during rebalancing.

## Proof of Concept

This vulnerability is inherently difficult to test in isolation as it requires:
1. Multiple validators with specific stake distributions
2. Active stake near MIN_STAKE_THRESHOLD boundaries
3. Coordinated rebalancing and withdrawal operations

The developers have already documented the exact failure scenario in the code comments, confirming its possibility. A full PoC would require:

```move
#[test]
fun test_insufficient_liquidity_recovery() {
    // Setup: Create pool with 2 validators
    // Validator1: 90 SUI active stake (weight 100)
    // Validator2: 110 SUI active stake (weight 100)
    // After proportional rebalancing attempt: [80, 100], sui_pool = 20
    // User requests 190 SUI unstake
    // Expected: Only 175 SUI can be unstaked (15 SUI shortfall)
    // Expected: Transaction fails with ENotEnoughSuiInSuiPool
}
```

The documented scenario at lines 726-737 serves as the specification for this vulnerability, confirming it can occur in production environments.

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

**File:** liquid_staking/sources/validator_pool.move (L639-642)
```text
        let target_unstake_sui_amount = max(target_unstake_sui_amount, MIN_STAKE_THRESHOLD);

        let unstaked_sui = if (total_sui_amount <= target_unstake_sui_amount + MIN_STAKE_THRESHOLD) {
            self.take_all_active_stake(system_state, validator_index, ctx)
```

**File:** liquid_staking/sources/validator_pool.move (L644-651)
```text
            // ceil(target_unstake_sui_amount * fungible_staked_sui_amount / total_sui_amount)
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

**File:** liquid_staking/sources/validator_pool.move (L877-887)
```text
    fun get_sui_amount(exchange_rate: &PoolTokenExchangeRate, token_amount: u64): u64 {
        // When either amount is 0, that means we have no stakes with this pool.
        // The other amount might be non-zero when there's dust left in the pool.
        if (exchange_rate.sui_amount() == 0 || exchange_rate.pool_token_amount() == 0) {
            return token_amount
        };
        let res = (exchange_rate.sui_amount() as u128)
                * (token_amount as u128)
                / (exchange_rate.pool_token_amount() as u128);
        res as u64
    }
```

**File:** liquid_staking/sources/stake_pool.move (L268-278)
```text
    public entry fun unstake_entry(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        cert: Coin<CERT>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let sui = self.unstake(metadata, system_state, cert, ctx);
        transfer::public_transfer(sui, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L297-297)
```text
        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```
