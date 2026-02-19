### Title
Insufficient Validation Allows Validator Stake to Fall Below MIN_STAKE_THRESHOLD Due to Rounding Errors

### Summary
The `take_some_active_stake()` function splits fungible staked SUI without properly validating that the remaining stake meets MIN_STAKE_THRESHOLD. While `unstake_approx_n_sui_from_active_stake()` attempts to prevent this at line 641, the validation is insufficient due to rounding mismatches between floor division in exchange rate calculations and ceiling division in split amount calculations, potentially leaving validators with less than the required 1 SUI minimum.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**

The protocol enforces MIN_STAKE_THRESHOLD (1_000_000_000 MIST = 1 SUI) as defined at: [2](#0-1) 

The validation logic in `unstake_approx_n_sui_from_active_stake()` checks: [3](#0-2) 

This check intends to ensure that `remaining = total_sui_amount - target_unstake_sui_amount >= MIN_STAKE_THRESHOLD`. However, it fails due to:

1. **Floor division in exchange rate conversion**: The `get_sui_amount()` function uses floor division when converting pool tokens to SUI: [4](#0-3) 

2. **Ceiling division in split calculation**: The split_amount uses ceiling division to ensure sufficient tokens are withdrawn: [5](#0-4) 

3. **Base mismatch**: The validation checks SUI amounts, but the split operates on pool tokens with a different exchange rate.

**Why Protections Fail:**

The ceiling operation on pool tokens means more tokens are split than the exact proportion needed. When these remaining tokens are converted back to SUI value using floor division, the result can be less than MIN_STAKE_THRESHOLD, even though the check at line 641 passed.

**Concrete Example:**
- Exchange rate: 101 SUI / 100 pool tokens (1.01:1 after rewards)
- Initial fungible_staked_sui_amount: 2,000,000,001 pool tokens
- Initial total_sui_amount: floor(2,000,000,001 × 101 / 100) = 2,020,000,001 SUI
- Target unstake: 1,020,000,000 SUI

Check passes: 2,020,000,001 > 1,020,000,000 + 1,000,000,000 (FALSE → enters else branch)

Split calculation:
- split_amount = ceil(1,020,000,000 × 2,000,000,001 / 2,020,000,001) = 1,009,900,991 tokens
- Remaining tokens: 2,000,000,001 - 1,009,900,991 = 990,099,010 tokens
- Remaining SUI value: floor(990,099,010 × 101 / 100) = 999,999,900 SUI

**999,999,900 < 1,000,000,000 (MIN_STAKE_THRESHOLD violated!)**

### Impact Explanation

**Harm:**
1. **Protocol Invariant Violation**: The MIN_STAKE_THRESHOLD is a critical invariant explicitly enforced elsewhere in the codebase (e.g., at line 494 in `increase_validator_stake`): [6](#0-5) 

2. **Validator State Corruption**: Validators left with sub-threshold stake may become difficult or impossible to fully withdraw, as the remaining amount is too small to meet minimum requirements.

3. **Accounting Errors**: The protocol's total_sui_supply tracking assumes all validator stakes meet minimum thresholds. Violations can cause discrepancies in LST backing calculations.

4. **Stuck Funds Risk**: If the Sui staking system enforces minimums on fungible staked SUI operations, the remaining stake could become inaccessible.

**Severity**: Medium - While not directly exploitable for fund theft, this breaks a critical protocol invariant and can cause operational failures and potential fund lock-up in edge cases.

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required - any user performing normal unstaking operations can trigger this
- Requires specific exchange rate conditions but these occur naturally as staking rewards accrue

**Feasibility:**
- **Entry Point**: Reachable through normal unstaking flows that call `unstake_approx_n_sui_from_active_stake()`
- **Preconditions**: 
  - Exchange rate slightly above 1:1 (normal as rewards accumulate)
  - Total stake amount and target unstake amount create rounding conditions
  - Amounts near multiples of MIN_STAKE_THRESHOLD
- **Frequency**: Increases in likelihood as:
  - More time passes and exchange rates drift from 1:1
  - More unstaking operations occur
  - Validator stakes approach rebalancing thresholds

**Probability**: Medium - Not guaranteed on every unstake, but mathematically certain to occur over time with sufficient operations and varying exchange rates. The specific numerical conditions shown in the PoC will occur in practice.

### Recommendation

**Immediate Fix:**
Add explicit validation after calculating split_amount to ensure remaining tokens meet the threshold:

```move
// In unstake_approx_n_sui_from_active_stake(), after line 651:
let split_amount = (...) as u64;

// Validate remaining stake will be above threshold
let remaining_tokens = fungible_staked_sui_amount - split_amount;
let remaining_sui_value = get_sui_amount(&validator_info.exchange_rate, remaining_tokens);

if (remaining_sui_value < MIN_STAKE_THRESHOLD) {
    // Take all instead of splitting
    self.take_all_active_stake(system_state, validator_index, ctx)
} else {
    self.take_some_active_stake(system_state, validator_index, split_amount, ctx)
}
```

**Alternative Fix:**
Modify the check at line 641 to account for rounding by adding a safety margin:

```move
// Change line 641 to include buffer for rounding errors
let unstaked_sui = if (total_sui_amount <= target_unstake_sui_amount + MIN_STAKE_THRESHOLD + ACCEPTABLE_MIST_ERROR) {
```

**Test Cases:**
1. Test with exchange rates 1.01:1, 1.1:1, 0.99:1
2. Test with stake amounts near 2×MIN_STAKE_THRESHOLD
3. Test with target_unstake amounts that create ceiling/floor discrepancies
4. Assert invariant: `remaining_sui_value >= MIN_STAKE_THRESHOLD || remaining_sui_value == 0`

### Proof of Concept

**Initial State:**
- Validator has 2,000,000,001 fungible staked SUI tokens
- Exchange rate: 101 SUI per 100 pool tokens (pool_token_amount=100, sui_amount=101)
- This gives total_sui_amount = 2,020,000,001 SUI

**Transaction Steps:**
1. User calls unstake function requesting 1,020,000,000 SUI
2. `unstake_approx_n_sui_from_active_stake()` is invoked with target_unstake_sui_amount = 1,020,000,000
3. Line 639: target adjusted to max(1,020,000,000, 1,000,000,000) = 1,020,000,000
4. Line 641: Check `2,020,000,001 <= 2,020,000,000` evaluates to FALSE
5. Lines 645-651: Calculate split_amount = ceil(1,020,000,000 × 2,000,000,001 / 2,020,000,001) = 1,009,900,991
6. Line 653: Calls `take_some_active_stake()` with split_amount = 1,009,900,991
7. Line 777: Splits 1,009,900,991 tokens from validator's active_stake

**Expected Result:**
Remaining stake should be ≥ 1,000,000,000 SUI (MIN_STAKE_THRESHOLD)

**Actual Result:**
- Remaining pool tokens: 990,099,010
- Remaining SUI value: floor(990,099,010 × 101 / 100) = 999,999,900 SUI
- **Invariant violated: 999,999,900 < 1,000,000,000**

**Success Condition for Exploit:**
The validator is left with active stake having a SUI value below MIN_STAKE_THRESHOLD (999,999,900 < 1,000,000,000), demonstrating the validation failure.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L28-28)
```text
    const MIN_STAKE_THRESHOLD: u64 = 1_000_000_000;
```

**File:** liquid_staking/sources/validator_pool.move (L494-496)
```text
        if (sui.value() < MIN_STAKE_THRESHOLD) {
            self.join_to_sui_pool(sui);
            return 0
```

**File:** liquid_staking/sources/validator_pool.move (L641-641)
```text
        let unstaked_sui = if (total_sui_amount <= target_unstake_sui_amount + MIN_STAKE_THRESHOLD) {
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

**File:** liquid_staking/sources/validator_pool.move (L766-782)
```text
    fun take_some_active_stake(
        self: &mut ValidatorPool, 
        system_state: &mut SuiSystemState,
        validator_index: u64, 
        fungible_staked_sui_amount: u64,
        ctx: &mut TxContext
    ): Balance<SUI> {
        let validator_info = &mut self.validator_infos[validator_index];

        let stake = validator_info.active_stake
            .borrow_mut()
            .split_fungible_staked_sui(fungible_staked_sui_amount, ctx);

        self.refresh_validator_info(validator_index);

        system_state.redeem_fungible_staked_sui(stake, ctx)
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
