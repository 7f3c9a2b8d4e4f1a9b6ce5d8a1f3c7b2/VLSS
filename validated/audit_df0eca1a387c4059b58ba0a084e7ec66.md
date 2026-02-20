# Audit Report

## Title
Division by Zero in split_n_sui When Total Validator Weight is Zero

## Summary
The `split_n_sui` function in `validator_pool.move` performs division by `total_weight` without checking if it's zero, causing transaction aborts when all validators become inactive. This prevents users from unstaking their LST tokens and locks funds until the validator situation is resolved.

## Finding Description

The `split_n_sui` function is responsible for withdrawing SUI from validators when the `sui_pool` buffer has insufficient balance. The vulnerability occurs in the weight-proportional unstaking calculation where the code divides by `total_weight` without verifying it's non-zero. [1](#0-0) 

This contrasts with similar functions in the same module that correctly guard against zero division:

**Protected function 1 - `stake_pending_sui`**: Has an early return when `total_weight == 0`. [2](#0-1) 

**Protected function 2 - `rebalance`**: Checks both `total_weight` and `total_sui_supply` before proceeding. [3](#0-2) 

**Root cause mechanism**: When validators become inactive during `refresh()`, their weights are set to zero and subtracted from `total_weight`. [4](#0-3) 

Crucially, validators are only removed from `validator_infos` if completely empty. [5](#0-4)  The `is_empty()` check requires all stakes to be none AND weight to be zero. [6](#0-5) 

This means validators with residual stake (e.g., `inactive_stake` not yet at activation epoch) remain in the vector with `assigned_weight = 0`. When all validators are inactive, `validator_infos.length() > 0` but `total_weight == 0`, causing the division by zero.

**Call paths to vulnerable function**:

1. **User unstake operation**: The `unstake` function calls `split_n_sui` to withdraw SUI for the user. [7](#0-6) 

2. **Admin fee collection**: The `collect_fees` function calls `split_n_sui` to withdraw accrued reward fees. [8](#0-7) 

## Impact Explanation

**Direct harm**: Users cannot unstake their LST tokens when all validators are inactive. Every `unstake()` transaction aborts with a division by zero error, effectively locking all user funds in the protocol.

**Recovery options**: Funds are not permanently lost but remain locked until either:
1. New active validators are added to the pool, OR
2. The contract is upgraded with a fix

**Affected users**: All LST token holders attempting to unstake during the period when `total_weight == 0`.

**Severity: Medium** - This represents a complete denial-of-service on core protocol functionality (unstaking), causing temporary fund lockup. While funds are not permanently lost and recovery is possible through administrative action, the operational impact is severe as it blocks a critical user operation.

## Likelihood Explanation

**Triggering conditions**: Requires all validators in the pool to become inactive simultaneously. This can occur when:
- Validators are removed from Sui's active validator set due to poor performance or slashing
- Network-wide validator reorganizations or governance decisions  
- Pool has few validators (1-3 validators), making simultaneous inactivity more probable

**Attacker requirements**: None - this is a protocol state issue triggered by external validator status changes, not an attack vector.

**Execution simplicity**: 
1. External event: All validators become inactive (outside protocol control)
2. User action: Anyone calls normal `unstake()` operation with their LST tokens
3. Result: Transaction aborts with division by zero

**Probability: Medium** - While uncommon for all validators in a well-diversified pool to simultaneously go inactive, it's realistic under:
- Small validator sets (especially during protocol launch)
- Network stress or validator set reorganizations
- Concentrated validator risk in the pool

## Recommendation

Add a zero-check guard at the beginning of `split_n_sui`, similar to the protection in `stake_pending_sui` and `rebalance`:

```move
public(package) fun split_n_sui(
    self: &mut ValidatorPool,
    system_state: &mut SuiSystemState,
    max_sui_amount_out: u64,
    ctx: &mut TxContext
): Balance<SUI> {
    // Add this check
    if (self.total_weight == 0) {
        // Return available sui_pool balance up to max_sui_amount_out
        return self.split_up_to_n_sui_from_sui_pool(max_sui_amount_out)
    };
    
    // Existing logic continues...
}
```

This ensures that when all validators are inactive, the function gracefully handles the situation by only withdrawing from the available `sui_pool` buffer.

## Proof of Concept

The vulnerability can be demonstrated with the following scenario:

1. **Setup**: Protocol has 2 validators, both with some inactive stake pending activation
2. **Trigger**: Both validators become inactive (removed from Sui's active validator set)
3. **State**: During `refresh()`, both validators get `assigned_weight = 0`, but remain in `validator_infos` because they have `inactive_stake.is_some()`
4. **Result**: `total_weight == 0` but `validator_infos.length() == 2`
5. **Exploit**: Any user calling `unstake()` will trigger `split_n_sui()` which attempts to divide by `total_weight` (zero), causing transaction abort

The division by zero occurs at the calculation in line 714-716 where `total_weight` is in the denominator with no prior validation.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L170-173)
```text
    fun is_empty(self: &ValidatorInfo): bool {
        self.active_stake.is_none() && self.inactive_stake.is_none() && self.total_sui_amount == 0
        && self.assigned_weight == 0
    }
```

**File:** liquid_staking/sources/validator_pool.move (L202-207)
```text
            if (!active_validator_addresses.contains(&self.validator_infos[i].validator_address)) {
                // unstake max amount of sui.
                self.unstake_approx_n_sui_from_validator(system_state, i, MAX_SUI_SUPPLY, ctx);
                self.total_weight = self.total_weight - self.validator_infos[i].assigned_weight;
                self.validator_infos[i].assigned_weight = 0;
            };
```

**File:** liquid_staking/sources/validator_pool.move (L209-217)
```text
            // remove empty validator on epoch refresh
            if (self.validator_infos[i].is_empty()) {
                let ValidatorInfo { active_stake, inactive_stake, extra_fields, .. } = self.validator_infos.remove(i);
                active_stake.destroy_none();
                inactive_stake.destroy_none();
                extra_fields.destroy_empty();

                continue
            };
```

**File:** liquid_staking/sources/validator_pool.move (L260-262)
```text
        if(self.total_weight == 0) {
            return false
        };
```

**File:** liquid_staking/sources/validator_pool.move (L403-405)
```text
        if (self.total_weight == 0 || self.total_sui_supply() == 0) {
            return
        };
```

**File:** liquid_staking/sources/validator_pool.move (L708-716)
```text
            let total_weight = self.total_weight as u128;
            let mut i = self.validators().length();
            
            while (i > 0 && self.sui_pool.value() < max_sui_amount_out) {
                i = i - 1;

                let to_unstake_i = 1 + (self.validator_infos[i].assigned_weight as u128 
                                        * ((to_unstake)as u128)
                                        / total_weight);
```

**File:** liquid_staking/sources/stake_pool.move (L297-297)
```text
        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L369-369)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
```
