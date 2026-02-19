# Audit Report

## Title
Division by Zero in split_n_sui When Total Validator Weight is Zero

## Summary
The `split_n_sui` function in `validator_pool.move` performs division by `total_weight` without checking if it's zero, causing transaction aborts when all validators become inactive. This prevents users from unstaking their LST tokens and locks funds until the validator situation is resolved.

## Finding Description

The `split_n_sui` function is responsible for withdrawing SUI from validators when the `sui_pool` buffer has insufficient balance. [1](#0-0) 

The vulnerability occurs at the weight-proportional unstaking calculation, where the code divides by `total_weight` without verifying it's non-zero: [2](#0-1) 

This contrasts with similar functions in the same module that correctly guard against zero division:

**Protected function 1 - `stake_pending_sui`**: [3](#0-2) 

**Protected function 2 - `rebalance`**: [4](#0-3) 

**Root cause mechanism**: When validators become inactive during `refresh()`, their weights are set to zero: [5](#0-4) 

Crucially, validators are only removed from `validator_infos` if completely empty: [6](#0-5) [7](#0-6) 

This means validators with residual stake (e.g., inactive_stake not yet at activation epoch) remain in the vector with `assigned_weight = 0`. When all validators are inactive, `validator_infos.length() > 0` but `total_weight == 0`, causing the division by zero.

**Call paths to vulnerable function**:

1. **User unstake operation**: [8](#0-7) 

2. **Admin fee collection**: [9](#0-8) 

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

Add a zero-check guard at the beginning of `split_n_sui`, consistent with the pattern used in `stake_pending_sui` and `rebalance`:

```move
public(package) fun split_n_sui(
    self: &mut ValidatorPool,
    system_state: &mut SuiSystemState,
    max_sui_amount_out: u64,
    ctx: &mut TxContext
): Balance<SUI> {
    // Add this check
    if (self.total_weight == 0) {
        // Return available balance from sui_pool only
        let available = min(self.sui_pool.value(), max_sui_amount_out);
        assert!(available >= max_sui_amount_out, ENotEnoughSuiInSuiPool);
        return self.split_from_sui_pool(available)
    };
    
    // Rest of the function remains unchanged...
```

This ensures that when all validators are inactive, the function only attempts to withdraw from the `sui_pool` buffer without triggering division by zero.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Initialize a pool with validators and stake SUI
2. Simulate all validators becoming inactive (by having them removed from Sui's active validator set)
3. Call `refresh()` which sets all validator weights to 0
4. Attempt to `unstake()` LST tokens
5. Transaction aborts with division by zero at line 716 of `validator_pool.move`

The exact test implementation would require access to Sui's validator system state manipulation capabilities in a test environment, but the code path is deterministic: any call to `split_n_sui` when `total_weight == 0` and `validator_infos.length() > 0` and `sui_pool.value() < max_sui_amount_out` will trigger the division by zero.

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

**File:** liquid_staking/sources/validator_pool.move (L210-217)
```text
            if (self.validator_infos[i].is_empty()) {
                let ValidatorInfo { active_stake, inactive_stake, extra_fields, .. } = self.validator_infos.remove(i);
                active_stake.destroy_none();
                inactive_stake.destroy_none();
                extra_fields.destroy_empty();

                continue
            };
```

**File:** liquid_staking/sources/validator_pool.move (L260-263)
```text
        if(self.total_weight == 0) {
            return false
        };
        let sui_per_weight = self.sui_pool.value() / self.total_weight;
```

**File:** liquid_staking/sources/validator_pool.move (L403-405)
```text
        if (self.total_weight == 0 || self.total_sui_supply() == 0) {
            return
        };
```

**File:** liquid_staking/sources/validator_pool.move (L695-700)
```text
    public(package) fun split_n_sui(
        self: &mut ValidatorPool,
        system_state: &mut SuiSystemState,
        max_sui_amount_out: u64,
        ctx: &mut TxContext
    ): Balance<SUI> {
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

**File:** liquid_staking/sources/stake_pool.move (L289-297)
```text
        self.refresh(metadata, system_state, ctx);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L366-370)
```text
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);

        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
        self.accrued_reward_fees = self.accrued_reward_fees - reward_fees.value();
```
