# Audit Report

## Title
Combined Boundary Logic Causes Unintentional Full Validator Unstaking

## Summary
A boundary condition vulnerability in the validator unstaking logic causes complete depletion of a validator's stake when only partial unstaking was intended. This occurs through the interaction of two boundary checks in `unstake_approx_n_sui_from_inactive_stake()` and `unstake_approx_n_sui_from_active_stake()`, combined with the `ACTIVE_STAKE_REDEEM_OFFSET`, leaving validators with assigned weight but zero stake.

## Finding Description

The vulnerability exists in the coordinated unstaking logic within `validator_pool.move`. When a user initiates a withdrawal that slightly exceeds a validator's inactive stake amount, the boundary conditions trigger unintended full unstaking of both inactive and active stakes. [1](#0-0) 

The root cause is the sequential interaction:

**First**, the inactive stake boundary check uses `<=` operator which fully unstakes when the requested amount is within `MIN_STAKE_THRESHOLD` (1 SUI) of the inactive stake: [2](#0-1) 

**Second**, after inactive stake is fully depleted, the remaining target amount (now very small) is increased by `ACTIVE_STAKE_REDEEM_OFFSET` (100 mist), then forced to minimum 1 SUI via `max()`, triggering the active stake boundary check: [3](#0-2) 

**Mathematical scenario:**
- Validator has: inactive_stake = 2 SUI, active_stake = 2 SUI
- User withdrawal targets ~2.000000001 SUI from this validator
- Inactive check: `2_000_000_000 <= 2_000_000_001 + 1_000_000_000` → TRUE → takes all 2 SUI
- Active target becomes: `max((2_000_000_001 - 2_000_000_000) + 100, 1_000_000_000) = 1_000_000_000`
- Active check: `2_000_000_000 <= 1_000_000_000 + 1_000_000_000` → TRUE → takes all 2 SUI

This leaves the validator with `total_sui_amount = 0` but `assigned_weight > 0`, violating the protocol's weight-proportional stake distribution invariant.

The entry point is the public `unstake_entry()` function accessible to any user: [4](#0-3) 

The validator is not automatically removed because the `is_empty()` check requires `assigned_weight == 0`: [5](#0-4) 

## Impact Explanation

The vulnerability creates a protocol invariant violation with operational consequences:

1. **Invariant Violation**: The protocol expects validators to maintain stake proportional to their assigned weights. A validator with `assigned_weight > 0` but `total_sui_amount = 0` breaks this fundamental relationship.

2. **Lost Staking Rewards**: The affected validator cannot earn staking rewards until restaked via `stake_pending_sui()` during the next epoch refresh or rebalance operation: [6](#0-5) 

3. **Validator Diversification Degradation**: Protocol stake becomes concentrated in remaining validators, temporarily reducing network decentralization.

4. **Operational State Inconsistency**: The validator persists in an inconsistent state where it holds weight allocation but cannot fulfill its staking function.

While there is no direct fund loss and the state is eventually corrected during the next staking operation, the temporary imbalance compromises the protocol's operational integrity and validator distribution strategy. The impact is **moderate** - affecting protocol health but not causing permanent damage.

## Likelihood Explanation

The vulnerability has **high likelihood** of occurrence:

1. **Public Access**: Any user can trigger via `unstake_entry()` with their LST tokens
2. **No Special Permissions**: Works with normal user withdrawal operations  
3. **Low Complexity**: Single transaction with withdrawal amount slightly exceeding inactive stake
4. **Deterministic Trigger**: Mathematical boundary conditions guarantee the behavior
5. **Unintentional Occurrence**: Can happen during routine protocol operations without malicious intent

The vulnerability is triggered when withdrawal amounts proportionally allocated to a validator slightly exceed that validator's inactive stake. Given the weighted distribution logic in `split_n_sui()`: [7](#0-6) 

This scenario naturally occurs during large withdrawals when validators hold both inactive and active stakes of similar magnitudes.

## Recommendation

Modify the boundary logic to prevent unintended full unstaking. Consider one of these approaches:

**Option 1**: Adjust the active stake target calculation to account for the actual remaining deficit instead of adding the offset when the deficit is very small:

```move
if (unstake_sui_amount > amount) {
    let remaining = unstake_sui_amount - amount;
    // Only add offset if remaining is significant
    let adjusted_target = if (remaining > MIN_STAKE_THRESHOLD) {
        remaining + ACTIVE_STAKE_REDEEM_OFFSET
    } else {
        remaining
    };
    amount = amount + self.unstake_approx_n_sui_from_active_stake(
        system_state, 
        validator_index, 
        adjusted_target, 
        ctx
    );
}
```

**Option 2**: Tighten the boundary conditions to use strict `<` for full unstaking decisions:

```move
// In both functions, change the condition to:
if (staked_sui_amount < target_unstake_sui_amount + MIN_STAKE_THRESHOLD) {
    // take all
} else {
    // partial
}
```

**Option 3**: Add a safeguard to prevent creating validators with zero stake but non-zero weight by automatically zeroing the weight when stake is depleted outside of refresh operations.

## Proof of Concept

```move
#[test]
fun test_boundary_causes_full_validator_unstaking() {
    // Setup: Create validator pool with one validator having 2 SUI inactive + 2 SUI active
    // User withdraws 2.000000001 SUI targeted at this validator
    // Expected: Partial unstaking (~2 SUI)
    // Actual: Full unstaking (4 SUI), leaving assigned_weight > 0 but total_sui_amount = 0
    
    // This test would demonstrate:
    // 1. Initial state: validator with assigned_weight=100, inactive=2 SUI, active=2 SUI
    // 2. Call unstake_approx_n_sui_from_validator with target=2_000_000_001
    // 3. Verify final state: validator has assigned_weight=100, total_sui_amount=0
    // 4. Confirm is_empty() returns false (validator not removed)
}
```

---

## Notes

The vulnerability is particularly concerning because it can occur without malicious intent during normal protocol operations. The mathematical boundary conditions are deterministic and will trigger whenever specific stake amounts and withdrawal targets align. The protocol's eventual self-correction through `stake_pending_sui()` during refresh mitigates permanent damage, but the temporary state inconsistency violates core protocol invariants and affects validator diversification strategy.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L170-173)
```text
    fun is_empty(self: &ValidatorInfo): bool {
        self.active_stake.is_none() && self.inactive_stake.is_none() && self.total_sui_amount == 0
        && self.assigned_weight == 0
    }
```

**File:** liquid_staking/sources/validator_pool.move (L254-279)
```text
    public(package) fun stake_pending_sui(
        self: &mut ValidatorPool, 
        system_state: &mut SuiSystemState, 
        ctx: &mut TxContext
    ): bool {
        let mut i = self.validator_infos.length();
        if(self.total_weight == 0) {
            return false
        };
        let sui_per_weight = self.sui_pool.value() / self.total_weight;
        while (i > 0) {
            i = i - 1;

            let validator_address = self.validator_infos[i].validator_address;
            let assigned_weight = self.validator_infos[i].assigned_weight;
            self.increase_validator_stake(
                system_state, 
                validator_address,
                sui_per_weight * assigned_weight,
                ctx
            );
        };
        

        true
    }
```

**File:** liquid_staking/sources/validator_pool.move (L601-614)
```text
    public(package) fun unstake_approx_n_sui_from_validator(
        self: &mut ValidatorPool, 
        system_state: &mut SuiSystemState,
        validator_index: u64, 
        unstake_sui_amount: u64,
        ctx: &mut TxContext
    ): u64 {
        let mut amount = self.unstake_approx_n_sui_from_inactive_stake(system_state, validator_index, unstake_sui_amount, ctx);
        if (unstake_sui_amount > amount) {
            amount = amount + self.unstake_approx_n_sui_from_active_stake(system_state, validator_index, unstake_sui_amount - amount + ACTIVE_STAKE_REDEEM_OFFSET, ctx);
        };

        amount
    }
```

**File:** liquid_staking/sources/validator_pool.move (L639-643)
```text
        let target_unstake_sui_amount = max(target_unstake_sui_amount, MIN_STAKE_THRESHOLD);

        let unstaked_sui = if (total_sui_amount <= target_unstake_sui_amount + MIN_STAKE_THRESHOLD) {
            self.take_all_active_stake(system_state, validator_index, ctx)
        } else {
```

**File:** liquid_staking/sources/validator_pool.move (L679-686)
```text
        let target_unstake_sui_amount = max(target_unstake_sui_amount, MIN_STAKE_THRESHOLD);

        let staked_sui_amount = validator_info.inactive_stake.borrow().staked_sui_amount();
        let staked_sui = if (staked_sui_amount <= target_unstake_sui_amount + MIN_STAKE_THRESHOLD) {
            self.take_all_inactive_stake(validator_index)
        } else {
            self.take_some_inactive_stake(validator_index, target_unstake_sui_amount, ctx)
        };
```

**File:** liquid_staking/sources/validator_pool.move (L714-723)
```text
                let to_unstake_i = 1 + (self.validator_infos[i].assigned_weight as u128 
                                        * ((to_unstake)as u128)
                                        / total_weight);
                                
                self.unstake_approx_n_sui_from_validator(
                    system_state,
                    i,
                    to_unstake_i as u64,
                    ctx
                );
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
