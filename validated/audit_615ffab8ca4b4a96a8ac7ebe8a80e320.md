# Audit Report

## Title
Silent Validator Weight Update Failure with Inconsistent Stake Distribution

## Summary
The `set_validator_weights()` function can successfully update weight values in validator records while failing to rebalance actual stake distribution, then emit a success event. When the `sui_pool` balance is insufficient to meet the `MIN_STAKE_THRESHOLD` (1 SUI), `increase_validator_stake()` silently returns 0 without error, but weight records are still updated, creating a persistent inconsistency between recorded weights and actual stake allocation.

## Finding Description

When an operator calls `stake_pool.set_validator_weights()`, it delegates to `validator_pool.set_validator_weights()` which performs rebalancing. [1](#0-0) 

The `validator_pool.set_validator_weights()` function updates `total_weight`, calls `rebalance()`, and then verifies the result. [2](#0-1) 

During rebalancing, the function attempts to increase stake for validators below their target allocation. [3](#0-2) 

However, `increase_validator_stake()` contains a silent failure path. When the available SUI from the pool is less than `MIN_STAKE_THRESHOLD` (1 SUI = 1_000_000_000 MIST), it returns 0 without throwing an error. [4](#0-3) 

Despite this stake allocation failure, execution continues and the `assigned_weight` fields are still updated in validator records **regardless of whether staking succeeded**. The return value from `increase_validator_stake()` is completely ignored. [5](#0-4) 

The `verify_validator_weights()` function only validates that the `assigned_weight` fields match the requested weights - it does NOT verify that actual stake distribution is proportional to those weights. [6](#0-5) 

Since the weights were updated in the data structure (even though stake wasn't redistributed), all assertions pass. Control returns to `stake_pool.set_validator_weights()` which unconditionally emits a success event, signaling that the weight update succeeded when it actually failed. [7](#0-6) 

The developers acknowledge this issue in comments but don't handle it properly. [8](#0-7) 

## Impact Explanation

**Protocol State Corruption:**
- Validator `assigned_weight` fields show updated values but actual stake distribution remains at old allocations
- Future `stake_pending_sui()` operations use these incorrect weights to distribute new stake from the sui_pool, compounding the error over time [9](#0-8) 
- Subsequent rebalancing operations calculate target amounts based on corrupted baseline weights
- Validators receive disproportionate stake amounts relative to their recorded weights

**Operational Consequences:**
- Pool becomes imbalanced until sufficient liquidity accumulates and another rebalance occurs
- Staking rewards distributed incorrectly across validators based on actual stake (not recorded weights)
- Protocol fails to meet intended validator diversification strategy
- Operators and users falsely believe weight update succeeded based on emitted event
- The inconsistency persists and compounds as new stake flows through the system using incorrect weight distributions

**Severity:** Medium. While no immediate fund loss occurs, the protocol enters an inconsistent state that violates the critical invariant that validator weights must accurately represent stake distribution. This leads to inefficient capital allocation and incorrect reward distribution over time.

## Likelihood Explanation

**Feasibility:** HIGH

The vulnerability triggers under realistic conditions:
- Occurs whenever `sui_pool` balance falls below `MIN_STAKE_THRESHOLD` (1 SUI) for the required stake increase amount
- Common during periods of high unstaking activity when users withdraw funds, depleting the sui_pool
- Also occurs when operators attempt weight updates before pending SUI has been staked to validators

**Trigger Requirements:**
- Operator with legitimate OperatorCap (no compromise needed)
- sui_pool balance insufficient to meet 1 SUI minimum per validator requiring stake increase
- Routine weight update operation

**Probability:** MEDIUM-HIGH

The condition is likely to occur regularly in production:
- High unstaking volume temporarily depletes sui_pool below threshold
- Operators may update weights multiple times per epoch for optimization
- The 1 SUI threshold is significant enough that pools frequently have less than this available for allocation
- Natural occurrence during normal protocol operations, not requiring any attack

## Recommendation

The issue can be fixed by tracking whether stake allocation actually succeeded and reverting if weights cannot be properly set:

1. **Option 1 - Revert on failure:** Modify `rebalance()` to track the return value from `increase_validator_stake()` and revert if any required stake increase returns 0 when the target amount is non-zero.

2. **Option 2 - Delay weight update:** Only update `assigned_weight` fields after verifying that actual stake distribution matches the target. This requires comparing actual stake amounts with target amounts before updating weights.

3. **Option 3 - Two-phase update:** Implement a two-phase approach where weights are tentatively updated, actual rebalancing is attempted, and then weights are rolled back if rebalancing fails to meet minimum thresholds.

The verification function should also be enhanced to check actual stake distribution proportionality, not just weight field values.

## Proof of Concept

```move
#[test]
fun test_weight_update_fails_silently_with_low_liquidity() {
    // Setup: Create stake pool with 2 validators
    // - Validator A: 100 SUI staked, weight 100
    // - Validator B: 100 SUI staked, weight 100
    // - sui_pool: 0.5 SUI (below MIN_STAKE_THRESHOLD)
    
    // Action: Operator updates weights to [50, 150]
    // Expected rebalance: Move 25 SUI from A to B
    // Required: Take 25 SUI from sui_pool to stake with B
    
    // Bug: increase_validator_stake() returns 0 because 0.5 SUI < 1 SUI threshold
    // But assigned_weight for B is still updated to 150
    
    // Result: 
    // - Validator A: 100 SUI staked, weight 50 (MISMATCH - should be ~87.5 SUI)
    // - Validator B: 100 SUI staked, weight 150 (MISMATCH - should be ~112.5 SUI)
    // - Success event emitted despite failure
    
    // Consequence: Next stake_pending_sui() will distribute based on weights [50, 150]
    // instead of actual distribution [100, 100], further imbalancing the pool
}
```

**Notes:**

This vulnerability represents a critical design flaw in the validator weight update mechanism. The protocol assumes that if `increase_validator_stake()` is called, staking will succeed, but the function has a silent failure path when liquidity is insufficient. The verification step only checks that weight fields were updated, not that actual stake was redistributed.

The developer comment acknowledges this limitation but treats it as acceptable, when in reality it violates the fundamental invariant that `assigned_weight` should reflect actual stake distribution. This becomes especially problematic because future operations like `stake_pending_sui()` rely on these weights to distribute new stake, causing the error to compound over time rather than self-correct.

The recommended fix should either ensure atomic updates (revert if rebalancing fails) or implement proper rollback mechanisms to maintain protocol invariants.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L462-466)
```text
        self.validator_pool.set_validator_weights(
            validator_weights,
            system_state,
            ctx
        );
```

**File:** liquid_staking/sources/stake_pool.move (L468-470)
```text
        emit(ValidatorWeightsUpdateEvent {
            validator_weights
        });
```

**File:** liquid_staking/sources/validator_pool.move (L263-275)
```text
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
```

**File:** liquid_staking/sources/validator_pool.move (L351-358)
```text
        self.total_weight = total_weight;

        self.rebalance(option::some<VecMap<address, u64>>(validator_weights), system_state, ctx);

        // There is a chance that the validator weights are not set correctly
        // due to sui pool balance not meeting the minimum stake threshold 
        // to create a new validator.
        self.verify_validator_weights(validator_weights);
```

**File:** liquid_staking/sources/validator_pool.move (L361-390)
```text
    fun verify_validator_weights(
        self: &ValidatorPool,
        validator_weights: VecMap<address, u64>,
    ) {
        let mut weight_sum = 0;
        let mut match_num = 0;
        let mut non_zero_weights_count = 0;

        self.validator_infos.do_ref!(|validator| {
            weight_sum = weight_sum + validator.assigned_weight;
            if (validator_weights.contains(&validator.validator_address) && validator.assigned_weight > 0) {
                match_num = match_num + 1;
                let weight = validator_weights.get(&validator.validator_address);

                assert!(weight == validator.assigned_weight, EInvalidValidatorWeight);
            };
        });

        // Count validators with non-zero weights in the input
        let v_size = validator_weights.size();
        v_size.do!(|i| {
            let (_, weight) = validator_weights.get_entry_by_idx(i);
            if (*weight > 0) {
                non_zero_weights_count = non_zero_weights_count + 1;
            };
        });

        assert!(weight_sum == self.total_weight, EInvalidValidatorWeightSum);
        assert!(match_num == non_zero_weights_count, EInvalidValidatorSize);  
    }
```

**File:** liquid_staking/sources/validator_pool.move (L463-471)
```text
            if (validator_current_amounts[i] < validator_target_amounts[i]) {
                self.increase_validator_stake(
                    system_state,
                    validator_addresses[i],
                    validator_target_amounts[i] - validator_current_amounts[i],
                    ctx
                );
            };
        });
```

**File:** liquid_staking/sources/validator_pool.move (L474-480)
```text
        validator_addresses.length().do!(|i| {
            let validator_address = validator_addresses[i];
            let mut validator_index = self.find_validator_index_by_address(validator_address);
            if (validator_index.is_some()) {
                self.validator_infos[validator_index.extract()].assigned_weight = validator_weights[i];
            };
        });
```

**File:** liquid_staking/sources/validator_pool.move (L493-497)
```text
        let sui = self.split_up_to_n_sui_from_sui_pool(sui_amount);
        if (sui.value() < MIN_STAKE_THRESHOLD) {
            self.join_to_sui_pool(sui);
            return 0
        };
```
