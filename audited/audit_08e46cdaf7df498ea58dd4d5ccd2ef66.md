# Audit Report

## Title
Silent Validator Weight Update Failure with Inconsistent Stake Distribution

## Summary
The `set_validator_weights()` function can successfully update weight values in validator records while failing to rebalance actual stake distribution, then emit a success event. When the `sui_pool` balance is insufficient to meet the `MIN_STAKE_THRESHOLD` (1 SUI), `increase_validator_stake()` silently returns 0 without error, but weight records are still updated, creating a permanent inconsistency between recorded weights and actual stake allocation.

## Finding Description

When an operator calls `stake_pool.set_validator_weights()`, it delegates to `validator_pool.set_validator_weights()` which performs rebalancing. [1](#0-0) 

The `validator_pool.set_validator_weights()` function updates `total_weight`, calls `rebalance()`, and then verifies the result. [2](#0-1) 

During rebalancing, the function attempts to increase stake for validators below their target allocation. [3](#0-2) 

However, `increase_validator_stake()` contains a silent failure path. When the available SUI from the pool is less than `MIN_STAKE_THRESHOLD` (1 SUI = 1_000_000_000 MIST), it returns 0 without throwing an error. [4](#0-3) 

Despite this stake allocation failure, execution continues and the `assigned_weight` fields are still updated in validator records regardless of whether staking succeeded. [5](#0-4) 

The `verify_validator_weights()` function only validates that the `assigned_weight` fields match the requested weights - it does NOT verify that actual stake distribution is proportional to those weights. [6](#0-5) 

Since the weights were updated in the data structure (even though stake wasn't redistributed), all assertions pass. Control returns to `stake_pool.set_validator_weights()` which unconditionally emits a success event, signaling that the weight update succeeded when it actually failed.

The developers acknowledge this issue in comments but don't handle it properly. [7](#0-6) 

## Impact Explanation

**Protocol State Corruption:**
- Validator `assigned_weight` fields show updated values but actual stake distribution remains at old allocations
- Future `stake_pending_sui()` operations use these incorrect weights to distribute new stake from the sui_pool [8](#0-7) 
- Subsequent rebalancing operations calculate target amounts based on corrupted baseline weights
- Validators receive disproportionate stake amounts relative to their recorded weights

**Operational Consequences:**
- Pool becomes imbalanced until sufficient liquidity accumulates and another rebalance occurs
- Staking rewards distributed incorrectly across validators based on actual stake (not recorded weights)
- Protocol fails to meet intended validator diversification strategy
- Operators and users falsely believe weight update succeeded based on emitted event
- The inconsistency compounds over time as new stake is distributed using wrong weights

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

Modify the `rebalance()` function to track whether stake allocation succeeded and revert the weight updates if actual staking failed. Options include:

1. **Check return value from increase_validator_stake:**
   - Track whether all required stake increases succeeded
   - Only update `assigned_weight` if the corresponding stake increase returned non-zero
   - Revert the entire transaction if any critical weight updates fail

2. **Improve verify_validator_weights:**
   - After updating weights, calculate expected stake distribution based on new weights
   - Compare actual `total_sui_amount` per validator against expected proportional amounts
   - Assert that actual distribution matches expected within acceptable tolerance

3. **Add minimum sui_pool check:**
   - Before starting rebalance, calculate total SUI needed for all required stake increases
   - Require sui_pool to have sufficient balance to execute all weight changes
   - Fail early with clear error message rather than silently corrupting state

The core issue is that weight updates and stake distribution updates are not atomic - weights are updated even when staking fails. The fix should ensure these operations succeed or fail together.

## Proof of Concept

```move
#[test]
fun test_weight_update_failure_with_insufficient_pool() {
    // Setup: Create pool with validator A having 100 SUI staked, weight 100
    // sui_pool has only 0.5 SUI
    
    // Action: Operator calls set_validator_weights({A: 200})
    // Expected: Should fail or preserve consistency
    // Actual: 
    //   - assigned_weight updated to 200
    //   - actual stake still ~100 SUI (increase_validator_stake returned 0)
    //   - verify_validator_weights passes (only checks field)
    //   - success event emitted
    
    // Result: Protocol state corrupted
    //   - validator_infos[A].assigned_weight = 200
    //   - validator_infos[A].total_sui_amount ≠ proportional to weight 200
    //   - Future stake_pending_sui uses weight 200 but actual stake is still old distribution
}
```

The test would demonstrate that after calling `set_validator_weights()` with insufficient sui_pool balance, the `assigned_weight` field is updated but the actual `total_sui_amount` does not reflect the proportional stake for that weight, creating a permanent inconsistency until the next successful rebalance.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L452-471)
```text
    public fun set_validator_weights(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        _: &OperatorCap,
        validator_weights: VecMap<address, u64>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);
        self.validator_pool.set_validator_weights(
            validator_weights,
            system_state,
            ctx
        );

        emit(ValidatorWeightsUpdateEvent {
            validator_weights
        });
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

**File:** liquid_staking/sources/validator_pool.move (L332-359)
```text
    public (package) fun set_validator_weights(
        self: &mut ValidatorPool,
        validator_weights: VecMap<address, u64>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();

        let v_size = validator_weights.size();
        assert!(v_size <= MAX_VALIDATORS, ETooManyValidators);

        let mut total_weight = 0;
        v_size.do!(|i| {
            let (_, weight) = validator_weights.get_entry_by_idx(i);
            total_weight = total_weight + *weight;
        });

        assert!(total_weight <= MAX_TOTAL_WEIGHT, EMaxTotalWeight);

        self.total_weight = total_weight;

        self.rebalance(option::some<VecMap<address, u64>>(validator_weights), system_state, ctx);

        // There is a chance that the validator weights are not set correctly
        // due to sui pool balance not meeting the minimum stake threshold 
        // to create a new validator.
        self.verify_validator_weights(validator_weights);
    }
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

**File:** liquid_staking/sources/validator_pool.move (L459-471)
```text
        // 4. increase the stake for validators that have less stake than the target amount
        validator_addresses.length().do!(|i| {
            // increase stake may not succeed due to the minimum stake threshold
            // so the validator will not be created
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

**File:** liquid_staking/sources/validator_pool.move (L473-480)
```text
        // 5. update the validator weights
        validator_addresses.length().do!(|i| {
            let validator_address = validator_addresses[i];
            let mut validator_index = self.find_validator_index_by_address(validator_address);
            if (validator_index.is_some()) {
                self.validator_infos[validator_index.extract()].assigned_weight = validator_weights[i];
            };
        });
```

**File:** liquid_staking/sources/validator_pool.move (L486-509)
```text
    public (package) fun increase_validator_stake(
        self: &mut ValidatorPool,
        system_state: &mut SuiSystemState,
        validator_address: address,
        sui_amount: u64,
        ctx: &mut TxContext
    ): u64 {
        let sui = self.split_up_to_n_sui_from_sui_pool(sui_amount);
        if (sui.value() < MIN_STAKE_THRESHOLD) {
            self.join_to_sui_pool(sui);
            return 0
        };

        let staked_sui = system_state.request_add_stake_non_entry(
            coin::from_balance(sui, ctx),
            validator_address,
            ctx
        );
        let staked_sui_amount = staked_sui.staked_sui_amount();

        self.join_stake(system_state,staked_sui, ctx);

        staked_sui_amount
    }
```
