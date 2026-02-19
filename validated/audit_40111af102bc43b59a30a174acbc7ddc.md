# Audit Report

## Title
Validator Weight Setting Fails Due to MIN_STAKE_THRESHOLD Causing DoS on Critical Operations

## Summary

The `set_validator_weights` function in `validator_pool.move` sets `total_weight` to include all input validator weights before attempting to create validators through `rebalance()`. However, validators that cannot receive at least `MIN_STAKE_THRESHOLD` (1 SUI) are not created. The subsequent `verify_validator_weights` check compares the sum of weights from existing validators against `total_weight`, causing transaction abortion with `EInvalidValidatorWeightSum` when pool liquidity is insufficient to meet the threshold for all validators.

## Finding Description

The vulnerability occurs across the validator weight setting flow in `validator_pool.move`:

**1. Setting total_weight optimistically**

In `set_validator_weights`, the function calculates and sets `self.total_weight` to the sum of ALL input validator weights before attempting to create them: [1](#0-0) 

**2. Conditional validator creation in rebalance**

The `rebalance` function attempts to increase stake for validators, but only assigns weights to validators that actually exist: [2](#0-1) 

**3. Threshold enforcement in increase_validator_stake**

The `increase_validator_stake` function returns 0 without creating a validator if the amount is below `MIN_STAKE_THRESHOLD`: [3](#0-2) 

The validator is only created when `join_stake` is called at line 506, which only happens if the threshold check passes. Otherwise, the SUI is returned to the pool and the function returns 0.

**4. Strict verification fails**

The `verify_validator_weights` function sums the weights of existing validators and asserts equality with `self.total_weight`: [4](#0-3) 

When validators fail to be created, `weight_sum` (sum of existing validators' weights) will be less than `self.total_weight` (sum of all input weights), causing the assertion at line 388 to fail.

**Root Cause**: The code acknowledges this issue with a comment but doesn't prevent the verification from failing: [5](#0-4) 

## Impact Explanation

**High Severity - Operational DoS**

This vulnerability prevents operators from executing critical governance functions:

1. **Cannot set validator weights** when pool has insufficient liquidity
2. **Cannot add new validators** during protocol initialization or when distributing stake across many validators  
3. **Cannot rebalance** the validator set to optimize staking returns

**Concrete Scenario**:
- Pool has 1.5 SUI total supply
- Operator attempts: `{validator_A: 100, validator_B: 100}`
- Each validator should receive: `1.5 * 100/200 = 0.75 SUI`
- Both amounts are `< MIN_STAKE_THRESHOLD (1 SUI)`
- Neither validator gets created (both `increase_validator_stake` calls return 0)
- Line 478 doesn't assign any weights (no validators exist)
- Line 388 assertion: `weight_sum (0) == total_weight (200)` → **FAILS**

This breaks the protocol's ability to manage validators during critical operational phases.

## Likelihood Explanation

**High Likelihood**

**Feasible Preconditions**:
- Pool liquidity: `total_sui_supply < MIN_STAKE_THRESHOLD * num_validators`
- Commonly occurs during:
  - Protocol launch with initial small deposits
  - Adding validators to distribute stake thinly
  - Rebalancing with many small-weight validators

**Execution Practicality**:
- Entry point is public operator function: [6](#0-5) 
- No attack needed - normal operator action triggers the bug
- Move's assertion semantics guarantee transaction abortion

**Operational Reality**:
- Operators will encounter this during normal operations
- No workaround except artificially increasing pool liquidity first
- Creates friction in validator management and delays

## Recommendation

Modify `verify_validator_weights` to only verify weights for validators that were successfully created, or adjust `total_weight` after rebalancing to reflect actual assigned weights:

**Option 1**: Recalculate `total_weight` after rebalancing based on actual assigned weights:
```move
public (package) fun set_validator_weights(
    self: &mut ValidatorPool,
    validator_weights: VecMap<address, u64>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext
) {
    // ... validation code ...
    
    self.rebalance(option::some<VecMap<address, u64>>(validator_weights), system_state, ctx);
    
    // Recalculate total_weight based on actual assigned weights
    let mut actual_total_weight = 0;
    self.validator_infos.do_ref!(|validator| {
        actual_total_weight = actual_total_weight + validator.assigned_weight;
    });
    self.total_weight = actual_total_weight;
    
    self.verify_validator_weights(validator_weights);
}
```

**Option 2**: Make `verify_validator_weights` more lenient by only checking validators that exist, not requiring all input weights to be assigned.

## Proof of Concept

```move
#[test]
fun test_set_validator_weights_dos_low_liquidity() {
    let mut scenario = test_scenario::begin(@0xCAFE);
    let ctx = scenario.ctx();
    
    // Create pool with only 1.5 SUI
    let mut pool = validator_pool::new(ctx);
    pool.join_to_sui_pool(balance::create_for_testing<SUI>(1_500_000_000)); // 1.5 SUI
    
    // Try to set weights for 2 validators with 100 weight each
    let mut validator_weights = vec_map::empty<address, u64>();
    validator_weights.insert(@0xVAL1, 100);
    validator_weights.insert(@0xVAL2, 100);
    
    // This should fail with EInvalidValidatorWeightSum
    // Each validator needs 0.75 SUI but MIN_STAKE_THRESHOLD is 1 SUI
    pool.set_validator_weights(validator_weights, &mut system_state, ctx);
    // Expected: Transaction aborts with EInvalidValidatorWeightSum (40006)
    
    scenario.end();
}
```

### Citations

**File:** liquid_staking/sources/validator_pool.move (L343-351)
```text
        let mut total_weight = 0;
        v_size.do!(|i| {
            let (_, weight) = validator_weights.get_entry_by_idx(i);
            total_weight = total_weight + *weight;
        });

        assert!(total_weight <= MAX_TOTAL_WEIGHT, EMaxTotalWeight);

        self.total_weight = total_weight;
```

**File:** liquid_staking/sources/validator_pool.move (L355-358)
```text
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

**File:** liquid_staking/sources/validator_pool.move (L460-480)
```text
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
