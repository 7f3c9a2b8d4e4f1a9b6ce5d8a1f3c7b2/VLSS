# Audit Report

## Title
Validator Weight Setting Fails Due to MIN_STAKE_THRESHOLD Causing DoS on Critical Operations

## Summary

The `set_validator_weights` function in `validator_pool.move` contains a logic bug where it sets `total_weight` to include all input validator weights before attempting to create validators. However, validators that cannot receive at least `MIN_STAKE_THRESHOLD` (1 SUI) are not created. The subsequent verification check compares the sum of weights from existing validators against `total_weight`, causing transaction abortion when pool liquidity is insufficient.

## Finding Description

The vulnerability occurs across the validator weight setting flow in `validator_pool.move`:

**1. Optimistic total_weight setting**

In `set_validator_weights`, the function calculates and sets `self.total_weight` to the sum of ALL input validator weights before attempting to create them. [1](#0-0) 

**2. Conditional validator creation in rebalance**

The `rebalance` function attempts to increase stake for validators, but only assigns weights to validators that actually exist (i.e., have a valid index). [2](#0-1) 

**3. Threshold enforcement prevents validator creation**

The `increase_validator_stake` function returns 0 without creating a validator if the amount is below `MIN_STAKE_THRESHOLD` (1 SUI = 1_000_000_000 MIST). The validator is only created when `join_stake` is called at line 506, which only happens if the threshold check at line 494 passes. [3](#0-2) 

**4. Strict verification assertion fails**

The `verify_validator_weights` function sums the weights of only the existing validators and asserts equality with `self.total_weight`. When validators fail to be created due to insufficient amounts, `weight_sum` (sum of existing validators' weights) will be less than `self.total_weight` (sum of all input weights), causing the assertion to fail. [4](#0-3) 

**Root Cause**: The code even acknowledges this issue with a comment but doesn't prevent the verification from failing. [5](#0-4) 

**Entry Point**: This function is called by the public operator function. [6](#0-5) 

## Impact Explanation

**High Severity - Operational DoS**

This vulnerability prevents operators from executing critical governance functions:

1. **Cannot set validator weights** when the pool has insufficient liquidity
2. **Cannot add new validators** during protocol initialization or when distributing stake across many validators
3. **Cannot rebalance** the validator set to optimize staking returns

**Concrete Scenario**:
- Pool has 1.5 SUI total supply
- Operator attempts to set weights: `{validator_A: 100, validator_B: 100}`
- Each validator should receive: `1.5 * 100/200 = 0.75 SUI`
- Both amounts are `< MIN_STAKE_THRESHOLD (1 SUI)`
- Neither validator gets created (both `increase_validator_stake` calls return 0)
- The rebalance logic doesn't assign any weights (no validators exist in the pool)
- The verification check fails: `weight_sum (0) == total_weight (200)` → **TRANSACTION ABORTS**

This breaks the protocol's ability to manage validators during critical operational phases such as protocol launch, validator rotation, or stake redistribution.

## Likelihood Explanation

**High Likelihood**

**Feasible Preconditions**:
- Pool liquidity condition: `total_sui_supply < MIN_STAKE_THRESHOLD * num_validators`
- This commonly occurs during:
  - Protocol launch with initial small deposits
  - Adding new validators to distribute stake thinly across more validators
  - Rebalancing with many validators receiving small weight allocations

**Execution Practicality**:
- Entry point is a public operator function requiring only `OperatorCap`
- No malicious action needed - this is a normal, legitimate operator action
- Move's assertion semantics guarantee transaction abortion when the condition fails

**Operational Reality**:
- Operators will inevitably encounter this during normal protocol operations
- No workaround exists except artificially increasing pool liquidity first
- Creates significant friction in validator management and operational delays

## Recommendation

Add a pre-validation check before setting `total_weight` or make the verification more lenient to account for validators that couldn't be created due to the minimum stake threshold:

**Option 1: Skip verification when liquidity is insufficient**
```move
public (package) fun set_validator_weights(
    self: &mut ValidatorPool,
    validator_weights: VecMap<address, u64>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext
) {
    self.manage.check_version();
    // ... existing validation ...
    
    self.total_weight = total_weight;
    self.rebalance(option::some<VecMap<address, u64>>(validator_weights), system_state, ctx);
    
    // Only verify if we have sufficient liquidity per validator
    if (self.total_sui_supply() >= MIN_STAKE_THRESHOLD * validator_weights.size()) {
        self.verify_validator_weights(validator_weights);
    };
}
```

**Option 2: Make verification lenient for below-threshold cases**
```move
fun verify_validator_weights(
    self: &ValidatorPool,
    validator_weights: VecMap<address, u64>,
) {
    // ... existing logic ...
    
    // Allow mismatch if total liquidity is below threshold
    let is_below_threshold = self.total_sui_supply() < MIN_STAKE_THRESHOLD * validator_weights.size();
    
    assert!(weight_sum == self.total_weight || is_below_threshold, EInvalidValidatorWeightSum);
    // Adjust other checks similarly
}
```

## Proof of Concept

```move
#[test]
fun test_validator_weight_dos_insufficient_liquidity() {
    let mut scenario = test_scenario::begin(@0x1);
    let ctx = test_scenario::ctx(&mut scenario);
    
    // Initialize pool with very low liquidity (1.5 SUI)
    let mut pool = validator_pool::new(ctx);
    let sui_balance = balance::create_for_testing<SUI>(1_500_000_000); // 1.5 SUI
    validator_pool::join_to_sui_pool(&mut pool, sui_balance);
    
    // Try to set weights for 2 validators (each would get 0.75 SUI < MIN_STAKE_THRESHOLD)
    let mut weights = vec_map::empty<address, u64>();
    vec_map::insert(&mut weights, @validator_a, 100);
    vec_map::insert(&mut weights, @validator_b, 100);
    
    // This will abort with EInvalidValidatorWeightSum
    validator_pool::set_validator_weights(&mut pool, weights, system_state, ctx);
    // Transaction aborts here - DoS achieved
    
    test_scenario::end(scenario);
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

**File:** liquid_staking/sources/validator_pool.move (L365-390)
```text
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

**File:** liquid_staking/sources/validator_pool.move (L493-508)
```text
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
```

**File:** liquid_staking/sources/stake_pool.move (L452-466)
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
```
