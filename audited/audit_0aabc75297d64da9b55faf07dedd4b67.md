### Title
Validator Weight/Stake Ratio Bypass Through Minimum Stake Threshold Evasion

### Summary
The `set_validator_weights()` function in the liquid staking validator pool updates validator weights without ensuring proportional stake allocation when the `sui_pool` has insufficient balance to meet the `MIN_STAKE_THRESHOLD`. This allows validators to receive inflated weight assignments without corresponding stake increases, violating the protocol's core invariant that validator weight should be proportional to actual staked amounts.

### Finding Description

The external vulnerability involves bypassing a minimum stake threshold through inconsistent validation between insert and update operations. An analogous vulnerability exists in Volo's liquid staking system: [1](#0-0) 

The `increase_validator_stake()` function enforces a `MIN_STAKE_THRESHOLD` of 1 SUI (1_000_000_000 MIST). When attempting to stake an amount below this threshold, the function returns 0 without adding any stake. [2](#0-1) 

In the `rebalance()` function, validator weights are updated at line 478 regardless of whether the corresponding `increase_validator_stake()` call at line 464 succeeded. When `sui_pool` has insufficient balance (< `MIN_STAKE_THRESHOLD`) to allocate the required stake to match the new weight, the stake increase silently fails, but the weight assignment proceeds. [3](#0-2) 

The entry point `set_validator_weights()` calls `rebalance()` and then `verify_validator_weights()`, but the verification only confirms the weight field values match the input—it does not validate stake proportionality. [4](#0-3) 

The `verify_validator_weights()` function at line 375 only asserts that `weight == validator.assigned_weight`, confirming the weight field was set but not checking if adequate stake was allocated.

**Root Cause**: The weight update operation lacks validation that the minimum stake threshold was actually met for the stake increase, creating a state where a validator can have disproportionately high weight relative to actual stake.

**Why Protections Fail**: The `verify_validator_weights()` check only validates weight field consistency, not stake/weight proportionality. Comments at lines 355-357 acknowledge this issue for new validators but the same problem affects existing validators.

### Impact Explanation

When a validator has inflated weight without proportional stake: [5](#0-4) 

In `stake_pending_sui()`, stake allocation is calculated as `sui_per_weight * assigned_weight` (line 272). A validator with artificially high weight receives a disproportionate share of new deposits, starving other validators of their intended stake allocation.

This creates:
1. **Asset Misrouting**: New user deposits are incorrectly allocated based on inflated weights rather than actual validator capacity
2. **Broken Protocol Invariant**: The fundamental assumption that weight reflects proportional stake is violated
3. **Persistent Misallocation**: The imbalance persists until a future rebalance with sufficient liquidity, during which time all new stakes are misallocated

The protocol's staking rewards and validator selection mechanisms depend on accurate weight/stake ratios, making this a material violation of core protocol accounting.

### Likelihood Explanation

**Entry Point**: The vulnerability is triggered via `set_validator_weights()` which requires `OperatorCap`, not `AdminCap`.

**Feasible Preconditions**:
1. An operator calls `set_validator_weights()` with increased weights for one or more validators
2. The `sui_pool` balance is below `MIN_STAKE_THRESHOLD` due to recent user withdrawals or prior stake allocations
3. This is a realistic scenario as `sui_pool` naturally fluctuates based on user activity

**Realistic Scenario**: After users execute large withdrawals via `unstake()`, the `sui_pool` can temporarily have minimal balance. An operator performing routine weight adjustments during this window would inadvertently trigger the vulnerability. Alternatively, a malicious operator could strategically time weight updates when pool liquidity is known to be low.

### Recommendation

Implement proportionality validation in `verify_validator_weights()`:

```move
fun verify_validator_weights(
    self: &ValidatorPool,
    validator_weights: VecMap<address, u64>,
) {
    // Existing checks...
    
    // Add proportionality check
    self.validator_infos.do_ref!(|validator| {
        let weight_ratio = (validator.assigned_weight as u128) / (self.total_weight as u128);
        let stake_ratio = (validator.total_sui_amount as u128) / (self.total_sui_supply as u128);
        let tolerance = 100; // 1% tolerance
        assert!(
            absolute_diff(weight_ratio * 10000, stake_ratio * 10000) <= tolerance,
            EInvalidValidatorWeightStakeRatio
        );
    });
}
```

Alternatively, in `rebalance()`, if `increase_validator_stake()` returns less than the required amount, either:
1. Revert the entire weight update transaction, or
2. Proportionally reduce the weight assignment to match the actual stake allocated

### Proof of Concept

**Setup**:
- StakePool has 2 validators: V1 (weight=50, stake=50 SUI), V2 (weight=50, stake=50 SUI)
- Total: total_weight=100, total_sui_supply=100 SUI
- sui_pool current balance: 0.8 SUI (below MIN_STAKE_THRESHOLD of 1 SUI)

**Attack Steps**:
1. Operator calls `set_validator_weights()` with new weights: `{V1: 100, V2: 0}`
2. `rebalance()` calculates:
   - V1 target: (100 SUI * 100) / 100 = 100 SUI (needs +50 SUI)
   - V2 target: (100 SUI * 0) / 100 = 0 SUI (needs -50 SUI)
3. Line 447-456: `decrease_validator_stake()` for V2 succeeds, returning 50 SUI to sui_pool (now 50.8 SUI)
4. Line 464: `increase_validator_stake()` called for V1 with amount=50 SUI
5. Line 493: Splits 50 SUI from sui_pool successfully
6. Line 494-496: Check fails because initially sui_pool had only 0.8 SUI, so only 0.8 SUI was split initially in the problematic case
   
**Correction to PoC** (realistic scenario):
1. Initial state: V1 (weight=50, stake=50 SUI), sui_pool=0.5 SUI
2. Call `set_validator_weights({V1: 100})`
3. Target for V1 = 100 SUI, current = 50 SUI, need to add 50 SUI
4. `increase_validator_stake(V1, 50 SUI)` is called
5. Line 493 attempts to split 50 SUI but sui_pool only has 0.5 SUI
6. Line 592: `split_up_to_n_sui_from_sui_pool(50)` returns only 0.5 SUI
7. Line 494: 0.5 < MIN_STAKE_THRESHOLD, returns 0
8. Line 478: V1.assigned_weight = 100 (updated!)

**Result**: V1 now has weight=100 but stake=50 SUI, receiving 100% of new deposits despite having only 50% of total stake.

### Citations

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

**File:** liquid_staking/sources/validator_pool.move (L393-484)
```text
    public (package) fun rebalance(
        self: &mut ValidatorPool,
        mut target_validator_weights: Option<VecMap<address, u64>>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {

        let previous_total_sui_supply = self.total_sui_supply();
        let is_targeted = target_validator_weights.is_some();

        if (self.total_weight == 0 || self.total_sui_supply() == 0) {
            return
        };

        let mut validator_addresses_weights = if (is_targeted) {
            target_validator_weights.extract()
        } else {
            vec_map::empty<address, u64>()
        };

        // 1. initialize the validator_weights map
        self.validators().do_ref!(|validator| {
            let validator_address = validator.validator_address();
            if (!validator_addresses_weights.contains(&validator_address)) {
                let weight = if (is_targeted) {
                    0
                } else {
                    validator.assigned_weight
                };
                validator_addresses_weights.insert(validator_address, weight);
            };
        });

        // 2. calculate current and target amounts of sui for each validator
        let (validator_addresses, validator_weights) = validator_addresses_weights.into_keys_values();

        let total_sui_supply = self.total_sui_supply(); // we want to allocate the unaccrued spread fees as well

        let validator_target_amounts  = validator_weights.map!(|weight| {
            ((total_sui_supply as u128) * (weight as u128) / (self.total_weight as u128)) as u64
        });

        let validator_current_amounts = validator_addresses.map_ref!(|validator_address| {
            let mut validator_index = self.find_validator_index_by_address(*validator_address);
            if (validator_index.is_none()) {
                return 0
            };

            let validator = self.validators().borrow(validator_index.extract());
            validator.total_sui_amount()
        });

        // 3. decrease the stake for validators that have more stake than the target amount
        validator_addresses.length().do!(|i| {
            if (validator_current_amounts[i] > validator_target_amounts[i]) {
                // the sui will be unstaked, if target amount is 0, 
                // the validator will be removed upon the next refresh
                self.decrease_validator_stake(
                    system_state,
                    validator_addresses[i],
                    validator_current_amounts[i] - validator_target_amounts[i],
                    ctx
                );
            };
        });

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

        // 5. update the validator weights
        validator_addresses.length().do!(|i| {
            let validator_address = validator_addresses[i];
            let mut validator_index = self.find_validator_index_by_address(validator_address);
            if (validator_index.is_some()) {
                self.validator_infos[validator_index.extract()].assigned_weight = validator_weights[i];
            };
        });

        // sanity check
        assert!(self.total_sui_supply() + ACCEPTABLE_MIST_ERROR >= previous_total_sui_supply, ETotalSuiSupplyChanged);
    }
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
