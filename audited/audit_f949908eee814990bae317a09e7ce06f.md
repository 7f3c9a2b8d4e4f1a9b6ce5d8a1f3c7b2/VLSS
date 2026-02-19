### Title
Weight-Stake Mismatch Due to Silent Failure of Stake Increase Operations in rebalance()

### Summary
In `validator_pool.rebalance()`, validator weights are updated after stake increase/decrease operations complete. When `increase_validator_stake` silently fails (e.g., due to MIN_STAKE_THRESHOLD not being met), validators end up with `assigned_weight` values that don't reflect their actual stake proportions. This breaks a critical protocol invariant and leads to incorrect distribution of new stakes and rewards.

### Finding Description

The vulnerability exists in the `rebalance()` function's execution flow: [1](#0-0) 

At these lines, `increase_validator_stake` is called to add stake to validators. However, the return value (actual staked amount) is completely ignored. [2](#0-1) 

The `increase_validator_stake` function has a critical early return: if the amount to be staked is less than MIN_STAKE_THRESHOLD (1 billion MIST = 1 SUI), it returns 0 without staking anything. [3](#0-2) [4](#0-3) 

The `split_up_to_n_sui_from_sui_pool` function uses `min()` to take at most what's available in sui_pool. If sui_pool has insufficient balance, it returns less than requested, which may fall below MIN_STAKE_THRESHOLD.

After the increase operations (which may have silently failed), weights are unconditionally updated: [5](#0-4) 

The verification function only checks that weights match the requested values, NOT that they match actual stake proportions: [6](#0-5) 

This check at line 375 only verifies that `assigned_weight` equals the requested weight from input, but doesn't validate against actual stake amounts.

### Impact Explanation

**Direct Impact:**
1. **Incorrect Stake Distribution**: When `stake_pending_sui()` is called during epoch refresh, new stakes are distributed based on `assigned_weight` rather than actual stake proportions. [7](#0-6) 

A validator with inflated weight (e.g., 100% weight but only 60% actual stake) receives 100% of new pending stakes, creating unfair allocation.

2. **Compounding Problem**: Each subsequent call to `stake_pending_sui` perpetuates and worsens the mismatch, as validators with incorrect weights continue receiving disproportionate allocations.

3. **Broken Invariant**: The fundamental assumption that `assigned_weight` reflects actual stake proportion is violated, affecting all weight-based calculations throughout the protocol.

**Affected Parties:**
- Protocol users whose stakes are incorrectly allocated
- Validators who should receive more stake but don't due to deflated weights
- Overall protocol fairness and decentralization goals

**Quantified Impact**: In a concrete scenario with 1.5 SUI total supply where a validator has 0.9 SUI (60% actual stake) but is assigned 100% weight, the mismatch is 40 percentage points. This validator would receive 100% of new stakes instead of the fair 60%.

### Likelihood Explanation

**Entry Point**: The vulnerability is triggered via `stake_pool::set_validator_weights`, which requires OperatorCap: [8](#0-7) 

**Feasibility**: While this requires operator privileges, the conditions for triggering are realistic operational scenarios:

1. Normal rebalancing operations by operators
2. Validators with existing stake below optimal levels  
3. Insufficient sui_pool liquidity (common during high staking demand)
4. Target stake increases that fall below MIN_STAKE_THRESHOLD after sui_pool withdrawal

**Complexity**: LOW - The operator simply calls `set_validator_weights` with valid target weights. The failure is unintentional and silent.

**Detection**: The issue is not easily detectable as `verify_validator_weights` passes all checks. The weight-stake mismatch only becomes apparent through detailed analysis of actual stake amounts vs weights.

**Probability**: MEDIUM-HIGH - This can occur during normal operations when:
- Multiple validators compete for limited sui_pool balance
- Small validators are being bootstrapped
- Rebalancing attempts during periods of low liquidity

### Recommendation

**Immediate Fix:**

1. **Check increase_validator_stake return value** and only update weights if the stake increase succeeded:

```move
// In rebalance(), replace lines 459-471 with:
validator_addresses.length().do!(|i| {
    if (validator_current_amounts[i] < validator_target_amounts[i]) {
        let actually_staked = self.increase_validator_stake(
            system_state,
            validator_addresses[i],
            validator_target_amounts[i] - validator_current_amounts[i],
            ctx
        );
        // Only proceed with weight update if we successfully staked
        if (actually_staked < validator_target_amounts[i] - validator_current_amounts[i] - MIN_STAKE_THRESHOLD) {
            // Revert or handle insufficient staking
        }
    }
});
```

2. **Enhance verify_validator_weights** to check actual stake proportions match weights:

```move
fun verify_validator_weights(
    self: &ValidatorPool,
    validator_weights: VecMap<address, u64>,
) {
    // ... existing checks ...
    
    // NEW: Verify weights match actual stake proportions
    let total_staked = self.total_sui_supply - self.sui_pool.value();
    self.validator_infos.do_ref!(|validator| {
        let expected_stake = (total_staked as u128) * (validator.assigned_weight as u128) / (self.total_weight as u128);
        let actual_stake = validator.total_sui_amount;
        // Allow small tolerance for rounding
        assert!(
            actual_stake >= (expected_stake as u64) - ACCEPTABLE_MIST_ERROR * 1000,
            EWeightStakeMismatch
        );
    });
}
```

3. **Add revert mechanism** if critical stake increases fail to prevent state inconsistency.

### Proof of Concept

**Initial State:**
- Validator V1 exists with: `total_sui_amount = 900_000_000` MIST (0.9 SUI), `assigned_weight = 60`
- `total_sui_supply = 1_500_000_000` MIST (1.5 SUI)
- `sui_pool = 600_000_000` MIST (0.6 SUI)
- `total_weight = 60`

**Step 1**: Operator calls `stake_pool::set_validator_weights` with input `{V1: 100}`, setting `total_weight = 100`

**Step 2**: In `validator_pool::set_validator_weights`, `rebalance()` is called:
- Target amount for V1 = `(1_500_000_000 * 100) / 100 = 1_500_000_000`
- Current amount for V1 = `900_000_000`
- Delta to stake = `600_000_000` MIST

**Step 3**: In `increase_validator_stake`:
- Calls `split_up_to_n_sui_from_sui_pool(600_000_000)`
- Returns `600_000_000` MIST from sui_pool
- Check: `600_000_000 < MIN_STAKE_THRESHOLD (1_000_000_000)` → TRUE
- Returns funds to sui_pool and returns `0`
- **No stake added!**

**Step 4**: Weight update (lines 473-480):
- V1 exists, so `validator_infos[0].assigned_weight = 100`

**Step 5**: `verify_validator_weights` check passes:
- `weight_sum = 100` ✓
- V1's assigned_weight matches requested ✓
- All assertions pass ✓

**Final State (Vulnerability Confirmed):**
- V1: `total_sui_amount = 900_000_000` (unchanged), `assigned_weight = 100`
- V1 has **100% weight but only 60% of actual stake** (900M / 1500M)
- Mismatch: **40 percentage points**

**Subsequent Impact:** Next call to `stake_pending_sui()` will allocate 100% of new stakes to V1 despite it only having 60% of current stake, further exacerbating the imbalance.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L28-28)
```text
    const MIN_STAKE_THRESHOLD: u64 = 1_000_000_000;
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

**File:** liquid_staking/sources/validator_pool.move (L588-594)
```text
    public(package) fun split_up_to_n_sui_from_sui_pool(
        self: &mut ValidatorPool, 
        max_sui_amount_out: u64
    ): Balance<SUI> {
        let sui_amount_out = min(self.sui_pool.value(), max_sui_amount_out);
        self.split_from_sui_pool(sui_amount_out)
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
