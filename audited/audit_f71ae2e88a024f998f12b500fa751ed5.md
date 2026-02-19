### Title
Division by Zero in Unstake Operations When Validator Weights Sum to Zero

### Summary
The `set_validator_weights()` function allows an OperatorCap holder to set validator weights that sum to zero without validation. This creates an inconsistent state where `total_weight` becomes 0 but validators retain their previous non-zero `assigned_weight` values, causing division by zero panics during unstake operations and preventing users from withdrawing staked funds.

### Finding Description

**Location:** `liquid_staking/sources/validator_pool.move`

**Root Cause:**

In `set_validator_weights()`, the function validates that the total weight does not exceed `MAX_TOTAL_WEIGHT` but fails to check if the total weight is greater than zero: [1](#0-0) 

When `total_weight` equals 0, the subsequent `rebalance()` call exits early due to the guard condition: [2](#0-1) 

This early exit means that validators' `assigned_weight` values are **never updated** to reflect the new zero weights. The protocol enters an inconsistent state where:
- `self.total_weight = 0`
- Individual `validator_infos[i].assigned_weight` retain their previous non-zero values

**Why Protections Fail:**

The `verify_validator_weights()` function does not prevent zero-sum weights: [3](#0-2) 

The assertions pass when both sides equal zero: `weight_sum == self.total_weight` (0 == 0) and `match_num == non_zero_weights_count` (0 == 0).

**Exploitation Path:**

When users attempt to unstake after weights are set to zero, the `split_n_sui()` function encounters division by zero: [4](#0-3) 

At line 714-716, the calculation `(assigned_weight * to_unstake) / total_weight` causes a panic when `total_weight = 0` but `assigned_weight > 0`.

### Impact Explanation

**Severity: HIGH**

**Direct Fund Impact:**
- All staked SUI funds become permanently locked when users cannot withdraw
- Users who deposited before the weight manipulation lose access to their principal
- The LST token becomes worthless as it cannot be redeemed

**Operational Impact:**
- New deposits continue to accumulate in the `sui_pool` without being staked
- No staking rewards are earned on new deposits since `stake_pending_sui()` exits early when `total_weight == 0`: [5](#0-4) 

- The LST exchange rate calculation becomes incorrect as it includes unstaked SUI in `total_sui_supply`

**Who Is Affected:**
- All LST holders with staked positions at the time of weight manipulation
- New depositors who receive non-yield-bearing LST tokens
- Protocol reputation and total value locked (TVL)

### Likelihood Explanation

**Attacker Capabilities:**
- Requires OperatorCap, which is a trusted but operational role (not AdminCap)
- Multiple OperatorCaps are minted during initialization: [6](#0-5) 

**Attack Complexity:**
- Single transaction call to `set_validator_weights()` with all weights set to 0
- No special preconditions or timing requirements needed
- Immediate effect once transaction executes

**Feasibility Conditions:**
- OperatorCap compromise through key leak, malicious operator, or social engineering
- Could be accidental misconfiguration (operator sets weights to 0 thinking it pauses staking)

**Detection/Operational Constraints:**
- Attack is irreversible once executed
- No on-chain mechanism to detect or prevent the inconsistent state
- Subsequent unstake operations fail immediately, alerting users but after damage is done

**Probability:** Medium-High given operational nature of OperatorCap and potential for misconfiguration.

### Recommendation

**Immediate Fix:**

Add a validation check in `set_validator_weights()` to ensure total weight is greater than zero:

```move
assert!(total_weight > 0, EInvalidValidatorWeightSum);
```

Insert this check after line 349, before setting `self.total_weight = total_weight`.

**Additional Safeguards:**

1. Add a minimum weight threshold constant (e.g., `MIN_TOTAL_WEIGHT = 100`) to prevent near-zero weights that could cause similar issues

2. Update `verify_validator_weights()` to explicitly check for non-zero total:
   ```move
   assert!(weight_sum > 0, EInvalidValidatorWeightSum);
   ```

3. Add a sanity check in `split_n_sui()` before the division operation to fail gracefully:
   ```move
   assert!(total_weight > 0, EInvalidValidatorWeightSum);
   ```

**Test Cases:**

1. Attempt to set all validator weights to 0 - should revert
2. Set weights to 0, then attempt unstake - should handle gracefully
3. Verify that `total_weight == sum(all assigned_weight)` invariant holds after weight updates

### Proof of Concept

**Initial State:**
- ValidatorPool has 2 validators with weights [100, 100]
- Total staked: 200 SUI across both validators
- `self.total_weight = 200`
- `validator_infos[0].assigned_weight = 100`
- `validator_infos[1].assigned_weight = 100`

**Attack Steps:**

1. **OperatorCap calls `set_validator_weights()`:**
   ```move
   let mut weights = vec_map::empty();
   weights.insert(validator1_address, 0);
   weights.insert(validator2_address, 0);
   stake_pool.set_validator_weights(weights, ...);
   ```

2. **State After Attack:**
   - `self.total_weight = 0` (set at line 351)
   - `rebalance()` returns early (line 403-405)
   - `validator_infos[0].assigned_weight = 100` (unchanged!)
   - `validator_infos[1].assigned_weight = 100` (unchanged!)
   - **Inconsistent state created**

3. **User Attempts Unstake:**
   ```move
   stake_pool.unstake_entry(lst_coin, ...);
   ```
   - Calls `validator_pool.split_n_sui()`
   - Line 708: `total_weight = 0`
   - Line 711: Loop enters if `sui_pool.value() < withdrawal_amount`
   - Line 714-716: **PANIC - Division by zero**
   - Transaction aborts, withdrawal fails

**Expected Result:** Withdrawal succeeds and user receives SUI

**Actual Result:** Transaction panics with division by zero error, funds remain locked

**Success Condition:** Any unstake operation after setting zero weights will consistently fail, demonstrating the vulnerability is exploitable and blocks all withdrawals.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L259-262)
```text
        let mut i = self.validator_infos.length();
        if(self.total_weight == 0) {
            return false
        };
```

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

**File:** liquid_staking/sources/stake_pool.move (L143-146)
```text
        // mint 2 operator caps and 1 admin cap
        transfer::public_transfer(OperatorCap { id: object::new(ctx) }, ctx.sender());
        transfer::public_transfer(OperatorCap { id: object::new(ctx) }, ctx.sender());
        transfer::public_transfer(admin_cap, ctx.sender());
```
