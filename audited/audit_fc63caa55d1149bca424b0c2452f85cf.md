### Title
Division by Zero in Validator Pool Unstaking When All Validators Become Inactive

### Summary
A division by zero vulnerability exists in the liquid staking module when `total_weight` becomes zero during validator inactivity. The `split_n_sui` function divides by `total_weight` without checking if it equals zero, causing all unstake operations to fail with an arithmetic error when all configured validators become inactive after an epoch change.

### Finding Description

**External Vulnerability Class Mapping**: Division by zero during unstaking operations where a denominator calculation can become zero under valid protocol conditions.

**Root Cause in Volo**: The `split_n_sui` function in `validator_pool.move` performs division by `total_weight` without validating it is non-zero. [1](#0-0) 

The `total_weight` field is initialized to zero when a new `ValidatorPool` is created: [2](#0-1) 

During epoch refresh, when validators are not in the active validator set, their weights are set to zero and subtracted from `total_weight`: [3](#0-2) 

**Exploit Path**:

1. User calls public entry function `unstake_entry`: [4](#0-3) 

2. This calls the `unstake` function which triggers `refresh`: [5](#0-4) 

3. During `refresh`, if all validators are not in the active validator address set, their weights are zeroed: [6](#0-5) 

4. After refresh, `unstake` calls `split_n_sui`: [7](#0-6) 

5. In `split_n_sui`, when `validators().length() > 0` but `total_weight == 0`, and the sui pool needs to be unstaked from validators, the division occurs without a zero check: [8](#0-7) 

**Why Protections Fail**: Unlike `stake_pending_sui` which has a zero check for `total_weight`: [9](#0-8) 

The `split_n_sui` function lacks this protection entirely.

### Impact Explanation

**Concrete Protocol Impact**:
- **Protocol-Level Denial of Service**: All user unstake operations fail with arithmetic errors
- **Fund Lock**: Users holding LST tokens cannot redeem them for SUI
- **Liquidity Crisis**: The protocol becomes completely non-functional for withdrawals
- **Cascading Effects**: Admin `collect_fees` function also calls `split_n_sui`, blocking fee collection: [10](#0-9) 

This is a **High Severity** issue as it breaks a critical invariant: users must always be able to redeem their LST tokens for the underlying SUI.

### Likelihood Explanation

**Realistic Trigger Conditions**:
1. All configured validators simultaneously removed from Sui's active validator set (due to poor performance, jailing, slashing, or network governance)
2. OR during initial deployment if `set_validator_weights` is not called before users stake
3. OR if operators set all validator weights to zero through misconfiguration

**Feasibility**: HIGH - Validator set changes are normal Sui network operations. Multiple validators becoming inactive simultaneously can occur during:
- Network upgrades or consensus issues
- Coordinated validator maintenance
- Validator performance degradation
- Protocol migration periods

The vulnerability window exists from the moment all validators become inactive until operators re-add active validators, during which all user withdrawals are blocked.

### Recommendation

Add a zero-check guard in `split_n_sui` before the division operation:

```move
let total_weight = self.total_weight as u128;
if (total_weight == 0) {
    // Return available sui_pool balance up to max_sui_amount_out
    // Skip validator unstaking logic
    let safe_amount = min(max_sui_amount_out, self.sui_pool.value());
    return self.sui_pool.split(safe_amount)
};
```

Alternatively, add an assertion at the start of `split_n_sui`:
```move
assert!(self.total_weight > 0, EInvalidValidatorWeightSum);
```

This ensures the function fails gracefully with a clear error rather than an arithmetic panic.

### Proof of Concept

**Reproducible Exploit Steps**:

1. **Initial Setup**: Deploy StakePool with 2 validators, weights [100, 100], total_weight = 200
2. **User Stakes**: Alice calls `stake_entry` with 1000 SUI, receives ~1000 LST tokens
3. **Validator Inactivity**: At epoch N+1, both validators removed from Sui active validator set
4. **Trigger Refresh**: Bob calls `stake_entry` with 1 SUI, triggering `refresh()`:
   - Lines 202-207 execute for each validator
   - `total_weight` decremented: 200 → 100 → 0
   - Both validators' `assigned_weight` set to 0
   - Validators remain in array but with zero weights
5. **Exploit**: Alice calls `unstake_entry` with her 1000 LST tokens:
   - Line 289: `refresh` called (no-op, already refreshed)
   - Line 297: `split_n_sui(system_state, sui_amount_out, ctx)` called
   - Line 708: `total_weight = 0`
   - Line 709: `i = 2` (two validators still in array)
   - Line 711: Condition `i > 0 && sui_pool.value() < max_sui_amount_out` evaluates TRUE
   - Line 714-716: **Division by zero** → Transaction aborts with arithmetic error
6. **Result**: Alice's LST tokens are locked. All subsequent unstake attempts fail until operators call `set_validator_weights` with active validators.

**State Preconditions**:
- `validators().length() > 0` (validators exist in array)
- `total_weight == 0` (all validator weights are zero)
- `sui_pool.value() < max_sui_amount_out` (need to unstake from validators)

These conditions naturally occur when all validators become inactive during epoch transitions, making this a realistic and high-impact vulnerability.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L68-78)
```text
    public(package) fun new(ctx: &mut TxContext): ValidatorPool {
        ValidatorPool {
            sui_pool: balance::zero(),
            validator_infos: vector::empty(),
            total_sui_supply: 0,
            last_refresh_epoch: ctx.epoch() - 1,
            total_weight: 0,
            manage: manage::new(),
            extra_fields: bag::new(ctx)
        }
    }
```

**File:** liquid_staking/sources/validator_pool.move (L192-207)
```text
        // get all active validator addresses
        let active_validator_addresses = system_state.active_validator_addresses();

        let mut i = self.validator_infos.length();
        while (i > 0) {
            i = i - 1;

            // withdraw all stake if validator is inactive.
            // notice that inacitve validator is not invalid stake
            // Time Complexity: O(n)
            if (!active_validator_addresses.contains(&self.validator_infos[i].validator_address)) {
                // unstake max amount of sui.
                self.unstake_approx_n_sui_from_validator(system_state, i, MAX_SUI_SUPPLY, ctx);
                self.total_weight = self.total_weight - self.validator_infos[i].assigned_weight;
                self.validator_infos[i].assigned_weight = 0;
            };
```

**File:** liquid_staking/sources/validator_pool.move (L260-263)
```text
        if(self.total_weight == 0) {
            return false
        };
        let sui_per_weight = self.sui_pool.value() / self.total_weight;
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

**File:** liquid_staking/sources/stake_pool.move (L287-289)
```text
        self.manage.check_version();
        self.manage.check_not_paused();
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L297-297)
```text
        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L369-370)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
        self.accrued_reward_fees = self.accrued_reward_fees - reward_fees.value();
```
