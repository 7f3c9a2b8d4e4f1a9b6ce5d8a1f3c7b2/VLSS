### Title
Division by Zero in Validator Weight Normalization Causes Unstake DoS

### Summary
The `split_n_sui` function in `validator_pool.move` performs division by `total_weight` without checking if it's zero, unlike other weight-based functions. When all validators become inactive, `total_weight` is set to zero while validators may still remain in the list with pending stakes, causing any unstake attempt to abort with division by zero, effectively locking user funds.

### Finding Description

**Root Cause**: The `split_n_sui` function calculates proportional unstaking amounts using division by `total_weight` without a zero-check guard. [1](#0-0) 

The division occurs at line 716 where `to_unstake_i = 1 + (... / total_weight)`. Unlike the guarded divisions in `stake_pending_sui` (line 260) and `rebalance` (line 403), this function has no protection. [2](#0-1) [3](#0-2) 

**How `total_weight` Becomes Zero**: During epoch refresh, when validators become inactive (not in Sui's active validator set), their weights are zeroed: [4](#0-3) 

Validators remain in the list if they still have pending stakes (not empty): [5](#0-4) [6](#0-5) 

**Execution Path**: When users call the public `unstake` function, it triggers `split_n_sui`: [7](#0-6) 

If the `sui_pool` has insufficient liquidity to cover the withdrawal (common after mass validator inactivity), the loop at line 711 executes and hits the unguarded division.

### Impact Explanation

**Direct Harm**: Users cannot unstake their LST tokens to retrieve their SUI. The transaction aborts on division by zero, preventing any withdrawal when `sui_pool` lacks sufficient liquidity. This effectively locks all user funds that require unstaking from validators.

**Affected Parties**: All LST holders attempting to unstake. Additionally, the admin cannot collect fees via `collect_fees` which also calls `split_n_sui`. [8](#0-7) 

**Severity Justification**: CRITICAL - While this is technically a DoS vulnerability, it results in complete fund lockup for all users. Users cannot access their staked SUI until either:
1. Validators become active again (may never happen)
2. Pending stakes fully clear and validators are removed
3. Manual intervention restores weights

The DoS persists indefinitely under adverse network conditions, making it equivalent to permanent fund loss.

### Likelihood Explanation

**Preconditions**: All validators in the pool must become inactive simultaneously. While unlikely under normal operation, this can occur during:
- Sui network disruptions or forks
- Coordinated validator shutdown events
- Mass validator slashing or ejection

**Attacker Capabilities**: No attacker needed - this is triggered by any user attempting legitimate unstake operations during the vulnerable state. Users have no way to detect or avoid the issue.

**Execution Complexity**: Trivial - simply call `unstake()` with any amount when the pool is in the vulnerable state.

**Detection**: Users will immediately encounter transaction failures when attempting to withdraw, but cannot distinguish this from other errors without examining on-chain state.

**Probability**: Medium-Low likelihood for complete validator inactivity, but CRITICAL impact warrants high severity classification.

### Recommendation

Add a guard check at the beginning of `split_n_sui` function, similar to other weight-based functions:

```move
public(package) fun split_n_sui(
    self: &mut ValidatorPool,
    system_state: &mut SuiSystemState,
    max_sui_amount_out: u64,
    ctx: &mut TxContext
): Balance<SUI> {
    // Add this check
    if (self.total_weight == 0) {
        // Handle zero weight case - either return available sui_pool or abort with clear error
        return self.split_up_to_n_sui_from_sui_pool(max_sui_amount_out)
    };
    
    // ... existing code
```

Alternatively, modify the weight calculation loop to skip when `total_weight == 0`:

```move
let total_weight = self.total_weight as u128;
if (total_weight > 0) {
    while (i > 0 && self.sui_pool.value() < max_sui_amount_out) {
        // ... existing unstaking logic
    };
}
```

**Test Cases**:
1. Set all validator weights to zero via validator inactivity
2. Ensure validators remain in list with pending stakes
3. Attempt unstake operation
4. Verify graceful handling instead of abort

### Proof of Concept

**Initial State**:
- Pool has 2 active validators with assigned weights (100 each)
- Users have staked 1000 SUI distributed across validators
- `total_weight = 200`
- `sui_pool` has minimal balance (< 100 SUI)

**Attack Sequence**:
1. Both validators become inactive (removed from Sui's active validator set)
2. Epoch rollover triggers `refresh()` which:
   - Initiates unstaking from inactive validators via `unstake_approx_n_sui_from_validator`
   - Sets each validator's weight to 0: `self.total_weight = 0`
   - Validators remain in list as they have pending inactive stakes (not empty)
3. User calls `unstake()` with 200 SUI worth of LST
4. `split_n_sui` is called with `max_sui_amount_out = 200`
5. Since `sui_pool.value() < 200`, the loop at line 711 executes
6. Line 716 attempts: `to_unstake_i = 1 + (weight * amount / 0)`
7. **Transaction aborts with arithmetic error (division by zero)**

**Expected Result**: User receives 200 SUI from unstaking

**Actual Result**: Transaction fails, user funds remain locked, cannot withdraw

**Success Condition**: Transaction completes and user receives SUI, OR fails with meaningful error allowing recovery

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

**File:** liquid_staking/sources/stake_pool.move (L280-297)
```text
    public fun unstake(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        lst: Coin<CERT>,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.manage.check_not_paused();
        self.refresh(metadata, system_state, ctx);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L360-369)
```text
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        _: &AdminCap,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);

        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
```
