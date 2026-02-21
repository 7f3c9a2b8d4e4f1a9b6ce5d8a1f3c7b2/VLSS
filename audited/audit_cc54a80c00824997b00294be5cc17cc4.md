# Audit Report

## Title
Division by Zero in Validator Weight Normalization Causes Unstake DoS

## Summary
The `split_n_sui` function performs division by `total_weight` without checking if it equals zero. When all validators become inactive simultaneously, their weights are zeroed while they may remain in the validator list with pending stakes. Any unstake operation requiring withdrawal from validators will trigger unguarded division by zero, causing transaction abortion and locking user funds.

## Finding Description

The vulnerability exists in the `split_n_sui` function which calculates proportional unstaking amounts across validators by dividing by `total_weight` without a zero-check guard. [1](#0-0) 

Other weight-based functions in the same contract include protective guards. The `stake_pending_sui` function has an early return when `total_weight` is zero [2](#0-1) , and the `rebalance` function similarly guards against this condition [3](#0-2) .

**How the Vulnerable State Occurs:**

During epoch refresh, when validators become inactive (not in Sui's active validator set), their weights are zeroed and subtracted from the pool's `total_weight`. [4](#0-3) 

Validators are only removed from the list if completely empty. The `is_empty()` check requires all stakes to be cleared AND weight to be zero. [5](#0-4)  Validators are checked for removal during refresh [6](#0-5) , but if any stake remains (active or inactive), they persist in the list.

If all validators become inactive but retain pending stakes, they remain in the validator list with zero weights, causing `total_weight` to be zero.

**Execution Path:**

When users call the public `unstake` function to redeem their LST tokens [7](#0-6) , it triggers `split_n_sui` to withdraw SUI from validators.

If the `sui_pool` has insufficient liquidity to cover the withdrawal, the loop at line 711 executes to unstake from validators. [8](#0-7)  This loop contains the unguarded division that will abort the transaction when `total_weight` is zero.

## Impact Explanation

**Direct Harm**: Users cannot unstake their LST tokens to retrieve their staked SUI. The transaction aborts with an arithmetic error (division by zero), preventing any withdrawal that requires unstaking from validators. This effectively locks all user funds until the vulnerable state is resolved.

**Affected Parties**: 
- All LST holders attempting to unstake their tokens
- Protocol administrators cannot collect fees, as `collect_fees` also calls `split_n_sui` [9](#0-8) 

**Severity Justification**: CRITICAL - While technically a DoS vulnerability, it results in complete fund lockup. Users cannot access their staked SUI until:
1. Validators become active again (may never happen in severe network events)
2. All pending stakes fully clear and validators are removed from the list
3. Manual protocol intervention restores weights or liquidity

The DoS persists indefinitely under adverse network conditions, making it functionally equivalent to permanent fund loss from the user's perspective.

## Likelihood Explanation

**Preconditions**: All validators in the pool must become inactive simultaneously while retaining some stake. While unlikely during normal operation, this can occur during:
- Sui network disruptions, hard forks, or consensus failures
- Mass validator slashing or ejection events
- Coordinated validator shutdown for maintenance or due to economic decisions

**Attacker Capabilities**: No attacker required. The vulnerability is triggered by any user attempting legitimate unstake operations during the vulnerable state. Users have no way to detect this condition before submitting their transaction.

**Execution Complexity**: Trivial - users simply call the standard `unstake()` function with any LST amount when the pool is in the vulnerable state.

**Probability**: Medium-Low likelihood for complete validator inactivity across all pool validators combined with stake retention. However, the CRITICAL impact (complete fund lockup) combined with the possibility during network stress events warrants high severity classification.

## Recommendation

Add a zero-check guard at the beginning of `split_n_sui`, similar to other weight-based functions:

```move
public(package) fun split_n_sui(
    self: &mut ValidatorPool,
    system_state: &mut SuiSystemState,
    max_sui_amount_out: u64,
    ctx: &mut TxContext
): Balance<SUI> {
    // Add guard check
    if (self.total_weight == 0) {
        // Handle edge case: return available sui_pool balance
        let safe_amount = min(self.sui_pool.value(), max_sui_amount_out);
        return self.split_from_sui_pool(safe_amount)
    };
    
    // ... rest of function
}
```

This ensures the function gracefully handles the edge case where all validators have zero weight, returning whatever liquidity is available in the sui_pool without attempting proportional unstaking.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize a stake pool with multiple validators
2. Simulate an epoch change where all validators become inactive
3. Ensure validators retain minimal stake (preventing removal)
4. Verify `total_weight` becomes 0 while validators remain in list
5. Drain sui_pool to force unstaking from validators
6. Call `unstake()` and observe transaction abortion due to division by zero

The test would confirm that the missing guard causes the DoS condition described above.

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

**File:** liquid_staking/sources/validator_pool.move (L260-262)
```text
        if(self.total_weight == 0) {
            return false
        };
```

**File:** liquid_staking/sources/validator_pool.move (L403-405)
```text
        if (self.total_weight == 0 || self.total_sui_supply() == 0) {
            return
        };
```

**File:** liquid_staking/sources/validator_pool.move (L708-724)
```text
            let total_weight = self.total_weight as u128;
            let mut i = self.validators().length();
            
            while (i > 0 && self.sui_pool.value() < max_sui_amount_out) {
                i = i - 1;

                let to_unstake_i = 1 + (self.validator_infos[i].assigned_weight as u128 
                                        * ((to_unstake)as u128)
                                        / total_weight);
                                
                self.unstake_approx_n_sui_from_validator(
                    system_state,
                    i,
                    to_unstake_i as u64,
                    ctx
                );
            };
```

**File:** liquid_staking/sources/stake_pool.move (L286-297)
```text
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

**File:** liquid_staking/sources/stake_pool.move (L369-369)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
```
