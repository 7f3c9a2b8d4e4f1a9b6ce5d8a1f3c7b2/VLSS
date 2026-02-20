# Audit Report

## Title
Division by Zero in Validator Weight Normalization Causes Unstake DoS

## Summary
The `split_n_sui` function performs division by `total_weight` without a zero-check guard. When all validators become inactive while retaining pending stakes, `total_weight` becomes zero but validators remain in the list. Any unstake attempt requiring withdrawal from validators triggers unguarded division, causing transaction abortion and effectively locking user funds.

## Finding Description

The vulnerability exists in the `split_n_sui` function which calculates proportional unstaking amounts by dividing by `total_weight` without checking if it's zero. [1](#0-0) 

Unlike other weight-based functions in the same contract, `split_n_sui` lacks a protective guard. The `stake_pending_sui` function includes an early return when `total_weight` is zero [2](#0-1) , and the `rebalance` function similarly guards against this condition [3](#0-2) .

**How the Vulnerable State Occurs:**

During epoch refresh, when validators become inactive (not in Sui's active validator set), their weights are zeroed and subtracted from the pool's `total_weight`. [4](#0-3) 

Critically, validators are only removed from the list if they are completely empty. [5](#0-4)  A validator is considered empty only when all stakes are cleared AND weight is zero. [6](#0-5) 

Therefore, if all validators become inactive but still have pending stakes (`inactive_stake` waiting for withdrawal), they remain in the validator list with zero weights, causing `total_weight` to be zero.

**Execution Path:**

When users call the public `unstake` function to redeem their LST tokens [7](#0-6) , it triggers `split_n_sui` to withdraw SUI from validators. [8](#0-7) 

If the `sui_pool` has insufficient liquidity to cover the withdrawal (common after mass validator inactivity causes liquidity drain), the loop executes to unstake from validators. [9](#0-8)  This loop contains the unguarded division that will abort the transaction when `total_weight` is zero.

## Impact Explanation

**Direct Harm**: Users cannot unstake their LST tokens to retrieve their staked SUI. The transaction aborts with an arithmetic error (division by zero), preventing any withdrawal that requires unstaking from validators. This effectively locks all user funds until the vulnerable state is resolved.

**Affected Parties**: 
- All LST holders attempting to unstake their tokens
- Protocol administrators cannot collect fees, as `collect_fees` also calls `split_n_sui` [10](#0-9) 

**Severity Justification**: CRITICAL - While technically a DoS vulnerability, it results in complete fund lockup. Users cannot access their staked SUI until one of the following occurs:
1. Validators become active again (may never happen in severe network events)
2. All pending stakes fully clear and validators are removed from the list
3. Manual protocol intervention (if possible) restores weights or liquidity

The DoS persists indefinitely under adverse network conditions, making it functionally equivalent to permanent fund loss from the user's perspective.

## Likelihood Explanation

**Preconditions**: All validators in the pool must become inactive simultaneously. While unlikely during normal operation, this can occur during:
- Sui network disruptions, hard forks, or consensus failures
- Mass validator slashing or ejection events
- Coordinated validator shutdown (maintenance, attacks, or economic decisions)

**Attacker Capabilities**: No attacker is required. The vulnerability is triggered by any user attempting legitimate unstake operations during the vulnerable state. Users have no way to detect this condition before submitting their transaction.

**Execution Complexity**: Trivial - users simply call the standard `unstake()` function with any LST amount when the pool is in the vulnerable state.

**Probability**: Medium-Low likelihood for complete validator inactivity across all pool validators. However, the CRITICAL impact (complete fund lockup) combined with the possibility during network stress events warrants high severity classification according to standard risk assessment frameworks.

## Recommendation

Add a zero-check guard to `split_n_sui` consistent with other weight-based functions:

```move
public(package) fun split_n_sui(
    self: &mut ValidatorPool,
    system_state: &mut SuiSystemState,
    max_sui_amount_out: u64,
    ctx: &mut TxContext
): Balance<SUI> {
    // Add early return guard
    if (self.total_weight == 0) {
        // Return available sui_pool balance only
        let safe_amount = min(self.sui_pool.value(), max_sui_amount_out);
        return self.split_from_sui_pool(safe_amount)
    };
    
    // Existing logic continues...
    {
        let to_unstake = if(max_sui_amount_out > self.sui_pool.value()) {
            max_sui_amount_out - self.sui_pool.value()
        } else {
            0
        };
        let total_weight = self.total_weight as u128;
        // ... rest of function
    }
}
```

This ensures that when all validators are inactive with zero total weight, the function returns only the available `sui_pool` balance without attempting to divide by zero.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a liquid staking pool with multiple validators
2. Staking SUI to create active stakes
3. Simulating all validators becoming inactive (network event)
4. Ensuring validators retain `inactive_stake` (pending withdrawal)
5. Attempting to unstake when `sui_pool` has insufficient liquidity

The transaction will abort at the division by zero when `total_weight == 0` and the unstake loop attempts to calculate proportional amounts.

**Notes**

This vulnerability demonstrates an inconsistency in defensive programming across the codebase. While `stake_pending_sui` and `rebalance` both guard against zero `total_weight`, `split_n_sui` does not. The missing guard becomes exploitable specifically when sui_pool liquidity is insufficient, forcing the function to unstake from validators. The combination of (1) all validators inactive with zero weights, (2) validators remaining in list due to pending stakes, and (3) insufficient sui_pool liquidity creates the perfect conditions for transaction abortion, effectively locking user funds.

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

**File:** liquid_staking/sources/stake_pool.move (L280-286)
```text
    public fun unstake(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        lst: Coin<CERT>,
        ctx: &mut TxContext
    ): Coin<SUI> {
```

**File:** liquid_staking/sources/stake_pool.move (L297-297)
```text
        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L369-369)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
```
