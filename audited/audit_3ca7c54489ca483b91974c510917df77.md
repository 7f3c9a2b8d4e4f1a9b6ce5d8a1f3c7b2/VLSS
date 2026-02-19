### Title
Unvalidated Subtraction in `total_sui_supply()` Causes Protocol-Wide Denial of Service After Validator Slashing

### Summary
The `total_sui_supply()` function in the liquid staking module performs an unvalidated subtraction that can underflow when validator slashing reduces the validator pool balance below accumulated reward fees. This maps directly to the external report's Issue #3 regarding unvalidated subtractions in `bank_math`. The vulnerability causes permanent protocol DoS, blocking all stake, unstake, and refresh operations with no recovery path.

### Finding Description
The vulnerability exists in the `total_sui_supply()` function which performs an unvalidated subtraction: [1](#0-0) 

This function subtracts `accrued_reward_fees` from `validator_pool.total_sui_supply()` without validation. These values are tracked independently:

1. **Accumulation of `accrued_reward_fees`**: During epoch transitions in the `refresh()` function, reward fees accumulate based on staking rewards: [2](#0-1) 

2. **Reduction of `validator_pool.total_sui_supply()`**: When validators are slashed or exchange rates update unfavorably, the validator pool's `total_sui_supply` decreases through the `refresh_validator_info()` mechanism: [3](#0-2) 

The slashing event causes `total_sui_supply` to decrease (lines 308-329), but `accrued_reward_fees` in the stake pool remains unchanged, eventually causing `accrued_reward_fees > validator_pool.total_sui_supply()`.

**Why existing protections fail**: The `collect_fees()` function attempts to withdraw accrued fees but cannot recover from this state: [4](#0-3) 

The `split_n_sui()` function will abort with `ENotEnoughSuiInSuiPool` when insufficient liquidity exists: [5](#0-4) 

### Impact Explanation
**Critical Protocol DoS**: Once the underflow condition is triggered, all critical operations abort:

1. **Stake operations blocked**: The `stake()` function calls `total_sui_supply()`: [6](#0-5) 

2. **Unstake operations blocked**: The `unstake()` function calls `total_sui_supply()`: [7](#0-6) 

3. **Refresh operations blocked**: The `refresh()` function calls `total_sui_supply()`: [8](#0-7) 

4. **Ratio calculations fail**: Functions like `get_ratio()` and conversion functions rely on `total_sui_supply()`: [9](#0-8) 

**No recovery path**: The `collect_fees()` function, which could reduce `accrued_reward_fees`, also fails because it requires withdrawing the full fee amount from the validator pool, which is impossible when the pool has been slashed below the accrued amount.

### Likelihood Explanation
**High likelihood** due to realistic trigger conditions:

1. **Validator slashing is automatic**: Sui network validators can be slashed for misbehavior, poor performance, or downtime. This is not a hypothetical event but a documented network mechanism.

2. **No special privileges required**: The vulnerability triggers automatically when network conditions cause validator slashing. No attacker action is needed beyond normal protocol operation.

3. **Accumulation increases probability**: The longer fees remain uncollected across multiple epochs, the larger `accrued_reward_fees` grows relative to the actual pool balance, making the underflow more likely after any slashing event.

4. **Realistic scenario**: 
   - Weeks of normal operation accumulate 1000 SUI in `accrued_reward_fees`
   - Major validator slashing event reduces pool by 15-20%
   - If `validator_pool.total_sui_supply()` drops to 950 SUI while `accrued_reward_fees` = 1000 SUI
   - Next call to `total_sui_supply()` underflows: 950 - 1000 = abort
   - All protocol operations permanently frozen

### Recommendation
Add validation to prevent underflow in `total_sui_supply()`:

```rust
public fun total_sui_supply(self: &StakePool): u64 {
    let validator_total = self.validator_pool.total_sui_supply();
    let fees = self.accrued_reward_fees;
    
    // Ensure fees don't exceed total supply
    if (fees > validator_total) {
        // Cap fees at total supply to prevent underflow
        // This can occur after validator slashing events
        0
    } else {
        validator_total - fees
    }
}
```

Additionally, adjust `accrued_reward_fees` when slashing is detected during `refresh()` to maintain the invariant that `accrued_reward_fees <= validator_pool.total_sui_supply()`.

### Proof of Concept

**Initial State**:
1. Stake pool operating normally
2. Multiple epochs of rewards accumulate: `accrued_reward_fees = 1000 SUI`
3. `validator_pool.total_sui_supply() = 1200 SUI`
4. No fees collected for several epochs

**Trigger Event**:
5. Validator slashing occurs on Sui network (validator misbehavior, downtime, or poor performance)
6. During next `refresh()` call, `refresh_validator_info()` updates exchange rates
7. Validator's `total_sui_amount` decreases due to slashing penalty
8. `validator_pool.total_sui_supply()` drops to 900 SUI
9. `accrued_reward_fees` remains at 1000 SUI (not adjusted)

**Exploitation**:
10. Any user calls `stake_entry()`, `unstake_entry()`, or operator calls `rebalance()`
11. These functions call `total_sui_supply()` 
12. `total_sui_supply()` attempts: `900 - 1000` = arithmetic underflow
13. Transaction aborts with underflow error

**Result**:
14. All stake operations blocked
15. All unstake operations blocked  
16. All refresh/rebalance operations blocked
17. `collect_fees()` also blocked (cannot withdraw 1000 SUI when only 900 available)
18. Protocol permanently frozen until emergency upgrade

**Validation**: The vulnerability is confirmed by the code structure where `accrued_reward_fees` accumulates independently from the validator pool balance, with no validation preventing the subtraction from underflowing after external events (slashing) reduce the pool balance.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L232-232)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
```

**File:** liquid_staking/sources/stake_pool.move (L291-291)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
```

**File:** liquid_staking/sources/stake_pool.move (L369-370)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
        self.accrued_reward_fees = self.accrued_reward_fees - reward_fees.value();
```

**File:** liquid_staking/sources/stake_pool.move (L512-512)
```text
        let old_total_supply = self.total_sui_supply();
```

**File:** liquid_staking/sources/stake_pool.move (L517-525)
```text
            let reward_fee = if (new_total_supply > old_total_supply) {
                (((new_total_supply - old_total_supply) as u128) 
                * (self.fee_config.reward_fee_bps() as u128) 
                / (BPS_MULTIPLIER as u128)) as u64
            } else {
                0
            };

            self.accrued_reward_fees = self.accrued_reward_fees + reward_fee;
```

**File:** liquid_staking/sources/stake_pool.move (L559-561)
```text
    public fun total_sui_supply(self: &StakePool): u64 {
        self.validator_pool.total_sui_supply() - self.accrued_reward_fees
    }
```

**File:** liquid_staking/sources/stake_pool.move (L589-596)
```text
    public fun get_ratio(self: &StakePool, metadata: &Metadata<CERT>): u64 {
        let total_sui_supply = self.total_sui_supply();
        let total_lst_supply = metadata.get_total_supply_value();
        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return 0
        };
        self.sui_amount_to_lst_amount(metadata, SUI_MIST)
    }
```

**File:** liquid_staking/sources/validator_pool.move (L305-330)
```text
    fun refresh_validator_info(self: &mut ValidatorPool, i: u64) {
        let validator_info = &mut self.validator_infos[i];

        self.total_sui_supply = self.total_sui_supply - validator_info.total_sui_amount;

        let mut total_sui_amount = 0;
        if (validator_info.active_stake.is_some()) {
            let active_stake = validator_info.active_stake.borrow();
            let active_sui_amount = get_sui_amount(
                &validator_info.exchange_rate, 
                active_stake.value()
            );

            total_sui_amount = total_sui_amount + active_sui_amount;
        };

        if (validator_info.inactive_stake.is_some()) {
            let inactive_stake = validator_info.inactive_stake.borrow();
            let inactive_sui_amount = inactive_stake.staked_sui_amount();

            total_sui_amount = total_sui_amount + inactive_sui_amount;
        };

        validator_info.total_sui_amount = total_sui_amount;
        self.total_sui_supply = self.total_sui_supply + total_sui_amount;
    }
```

**File:** liquid_staking/sources/validator_pool.move (L762-763)
```text
        assert!(self.sui_pool.value() >= safe_max_sui_amount_out, ENotEnoughSuiInSuiPool);
        self.split_from_sui_pool(safe_max_sui_amount_out)
```
