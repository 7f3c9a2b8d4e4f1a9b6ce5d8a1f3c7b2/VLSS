### Title
Inefficient Capital Allocation Due to Lack of Inactive Stake Prioritization in Withdrawal Flow

### Summary
Volo's liquid staking system distributes unstaking proportionally by validator weight without prioritizing validators that hold `inactive_stake` (non-yielding StakedSui objects pending activation). This results in unnecessarily unstaking from yield-generating `active_stake` while leaving non-yielding `inactive_stake` in place, reducing overall APY for remaining stakers and causing economic inefficiency.

### Finding Description

The external report describes a vulnerability where a protocol distributes unstaking proportionally across pools without prioritizing inactive (non-yielding) pools first. Volo's `ValidatorPool::split_n_sui` function exhibits the same vulnerability class.

**Root Cause in Volo:**

In the liquid staking system, each validator can hold two types of stakes:
1. `active_stake` (FungibleStakedSui): Already activated and earning rewards
2. `inactive_stake` (StakedSui): Pending activation (becomes active at `stake_activation_epoch`), NOT earning rewards until activated [1](#0-0) 

When users withdraw, the `split_n_sui` function distributes unstaking across validators proportionally by their `assigned_weight`: [2](#0-1) 

This weight-based distribution does NOT consider whether validators have `inactive_stake`. While `unstake_approx_n_sui_from_validator` prioritizes inactive over active stake **within** each validator: [3](#0-2) 

There is no cross-validator prioritization. The protocol lacks any tracking of total inactive stake amounts to enable such prioritization (grep search confirmed no `inactive_pools_amount` or similar fields exist).

**Exploit Path:**

1. User calls `StakePool::unstake()` which triggers `ValidatorPool::split_n_sui()` [4](#0-3) 

2. `split_n_sui` calculates unstaking per validator proportionally by weight [5](#0-4) 

3. For each validator, it unstakes the calculated amount, prioritizing inactive within that validator but not globally

4. Result: Active stakes are unstaked from some validators even though other validators have unused inactive stakes

**Why Current Protections Fail:**

- The `refresh()` function only handles validators removed from the active validator set (not in `active_validator_addresses`), not validators with inactive stakes [6](#0-5) 

- No mechanism exists to count or prioritize validators based on inactive stake amounts
- The weight-based distribution treats all validators equally regardless of their inactive/active stake composition

### Impact Explanation

**Economic Impact:**
- **Reduced APY for remaining stakers**: When 100 SUI of active stake is unstaked while 100 SUI of inactive stake remains, the protocol loses that epoch's rewards on the unnecessarily unstaked amount (typically 3-5% APY annually, or ~0.008-0.014% per epoch)
- **Compounding inefficiency**: This happens on every withdrawal during epochs when validators have inactive stakes (entire epoch N+1 after staking in epoch N)
- **Scale**: For a protocol with 1M SUI TVL and 10% daily withdrawal rate, suboptimal unstaking could affect 100K SUI daily

**Operational Impact:**
- Increased gas costs: Accessing more validators than necessary for unstaking operations
- Slower epoch-over-epoch capital efficiency

This qualifies as **valuation/fee misdirection** (economic loss to stakers) and **accounting/fee corruption** (incorrect allocation of yield-generating vs non-yielding capital).

### Likelihood Explanation

**Likelihood: HIGH**

The vulnerability triggers under normal protocol operation:

1. **Common precondition**: Validators have inactive stakes whenever staking occurs in epoch N (stakes become active in epoch N+1). This is the standard Sui staking mechanism.

2. **Automatic trigger**: Any user withdrawal via `StakePool::unstake()` during epochs when validators have inactive stakes will exhibit this inefficiency.

3. **No special permissions needed**: Any user can call the public `unstake()` function.

4. **Realistic frequency**: 
   - Fresh stakes create inactive stakes that persist for one full epoch
   - Active protocols receive continuous deposits, meaning inactive stakes are nearly always present
   - Withdrawals happen continuously in production environments

5. **Not blocked by existing checks**: All existing validations (minimum amounts, fee calculations, exchange rate checks) do not prevent this inefficiency.

The scenario is not theoretical - it represents the standard operational flow of the liquid staking protocol.

### Recommendation

Implement inactive stake prioritization similar to the external report's fix. Modify `split_n_sui` to:

1. **Add tracking field** to `ValidatorPool`:
   ```move
   total_inactive_stake_amount: u64
   ```
   Updated during `join_stake`, `refresh_validator_info`, and validator removal.

2. **Modify `split_n_sui` logic**:
   ```move
   // Before weight-based distribution
   if (self.total_inactive_stake_amount > 0 && to_unstake > 0) {
       // First, drain all inactive stakes across validators
       let mut i = 0;
       while (i < self.validator_infos.length() && to_unstake > 0) {
           if (self.validator_infos[i].inactive_stake.is_some()) {
               let unstaked = self.unstake_approx_n_sui_from_inactive_stake(
                   system_state, i, to_unstake, ctx
               );
               to_unstake = to_unstake - unstaked;
               // Join to sui_pool happens inside unstake function
           };
           i = i + 1;
       };
   };
   // Then proceed with weight-based distribution for remaining amount
   ```

3. **Update `refresh_validator_info`** to maintain `total_inactive_stake_amount` accuracy.

This ensures non-yielding inactive stakes are fully utilized before touching yield-generating active stakes.

### Proof of Concept

**Setup:**
1. Protocol has two validators in `ValidatorPool`:
   - Validator A: `assigned_weight = 100`, holds 80 SUI in `inactive_stake` (pending activation), 20 SUI in `active_stake`
   - Validator B: `assigned_weight = 100`, holds 0 SUI in `inactive_stake`, 100 SUI in `active_stake`
2. `total_weight = 200`, `sui_pool = 0`

**Execution:**
1. User calls `StakePool::unstake()` requesting 60 SUI withdrawal
2. `split_n_sui(60)` is invoked
3. Current logic calculates:
   - `to_unstake_A = 1 + (100 * 60 / 200) = 31 SUI`
   - `to_unstake_B = 1 + (100 * 60 / 200) = 31 SUI`
4. Validator A: unstakes 31 from inactive_stake (has 80, takes 31)
5. Validator B: unstakes 31 from active_stake (has 100, takes 31)
6. Total unstaked: 62 SUI (satisfies withdrawal)

**Inefficiency:**
- 31 SUI of active stake (yielding) was unstaked from Validator B
- 49 SUI of inactive stake (non-yielding) remains in Validator A
- **Optimal behavior**: Unstake 60 SUI entirely from Validator A's 80 SUI inactive stake, leave all active stakes intact
- **Economic loss**: The 31 SUI unnecessarily unstaked from active stake loses one epoch of rewards (~0.01% or ~0.003 SUI)

**Impact scales linearly** with withdrawal volume and number of validators holding inactive stakes.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L56-66)
```text
    public struct ValidatorInfo has store {
        staking_pool_id: ID,
        validator_address: address,
        active_stake: Option<FungibleStakedSui>,
        inactive_stake: Option<StakedSui>,
        exchange_rate: PoolTokenExchangeRate,
        total_sui_amount: u64,
        assigned_weight: u64,
        last_refresh_epoch: u64,
        extra_fields: Bag
    }
```

**File:** liquid_staking/sources/validator_pool.move (L199-207)
```text
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

**File:** liquid_staking/sources/validator_pool.move (L608-611)
```text
        let mut amount = self.unstake_approx_n_sui_from_inactive_stake(system_state, validator_index, unstake_sui_amount, ctx);
        if (unstake_sui_amount > amount) {
            amount = amount + self.unstake_approx_n_sui_from_active_stake(system_state, validator_index, unstake_sui_amount - amount + ACTIVE_STAKE_REDEEM_OFFSET, ctx);
        };
```

**File:** liquid_staking/sources/validator_pool.move (L711-724)
```text
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

**File:** liquid_staking/sources/stake_pool.move (L289-297)
```text
        self.refresh(metadata, system_state, ctx);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```
