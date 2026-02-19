### Title
Last Staker Advantage: Epoch Boundary Reward Dilution via Inactive Stake Ratio Manipulation

### Summary
Users who stake immediately before an epoch boundary receive LST tokens based on a ratio that includes their pending/inactive SUI in `total_sui_supply`, but this SUI does not earn rewards for that epoch. When the epoch changes and rewards are distributed to active stakes only, the new staker's LST value increases proportionally with all other holders, allowing them to capture rewards they never earned. This can be exploited for risk-free profit by timing stakes at epoch boundaries and immediately unstaking after rewards distribution.

### Finding Description

The vulnerability exists in the interaction between the staking flow and the reward distribution mechanism: [1](#0-0) 

When a user calls `stake()`, the function first calls `refresh()`, then calculates the LST mint amount using `sui_amount_to_lst_amount()`. This calculation uses the current `total_sui_supply` before the user's SUI is added: [2](#0-1) 

After minting LST, the user's SUI is added to the pool: [3](#0-2) 

This calls `join_to_sui_pool()` which immediately increases `total_sui_supply`: [4](#0-3) 

The SUI is then staked with validators, but becomes "inactive" stake with `stake_activation_epoch = current_epoch + 1`: [5](#0-4) [6](#0-5) 

Critically, when calculating `total_sui_supply` during epoch refresh, **both active and inactive stakes are counted**: [7](#0-6) 

However, only active stakes earn rewards. When the epoch changes and `refresh()` updates exchange rates with rewards, the inactive stake receives no rewards but is still included in the total supply calculation. This causes the ratio `total_sui_supply / total_lst_supply` to improve for ALL LST holders, including the late staker whose SUI contributed nothing to those rewards.

The unstake function has no lockup period preventing immediate withdrawal: [8](#0-7) 

### Impact Explanation

**Direct Fund Impact**: This vulnerability enables systematic theft of staking rewards from existing LST holders.

**Quantified Example**:
- Initial state: 10,000 SUI active stake, 10,000 LST outstanding
- Attacker stakes 1,000 SUI at end of Epoch 100
- Attacker receives 1,000 LST at 1:1 ratio
- Attacker's SUI becomes inactive (earns 0 rewards for Epoch 100)
- Epoch changes: 10,000 active SUI earns 2.74 SUI in rewards (0.1% daily)
- After refresh: total_sui_supply = 11,002.74, total_lst_supply = 11,000
- Attacker's 1,000 LST now worth: 1,000 × 11,002.74 / 11,000 = 1,000.249 SUI
- **Attacker profit: 0.249 SUI (9.1% of total epoch rewards)**
- **Original stakers' loss: 0.249 SUI (their rewards diluted)**

**Scaling**: With 100,000 SUI stake and daily epochs:
- Daily profit: ~24.9 SUI
- Annual profit: ~9,088 SUI (~90.9% return with near-zero risk/time exposure)
- This compounds as it can be repeated every epoch

**Affected parties**: All existing LST holders suffer proportional reward dilution with each late staker attack.

### Likelihood Explanation

**Reachable Entry Point**: The `stake_entry()` and `unstake_entry()` functions are public entry points accessible to any user.

**Feasible Preconditions**: 
- Attacker only needs to time their stake transaction to execute near the end of an epoch
- Sui epoch boundaries are predictable (occur at fixed times)
- No special permissions or capabilities required
- No minimum holding period enforced

**Execution Practicality**:
1. Monitor epoch timing (publicly available)
2. Submit stake transaction ~1 second before epoch boundary
3. Wait for epoch to change (automatic, occurs on-chain)
4. Call unstake immediately after epoch change
5. Extract profit

**Economic Rationality**:
- Attack cost: Only gas fees for stake/unstake transactions
- Profit: Proportional to stake size and epoch rewards (~9% of rewards captured)
- Risk: Near-zero (holding period < 1 epoch, can unstake immediately)
- Repeatability: Every epoch (multiple times daily on Sui)
- Detection difficulty: Appears as normal staking activity

**Attack Complexity**: Low - requires only two transactions with precise timing. Can be automated with bots monitoring epoch boundaries.

### Recommendation

**Immediate Mitigation**: Implement one of the following approaches:

1. **Exclude inactive stake from ratio calculations**: When calculating `total_sui_supply` for ratio purposes, only count active stakes that are earning rewards:

```move
// In validator_pool.move refresh_validator_info()
// Only add active_sui_amount to total_sui_supply, not inactive
if (validator_info.active_stake.is_some()) {
    let active_sui_amount = get_sui_amount(&validator_info.exchange_rate, active_stake.value());
    total_sui_amount = total_sui_amount + active_sui_amount;
};
// Do NOT add inactive_stake to total_sui_amount for ratio calculations
```

2. **Implement minimum lockup period**: Add a lockup period (e.g., 1 epoch) before LST can be unstaked. Store stake timestamp with each mint and enforce in unstake:

```move
// Add to StakePool or use dynamic fields
public struct UserStake has store {
    amount: u64,
    stake_epoch: u64
}

// In unstake(), check:
assert!(ctx.epoch() > user_stake.stake_epoch, ELockupNotExpired);
```

3. **Time-weighted reward distribution**: Track when each stake becomes active and distribute rewards proportionally based on time actively staked.

**Invariant Check**: Add assertion in `refresh()` to verify that reward distribution doesn't dilute existing stakers:
```move
// Before rewards distribution, record old ratio
// After rewards distribution, verify new stakers didn't capture disproportionate rewards
```

**Test Cases**: Add regression tests for:
- Staking at epoch boundaries
- Verifying inactive stake doesn't capture active stake rewards  
- Ensuring ratio calculations properly exclude non-earning stakes

### Proof of Concept

**Initial State** (Epoch 100):
```
total_sui_supply = 10,000 SUI (all active)
total_lst_supply = 10,000 LST
ratio = 1:1
```

**Step 1** - Attacker stakes 1,000 SUI at end of Epoch 100:
```
Transaction: stake_entry(1,000 SUI)
Result: 
- Attacker receives 1,000 LST
- total_sui_supply = 11,000 (10,000 active + 1,000 inactive)
- total_lst_supply = 11,000 LST
```

**Step 2** - Epoch changes from 100 to 101:
```
System rewards distribution:
- 10,000 active SUI earns 2.74 SUI (0.0274% for 1 epoch)
- 1,000 inactive SUI earns 0 SUI (not active during Epoch 100)
```

**Step 3** - First transaction in Epoch 101 triggers refresh():
```
refresh() executes:
- Updates exchange rates
- total_sui_supply recalculated = 10,002.74 + 1,000 = 11,002.74 SUI
- total_lst_supply unchanged = 11,000 LST
- New ratio = 11,002.74 / 11,000 ≈ 1.00025
```

**Step 4** - Attacker unstakes immediately:
```
Transaction: unstake_entry(1,000 LST)
Result:
- Attacker receives: 1,000 × 11,002.74 / 11,000 = 1,000.249 SUI
- Profit: 1,000.249 - 1,000 = 0.249 SUI
```

**Expected vs Actual**:
- Expected: Attacker should receive ≤ 1,000 SUI (no rewards earned)
- Actual: Attacker receives 1,000.249 SUI (captured 9.1% of epoch rewards)
- Success condition: `attacker_sui_out > attacker_sui_in` with holding period < 1 epoch

**Repeatability**: Attack can be executed every epoch with compounding returns, making it economically significant despite small per-epoch profit percentage.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L229-242)
```text
        self.refresh(metadata,system_state, ctx);
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);

        let old_sui_supply = (self.total_sui_supply() as u128);
        let old_lst_supply = (total_lst_supply(metadata) as u128);

        let mut sui_balance = sui.into_balance();
        let sui_amount_in = sui_balance.value();

        // deduct fees
        let mint_fee_amount = self.fee_config.calculate_stake_fee(sui_balance.value());
        self.fees.join(sui_balance.split(mint_fee_amount));
        
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
```

**File:** liquid_staking/sources/stake_pool.move (L263-263)
```text
        self.join_to_sui_pool(sui_balance);
```

**File:** liquid_staking/sources/stake_pool.move (L280-333)
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

        // deduct fee
        let redeem_fee_amount = self.fee_config.calculate_unstake_fee(sui.value());
        let redistribution_amount = 
            if(total_lst_supply(metadata) == lst.value()) {
                0
            } else {
                self.fee_config.calculate_unstake_fee_redistribution(redeem_fee_amount)
            };

        let mut fee = sui.split(redeem_fee_amount as u64);
        let redistribution_fee = fee.split(redistribution_amount);

        self.fees.join(fee);
        self.join_to_sui_pool(redistribution_fee);

        emit(UnstakeEventExt {
            lst_amount_in: lst.value(),
            sui_amount_out: sui.value(),
            fee_amount: redeem_fee_amount - redistribution_amount,
            redistribution_amount: redistribution_amount
        });

        emit_unstaked(ctx.sender(), lst.value(), sui.value());

        // invariant: sui_out / lst_in <= old_sui_supply / old_lst_supply
        // -> sui_out * old_lst_supply <= lst_in * old_sui_supply
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );

        metadata.burn_coin(lst);

        coin::from_balance(sui, ctx)
    }
```

**File:** liquid_staking/sources/stake_pool.move (L628-645)
```text
    public fun sui_amount_to_lst_amount(
        self: &StakePool, 
        metadata: &Metadata<CERT>,
        sui_amount: u64
    ): u64 {
        let total_sui_supply = self.total_sui_supply();
        let total_lst_supply = metadata.get_total_supply_value();

        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return sui_amount
        };

        let lst_amount = (total_lst_supply as u128)
            * (sui_amount as u128)
            / (total_sui_supply as u128);

        lst_amount as u64
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

**File:** liquid_staking/sources/validator_pool.move (L531-534)
```text
    public(package) fun join_to_sui_pool(self: &mut ValidatorPool, sui: Balance<SUI>) {
        self.total_sui_supply = self.total_sui_supply + sui.value();
        self.sui_pool.join(sui);
    }
```

**File:** liquid_staking/sources/validator_pool.move (L548-554)
```text
        if (stake.stake_activation_epoch() <= ctx.epoch()) {
            let fungible_staked_sui = system_state.convert_to_fungible_staked_sui(stake, ctx);
            self.join_fungible_staked_sui_to_validator(validator_index, fungible_staked_sui);
        } else {
            self.join_inactive_stake_to_validator(validator_index, stake);
        };
    }
```
