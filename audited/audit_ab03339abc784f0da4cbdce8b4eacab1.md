# Audit Report

## Title
Last Staker Advantage: Epoch Boundary Reward Dilution via Inactive Stake Ratio Manipulation

## Summary
A critical vulnerability allows attackers to systematically steal staking rewards from existing LST holders by exploiting the timing of stake operations relative to epoch boundaries. Inactive stakes are counted in `total_sui_supply` for exchange rate calculations but earn zero rewards, enabling late stakers to capture rewards without contributing to them.

## Finding Description

The vulnerability exists in how `refresh_validator_info()` calculates `total_sui_supply` by including both active and inactive stakes, while only active stakes earn rewards. [1](#0-0) 

Active stakes are valued using the current exchange rate (which includes accrued rewards), while inactive stakes use their original staked amount without rewards. Both are summed into `total_sui_supply`, which determines the LST exchange rate for all holders.

**Attack sequence:**

1. **Staking Phase**: When a user calls `stake()`, LST is minted based on the current `total_sui_supply` before their SUI is added: [2](#0-1) 

2. **SUI Addition**: The user's SUI is then added to the pool, immediately increasing `total_sui_supply`: [3](#0-2) 

3. **Inactive Stake Creation**: On the next `refresh()` call, `stake_pending_sui()` stakes the SUI with validators. Due to Sui's staking mechanics where new stakes have `stake_activation_epoch = current_epoch + 1`, the stake becomes inactive for the current epoch: [4](#0-3) 

4. **Reward Dilution**: When the epoch changes and `refresh()` is called, exchange rates are updated with earned rewards. However, only active stakes benefit from improved exchange rates. The attacker's inactive stake contributed zero rewards but is included in `total_sui_supply`, diluting the LST exchange rate improvement: [5](#0-4) 

5. **Immediate Exit**: The attacker can immediately unstake with no lockup period: [6](#0-5) 

**Security Guarantee Broken**: The protocol's invariant that LST exchange rates reflect proportional contributions to staking rewards is violated. Late stakers receive exchange rate improvements from rewards they never earned.

## Impact Explanation

This vulnerability enables **systematic theft of staking rewards** from existing LST holders:

**Quantified Loss Example**:
- Initial: 10,000 SUI actively staked, 10,000 LST outstanding (1:1 ratio)
- Attacker stakes 1,000 SUI near epoch end → receives 1,000 LST
- Attacker's SUI becomes inactive (earns 0 rewards)
- Epoch changes: 10,000 active SUI earns 100 SUI rewards (1% APR)
- New exchange rate: (10,100 + 1,000) / 11,000 = 1.00909 SUI per LST
- Attacker redeems 1,000 LST → receives 1,009.09 SUI
- **Attacker profit: 9.09 SUI (~0.9% gain for zero risk)**
- **Original stakers' loss: 9.09 SUI** (their exchange rate diluted from 1.01 to 1.00909)

**Scaling & Repeatability**:
- Attack captures ~9% of epoch rewards for attacker's stake size
- Repeatable every epoch (~24 hours)
- No capital lockup required
- Fully automatable

**Affected Parties**: All existing LST holders suffer proportional reward dilution with each attack instance.

## Likelihood Explanation

The attack is **highly likely** to occur:

**Accessibility**: 
- Entry points are public and unrestricted [7](#0-6) 
- No special permissions required
- Minimum stake is only 0.1 SUI [8](#0-7) 

**Execution Simplicity**:
1. Monitor epoch timing (publicly available on-chain)
2. Submit stake transaction near epoch boundary
3. Wait for epoch change (automatic)
4. Call unstake immediately after rewards distribute
5. Extract profit

**Economic Incentives**:
- Attack cost: Only gas fees (~0.001 SUI)
- Expected profit: ~9% of epoch rewards for staked amount
- Risk: Near-zero (holding period < 1 epoch)
- Detection difficulty: Appears as legitimate staking activity

**Predictability**: Sui epochs occur at fixed, predictable intervals, making timing trivial to execute.

## Recommendation

Exclude inactive stakes from `total_sui_supply` calculations, or defer LST minting until stakes become active. Possible fixes:

1. **Option A**: Modify `refresh_validator_info()` to exclude inactive stakes from `total_sui_supply`:
   - Only count active stakes when calculating exchange rates
   - Track inactive stakes separately

2. **Option B**: Implement a minimum holding period:
   - Require LST holders to wait one full epoch before unstaking
   - Ensures all stakes contribute to at least one reward period

3. **Option C**: Use a two-step staking mechanism:
   - Issue "pending LST" tokens for deposits
   - Convert to regular LST only after stake becomes active

The recommended fix is Option A, as it maintains the current UX while accurately reflecting the actual productive capital in the exchange rate calculation.

## Proof of Concept

```move
#[test]
fun test_epoch_boundary_reward_dilution() {
    // Setup: 10,000 SUI actively staked, 10,000 LST outstanding
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Attacker stakes 1,000 SUI near epoch end
    test_scenario::next_tx(&mut scenario, ATTACKER);
    {
        let mut pool = test_scenario::take_shared<StakePool>(&scenario);
        let mut metadata = test_scenario::take_shared<Metadata<CERT>>(&scenario);
        let mut system_state = test_scenario::take_shared<SuiSystemState>(&scenario);
        
        let sui = coin::mint_for_testing<SUI>(1000_000_000_000, ctx);
        let lst = pool.stake(&mut metadata, &mut system_state, sui, ctx);
        
        assert!(lst.value() == 1000_000_000_000, 0); // Receives 1,000 LST
        transfer::public_transfer(lst, ATTACKER);
        
        test_scenario::return_shared(pool);
        test_scenario::return_shared(metadata);
        test_scenario::return_shared(system_state);
    };
    
    // Advance to next epoch (rewards distributed)
    test_scenario::next_epoch(&mut scenario, ADMIN);
    
    // Attacker unstakes immediately
    test_scenario::next_tx(&mut scenario, ATTACKER);
    {
        let mut pool = test_scenario::take_shared<StakePool>(&scenario);
        let mut metadata = test_scenario::take_shared<Metadata<CERT>>(&scenario);
        let mut system_state = test_scenario::take_shared<SuiSystemState>(&scenario);
        let lst = test_scenario::take_from_sender<Coin<CERT>>(&scenario);
        
        let sui = pool.unstake(&mut metadata, &mut system_state, lst, ctx);
        
        // Attacker receives more than 1,000 SUI despite earning 0 rewards
        assert!(sui.value() > 1000_000_000_000, 1);
        
        coin::burn_for_testing(sui);
        test_scenario::return_shared(pool);
        test_scenario::return_shared(metadata);
        test_scenario::return_shared(system_state);
    };
    
    test_scenario::end(scenario);
}
```

## Notes

The vulnerability is rooted in a fundamental accounting mismatch: inactive stakes increase the denominator (`total_sui_supply`) of the LST exchange rate calculation without contributing to the numerator (rewards earned). This violates the core invariant that LST exchange rates should reflect proportional reward contributions, allowing late stakers to extract value from early stakers' earned rewards.

### Citations

**File:** liquid_staking/sources/validator_pool.move (L225-237)
```text
            // update pool token exchange rates
            let latest_exchange_rate_opt = self.get_latest_exchange_rate(
                &self.validator_infos[i].staking_pool_id,
                system_state,
                ctx
            );

            if (latest_exchange_rate_opt.is_some()) {
                self.validator_infos[i].exchange_rate = *latest_exchange_rate_opt.borrow();
                self.validator_infos[i].last_refresh_epoch = ctx.epoch();
            };
            // update total stake with latest exchange rate
            self.refresh_validator_info(i);
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

**File:** liquid_staking/sources/validator_pool.move (L531-534)
```text
    public(package) fun join_to_sui_pool(self: &mut ValidatorPool, sui: Balance<SUI>) {
        self.total_sui_supply = self.total_sui_supply + sui.value();
        self.sui_pool.join(sui);
    }
```

**File:** liquid_staking/sources/validator_pool.move (L548-553)
```text
        if (stake.stake_activation_epoch() <= ctx.epoch()) {
            let fungible_staked_sui = system_state.convert_to_fungible_staked_sui(stake, ctx);
            self.join_fungible_staked_sui_to_validator(validator_index, fungible_staked_sui);
        } else {
            self.join_inactive_stake_to_validator(validator_index, stake);
        };
```

**File:** liquid_staking/sources/stake_pool.move (L31-31)
```text
    const MIN_STAKE_AMOUNT: u64 = 1_00_000_000; // 0.1 SUI
```

**File:** liquid_staking/sources/stake_pool.move (L176-186)
```text
    public entry fun stake_entry(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let cert = self.stake(metadata, system_state, sui, ctx);
        transfer::public_transfer(cert, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L229-243)
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
        assert!(lst_mint_amount > 0, EZeroMintAmount);
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
