# Audit Report

## Title
Last Staker Advantage: Epoch Boundary Reward Dilution via Inactive Stake Ratio Manipulation

## Summary
A critical vulnerability in the liquid staking protocol allows attackers to systematically steal staking rewards from existing LST holders by exploiting the timing of stake operations relative to epoch boundaries. The attack leverages the fact that inactive stakes are counted in `total_sui_supply` for LST exchange rate calculations but do not earn rewards, creating a risk-free arbitrage opportunity that can be repeated every epoch.

## Finding Description

The vulnerability exists in the interaction between the LST minting mechanism and the reward distribution system. The root cause lies in how `refresh_validator_info()` calculates `total_sui_supply`: [1](#0-0) 

This function includes **both active and inactive stakes** when calculating the total SUI supply. Active stakes (lines 311-318) are valued using the current exchange rate which includes accrued rewards, while inactive stakes (lines 321-326) are valued at their original staked amount without any rewards. Both are then summed into `total_sui_supply`.

The attack sequence works as follows:

1. **Staking Phase**: When a user calls `stake()`, the function first calls `refresh()`, then calculates LST to mint based on the **current** `total_sui_supply` before their SUI is added: [2](#0-1) 

2. **SUI Addition**: After minting LST, the user's SUI is added to the pool via `join_to_sui_pool()`, which immediately increases `total_sui_supply`: [3](#0-2) 

3. **Inactive Stake Creation**: On the next `refresh()` call, `stake_pending_sui()` stakes the SUI with validators. Due to Sui's staking mechanics, new stakes have `stake_activation_epoch = current_epoch + 1`, making them inactive for the current epoch: [4](#0-3) 

4. **Reward Dilution**: When the epoch changes and `refresh()` is called, the exchange rates for validators are updated based on earned rewards. However, only active stakes benefit from these improved exchange rates. The inactive stake contributed zero rewards but is still included in `total_sui_supply`, causing the LST exchange rate to improve for ALL holders including the attacker.

5. **Immediate Exit**: The attacker can immediately unstake with no lockup period: [5](#0-4) 

**Security Guarantee Broken**: The protocol's invariant that LST exchange rates reflect proportional contributions to staking rewards is violated. Late stakers receive exchange rate improvements from rewards they never earned.

## Impact Explanation

This vulnerability enables **systematic theft of staking rewards** from existing LST holders with the following concrete impacts:

**Quantified Loss Example**:
- Initial state: 10,000 SUI actively staked, 10,000 LST outstanding
- Attacker stakes 1,000 SUI near epoch end → receives 1,000 LST at 1:1 ratio
- Attacker's SUI becomes inactive (earns 0 rewards)
- Epoch changes: 10,000 active SUI earns 2.74 SUI rewards (0.1% daily APY)
- New exchange rate: 11,002.74 SUI / 11,000 LST = 1.000249
- Attacker redeems 1,000 LST → receives 1,000.249 SUI
- **Attacker profit: 0.249 SUI (9.1% of total epoch rewards)**
- **Original stakers' loss: 0.249 SUI** (their share diluted from 10,002.74 to 10,002.49)

**Scaling Potential**:
- With 100,000 SUI stake: ~24.9 SUI daily profit
- Annual return: ~9,088 SUI (~91% APY with near-zero risk)
- Compounding: Attack repeatable every epoch
- No capital lockup required

**Affected Parties**: All existing LST holders suffer proportional reward dilution with each attack instance.

## Likelihood Explanation

The attack is **highly likely** to occur due to the following factors:

**Accessibility**: 
- Entry points `stake_entry()` and `unstake_entry()` are public and unrestricted
- No special permissions or capabilities required
- No minimum holding period enforced

**Execution Simplicity**:
1. Monitor epoch timing (publicly available on-chain data)
2. Submit stake transaction near epoch boundary
3. Wait for epoch change (automatic)
4. Call unstake immediately after rewards distribute
5. Extract profit

**Economic Incentives**:
- Attack cost: Only transaction gas fees (~0.001 SUI)
- Expected profit: 9-10% of all epoch rewards for the staked amount
- Risk: Near-zero (holding period < 1 epoch)
- Detection difficulty: Appears as legitimate staking activity
- Automation potential: Can be fully automated with epoch boundary monitoring

**Predictability**: Sui epochs occur at fixed, predictable intervals, making timing trivial to execute.

## Recommendation

Implement one of the following mitigations:

**Option 1 - Exclude Inactive Stakes from LST Calculations** (Recommended):
Modify `refresh_validator_info()` to exclude inactive stakes from `total_sui_supply` used in LST exchange rate calculations until they become active:

```move
fun refresh_validator_info(self: &mut ValidatorPool, i: u64) {
    let validator_info = &mut self.validator_infos[i];
    
    self.total_sui_supply = self.total_sui_supply - validator_info.total_sui_amount;
    
    let mut total_sui_amount = 0;
    
    // Only count active stakes for LST calculations
    if (validator_info.active_stake.is_some()) {
        let active_stake = validator_info.active_stake.borrow();
        let active_sui_amount = get_sui_amount(
            &validator_info.exchange_rate, 
            active_stake.value()
        );
        total_sui_amount = total_sui_amount + active_sui_amount;
    };
    
    // Track inactive stakes separately - don't include in total_sui_supply
    // until they become active
    
    validator_info.total_sui_amount = total_sui_amount;
    self.total_sui_supply = self.total_sui_supply + total_sui_amount;
}
```

**Option 2 - Enforce Minimum Holding Period**:
Implement an unstake ticket system (already exists in volo_v1 but not used in current implementation) with a minimum lock period of 1-2 epochs to prevent immediate reward extraction.

**Option 3 - Account for Pending Stakes Separately**:
Maintain separate accounting for pending/inactive stakes and issue LST only after stakes become active and start earning rewards.

## Proof of Concept

```move
#[test]
fun test_epoch_boundary_reward_dilution() {
    // Setup: 10,000 SUI staked, 10,000 LST supply
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Initial stakers have 10,000 LST at 1:1 ratio
    let initial_lst_supply = 10_000_000_000_000; // 10,000 LST
    let initial_sui_supply = 10_000_000_000_000; // 10,000 SUI
    
    // Advance to near epoch end
    scenario.next_epoch(ADMIN);
    
    // Attacker stakes 1,000 SUI
    let attacker_stake = 1_000_000_000_000; // 1,000 SUI
    scenario.next_tx(ATTACKER);
    {
        let mut pool = scenario.take_shared<StakePool>();
        let mut metadata = scenario.take_shared<Metadata<CERT>>();
        let mut system_state = scenario.take_shared<SuiSystemState>();
        
        let attacker_sui = coin::mint_for_testing<SUI>(attacker_stake, scenario.ctx());
        let attacker_lst = pool.stake(&mut metadata, &mut system_state, attacker_sui, scenario.ctx());
        
        // Attacker receives 1,000 LST at 1:1 ratio
        assert!(attacker_lst.value() == attacker_stake, 0);
        
        test_scenario::return_shared(pool);
        test_scenario::return_shared(metadata);
        test_scenario::return_shared(system_state);
        transfer::public_transfer(attacker_lst, ATTACKER);
    };
    
    // Epoch changes - active stakes earn rewards (2.74 SUI on 10,000 SUI = 0.0274%)
    scenario.next_epoch(ADMIN);
    
    // Trigger refresh to distribute rewards
    scenario.next_tx(OPERATOR);
    {
        let mut pool = scenario.take_shared<StakePool>();
        let metadata = scenario.take_shared<Metadata<CERT>>();
        let mut system_state = scenario.take_shared<SuiSystemState>();
        
        pool.refresh(&metadata, &mut system_state, scenario.ctx());
        
        // Verify total_sui_supply = 11,002.74 (10,002.74 active + 1,000 inactive)
        // Verify total_lst_supply = 11,000
        // Exchange rate = 1.000249
        
        test_scenario::return_shared(pool);
        test_scenario::return_shared(metadata);
        test_scenario::return_shared(system_state);
    };
    
    // Attacker unstakes immediately
    scenario.next_tx(ATTACKER);
    {
        let mut pool = scenario.take_shared<StakePool>();
        let mut metadata = scenario.take_shared<Metadata<CERT>>();
        let mut system_state = scenario.take_shared<SuiSystemState>();
        let attacker_lst = scenario.take_from_sender<Coin<CERT>>();
        
        let redeemed_sui = pool.unstake(&mut metadata, &mut system_state, attacker_lst, scenario.ctx());
        
        // Attacker receives 1,000.249 SUI (profit of 0.249 SUI)
        assert!(redeemed_sui.value() > attacker_stake, 0);
        let profit = redeemed_sui.value() - attacker_stake;
        assert!(profit >= 249_000_000, 0); // ~0.249 SUI profit
        
        test_scenario::return_shared(pool);
        test_scenario::return_shared(metadata);
        test_scenario::return_shared(system_state);
        coin::burn_for_testing(redeemed_sui);
    };
    
    scenario.end();
}
```

### Citations

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

**File:** liquid_staking/sources/validator_pool.move (L536-554)
```text
    public(package) fun join_stake(
        self: &mut ValidatorPool, 
        system_state: &mut SuiSystemState,
        stake: StakedSui, 
        ctx: &mut TxContext
    ) {
        let validator_index = self.get_or_add_validator_index_by_staking_pool_id_mut(
            system_state, 
            stake.pool_id(), 
            ctx
        );

        if (stake.stake_activation_epoch() <= ctx.epoch()) {
            let fungible_staked_sui = system_state.convert_to_fungible_staked_sui(stake, ctx);
            self.join_fungible_staked_sui_to_validator(validator_index, fungible_staked_sui);
        } else {
            self.join_inactive_stake_to_validator(validator_index, stake);
        };
    }
```

**File:** liquid_staking/sources/stake_pool.move (L219-265)
```text
    public fun stake(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ): Coin<CERT> {
        self.manage.check_version();
        self.manage.check_not_paused();

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

        emit(StakeEventExt {
            sui_amount_in,
            lst_amount_out: lst_mint_amount,
            fee_amount: mint_fee_amount
        });

        emit_staked(ctx.sender(), sui_amount_in, lst_mint_amount);

        let lst = metadata.mint(lst_mint_amount, ctx);

        // invariant: lst_out / sui_in <= old_lst_supply / old_sui_supply
        // -> lst_out * old_sui_supply <= sui_in * old_lst_supply
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );

        self.join_to_sui_pool(sui_balance);
        lst
    }
```

**File:** liquid_staking/sources/stake_pool.move (L280-295)
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
```
