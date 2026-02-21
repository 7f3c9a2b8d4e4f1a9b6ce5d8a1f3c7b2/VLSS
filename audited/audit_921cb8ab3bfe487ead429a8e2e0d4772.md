# Audit Report

## Title
First Mint After Zero Supply Allows Theft of Remaining Pool SUI

## Summary
A critical vulnerability exists in the liquid staking pool that allows an attacker to steal all remaining SUI when CERT supply reaches zero but SUI remains in the pool. The special case handling for zero supply enables minting CERT at a 1:1 ratio regardless of existing SUI balance, which can be immediately unstaked at a favorable ratio to extract all pool funds.

## Finding Description

The vulnerability stems from the interaction between three key mechanisms in the liquid staking pool:

**1. Zero Supply Ratio Calculation**

When either `total_sui_supply` or `total_lst_supply` is zero, the `sui_amount_to_lst_amount()` function returns a 1:1 ratio. [1](#0-0) 

**2. Special Case Invariant Bypass**

The `stake()` function includes an explicit special case that bypasses the ratio invariant check when `old_sui_supply > 0 && old_lst_supply == 0`. [2](#0-1)  This was likely intended for initial pool creation but creates an exploitable path when the pool returns to zero CERT supply after being active.

**3. Proportional Unstaking**

The `lst_amount_to_sui_amount()` function calculates unstake amounts proportionally based on the current pool state. [3](#0-2)  When an attacker owns all CERT, they receive proportional access to all SUI in the pool.

**How SUI Remains When CERT Supply Is Zero**

The `total_sui_supply()` calculation excludes accrued reward fees [4](#0-3) , but includes SUI that can accumulate through:

- **Boosted rewards**: Added to the pool via `join_to_sui_pool()` during epoch rollovers [5](#0-4) 
- **Redistribution fees**: From non-final unstakes that go back to the pool [6](#0-5) 

The `join_to_sui_pool()` function increases `total_sui_supply` when adding SUI to the pool. [7](#0-6) 

**Attack Execution**

When `total_lst_supply = 0` but `total_sui_supply() = X > 0` (where X could be several SUI from accumulated boosted rewards):

1. Attacker calls `stake_entry()` with 0.1 SUI (minimum stake amount [8](#0-7) )
2. After stake fees, receives ~0.099 CERT (1:1 ratio due to zero LST supply)
3. New state: `total_sui_supply() = X + 0.099`, `total_lst_supply = 0.099`
4. Attacker calls `unstake_entry()` with all 0.099 CERT
5. Receives: `(X + 0.099) * 0.099 / 0.099 = X + 0.099` SUI (before fees)
6. After unstake fees, attacker receives approximately `X + 0.099` SUI minus fees
7. **Net profit: Most of X (the remaining pool SUI) minus transaction fees**

Both `stake_entry()` and `unstake_entry()` are public entry functions accessible to anyone. [9](#0-8) [10](#0-9) 

The unstake invariant check passes because the attacker owns all CERT and receives proportional SUI. [11](#0-10) 

## Impact Explanation

**CRITICAL - Direct Fund Theft**

- **Complete theft** of all effective SUI supply in the pool (approximately 98-99% after fees)
- Affects **legitimate users** who have accumulated rewards or fees in the pool
- **Repeatable** - can be executed each time the pool returns to zero supply state
- **No victim interaction required** - attacker can monitor on-chain state and front-run any legitimate staker

The attack is economically rational with extremely high ROI:
- Cost: 0.1 SUI + transaction fees (approximately 2-3% of stake/unstake amounts)
- Profit: All remaining SUI in pool (potentially several SUI from accumulated boosted rewards)
- ROI: Can exceed 20-100x if significant boosted rewards have accumulated

This breaks the fundamental security guarantee that the pool's SUI reserves should only be accessible proportionally to existing CERT holders.

## Likelihood Explanation

**HIGH - Practically Exploitable**

**Feasible Preconditions:**
- Zero CERT supply occurs **naturally** when the last user unstakes all their tokens
- SUI accumulates in the pool from boosted rewards added during epoch rollovers
- The minimum stake requirement is only 0.1 SUI, making the attack cheap to execute
- No special permissions or capabilities required

**Attack Simplicity:**
- Only two transactions: `stake_entry()` followed by `unstake_entry()`
- No race conditions or complex timing requirements
- All invariant checks pass due to the explicit special case allowance
- Works entirely within normal Sui Move execution model

**Real-World Feasibility:**
- Attacker can monitor on-chain state to detect zero CERT supply
- Can execute immediately after epoch rollover when boosted rewards are added
- Can front-run any legitimate staker attempting to mint CERT
- Pool continues accepting stakes at zero supply with no preventive guards

## Recommendation

Remove or restrict the special case that allows bypassing the ratio invariant when LST supply is zero but SUI supply exists. The special case should only apply during true initialization (when both supplies are zero):

```move
// In stake() function, replace line 257-261 with:
assert!(
    ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
    || (old_sui_supply == 0 && old_lst_supply == 0), // Only allow during initialization
    ERatio
);
```

Additionally, consider adding a guard to prevent staking when LST supply is zero but SUI supply is non-zero:

```move
// In stake() function, after line 233:
assert!(
    !(old_lst_supply == 0 && old_sui_supply > 0),
    ECannotStakeWithZeroSupply  // New error code
);
```

## Proof of Concept

```move
#[test]
fun test_zero_supply_theft() {
    let mut scenario = test_scenario::begin(@0xA);
    
    // Setup: Create pool and reach zero CERT supply state
    // ... (pool creation code)
    
    // Simulate boosted rewards being added (2 SUI)
    let boosted_sui = coin::mint_for_testing<SUI>(2_000_000_000, scenario.ctx());
    stake_pool.deposit_boosted_balance(&operator_cap, &mut boosted_sui, 2_000_000_000, scenario.ctx());
    coin::burn_for_testing(boosted_sui);
    
    // Trigger epoch rollover to add boosted rewards to pool
    test_scenario::next_epoch(&mut scenario, @0xA);
    stake_pool.refresh(&metadata, &mut system_state, scenario.ctx());
    
    // At this point: total_lst_supply = 0, total_sui_supply = 2 SUI
    assert!(total_lst_supply(&metadata) == 0, 0);
    assert!(stake_pool.total_sui_supply() > 0, 1);
    
    // Attack: Stake minimum amount
    test_scenario::next_tx(&mut scenario, @0xATTACKER);
    let attacker_sui = coin::mint_for_testing<SUI>(100_000_000, scenario.ctx()); // 0.1 SUI
    let cert = stake_pool.stake(&mut metadata, &mut system_state, attacker_sui, scenario.ctx());
    
    // Attacker now owns all CERT, immediately unstake
    let recovered_sui = stake_pool.unstake(&mut metadata, &mut system_state, cert, scenario.ctx());
    
    // Verify attacker stole pool funds
    assert!(recovered_sui.value() > 2_000_000_000, 2); // Got more than the 2 SUI that was in pool
    
    coin::burn_for_testing(recovered_sui);
    test_scenario::end(scenario);
}
```

### Citations

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

**File:** liquid_staking/sources/stake_pool.move (L257-261)
```text
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );
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

**File:** liquid_staking/sources/stake_pool.move (L301-312)
```text
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
```

**File:** liquid_staking/sources/stake_pool.move (L325-328)
```text
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L527-533)
```text
            let mut boosted_reward_amount = self.boosted_reward_amount;

            if (new_total_supply > old_total_supply) {
                // boosted_reward_amount = min(new_reward, boosted_balance, set_reward_amount)
                boosted_reward_amount = boosted_reward_amount.min(new_total_supply - old_total_supply).min(self.boosted_balance.value());
                let boosted_reward = self.boosted_balance.split(boosted_reward_amount);
                self.join_to_sui_pool(boosted_reward);
```

**File:** liquid_staking/sources/stake_pool.move (L559-561)
```text
    public fun total_sui_supply(self: &StakePool): u64 {
        self.validator_pool.total_sui_supply() - self.accrued_reward_fees
    }
```

**File:** liquid_staking/sources/stake_pool.move (L636-638)
```text
        if (total_sui_supply == 0 || total_lst_supply == 0) {
            return sui_amount
        };
```

**File:** liquid_staking/sources/stake_pool.move (L657-661)
```text
        let sui_amount = (total_sui_supply as u128)
            * (lst_amount as u128) 
            / (total_lst_supply as u128);

        sui_amount as u64
```

**File:** liquid_staking/sources/validator_pool.move (L531-534)
```text
    public(package) fun join_to_sui_pool(self: &mut ValidatorPool, sui: Balance<SUI>) {
        self.total_sui_supply = self.total_sui_supply + sui.value();
        self.sui_pool.join(sui);
    }
```
