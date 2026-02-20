# Audit Report

## Title
Stale Exchange Rate Causes User Fund Loss During Safe Mode or Missing Exchange Rate Data

## Summary
When the Sui system enters safe mode or exchange rate data is unavailable, the protocol fails to update validator exchange rates but continues to recalculate accounting values using stale rates. This causes `total_sui_supply` to be understated, resulting in users receiving less SUI than their proportional share when unstaking.

## Finding Description

The vulnerability exists in the exchange rate update mechanism within `ValidatorPool::refresh()`.

When a user calls `unstake_entry()`, the function invokes `refresh()` to update validator accounting before calculating the user's SUI payout. [1](#0-0)  The refresh operation calls into the validator pool to update exchange rates. [2](#0-1) 

In `ValidatorPool::refresh()`, the code attempts to retrieve the latest exchange rate for each validator by calling `get_latest_exchange_rate()`. [3](#0-2)  According to the function documentation, this returns `None` if the staking pool is inactive or if the Sui system is in safe mode. [4](#0-3) 

**Critical Issue:** When `None` is returned, the exchange rate is NOT updated (the validator retains its stale exchange rate from the previous successful update). [5](#0-4)  However, execution continues without any error or guard, and `refresh_validator_info()` is called unconditionally on the next line. [6](#0-5) 

The `refresh_validator_info()` function explicitly states in its comment that it "assumes the exchange rate is up to date," but this assumption is violated when the exchange rate update fails. [7](#0-6)  The function recalculates `total_sui_amount` using the stale exchange rate via `get_sui_amount()`. [8](#0-7)  This understated value is then written back to the validator's `total_sui_amount` and propagated to `total_sui_supply`. [9](#0-8) 

When users unstake, their SUI entitlement is calculated by `lst_amount_to_sui_amount()` using the formula: `(total_sui_supply * lst_amount) / total_lst_supply`. [10](#0-9)  Because `total_sui_supply` is understated due to the stale exchange rate, users receive less SUI than their fair proportional share.

The protocol's `total_sui_supply` is defined as the sum of all validators' `total_sui_amount` plus the sui_pool buffer. [11](#0-10)  Therefore, when individual validator `total_sui_amount` values are understated, the entire protocol's `total_sui_supply` calculation is affected. [12](#0-11) 

## Impact Explanation

**Direct User Fund Loss:** Users unstaking their LST tokens receive permanently less SUI than their fair proportional share of the protocol's total assets.

**Quantified Impact:**
- If the real exchange rate has increased from 1.00 to 1.10 (10% staking rewards), but the protocol continues using the stale 1.00 rate
- A user with 10% of LST supply entitled to 110 SUI (10% of 1100 total) will only receive 100 SUI (10% of understated 1000 total)
- **User loss: 10 SUI representing 9.1% of their entitled amount**

The loss percentage equals the percentage increase in exchange rate that went unrecorded. In periods of high staking rewards or extended safe mode duration, losses compound for multiple validators.

**Who Is Affected:** All users unstaking during the period when exchange rates are stale. The "missing" value remains in the protocol but is effectively stolen from unstaking users and redistributed to remaining stakers.

**Severity: HIGH** - This breaks the protocol's core invariant that LST tokens represent proportional shares of total SUI. There is no recovery mechanism for affected users. The existing ratio invariant check only prevents over-payment, not under-payment. [13](#0-12) 

## Likelihood Explanation

**Preconditions:**
- Sui system enters safe mode OR exchange rate data is unavailable for the current epoch
- Users attempt to unstake during this period

**Feasibility:** The code explicitly documents safe mode as an expected scenario through the comment stating exchange rates are unavailable "if sui system is currently in safe mode." [4](#0-3)  Safe mode is a documented feature of the Sui blockchain that can be activated during network security incidents, major protocol upgrades, or critical system maintenance.

**Attack Complexity:** None required - this is a protocol design flaw, not an attack. Users simply call the normal `unstake_entry()` function during safe mode. [14](#0-13) 

**Detection:** Users have no visibility into whether exchange rates were successfully updated. The transaction succeeds normally, silently delivering less value than entitled.

**Probability Assessment: MEDIUM-HIGH**
- Safe mode occurrences are infrequent but documented as a real possibility
- When triggered, it affects ALL unstake operations until exchange rates become available again
- Duration could persist for multiple epochs if safe mode extends

## Recommendation

Add a guard to prevent `refresh_validator_info()` from executing when the exchange rate was not successfully updated. The protocol should either:

1. **Skip the refresh entirely and revert** if exchange rates cannot be updated during critical operations
2. **Track exchange rate staleness** and prevent unstaking when rates are stale
3. **Use the last successful epoch's rate** only after explicit validation that it's still within acceptable bounds

Recommended fix:
```move
if (latest_exchange_rate_opt.is_some()) {
    self.validator_infos[i].exchange_rate = *latest_exchange_rate_opt.borrow();
    self.validator_infos[i].last_refresh_epoch = ctx.epoch();
    // Only refresh validator info when exchange rate was successfully updated
    self.refresh_validator_info(i);
} else {
    // Exchange rate unavailable (safe mode or inactive pool)
    // Do NOT recalculate accounting with stale rates
    // Either skip this validator or abort the transaction
    abort ESafeMode
};
```

## Proof of Concept

A complete PoC would require simulating Sui system safe mode, but the vulnerability path is directly observable in the code:

1. User calls `unstake_entry()` during safe mode
2. `refresh()` is invoked → calls `validator_pool.refresh()`
3. `get_latest_exchange_rate()` returns `option::none()` (safe mode active)
4. Lines 232-235 skipped (exchange rate NOT updated, remains stale)
5. Line 237: `refresh_validator_info(i)` called unconditionally
6. Lines 313-316: Calculates `active_sui_amount` using STALE exchange rate
7. Line 329: Updates `total_sui_supply` with UNDERSTATED value
8. Back in `unstake()`: Line 294 calculates payout using understated supply
9. User receives less SUI than proportional entitlement

The vulnerability is demonstrable by comparing:
- Expected payout = `(real_total_sui * lst_amount) / total_lst`  
- Actual payout = `(understated_total_sui * lst_amount) / total_lst`
- Loss = Expected - Actual

**Notes:**

This vulnerability directly violates the liquid staking protocol's fundamental invariant that each LST token represents a proportional claim on the total SUI held by the protocol. The issue is particularly severe because:

1. It's **undetectable to users** - transactions succeed normally with no error indication
2. It's **irreversible** - once users receive reduced payouts, there's no recovery mechanism
3. It creates **wealth redistribution** - the missing value stays in the protocol and effectively transfers to remaining stakers
4. Safe mode is **explicitly documented** in the codebase as an expected scenario, making this a realistic attack surface

The root cause is the architectural assumption that exchange rates will always be available, combined with the unconditional execution of accounting recalculation logic regardless of whether the exchange rate update succeeded.

### Citations

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

**File:** liquid_staking/sources/stake_pool.move (L289-289)
```text
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L323-328)
```text
        // invariant: sui_out / lst_in <= old_sui_supply / old_lst_supply
        // -> sui_out * old_lst_supply <= lst_in * old_sui_supply
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L514-514)
```text
        if (self.validator_pool.refresh(system_state, ctx)) { // epoch rolled over
```

**File:** liquid_staking/sources/stake_pool.move (L559-560)
```text
    public fun total_sui_supply(self: &StakePool): u64 {
        self.validator_pool.total_sui_supply() - self.accrued_reward_fees
```

**File:** liquid_staking/sources/stake_pool.move (L657-659)
```text
        let sui_amount = (total_sui_supply as u128)
            * (lst_amount as u128) 
            / (total_lst_supply as u128);
```

**File:** liquid_staking/sources/validator_pool.move (L43-43)
```text
        /// total_sui_supply = sum(validator_infos.total_sui_amount) + sui_pool
```

**File:** liquid_staking/sources/validator_pool.move (L226-230)
```text
            let latest_exchange_rate_opt = self.get_latest_exchange_rate(
                &self.validator_infos[i].staking_pool_id,
                system_state,
                ctx
            );
```

**File:** liquid_staking/sources/validator_pool.move (L232-235)
```text
            if (latest_exchange_rate_opt.is_some()) {
                self.validator_infos[i].exchange_rate = *latest_exchange_rate_opt.borrow();
                self.validator_infos[i].last_refresh_epoch = ctx.epoch();
            };
```

**File:** liquid_staking/sources/validator_pool.move (L237-237)
```text
            self.refresh_validator_info(i);
```

**File:** liquid_staking/sources/validator_pool.move (L281-282)
```text
    /// Returns the latest exchange rate for a given staking pool ID.
    /// Returns None if the staking pool is inactive or if sui system is currently in safe mode.
```

**File:** liquid_staking/sources/validator_pool.move (L303-304)
```text
    /// Update the total sui amount for the validator and modify the 
    /// pool sui supply accordingly assumes the exchange rate is up to date
```

**File:** liquid_staking/sources/validator_pool.move (L313-316)
```text
            let active_sui_amount = get_sui_amount(
                &validator_info.exchange_rate, 
                active_stake.value()
            );
```

**File:** liquid_staking/sources/validator_pool.move (L328-329)
```text
        validator_info.total_sui_amount = total_sui_amount;
        self.total_sui_supply = self.total_sui_supply + total_sui_amount;
```
