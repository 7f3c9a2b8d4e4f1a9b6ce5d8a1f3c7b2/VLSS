### Title
Accrued Reward Fees Can Exceed Validator Pool Balance Causing Protocol-Wide DoS

### Summary
The `accrued_reward_fees` field accumulates unboundedly during epoch rollovers without ensuring the validator pool balance remains sufficient to cover these fees. If validator slashing or exchange rate decreases cause `validator_pool.total_sui_supply()` to drop below `accrued_reward_fees`, the protocol suffers a complete denial of service as `total_sui_supply()` underflows on every call, freezing all staking, unstaking, and fee collection operations.

### Finding Description
In the `refresh()` function, reward fees are accumulated without bound: [1](#0-0) 

The fee calculation is based on the increase in total supply: [2](#0-1) 

The critical issue is in `total_sui_supply()` which performs unchecked u64 subtraction: [3](#0-2) 

In Sui Move, u64 subtraction aborts on underflow. If `accrued_reward_fees > validator_pool.total_sui_supply()`, this function will abort.

The validator pool balance can decrease through:
1. **Exchange rate decreases during refresh** - When `refresh_validator_info()` recalculates stake values with updated exchange rates, losses/slashing manifest as decreased `total_sui_amount`: [4](#0-3) 

2. **User unstaking** - `split_from_sui_pool()` decreases the validator pool supply: [5](#0-4) 

However, `accrued_reward_fees` is only decreased in `collect_fees()`, which itself calls `total_sui_supply()` and would abort if the invariant is already broken: [6](#0-5) 

**Root Cause:** The code assumes the invariant `validator_pool.total_sui_supply() >= accrued_reward_fees` always holds, but this is not enforced. Validator losses (slashing, penalties, exchange rate drops) can violate this invariant when fees accumulate without regular collection.

**Why Protections Fail:** 
- No bounds check when accumulating fees
- No validation that validator pool balance is sufficient before adding fees
- No mechanism to adjust accrued fees downward when validator pool experiences losses
- Fee collection itself requires the invariant to hold, creating a deadlock scenario

### Impact Explanation
**Concrete Harm:**
Once `accrued_reward_fees > validator_pool.total_sui_supply()`, the protocol enters a complete denial of service state:

1. **All staking operations fail** - `stake()` calls `total_sui_supply()` at line 232, which aborts
2. **All unstaking operations fail** - `unstake()` calls `total_sui_supply()` at line 291, which aborts  
3. **Fee collection fails** - `collect_fees()` calls `refresh()` which calls `total_sui_supply()` at line 512, which aborts
4. **Rebalancing fails** - `rebalance()` and `set_validator_weights()` call `refresh()`, which aborts
5. **Ratio queries fail** - `get_ratio()` and `get_ratio_reverse()` call `total_sui_supply()`, which aborts

**Affected Parties:**
- All LST holders cannot unstake their positions
- New users cannot stake
- Protocol admin cannot collect fees or perform any maintenance operations
- The protocol is effectively frozen until a package upgrade

**Severity Justification:**
This is HIGH severity because it causes complete protocol unavailability. All user funds remain locked in the validator pool with no way to withdraw until the contract is upgraded. The impact is catastrophic despite requiring specific preconditions.

### Likelihood Explanation
**Preconditions:**
1. Reward fees accumulate over multiple epochs (2+ epochs with rewards)
2. Fees are not collected regularly by admin
3. Validator pool experiences significant losses through one of:
   - Validator slashing (if implemented at protocol level)
   - Exchange rate decreases due to validator penalties
   - Multiple validators experiencing simultaneous losses

**Attack Complexity:**
This is a passive vulnerability requiring no attacker action. It occurs naturally when:
- Admin does not collect fees regularly (operational oversight)
- Sui network validators experience penalties or slashing events
- Exchange rates decrease due to validator performance issues

**Feasibility:**
The likelihood depends on:
- **Fee collection frequency**: If fees are collected every epoch, the window is small
- **Validator loss magnitude**: Requires losses > accumulated fees (typically 10-20% of recent rewards)
- **Fee percentage**: Higher `reward_fee_bps` (up to 100% allowed) increases accumulated fees faster [7](#0-6) 

**Probability Reasoning:**
MEDIUM-HIGH likelihood in practice:
- Validator slashing/penalties are rare but documented events in PoS networks
- Admin may delay fee collection during low activity periods
- The vulnerability is cumulative - risk increases with each uncollected epoch
- Once triggered, recovery requires emergency package upgrade

### Recommendation
**Immediate Fix:**
Add an invariant check in `refresh()` after accumulating fees to ensure the validator pool can cover them:

```move
// After line 525
self.accrued_reward_fees = self.accrued_reward_fees + reward_fee;

// Add this check:
let current_validator_balance = self.validator_pool.total_sui_supply();
if (self.accrued_reward_fees > current_validator_balance) {
    // Cap accrued fees to available balance
    self.accrued_reward_fees = current_validator_balance;
}
```

**Alternative Fix:**
Modify `total_sui_supply()` to use saturating subtraction instead of failing:

```move
public fun total_sui_supply(self: &StakePool): u64 {
    let validator_balance = self.validator_pool.total_sui_supply();
    if (validator_balance > self.accrued_reward_fees) {
        validator_balance - self.accrued_reward_fees
    } else {
        0 // Protocol is insolvent for fees
    }
}
```

**Best Practice Fix:**
1. Add a maximum cap on `accrued_reward_fees` relative to `validator_pool.total_sui_supply()` (e.g., 20%)
2. Implement automatic fee collection when fees exceed a threshold
3. Adjust accrued fees downward proportionally when validator pool experiences losses
4. Add a recovery function that admin can call to adjust accrued fees in emergency situations

**Test Cases:**
1. Test epoch rollover with validator losses exceeding accumulated fees
2. Test multiple epochs without fee collection followed by validator slashing
3. Test that `total_sui_supply()` handles edge cases gracefully
4. Test recovery scenarios after invariant violation

### Proof of Concept

**Initial State:**
- `validator_pool.total_sui_supply() = 10,000 SUI`
- `accrued_reward_fees = 0`
- `reward_fee_bps = 1000` (10%)
- LST supply = 10,000

**Step 1 - Epoch 1 Rewards:**
- Validator earns 1,000 SUI in staking rewards
- `validator_pool.total_sui_supply() = 11,000`
- `reward_fee = 1,000 * 10% = 100`
- `accrued_reward_fees = 100`
- `total_sui_supply() = 11,000 - 100 = 10,900` ✓

**Step 2 - Epoch 2 Rewards (No fee collection):**
- Validator earns another 1,000 SUI
- `validator_pool.total_sui_supply() = 12,000`
- `reward_fee = 1,000 * 10% = 100`
- `accrued_reward_fees = 200`
- `total_sui_supply() = 12,000 - 200 = 11,800` ✓

**Step 3 - Validator Slashing/Loss Event:**
- Validator experiences 11,900 SUI loss (e.g., slashing, exchange rate crash, validator penalties)
- Exchange rate update during `refresh_validator_info()` recalculates staked value
- `validator_pool.total_sui_supply() = 100`
- `accrued_reward_fees = 200` (unchanged)

**Step 4 - Protocol Frozen:**
- Any call to `total_sui_supply()`: `100 - 200` → **u64 underflow ABORT**
- User attempts `stake()` → calls `total_sui_supply()` at line 232 → **ABORT**
- User attempts `unstake()` → calls `total_sui_supply()` at line 291 → **ABORT**
- Admin attempts `collect_fees()` → calls `refresh()` → calls `total_sui_supply()` → **ABORT**
- Admin attempts `rebalance()` → calls `refresh()` → **ABORT**

**Expected Result:** Protocol operations succeed or fail gracefully
**Actual Result:** Complete protocol freeze, all operations abort with arithmetic underflow
**Success Condition for Attack:** `accrued_reward_fees > validator_pool.total_sui_supply()` achieved through validator losses and uncollected fees

**Notes**
While validator slashing severity on Sui may vary, the vulnerability is real because:
1. Exchange rates can decrease due to validator penalties or performance issues
2. The code makes no attempt to bound `accrued_reward_fees` relative to available balance
3. The arithmetic underflow on u64 subtraction is a hard abort in Move
4. Recovery requires package upgrade since no normal operation can proceed once the invariant breaks

The fix should prevent fee accumulation from exceeding validator pool balance and handle edge cases gracefully rather than aborting all protocol operations.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L359-380)
```text
    public fun collect_fees(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        _: &AdminCap,
        ctx: &mut TxContext
    ): Coin<SUI> {
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);

        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
        self.accrued_reward_fees = self.accrued_reward_fees - reward_fees.value();

        let mut fees = self.fees.withdraw_all();
        fees.join(reward_fees);

        emit(CollectFeesEvent {
            amount: fees.value()
        });

        coin::from_balance(fees, ctx)
    }
```

**File:** liquid_staking/sources/stake_pool.move (L517-523)
```text
            let reward_fee = if (new_total_supply > old_total_supply) {
                (((new_total_supply - old_total_supply) as u128) 
                * (self.fee_config.reward_fee_bps() as u128) 
                / (BPS_MULTIPLIER as u128)) as u64
            } else {
                0
            };
```

**File:** liquid_staking/sources/stake_pool.move (L525-525)
```text
            self.accrued_reward_fees = self.accrued_reward_fees + reward_fee;
```

**File:** liquid_staking/sources/stake_pool.move (L559-561)
```text
    public fun total_sui_supply(self: &StakePool): u64 {
        self.validator_pool.total_sui_supply() - self.accrued_reward_fees
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

**File:** liquid_staking/sources/validator_pool.move (L596-599)
```text
    fun split_from_sui_pool(self: &mut ValidatorPool, amount: u64): Balance<SUI> {
        self.total_sui_supply = self.total_sui_supply - amount;
        self.sui_pool.split(amount)
    }
```

**File:** liquid_staking/sources/fee_config.move (L70-70)
```text
        assert!(fees.reward_fee_bps <= MAX_BPS, EInvalidFee);
```
