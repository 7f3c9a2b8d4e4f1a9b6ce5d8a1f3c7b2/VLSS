### Title
Boosted Balance Funds Can Be Permanently Locked When Admin Reduces Reward Amount Cap

### Summary
The `boosted_balance` field in the StakePool has no withdrawal mechanism and can only be distributed through the `refresh()` function, which is capped by `boosted_reward_amount`. If an admin reduces `boosted_reward_amount` after an operator deposits funds into `boosted_balance`, the remaining funds become locked and may never be distributed to LST holders. Setting `boosted_reward_amount` to zero permanently locks all remaining boosted funds.

### Finding Description

The vulnerability exists in the interaction between three functions in `stake_pool.move`:

1. **Deposit mechanism**: Operators can deposit SUI into `boosted_balance` with no restrictions on amount [1](#0-0) 

2. **Distribution cap**: During epoch rollovers in `refresh()`, the amount withdrawn from `boosted_balance` is strictly limited by the minimum of three values: the configured `boosted_reward_amount`, actual rewards earned, and available `boosted_balance` [2](#0-1) 

3. **Admin control**: The admin can update `boosted_reward_amount` to any value including zero at any time [3](#0-2) 

**Root Cause**: There is no function to withdraw funds from `boosted_balance` directly. The only way to extract value is through the `refresh()` function during epoch changes, which respects the `boosted_reward_amount` cap. Even `collect_fees()` only withdraws from `fees` and `accrued_reward_fees`, not from `boosted_balance` [4](#0-3) 

**Why Protections Fail**: The codebase has no validation preventing the admin from setting `boosted_reward_amount` lower than the current `boosted_balance`. There is no invariant check to ensure deposited funds can eventually be distributed.

### Impact Explanation

**Direct Fund Impact**: 
- Deposited operator funds become locked in `boosted_balance`
- If `boosted_reward_amount = 0`, funds are **permanently locked** with no recovery mechanism
- If `boosted_reward_amount` is reduced to a small value (e.g., from 1000 SUI/epoch to 10 SUI/epoch), remaining funds require proportionally more epochs to distribute

**Quantified Impact Example**:
- Operator deposits 10,000 SUI into `boosted_balance`
- Admin initially sets `boosted_reward_amount = 1000` SUI/epoch
- After 5 epochs, 5,000 SUI distributed, 5,000 SUI remains
- Admin reduces `boosted_reward_amount = 10` SUI/epoch
- Remaining 5,000 SUI now requires 500 epochs (~500 days) to fully distribute
- If admin sets `boosted_reward_amount = 0`, the 5,000 SUI is permanently lost

**Affected Parties**: 
- Protocol operators who deposit boosted rewards lose custody of their funds
- Potentially affects protocol treasury or partner organizations funding boosted rewards

**Severity Justification**: Medium - While this requires admin action (not purely adversarial), it can occur through legitimate operational decisions (e.g., adjusting reward strategy due to market conditions) and results in permanent fund loss.

### Likelihood Explanation

**Reachable Entry Points**: 
- `deposit_boosted_balance()` is a public function callable by any OperatorCap holder
- `update_boosted_reward_amount()` is a public function callable by any AdminCap holder
- Both are legitimate protocol operations

**Feasible Preconditions**: 
- Normal protocol operation
- No special state required
- Does not require compromised admin (can occur through legitimate parameter adjustment)

**Execution Practicality**: 
Simple two-step sequence:
1. Operator deposits funds via `deposit_boosted_balance()`
2. Admin later reduces reward amount via `update_boosted_reward_amount()`

**Probability Reasoning**: 
This can realistically occur when:
- Market conditions change and protocol needs to reduce boosted rewards
- Protocol transitions between different reward strategies
- Admin misconfigures parameters
- Protocol winds down boosted rewards program

The likelihood is **Medium** because while it requires admin action, this action is part of normal protocol governance and parameter management, not malicious behavior.

### Recommendation

**Code-level Mitigation**:

Add a withdrawal function for unused boosted balance:

```move
public fun withdraw_boosted_balance(
    self: &mut StakePool,
    _: &AdminCap,
    amount: u64,
    ctx: &mut TxContext
): Coin<SUI> {
    self.manage.check_version();
    assert!(amount <= self.boosted_balance.value(), EInsufficientBoostedBalance);
    
    let withdrawn = self.boosted_balance.split(amount);
    
    emit(WithdrawBoostedBalanceEvent {
        amount
    });
    
    coin::from_balance(withdrawn, ctx)
}
```

**Invariant Checks**:

Add validation in `update_boosted_reward_amount()`:

```move
public fun update_boosted_reward_amount(
    self: &mut StakePool,
    _: &AdminCap,
    amount: u64,
) {
    self.manage.check_version();
    
    // Warning: ensure boosted_balance can be fully distributed
    // at new rate, or provide withdrawal mechanism
    
    emit(BoostedRewardAmountUpdateEvent {
        old_value: self.boosted_reward_amount,
        new_value: amount
    });
    self.boosted_reward_amount = amount;
}
```

**Test Cases**:
1. Test depositing boosted balance, reducing reward amount to 0, verify funds can be withdrawn
2. Test depositing boosted balance, reducing reward amount to small value, verify reasonable distribution timeline
3. Test that reducing reward amount below current balance triggers appropriate warnings or requires explicit acknowledgment

### Proof of Concept

**Initial State**:
- StakePool initialized with `boosted_balance = 0 SUI`
- Admin sets `boosted_reward_amount = 1000 SUI`

**Transaction Sequence**:

1. **Operator deposits boosted funds**:
   - Call `deposit_boosted_balance(coin: 10000 SUI)`
   - Result: `boosted_balance = 10000 SUI`

2. **First epoch rollover**:
   - Call `refresh()` during epoch change
   - Assuming `new_rewards >= 1000`, exactly 1000 SUI withdrawn from `boosted_balance`
   - Result: `boosted_balance = 9000 SUI`

3. **Admin reduces reward amount**:
   - Call `update_boosted_reward_amount(amount: 0)`
   - Result: `boosted_reward_amount = 0`

4. **Subsequent epoch rollovers**:
   - Call `refresh()` during epoch changes
   - At line 531, `boosted_reward_amount = 0.min(new_rewards).min(9000)` = 0
   - At line 532, `self.boosted_balance.split(0)` = 0 SUI withdrawn
   - Result: `boosted_balance = 9000 SUI` **permanently locked**

**Expected vs Actual Result**:
- **Expected**: Deposited funds should be withdrawable or fully distributable
- **Actual**: 9000 SUI remains permanently locked in `boosted_balance` with no recovery mechanism

**Success Condition**: The remaining 9000 SUI in `boosted_balance` cannot be withdrawn or distributed, demonstrating permanent fund lock.

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

**File:** liquid_staking/sources/stake_pool.move (L438-449)
```text
    public fun update_boosted_reward_amount(
        self: &mut StakePool,
        _: &AdminCap,
        amount: u64,
    ) {
        self.manage.check_version();
        emit(BoostedRewardAmountUpdateEvent {
            old_value: self.boosted_reward_amount,
            new_value: amount
        });
        self.boosted_reward_amount = amount;
    }
```

**File:** liquid_staking/sources/stake_pool.move (L473-487)
```text
    public fun deposit_boosted_balance(
        self: &mut StakePool,
        _: &OperatorCap,
        coin: &mut Coin<SUI>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let before_balance = self.boosted_balance.value();
        self.boosted_balance.join(coin::into_balance(coin.split(amount, ctx)));
        emit(DepositBoostedBalanceEvent {
            before_balance,
            after_balance: self.boosted_balance.value()
        });
    }
```

**File:** liquid_staking/sources/stake_pool.move (L527-536)
```text
            let mut boosted_reward_amount = self.boosted_reward_amount;

            if (new_total_supply > old_total_supply) {
                // boosted_reward_amount = min(new_reward, boosted_balance, set_reward_amount)
                boosted_reward_amount = boosted_reward_amount.min(new_total_supply - old_total_supply).min(self.boosted_balance.value());
                let boosted_reward = self.boosted_balance.split(boosted_reward_amount);
                self.join_to_sui_pool(boosted_reward);
            } else {
                boosted_reward_amount = 0;
            };
```
