### Title
LST Redemption Fee Causes Withdrawal Transaction Failures in Suilend Staker

### Summary
The `unstake_n_sui()` function redeems LST tokens but doesn't account for redemption fees deducted by the external liquid staking protocol. This causes callers (`withdraw()` and `claim_fees()`) to fail when they attempt to split the expected amount from `sui_balance`, as insufficient SUI was actually received after fees. This breaks all Suilend reserve withdrawals that require unstaking.

### Finding Description

The vulnerability exists in the Suilend staker module at three interconnected points: [1](#0-0) 

In `unstake_n_sui()`, the function calculates the LST amount to redeem using ceiling division to ensure at least `sui_amount_out` worth of LST is redeemed. However, when it calls `liquid_staking::redeem()` at lines 181-186, the actual SUI returned is reduced by redemption fees applied by the external liquid staking protocol. [2](#0-1) 

The `withdraw()` function calls `unstake_n_sui()` with the additional amount needed (line 90), then immediately tries to split exactly `withdraw_amount` at line 93. If redemption fees reduced the SUI received, `sui_balance` won't contain enough funds, causing the split operation to fail. [3](#0-2) 

Similarly, `claim_fees()` has the same issue at line 152 where it tries to split exactly `excess_sui` after calling `unstake_n_sui()`.

The external liquid staking redemption applies fees as evidenced by the Volo LST implementation: [4](#0-3) 

This shows that LST redemption deducts `redeem_fee_amount` (line 300) from the SUI before returning it, meaning the actual SUI received is less than the calculated `sui_amount_out`.

The Suilend reserve calls this staker withdrawal function: [5](#0-4) 

When `unstake_sui_from_staker()` is invoked, it expects the staker to provide exactly `withdraw_amount` of SUI (line 889), which is then used by `fulfill_liquidity_request()`: [6](#0-5) 

The `fulfill_liquidity_request()` function splits the exact requested `amount` at line 813, which will fail if the staker didn't add sufficient SUI due to redemption fees.

### Impact Explanation

**Concrete Harm:**
- All Suilend reserve withdrawals/borrows requiring LST unstaking will fail with balance split errors
- Users cannot access their deposited funds when reserve liquidity is low and requires unstaking
- Protocol fee collection via `claim_fees()` will also fail, preventing protocol revenue extraction

**Quantified Damage:**
- 100% DoS of withdrawals when `available_amount < withdraw_amount` and unstaking is needed
- The fee shortfall equals `sui_amount_out * fee_bps / 10000` where fee_bps is the LST redemption fee
- For typical LST fees of 0.5-2%, the shortfall can be 0.5-2% of the unstake amount

**Affected Parties:**
- Suilend users attempting to withdraw or borrow SUI
- Protocol operators unable to claim fees
- The Suilend reserve becomes partially locked

**Severity Justification:**
HIGH severity due to complete DoS of core withdrawal functionality affecting all users when unstaking is required. The issue is deterministic and not dependent on market conditions.

### Likelihood Explanation

**Attacker Capabilities:**
- No attacker required - this is a bug triggered by normal user operations
- Any user withdrawal when reserve needs to unstake will trigger the failure

**Attack Complexity:**
- Trivial - simply attempt to withdraw when `available_amount` is insufficient
- No special conditions or timing requirements

**Feasibility Conditions:**
- Reserve must have staked LST (which is its normal state per the staker design)
- Available SUI balance must be less than withdrawal amount (common during high utilization)
- External LST protocol must charge redemption fees (standard practice, as shown in Volo's own LST)

**Detection/Operational Constraints:**
- Issue will be immediately apparent on first withdrawal requiring unstaking
- Every affected transaction will fail with a balance::split error
- No way to work around without code fix

**Probability:**
HIGH likelihood - occurs during normal protocol operation whenever withdrawals exceed available balance. The preconditions (staked LST, redemption fees) are the designed and expected state of the system.

### Recommendation

**Code-level Mitigation:**

1. Modify `unstake_n_sui()` to return the actual SUI amount received:
   - Change function signature to return `u64` 
   - Return `sui.into_balance().value()` before joining to `sui_balance`

2. Update `withdraw()` to handle actual amount received:
   - Store result from `unstake_n_sui()` 
   - Calculate actual available: `min(withdraw_amount, sui_balance.value())`
   - Split the actual available amount instead of assuming exact `withdraw_amount`

3. Update `claim_fees()` similarly:
   - Use actual SUI received from unstaking
   - Split only what's actually available

4. Add invariant check after redemption:
   ```move
   let sui_received = sui.into_balance();
   let received_value = balance::value(&sui_received);
   assert!(received_value >= min_acceptable_amount, EInsufficientRedemption);
   staker.sui_balance.join(sui_received);
   ```

**Test Cases:**
- Test withdrawal with redemption fees of 0.5%, 1%, 2%
- Test claim_fees with various fee configurations
- Verify transaction doesn't abort and returns proportional amount
- Test edge case where fees cause available balance to fall below MIN_AVAILABLE_AMOUNT

### Proof of Concept

**Initial State:**
- Suilend Reserve has `staker` with 100 SUI staked as LST
- Reserve `available_amount` = 50 SUI
- External LST protocol charges 1% redemption fee

**Transaction Steps:**

1. User calls reserve withdrawal for 150 SUI
2. `unstake_sui_from_staker()` calculates: `withdraw_amount = 150 - 50 = 100`
3. Calls `staker::withdraw(staker, 100, system_state, ctx)`
4. In `withdraw()`:
   - Line 89: `unstake_amount = 100 - 0 = 100` (assuming sui_balance is empty)
   - Line 90: Calls `unstake_n_sui(system_state, 100, ctx)`
5. In `unstake_n_sui()`:
   - Calculates LST to redeem for 100 SUI
   - Calls `liquid_staking::redeem()` 
   - LST protocol deducts 1% fee = 1 SUI
   - Actually receives 99 SUI
   - Line 188: Joins 99 SUI to `sui_balance`, now contains 99 SUI
6. Back in `withdraw()`:
   - Line 93: Attempts `sui_balance.split(100)`
   - **FAILS**: Balance only contains 99 SUI but trying to split 100

**Expected vs Actual:**
- Expected: Successfully withdraw 150 SUI (or proportionally less)
- Actual: Transaction aborts with insufficient balance error

**Success Condition:**
Transaction abort proves the vulnerability - the staker cannot fulfill withdrawal requests when redemption fees are applied.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L80-97)
```text
    public(package) fun withdraw<P: drop>(
        staker: &mut Staker<P>,
        withdraw_amount: u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ): Balance<SUI> {
        staker.liquid_staking_info.refresh(system_state, ctx);

        if (withdraw_amount > staker.sui_balance.value()) {
            let unstake_amount = withdraw_amount - staker.sui_balance.value();
            staker.unstake_n_sui(system_state, unstake_amount, ctx);
        };

        let sui = staker.sui_balance.split(withdraw_amount);
        staker.liabilities = staker.liabilities - sui.value();

        sui
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L131-157)
```text
    public(package) fun claim_fees<P: drop>(
        staker: &mut Staker<P>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ): Balance<SUI> {
        staker.liquid_staking_info.refresh(system_state, ctx);

        let total_sui_supply = staker.total_sui_supply();

        // leave 1 SUI extra, just in case
        let excess_sui = if (total_sui_supply > staker.liabilities + MIST_PER_SUI) {
            total_sui_supply - staker.liabilities - MIST_PER_SUI
        } else {
            0
        };

        if (excess_sui > staker.sui_balance.value()) {
            let unstake_amount = excess_sui - staker.sui_balance.value();
            staker.unstake_n_sui(system_state, unstake_amount, ctx);
        };

        let sui = staker.sui_balance.split(excess_sui);

        assert!(staker.total_sui_supply() >= staker.liabilities, EInvariantViolation);

        sui
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L163-189)
```text
    fun unstake_n_sui<P: drop>(
        staker: &mut Staker<P>,
        system_state: &mut SuiSystemState,
        sui_amount_out: u64,
        ctx: &mut TxContext,
    ) {
        if (sui_amount_out == 0) {
            return
        };

        let total_sui_supply = (staker.liquid_staking_info.total_sui_supply() as u128);
        let total_lst_supply = (staker.liquid_staking_info.total_lst_supply() as u128);

        // ceil lst redemption amount
        let lst_to_redeem =
            ((sui_amount_out as u128) * total_lst_supply + total_sui_supply - 1) / total_sui_supply;
        let lst = balance::split(&mut staker.lst_balance, (lst_to_redeem as u64));

        let sui = liquid_staking::redeem(
            &mut staker.liquid_staking_info,
            coin::from_balance(lst, ctx),
            system_state,
            ctx,
        );

        staker.sui_balance.join(sui.into_balance());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L294-333)
```text
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L802-817)
```text
    public(package) fun fulfill_liquidity_request<P, T>(
        reserve: &mut Reserve<P>,
        request: LiquidityRequest<P, T>,
    ): Balance<T> {
        let LiquidityRequest { amount, fee } = request;

        let balances: &mut Balances<P, T> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );

        let mut liquidity = balance::split(&mut balances.available_amount, amount);
        balance::join(&mut balances.fees, balance::split(&mut liquidity, fee));

        liquidity
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L869-899)
```text
    public(package) fun unstake_sui_from_staker<P, T>(
        reserve: &mut Reserve<P>,
        liquidity_request: &LiquidityRequest<P, T>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        assert!(reserve.coin_type == type_name::get<SUI>() && type_name::get<T>() == type_name::get<SUI>(), EWrongType);
        if (!dynamic_field::exists_(&reserve.id, StakerKey {})) {
            return
        };

        let balances: &Balances<P, SUI> = dynamic_field::borrow(&reserve.id, BalanceKey {});
        if (liquidity_request.amount <= balance::value(&balances.available_amount)) {
            return
        };
        let withdraw_amount = liquidity_request.amount - balance::value(&balances.available_amount);

        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});
        let sui = staker::withdraw(
            staker,
            withdraw_amount, 
            system_state, 
            ctx
        );

        let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );
        balance::join(&mut balances.available_amount, sui);
    }
```
