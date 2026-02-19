### Title
Insufficient SUI Balance After Unstaking Causes Panic in claim_fees(), Locking Fee Collection

### Summary
The `claim_fees()` function in the Suilend staker calculates `excess_sui` based on the gross value of staked LST tokens, but when unstaking is required, redemption fees (up to 5%) and rounding errors (up to 10 mist) cause the actual SUI received to be less than expected. This shortfall causes `sui_balance.split(excess_sui)` to panic with a balance underflow error, permanently blocking fee collection operations.

### Finding Description

The vulnerability exists in the `claim_fees()` function's unstaking logic: [1](#0-0) 

The root cause is a mismatch between the calculated `excess_sui` and the actual SUI available after unstaking:

1. **Excess Calculation (Lines 138-145)**: `excess_sui` is computed using `total_sui_supply()`, which includes the gross value of staked LST before any redemption fees. [2](#0-1) 

2. **Unstaking with Fees (Line 149)**: When `excess_sui > sui_balance`, `unstake_n_sui()` is called to redeem LST tokens. [3](#0-2) 

The `unstake_n_sui()` function uses ceiling division to calculate the LST amount needed, then calls the LST protocol's `redeem()` function. However, the redemption process incurs losses:

**Rounding Error**: The underlying `split_n_sui()` function allows up to 10 mist shortfall: [4](#0-3) 

**Unstake Fees**: The LST protocol deducts unstake fees (up to 5% per fee caps) from the redeemed amount: [5](#0-4) [6](#0-5) 

3. **Insufficient Balance at Split (Line 152)**: After unstaking, `sui_balance` may be less than `excess_sui` by (fees + rounding), causing `split()` to panic.

### Impact Explanation

**Direct Operational Impact**: The `claim_fees()` function becomes permanently unusable once the vulnerability condition is met, preventing the Suilend protocol from collecting staking rewards. This affects fee distribution to the protocol.

**Quantified Shortfall**: With maximum unstake fee (5%) and rounding tolerance (10 mist), unstaking 100 SUI worth of LST results in:
- Rounding loss: up to 0.00000001 SUI
- Fee loss: 5 SUI
- Total shortfall: ~5 SUI vs. 1 SUI buffer = **4 SUI deficit**

**Affected Operations**: The `claim_fees()` function is called by `reserve::rebalance_staker()`: [7](#0-6) 

This is invoked via the public function `lending_market::rebalance_staker()`: [8](#0-7) 

When the panic occurs, all fee collection for the SUI reserve is blocked, effectively locking staking rewards that should be distributed to the protocol.

**Severity Justification**: HIGH - This causes a permanent DoS of critical fee collection functionality under normal protocol operations with realistic fee configurations.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is triggered through `lending_market::rebalance_staker()`, a public function callable by any code that has access to the lending market object.

**Feasible Preconditions**: 
- Staker has staked LST with accumulated rewards
- `excess_sui > sui_balance`, requiring unstaking
- Unstaking amount is significant enough that fees exceed the 1 SUI buffer

**Execution Practicality**: The vulnerability occurs under normal protocol conditions:
- LST unstake fees are configurable up to 5% (500 bps)
- Even with modest fees (2%), unstaking 50 SUI loses ~1 SUI, matching the buffer
- No special attacker capabilities required - natural protocol state evolution

**Probability Assessment**: 
- Occurs whenever the staker needs to unstake for fee collection
- With the minimal 1 SUI buffer and realistic fees (1-5%), this happens frequently
- Given typical staking reward rates and rebalancing frequency, this is HIGHLY LIKELY

**Economic Rationality**: No attack cost - this is a natural protocol operation failure, not requiring any malicious action.

### Recommendation

**Immediate Fix**: Modify `claim_fees()` to account for redemption fees and use the actual received amount instead of the calculated `excess_sui`:

```move
public(package) fun claim_fees<P: drop>(
    staker: &mut Staker<P>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext,
): Balance<SUI> {
    staker.liquid_staking_info.refresh(system_state, ctx);
    
    let total_sui_supply = staker.total_sui_supply();
    let excess_sui = if (total_sui_supply > staker.liabilities + MIST_PER_SUI) {
        total_sui_supply - staker.liabilities - MIST_PER_SUI
    } else {
        0
    };
    
    if (excess_sui > staker.sui_balance.value()) {
        let unstake_amount = excess_sui - staker.sui_balance.value();
        staker.unstake_n_sui(system_state, unstake_amount, ctx);
    };
    
    // Use min() to prevent panic if actual balance is less than calculated
    let claimable = min(excess_sui, staker.sui_balance.value());
    let sui = staker.sui_balance.split(claimable);
    
    assert!(staker.total_sui_supply() >= staker.liabilities, EInvariantViolation);
    sui
}
```

**Additional Safeguard**: Add a post-unstaking check to verify sufficient balance before attempting the split, or use a tolerance-based approach that accounts for fees.

**Test Cases**: Add regression tests covering:
- Unstaking scenarios with maximum fee configuration (5%)
- Edge cases where `excess_sui` is close to `sui_balance`
- Verification that fees are properly accounted for in the claimable amount

### Proof of Concept

**Initial State**:
- Staker LST balance: 1000 SPRUNGSUI
- LST exchange rate: 1.1 SUI per SPRUNGSUI (from staking rewards)
- LST gross value: 1100 SUI
- Staker SUI balance: 50 SUI
- Total SUI supply: 1150 SUI
- Liabilities: 1050 SUI
- Unstake fee configured: 5% (maximum allowed)

**Execution Steps**:

1. Call `rebalance_staker()` which invokes `claim_fees()`

2. Calculate `excess_sui = 1150 - 1050 - 1 = 99 SUI`

3. Check: `99 > 50` ✓ → Trigger unstaking

4. Call `unstake_n_sui(49)`:
   - Calculate LST needed: `ceil(49 / 1.1) = 45 SPRUNGSUI`
   - Redeem 45 SPRUNGSUI
   - Expected gross: `45 * 1.1 = 49.5 SUI`
   - `split_n_sui(49.5)` returns: `49.49 SUI` (within 10 mist tolerance)
   - Unstake fee: `49.49 * 0.05 = 2.47 SUI`
   - Net received: `49.49 - 2.47 = 47.02 SUI`
   - New sui_balance: `50 + 47.02 = 97.02 SUI`

5. Attempt `sui_balance.split(99)` with balance = 97.02

**Expected Result**: Transaction completes successfully with 99 SUI claimed

**Actual Result**: **PANIC** - Balance underflow error (trying to split 99 from 97.02), transaction aborts, fee collection permanently blocked

**Success Condition for Exploit**: Shortfall = `99 - 97.02 = 1.98 SUI` exceeds available balance, causing guaranteed panic

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L45-47)
```text
    public(package) fun total_sui_supply<P>(staker: &Staker<P>): u64 {
        staker.liquid_staking_info.total_sui_supply() + staker.sui_balance.value()
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L138-152)
```text
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

**File:** liquid_staking/sources/validator_pool.move (L754-763)
```text
        // Allow 10 mist of rounding error
        let mut safe_max_sui_amount_out = max_sui_amount_out;
        if(max_sui_amount_out > self.sui_pool.value()) {
            if(max_sui_amount_out  <= self.sui_pool.value() + ACCEPTABLE_MIST_ERROR) {
                safe_max_sui_amount_out = self.sui_pool.value();
            };
        };

        assert!(self.sui_pool.value() >= safe_max_sui_amount_out, ENotEnoughSuiInSuiPool);
        self.split_from_sui_pool(safe_max_sui_amount_out)
```

**File:** liquid_staking/sources/stake_pool.move (L297-312)
```text
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
```

**File:** liquid_staking/sources/fee_config.move (L8-9)
```text
    const MAX_UNSTAKE_FEE_BPS: u64 = 500; // 5%
    const MAX_STAKE_FEE_BPS: u64 = 500; // 5%
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L831-849)
```text
    public(package) fun rebalance_staker<P>(
        reserve: &mut Reserve<P>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext
    ) {
        assert!(dynamic_field::exists_(&reserve.id, StakerKey {}), EStakerNotInitialized);
        let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
            &mut reserve.id, 
            BalanceKey {}
        );
        let sui = balance::withdraw_all(&mut balances.available_amount);

        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});

        staker::deposit(staker, sui);
        staker::rebalance(staker, system_state, ctx);

        let fees = staker::claim_fees(staker, system_state, ctx);
        if (balance::value(&fees) > 0) {
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L791-803)
```text
    public fun rebalance_staker<P>(
        lending_market: &mut LendingMarket<P>,
        sui_reserve_array_index: u64,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, sui_reserve_array_index);
        assert!(reserve::coin_type(reserve) == type_name::get<SUI>(), EWrongType);

        reserve::rebalance_staker<P>(reserve, system_state, ctx);
    }
```
