### Title
Tolerance Mechanism in Liquid Staking Unstaking Can Cause DoS in Staker Fee Collection and Withdrawals

### Summary
The `claim_fees()` and `withdraw()` functions in the Suilend staker module assume that `unstake_n_sui()` will always add at least the requested amount of SUI to the balance. However, the underlying `validator_pool::split_n_sui()` function contains a tolerance mechanism that can return up to 10 mist less than requested. This mismatch causes the subsequent `balance.split()` operation to panic, permanently locking fee collection and potentially blocking user withdrawals until validator liquidity conditions improve.

### Finding Description

**Vulnerable Functions:**
1. `claim_fees()` - [1](#0-0) 
2. `withdraw()` - [2](#0-1) 

**Root Cause:**

Both functions follow an identical vulnerable pattern:
- Check if more SUI is needed than currently in `sui_balance`
- Call `unstake_n_sui()` to unstake the difference
- Attempt to split the exact originally calculated amount from `sui_balance`

The `unstake_n_sui()` helper function uses ceiling division to calculate LST tokens to redeem, intending to return at least the requested amount: [3](#0-2) 

However, it calls `liquid_staking::redeem()` which internally uses `validator_pool::split_n_sui()`. This function contains a critical tolerance mechanism: [4](#0-3) 

This tolerance mechanism adjusts the returned amount downward (by up to `ACCEPTABLE_MIST_ERROR` = 10 mist) when the pool doesn't have quite enough liquidity. The constant is defined here: [5](#0-4) 

**Why Protections Fail:**

The comment in `unstake_n_sui()` states "this function can unstake slightly more sui than requested due to rounding" but doesn't account for the possibility of receiving LESS due to the downstream tolerance mechanism. Neither `claim_fees()` nor `withdraw()` validate that the actual amount received after unstaking meets their requirements before attempting the split operation.

**Execution Path:**
1. `claim_fees()` calculates `excess_sui` (e.g., 1000 SUI)
2. Checks at line 147: `excess_sui > sui_balance.value()` (e.g., 1000 > 500)
3. Calls `unstake_n_sui()` with `unstake_amount = 500 SUI`
4. Inside `unstake_n_sui()`, LST is redeemed via the liquid staking system
5. `validator_pool::split_n_sui()` attempts to unstake but only has 499.999999990 SUI available
6. Due to tolerance mechanism (difference ≤ 10 mist), returns 499.999999990 SUI instead of failing
7. This joins to `sui_balance`, making total = 999.999999990 SUI
8. At line 152: attempts `sui_balance.split(1000 SUI)` → **PANIC** (insufficient balance)

The same issue affects `withdraw()` which is called during reserve operations: [6](#0-5) 

### Impact Explanation

**Concrete Harm:**
1. **Fee Collection DoS**: The `claim_fees()` function is called by Suilend reserves to collect staking rewards from SUI reserves with initialized stakers. When this panics, the protocol cannot collect earned staking fees.

2. **Withdrawal Blocking**: The `withdraw()` function is used to withdraw SUI from the staker. If this panics, operations depending on withdrawals may fail.

**Affected Parties:**
- Protocol operators cannot collect staking rewards
- Users may be unable to withdraw if their withdrawals trigger this path
- The Suilend reserve using this staker becomes operationally impaired

**Severity Justification:**
HIGH severity because:
- Causes complete operational DoS of critical fee collection function
- No workaround available while validator liquidity is constrained
- Affects actual deployed integration (Suilend's use of Volo liquid staking)
- Can persist until validator pool liquidity improves naturally

### Likelihood Explanation

**Realistic Conditions:**
- Occurs naturally during periods of high withdrawal activity when validator pools have tight liquidity
- The 10 mist tolerance is small but the issue manifests when accumulated rounding or exchange rate conversions cause the shortfall
- No attacker action required - normal protocol operations trigger the vulnerability

**Feasibility:**
- Entry point is a normal package-level function called during reserve operations
- Preconditions are common operational scenarios (tight validator liquidity)
- No special permissions or economic resources required
- Occurs deterministically under the described conditions

**Probability:**
Medium-to-High probability during:
- Epoch boundaries when many users unstake simultaneously
- High market volatility causing withdrawal waves
- Natural validator rebalancing operations

Once triggered, the condition persists until enough SUI becomes available in validator pools to satisfy the exact amount without invoking the tolerance adjustment.

### Recommendation

**Code-Level Mitigation:**

1. **For `claim_fees()`**: After unstaking, verify the actual `sui_balance` value and adjust `excess_sui` accordingly:

```move
// After line 149 (unstake operation)
let actual_balance = staker.sui_balance.value();
let actual_excess_sui = if (actual_balance >= excess_sui) {
    excess_sui
} else {
    actual_balance
};
let sui = staker.sui_balance.split(actual_excess_sui);
```

2. **For `withdraw()`**: Similarly adjust to split only the available amount:

```move
// After line 90 (unstake operation)  
let actual_available = staker.sui_balance.value();
let actual_withdraw = min(withdraw_amount, actual_available);
let sui = staker.sui_balance.split(actual_withdraw);
```

3. **Add invariant check in `unstake_n_sui()`**: Document that the function may return slightly less than requested and return the actual amount:

```move
fun unstake_n_sui(...): u64 { // returns actual amount unstaked
    // existing logic
    let sui_before = staker.sui_balance.value();
    // ... unstake and join ...
    let sui_after = staker.sui_balance.value();
    sui_after - sui_before // return actual amount added
}
```

**Test Cases:**
- Simulate tight validator liquidity where `split_n_sui` invokes tolerance adjustment
- Test `claim_fees()` when unstaking returns less than requested
- Test `withdraw()` with various balance/unstake combinations
- Verify operations succeed with adjusted amounts rather than panicking

### Proof of Concept

**Initial State:**
- Staker has 500 SUI in `sui_balance`
- Staker has 1000 LST in `lst_balance` representing ~1000 SUI of staked value
- Total liabilities: 500 SUI
- Validator pools have exactly 499.999999990 SUI liquid (rest is locked in stakes)

**Exploitation Steps:**

1. Call `claim_fees()`
2. Calculates `excess_sui = 1000 - 500 - 1 = 499 SUI` (simplified example)
3. Check at line 147: `499 > 500` is false, so initially might not trigger
4. Adjust example: total_sui_supply = 1500, liabilities = 500
5. `excess_sui = 1500 - 500 - 1 = 999 SUI`
6. Line 147: `999 > 500` → true
7. Line 149: calls `unstake_n_sui(system_state, 499, ctx)`
8. `unstake_n_sui` calculates LST to redeem and calls liquid_staking::redeem()
9. `split_n_sui()` tries to get 499 SUI but pool only has 498.999999990 available
10. Tolerance check: `499 - 498.999999990 = 0.000000010 SUI (10 mist) ≤ ACCEPTABLE_MIST_ERROR`
11. Returns 498.999999990 SUI instead of panicking
12. `sui_balance` becomes `500 + 498.999999990 = 998.999999990 SUI`
13. Line 152: attempts `sui_balance.split(999)` with only 998.999999990 available
14. **Result**: Transaction panics with insufficient balance error

**Expected vs Actual:**
- Expected: Function should either succeed with adjusted amount or fail gracefully
- Actual: Transaction aborts, locking all subsequent `claim_fees()` calls until validator liquidity improves

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

**File:** liquid_staking/sources/validator_pool.move (L32-32)
```text
    const ACCEPTABLE_MIST_ERROR: u64 = 10;
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L843-862)
```text
        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});

        staker::deposit(staker, sui);
        staker::rebalance(staker, system_state, ctx);

        let fees = staker::claim_fees(staker, system_state, ctx);
        if (balance::value(&fees) > 0) {
            event::emit(ClaimStakingRewardsEvent {
                lending_market_id: object::id_to_address(&reserve.lending_market_id),
                coin_type: reserve.coin_type,
                reserve_id: object::uid_to_address(&reserve.id),
                amount: balance::value(&fees),
            });

            let balances: &mut Balances<P, SUI> = dynamic_field::borrow_mut(
                &mut reserve.id,
                BalanceKey {}
            );

            balance::join(&mut balances.fees, fees);
```
