### Title
Minimum Stake Amount Mismatch Causes SUI Deposits to Accumulate Without Earning Staking Yield

### Summary
The Suilend staker module defines `MIN_DEPLOY_AMOUNT` as 1,000,000 MIST (0.001 SUI), but the liquid staking system requires a minimum of 100,000,000 MIST (0.1 SUI) to stake. This 100x mismatch creates a dead zone where deposits between 0.001-0.1 SUI trigger staking attempts that abort, causing these funds to remain idle in the reserve without earning staking rewards, thereby reducing the overall APY for all depositors.

### Finding Description

The root cause is a configuration error in the minimum stake threshold: [1](#0-0) 

Despite the comment claiming "1 SUI", `MIN_DEPLOY_AMOUNT` is actually set to 1,000,000 MIST = 0.001 SUI. However, the liquid staking system enforces a much higher minimum: [2](#0-1) 

The liquid staking `stake()` function requires at least 0.1 SUI (100,000,000 MIST): [3](#0-2) 

The vulnerability manifests when `rebalance_staker` is called on a reserve with available SUI in the problematic range: [4](#0-3) 

The function withdraws ALL available SUI and deposits it to the staker, then calls `rebalance()`. The staker's rebalance logic checks if the balance exceeds the lower threshold: [5](#0-4) 

When `sui_balance` is between 0.001-0.1 SUI, the check at line 106 passes, so the function attempts to mint LST tokens. However, the underlying `liquid_staking_info.mint()` call enforces the 0.1 SUI minimum, causing the transaction to abort with `EUnderMinAmount`.

### Impact Explanation

**Economic Impact:**
- SUI deposits between 0.001-0.1 SUI cannot be staked and remain idle in the reserve's `available_amount`
- These funds earn lending yield from borrows but miss out on SUI staking rewards (typically 3-5% APY)
- All depositors in the reserve experience reduced overall APY proportional to the idle funds

**Who is Affected:**
- All users depositing to SUI reserves in Suilend
- The protocol itself loses competitiveness if APY is consistently lower than competitors

**Quantified Damage:**
For a reserve with 10,000 SUI total value and 0.099 SUI stuck in the dead zone:
- Loss: 0.099 SUI × 4% annual staking yield = 0.00396 SUI/year
- Relative impact: 0.00099% APY reduction

For smaller reserves or repeated occurrences, the impact compounds. Over time, as small deposits accumulate, this dead zone is frequently occupied, creating persistent APY drag.

### Likelihood Explanation

**Highly Probable - Occurs Naturally:**
- No attacker action required - small deposits naturally accumulate through normal user behavior
- Suilend has no minimum deposit requirement, allowing deposits of any size
- `rebalance_staker` is publicly callable via `lending_market::rebalance_staker()`
- The 0.099 SUI dead zone (0.001 to 0.1 SUI) is relatively wide given typical transaction amounts

**Execution Path:**
1. Users deposit small amounts of SUI (< 0.1 SUI) to the reserve
2. Available SUI accumulates in the reserve's `available_amount`
3. Anyone calls `rebalance_staker()` when balance is in dead zone
4. Transaction aborts, funds remain unstaked
5. Process repeats until enough deposits accumulate to exceed 0.1 SUI

**Constraints:**
- The issue self-resolves when deposits grow past 0.1 SUI
- Frequency depends on deposit patterns and reserve size
- No manipulation needed - happens organically

### Recommendation

**Immediate Fix:**
Correct the `MIN_DEPLOY_AMOUNT` constant to match or exceed the liquid staking minimum:

```move
const MIN_DEPLOY_AMOUNT: u64 = 100_000_000; // 0.1 SUI - matches liquid staking minimum
```

**Additional Safety Checks:**
Add a validation in `staker::rebalance()` to verify the amount meets the downstream requirement before attempting to mint:

```move
public(package) fun rebalance<P: drop>(
    staker: &mut Staker<P>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext,
) {
    staker.liquid_staking_info.refresh(system_state, ctx);
    
    let sui_value = staker.sui_balance.value();
    // Only attempt staking if we meet the liquid staking minimum
    if (sui_value < 100_000_000) { // 0.1 SUI minimum for liquid staking
        return
    };
    
    // ... rest of function
}
```

**Testing:**
- Add test case with deposits in the 0.001-0.1 SUI range
- Verify rebalancing succeeds without aborting
- Confirm all deposited SUI earns staking yield
- Test boundary conditions at exactly 0.1 SUI

### Proof of Concept

**Initial State:**
- Suilend lending market with SUI reserve initialized with staker
- Reserve has 0.05 SUI in `available_amount`

**Transaction Steps:**
1. User calls `lending_market::rebalance_staker(lending_market, sui_reserve_index, system_state, ctx)`
2. Function withdraws 0.05 SUI from reserve's `available_amount`
3. Deposits 0.05 SUI to `staker.sui_balance` 
4. Calls `staker::rebalance()`
5. Check passes: 0.05 SUI >= 0.001 SUI (`MIN_DEPLOY_AMOUNT`)
6. Attempts to mint LST via `liquid_staking_info.mint()` with 0.05 SUI
7. Liquid staking's `stake()` function checks: 0.05 SUI >= 0.1 SUI (`MIN_STAKE_AMOUNT`)
8. **Transaction aborts with `EUnderMinAmount` error**

**Expected Result:**
Transaction should succeed and stake the 0.05 SUI, or return early without attempting to stake.

**Actual Result:**
Transaction aborts, 0.05 SUI remains in reserve's `available_amount` without earning staking yield, reducing APY for all depositors.

**Success Condition for Exploit:**
The vulnerability is triggered whenever reserve's `available_amount` is between 0.001-0.1 SUI and `rebalance_staker()` is called - no attacker manipulation required.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L20-20)
```text
    const MIN_DEPLOY_AMOUNT: u64 = 1_000_000; // 1 SUI
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L106-117)
```text
        if (staker.sui_balance.value() < MIN_DEPLOY_AMOUNT) {
            return
        };

        let sui = staker.sui_balance.withdraw_all();
        let lst = staker
            .liquid_staking_info
            .mint(
                system_state,
                coin::from_balance(sui, ctx),
                ctx,
            );
```

**File:** liquid_staking/sources/stake_pool.move (L31-31)
```text
    const MIN_STAKE_AMOUNT: u64 = 1_00_000_000; // 0.1 SUI
```

**File:** liquid_staking/sources/stake_pool.move (L230-230)
```text
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L841-846)
```text
        let sui = balance::withdraw_all(&mut balances.available_amount);

        let staker: &mut Staker<SPRUNGSUI> = dynamic_field::borrow_mut(&mut reserve.id, StakerKey {});

        staker::deposit(staker, sui);
        staker::rebalance(staker, system_state, ctx);
```
