# Audit Report

## Title
Redemption Return Mismatch Causes Withdrawal and Fee Claim Failures Due to Unaccounted Fees and Rounding

## Summary
The `unstake_n_sui()` function in the Suilend staker module fails to account for unstake fees (up to 5%) and rounding errors (up to 10 MIST) that are deducted by the liquid staking protocol during LST redemption. This causes legitimate withdrawals and fee claims to abort when they attempt to split more SUI than is actually available in the balance.

## Finding Description

The vulnerability exists in the interaction between `unstake_n_sui()` and its callers (`withdraw()` and `claim_fees()`) in the Staker module. [1](#0-0) 

In `unstake_n_sui()`, the function calculates the LST amount to redeem using ceiling division to ensure sufficient LST is burned for the target `sui_amount_out`. However, when it calls `liquid_staking::redeem()` (which internally calls the `unstake()` function in the liquid staking protocol), the actual SUI returned is reduced by fees.

The liquid staking protocol's `unstake()` function deducts fees from the redeemed SUI: [2](#0-1) 

Specifically, the fee deduction occurs at: [3](#0-2) 

The unstake fee can be up to 5% (500 bps) as defined by the fee caps: [4](#0-3) 

Additionally, the `split_n_sui()` function can return up to 10 MIST less than requested due to acceptable rounding tolerance: [5](#0-4) 

Where `ACCEPTABLE_MIST_ERROR` is defined as: [6](#0-5) 

The critical failure occurs in the `withdraw()` function: [7](#0-6) 

When `sui_balance` is insufficient (line 88), it calls `unstake_n_sui(unstake_amount)` expecting to receive at least `unstake_amount` in SUI. However, if fees are deducted, `sui_balance` will be short of the required amount, causing the subsequent `split(withdraw_amount)` at line 93 to abort with insufficient balance.

The same issue affects `claim_fees()`: [8](#0-7) 

## Impact Explanation

**Direct Operational Impact (DoS):**
- Legitimate user withdrawals fail when unstake fees are configured or rounding errors occur
- Fee collection by the protocol fails, preventing administrators from claiming protocol revenue  
- With even a 1% unstake fee, any withdrawal requiring unstaking will systematically fail

**Quantified Damage:**
If `unstake_fee_bps = 100` (1%), attempting to withdraw 1000 SUI when `sui_balance` has 100 SUI:
- Needs to unstake: 900 SUI
- After 1% fee: receives ~891 SUI  
- Total balance: 100 + 891 = 991 SUI
- Attempts to split 1000 SUI → **TRANSACTION ABORTS**

With maximum 5% fee, the shortfall is even more severe (900 SUI needed, ~855 SUI received).

**Who is Affected:**
- All users attempting withdrawals when the staker needs to unstake LST
- Protocol administrators unable to claim accumulated fees
- The Suilend integration becomes effectively unusable when fees are enabled

## Likelihood Explanation

**Reachable Entry Point:**
The `withdraw()` function is `public(package)` and called during normal Suilend reserve operations, making this reachable through standard protocol usage without requiring any special permissions.

**Feasible Preconditions:**
- Unstake fees are enabled (configurable up to 5%)
- User requests a withdrawal larger than current `sui_balance`  
- This is a common scenario in normal operation

**Execution Practicality:**
The issue is deterministic and occurs automatically whenever:
1. Unstake fees are non-zero (any value from 0.01% to 5%)
2. Withdrawal requires unstaking LST to meet the amount
3. No special attacker actions needed - legitimate users are affected

**Economic Rationality:**
This is not an attack but a logic error that manifests during normal operations. The likelihood is **HIGH** because it occurs naturally whenever fees are configured.

## Recommendation

Modify `unstake_n_sui()` to account for fees and rounding errors by unstaking slightly more than needed, or adjust the callers to handle the shortfall:

**Option 1: Adjust `unstake_n_sui()` to over-unstake**
```move
fun unstake_n_sui<P: drop>(
    staker: &mut Staker<P>,
    system_state: &mut SuiSystemState,
    sui_amount_out: u64,
    ctx: &mut TxContext,
) {
    if (sui_amount_out == 0) {
        return
    };
    
    // Account for maximum fee (5%) and rounding error (10 MIST)
    let sui_amount_with_buffer = sui_amount_out + (sui_amount_out * 500 / 10000) + 10;
    
    let total_sui_supply = (staker.liquid_staking_info.total_sui_supply() as u128);
    let total_lst_supply = (staker.liquid_staking_info.total_lst_supply() as u128);
    
    let lst_to_redeem = 
        ((sui_amount_with_buffer as u128) * total_lst_supply + total_sui_supply - 1) / total_sui_supply;
    // ... rest of the function
}
```

**Option 2: Adjust callers to handle actual received amount**
```move
public(package) fun withdraw<P: drop>(
    staker: &mut Staker<P>,
    withdraw_amount: u64,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext,
): Balance<SUI> {
    staker.liquid_staking_info.refresh(system_state, ctx);
    
    if (withdraw_amount > staker.sui_balance.value()) {
        let unstake_amount = withdraw_amount - staker.sui_balance.value();
        let balance_before = staker.sui_balance.value();
        staker.unstake_n_sui(system_state, unstake_amount, ctx);
        let actual_received = staker.sui_balance.value() - balance_before;
        
        // Adjust withdraw_amount to actual available
        withdraw_amount = withdraw_amount.min(staker.sui_balance.value());
    };
    
    let sui = staker.sui_balance.split(withdraw_amount);
    staker.liabilities = staker.liabilities - sui.value();
    
    sui
}
```

## Proof of Concept

```move
#[test]
fun test_withdrawal_fails_with_fees() {
    let mut scenario = test_scenario::begin(@0xA);
    
    // Setup: Create staker with 100 SUI in sui_balance and LST tokens
    let mut staker = create_test_staker(&mut scenario);
    deposit(&mut staker, balance::create_for_testing(100_000_000_000)); // 100 SUI
    
    // Setup: Configure 1% unstake fee in liquid staking protocol
    setup_liquid_staking_with_fee(1, &mut scenario); // 1% fee
    
    // Stake some SUI to get LST tokens  
    rebalance(&mut staker, &mut system_state, &mut scenario);
    
    // User attempts to withdraw 1000 SUI (needs to unstake 900 SUI)
    // Expected: Transaction should succeed
    // Actual: Transaction aborts because only ~891 SUI is received after 1% fee
    let sui = withdraw(&mut staker, 1000_000_000_000, &mut system_state, &mut scenario);
    // ^ This line will ABORT with insufficient balance error
    
    test_scenario::end(scenario);
}
```

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

**File:** liquid_staking/sources/stake_pool.move (L280-333)
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

**File:** liquid_staking/sources/fee_config.move (L8-8)
```text
    const MAX_UNSTAKE_FEE_BPS: u64 = 500; // 5%
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
