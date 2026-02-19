# Audit Report

## Title
Unstake Fee Not Accounted For in claim_fees() Causes Transaction Abort at Epoch Boundaries

## Summary
The `claim_fees()` function in the Suilend staker contains a critical logic error where it fails to account for unstake fees when redeeming LST tokens. When staking rewards accrue at epoch boundaries and require unstaking LST to collect fees, the transaction aborts due to insufficient SUI balance, permanently blocking fee collection until manual intervention.

## Finding Description

The vulnerability exists in the interaction between three components of the Suilend staker module:

**1. Fee Collection Flow**

The `claim_fees()` function calculates `excess_sui` based on the total SUI supply after rewards accrue [1](#0-0) . When `excess_sui` exceeds the current SUI balance, it calls `unstake_n_sui()` to redeem the shortfall, then attempts to split `excess_sui` from the balance.

**2. LST Redemption Calculation**

The `unstake_n_sui()` function calculates the LST tokens to redeem using ceiling division based on the exchange rate [2](#0-1) . The formula assumes that redeeming the calculated LST amount will yield exactly `sui_amount_out` SUI, but it does NOT account for the unstake fee that will be deducted.

**3. Fee Deduction in Unstake**

The liquid staking `unstake()` function retrieves SUI from validators, then deducts the unstake fee before returning [3](#0-2) . This fee can be configured up to 500 basis points (5%) [4](#0-3) .

**Root Cause Analysis:**

The `unstake_n_sui()` calculation at lines 177-178 uses:
```
lst_to_redeem = ceil(sui_amount_out * total_lst_supply / total_sui_supply)
```

This assumes the gross exchange rate will be maintained after redemption. However, the `unstake()` function at lines 300-308 deducts fees:
```
redeem_fee_amount = calculate_unstake_fee(sui.value())
fee = sui.split(redeem_fee_amount)
```

The actual SUI received is therefore `sui_amount_out - redeem_fee_amount`, creating a shortfall. When `claim_fees()` attempts to split `excess_sui` at line 152, the transaction aborts with insufficient balance.

The ceiling division in `unstake_n_sui()` only compensates for rounding errors in the exchange rate, not the systematic fee deduction that occurs during every redemption.

## Impact Explanation

**Denial of Service - Critical Operational Function**

This vulnerability causes a complete denial of service for the fee collection mechanism:

1. **Automatic Trigger**: When staking rewards accrue at epoch boundaries (every ~24 hours on Sui), `total_sui_supply()` increases
2. **Blocking Condition**: If the increase requires unstaking LST to collect fees, and any non-zero unstake fee is configured, the transaction will abort
3. **Permanent Block**: Fee collection remains blocked until either:
   - The unstake fee is set to zero (requires admin action)
   - Manual intervention to rebalance the staker's SUI/LST holdings
4. **Invariant Violation**: The invariant check at line 154 never executes, as the transaction aborts before reaching it

**Severity Justification - HIGH:**
- Reliably DoS's a core protocol operation (fee collection)
- Triggered automatically by normal protocol operation (epoch progression + rewards)
- No attacker action required - this is an inherent logic bug
- Affects operational integrity and protocol revenue collection
- With maximum 5% fee, even small unstaking amounts create significant shortfalls

**Affected Parties:**
- Suilend protocol cannot collect earned fees from the staker
- Protocol revenue is locked until manual remediation
- Operational maintenance becomes more complex and error-prone

## Likelihood Explanation

**Likelihood Assessment: HIGH**

**Reachable Entry Point:**
The `claim_fees()` function is declared as `public(package)` [5](#0-4) , making it callable by the protocol for routine fee collection.

**Feasible Preconditions:**
1. The liquid staking pool has `unstake_fee_bps > 0` configured - this is a normal operational parameter
2. Staking rewards accrue at epoch boundaries - this happens automatically on Sui
3. The staker holds most assets in LST rather than SUI buffer - this is the expected state for capital efficiency
4. The reward amount is sufficient that `excess_sui > sui_balance.value()` - very common scenario

**Execution Practicality:**
- No malicious actor required - bug manifests during normal operations
- Epoch boundaries occur automatically every ~24 hours
- Staking rewards accrue naturally from Sui validators
- Even a 1 basis point (0.01%) fee will trigger the issue
- The bug is deterministic given the preconditions

**Probability Assessment:**
Once unstake fees are enabled (a standard protocol configuration), this bug will manifest at virtually every epoch boundary where rewards are sufficient to require unstaking. This makes it a near-certain occurrence under normal operational conditions.

## Recommendation

Modify the `unstake_n_sui()` function to account for unstake fees when calculating the LST redemption amount. The fix should:

1. **Query the fee configuration** before calculating LST to redeem
2. **Calculate the gross amount needed** to receive the desired net SUI after fees
3. **Apply the adjusted calculation**:

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

    let total_sui_supply = (staker.liquid_staking_info.total_sui_supply() as u128);
    let total_lst_supply = (staker.liquid_staking_info.total_lst_supply() as u128);
    
    // Get the unstake fee rate
    let fee_bps = staker.liquid_staking_info.fee_config().unstake_fee_bps();
    
    // Calculate gross amount needed to receive sui_amount_out after fees
    // gross_amount = sui_amount_out / (1 - fee_rate)
    // gross_amount = sui_amount_out * 10000 / (10000 - fee_bps)
    let gross_sui_needed = ((sui_amount_out as u128) * 10000) / (10000 - (fee_bps as u128));
    
    // ceil lst redemption amount based on gross amount
    let lst_to_redeem = (gross_sui_needed * total_lst_supply + total_sui_supply - 1) / total_sui_supply;
    
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

This ensures the staker receives at least `sui_amount_out` SUI after fee deduction, preventing the balance shortfall in `claim_fees()`.

## Proof of Concept

```move
#[test]
fun test_claim_fees_unstake_fee_abort() {
    let mut scenario = test_scenario::begin(@0x1);
    let ctx = scenario.ctx();
    
    // Setup: Create staker with treasury cap
    let treasury_cap = create_treasury_for_testing<SPRUNGSUI>(ctx);
    let mut staker = create_staker(treasury_cap, ctx);
    
    // Configure unstake fee to 100 bps (1%)
    staker.liquid_staking_info.fee_config_mut().set_unstake_fee_bps(100);
    
    // Setup initial state: deposit SUI and stake it to LST
    let initial_sui = balance::create_for_testing<SUI>(1_000_000_000); // 1 SUI
    staker.deposit(initial_sui);
    staker.rebalance(&mut system_state, ctx);
    
    // Simulate epoch boundary with rewards (10% APY)
    // This increases total_sui_supply
    simulate_staking_rewards(&mut staker.liquid_staking_info, 100_000_000); // 0.1 SUI reward
    
    // Now staker has:
    // - liabilities: 1 SUI
    // - total_sui_supply: 1.1 SUI (1 SUI + 0.1 reward)
    // - sui_balance: ~0 SUI (all staked to LST)
    // - excess_sui should be ~0.099 SUI (1.1 - 1 - 0.001 buffer)
    
    // Attempt to claim fees - this will abort due to insufficient balance
    let fees = staker.claim_fees(&mut system_state, ctx);
    // Expected: Transaction aborts at sui_balance.split(excess_sui)
    // Actual SUI received from unstake = 0.099 - (0.099 * 0.01) = 0.09801 SUI
    // Shortfall = 0.099 - 0.09801 = 0.00099 SUI
    
    balance::destroy_for_testing(fees);
    destroy_staker_for_testing(staker);
    scenario.end();
}
```

The test demonstrates that when `claim_fees()` attempts to collect fees after rewards accrue, the transaction aborts because `unstake_n_sui()` doesn't account for the 1% unstake fee, resulting in a balance shortfall.

### Citations

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
