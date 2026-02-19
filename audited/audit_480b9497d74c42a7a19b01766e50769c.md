### Title
Hardcoded Validator Address Creates Irrecoverable Staking Risk in Suilend Staker Module

### Summary
The Suilend staker module hardcodes a single validator address (`SUILEND_VALIDATOR`) that receives all staked SUI, with no mechanism to change validators without a smart contract upgrade. If this validator becomes malicious, jailed, or changes to 0% commission, all staked assets lose rewards or face liquidity issues with no recovery path.

### Finding Description

The `SUILEND_VALIDATOR` address is hardcoded as a constant in the staker module: [1](#0-0) 

This hardcoded validator is used exclusively in the `rebalance()` function, which stakes all available SUI to this single validator with maximum amount (`U64_MAX`): [2](#0-1) 

The `Staker` struct holds an `AdminCap<P>` from the liquid_staking module: [3](#0-2) 

However, the staker module exposes NO public or package functions that allow:
1. Accessing or using the stored `AdminCap` for validator management
2. Calling the liquid_staking module's `set_validator_weights` function
3. Minting an `OperatorCap` (which the `AdminCap` could do)
4. Changing the hardcoded validator address

The only exposed staker functions are: [4](#0-3) [5](#0-4) 

While the underlying liquid_staking module supports multi-validator staking and weight management through `set_validator_weights`: [6](#0-5) 

And the `AdminCap` can mint `OperatorCap` for validator management: [7](#0-6) 

These capabilities are completely inaccessible from the Suilend staker module due to the lack of wrapper functions.

The `rebalance_staker` function in the reserve module calls the staker's `rebalance()` with no validator selection: [8](#0-7) 

### Impact Explanation

**Direct Financial Impact:**
- If the validator has 0% commission or reduces commission significantly, all staked SUI (potentially millions of dollars) loses staking rewards (typically 3-5% APY)
- If the validator is jailed or becomes inactive, the liquid_staking module will automatically unstake inactive validators on epoch refresh, but the very next `rebalance_staker` call will immediately restake to the same validator, creating a perpetual cycle of staking/unstaking with associated transaction costs and loss of rewards

**Operational Impact:**
- If the validator becomes malicious or has degraded performance, there is no mechanism to migrate funds to a healthier validator
- The only recovery mechanism is a smart contract upgrade, which requires coordination, testing, and deployment time during which funds remain at risk
- Users withdrawing from the Suilend reserve may face delays if the validator is jailed and unstaking periods apply

**Who is Affected:**
All users who deposit SUI into Suilend reserves that utilize this staker module for yield generation.

**Severity Justification:**
High severity due to:
1. Systematic risk affecting all staked funds
2. No recovery mechanism short of contract upgrade
3. Loss of material value (3-5% APY on potentially significant TVL)
4. Violation of best practices for decentralized staking (single validator dependency)

### Likelihood Explanation

**No Attacker Required:**
This is not an exploit requiring malicious action—it's a design flaw that creates systematic risk. The risk materializes if:
1. The validator decides to change commission to 0% (their prerogative)
2. The validator gets jailed due to downtime or misbehavior (happens periodically on Sui network)
3. The validator becomes compromised or acts maliciously
4. The validator's performance degrades relative to other validators

**Feasibility:**
Validator behavior changes are common in Proof-of-Stake networks:
- Commission changes are routine operational decisions
- Jailing occurs when validators fail to meet performance requirements
- Validator performance varies based on hardware, network, and operational practices

**Detection:**
The issue is immediately observable—every `rebalance()` call stakes to the same hardcoded validator, visible on-chain. However, there's no mitigation available even after detection.

**Probability:**
Given the long-term nature of staking protocols and the frequency of validator operational changes in PoS networks, the probability of the hardcoded validator experiencing issues (commission changes, jailing, or degraded performance) over the protocol's lifetime is HIGH.

### Recommendation

**Immediate Fix:**
Add validator management functions to the staker module that expose the underlying liquid_staking capabilities:

```move
// Add to staker.move module
public(package) fun set_validator_weights<P: drop>(
    staker: &mut Staker<P>,
    validator_weights: VecMap<address, u64>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext
) {
    // Mint OperatorCap using the stored AdminCap
    let operator_cap = liquid_staking::mint_operator_cap(
        &mut staker.liquid_staking_info,
        &staker.admin,
        ctx.sender(),
        ctx
    );
    
    // Call set_validator_weights
    liquid_staking::set_validator_weights(
        &mut staker.liquid_staking_info,
        &operator_cap,
        validator_weights,
        system_state,
        ctx
    );
    
    // Destroy or store the operator_cap
}
```

**Alternative Approach:**
Instead of hardcoding the validator, pass it as a parameter or store it as mutable state:

```move
public struct Staker<phantom P> has store {
    admin: AdminCap<P>,
    liquid_staking_info: LiquidStakingInfo<P>,
    lst_balance: Balance<P>,
    sui_balance: Balance<SUI>,
    liabilities: u64,
    // Add mutable validator address
    target_validator: address,
}
```

**Governance Integration:**
Expose these functions through the `LendingMarketOwnerCap` in reserve.move and lending_market.move to allow authorized validator management.

**Invariant Checks:**
- Add a requirement that the staker's validator is in the active validator set before rebalancing
- Implement health checks on validator performance (commission rate, uptime) before staking
- Add events when validator changes occur for monitoring

**Test Cases:**
1. Test validator change functionality works correctly
2. Test that staking fails gracefully if validator is jailed
3. Test that funds can be migrated from one validator to another
4. Test multi-validator distribution if supported

### Proof of Concept

**Initial State:**
1. Suilend reserve with initialized staker using `SUILEND_VALIDATOR` (`0xce8e...de89`)
2. SUI deposited into reserve
3. `rebalance_staker` called, staking SUI to the hardcoded validator

**Scenario 1: Validator Changes Commission to 0%**
1. Validator operator changes commission rate to 0% (their right as validator operator)
2. Time passes (epochs roll over)
3. All staking rewards go to validator, not to protocol or users
4. **Expected:** Protocol can change to different validator
5. **Actual:** No mechanism exists to change validator; funds continue staking to 0% commission validator indefinitely

**Scenario 2: Validator Gets Jailed**
1. Validator fails to meet uptime requirements and gets jailed by Sui system
2. Liquid staking's `refresh()` automatically unstakes from jailed validator
3. User deposits more SUI, triggering `rebalance_staker()`
4. `rebalance()` is called, which stakes to hardcoded validator again
5. **Expected:** Funds stake to active, healthy validator
6. **Actual:** Funds stake back to jailed validator, get immediately unstaked, creating wasteful cycle

**Success Condition:**
Demonstrate that once the validator address is set at deployment, there exists no transaction sequence (using available public/package functions) that can change the staking destination to a different validator address, regardless of who signs the transaction (admin, operator, or owner).

### Notes

This vulnerability is particularly concerning because:

1. **Defense in Depth Violation:** The underlying liquid_staking module HAS the capability for multi-validator management, but the Suilend integration layer doesn't expose it

2. **Single Point of Failure:** All staked funds depend on a single validator's continued good behavior and performance

3. **Upgrade-Only Recovery:** The only mitigation requires smart contract upgrade, deployment, and potential state migration—a slow and risky process during which funds remain exposed

4. **Time Sensitivity:** If the validator becomes jailed or malicious, every day of delay in upgrading the contract represents lost rewards or increased risk

The fix should be prioritized before significant TVL accumulates in the Suilend SUI reserve's staker.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L16-17)
```text
    const SUILEND_VALIDATOR: address =
        @0xce8e537664ba5d1d5a6a857b17bd142097138706281882be6805e17065ecde89;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L23-29)
```text
    public struct Staker<phantom P> has store {
        admin: AdminCap<P>,
        liquid_staking_info: LiquidStakingInfo<P>,
        lst_balance: Balance<P>,
        sui_balance: Balance<SUI>,
        liabilities: u64, // how much sui is owed to the reserve
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L54-97)
```text
    public(package) fun create_staker<P: drop>(
        treasury_cap: TreasuryCap<P>,
        ctx: &mut TxContext,
    ): Staker<P> {
        assert!(coin::total_supply(&treasury_cap) == 0, ETreasuryCapNonZeroSupply);

        let (admin_cap, liquid_staking_info) = liquid_staking::create_lst(
            fees::new_builder(ctx).to_fee_config(),
            treasury_cap,
            ctx,
        );

        Staker {
            admin: admin_cap,
            liquid_staking_info,
            lst_balance: balance::zero(),
            sui_balance: balance::zero(),
            liabilities: 0,
        }
    }

    public(package) fun deposit<P>(staker: &mut Staker<P>, sui: Balance<SUI>) {
        staker.liabilities = staker.liabilities + sui.value();
        staker.sui_balance.join(sui);
    }

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L99-129)
```text
    public(package) fun rebalance<P: drop>(
        staker: &mut Staker<P>,
        system_state: &mut SuiSystemState,
        ctx: &mut TxContext,
    ) {
        staker.liquid_staking_info.refresh(system_state, ctx);

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
        staker.lst_balance.join(lst.into_balance());

        staker
            .liquid_staking_info
            .increase_validator_stake(
                &staker.admin,
                system_state,
                SUILEND_VALIDATOR,
                U64_MAX,
                ctx,
            );
    }
```

**File:** liquid_staking/sources/stake_pool.move (L346-357)
```text
    public fun mint_operator_cap(
        self: &mut StakePool,
        _: &AdminCap,
        recipient: address,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        transfer::public_transfer(OperatorCap { id: object::new(ctx) }, recipient);
        emit(MintOperatorCapEvent {
            recipient
        });
    }
```

**File:** liquid_staking/sources/stake_pool.move (L452-471)
```text
    public fun set_validator_weights(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState,
        _: &OperatorCap,
        validator_weights: VecMap<address, u64>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        self.refresh(metadata, system_state, ctx);
        self.validator_pool.set_validator_weights(
            validator_weights,
            system_state,
            ctx
        );

        emit(ValidatorWeightsUpdateEvent {
            validator_weights
        });
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L831-867)
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
        }
        else {
            balance::destroy_zero(fees);
        };
    }
```
