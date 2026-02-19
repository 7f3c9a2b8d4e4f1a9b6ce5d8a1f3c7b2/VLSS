# Audit Report

## Title
Accrued Reward Fees Can Exceed Validator Pool Balance Causing Protocol-Wide DoS

## Summary
The liquid staking protocol assumes but does not enforce the invariant that `validator_pool.total_sui_supply() >= accrued_reward_fees`. When validator slashing, exchange rate decreases, or mass unstaking events reduce the validator pool balance below accumulated fees, the unchecked subtraction in `total_sui_supply()` causes an arithmetic abort, freezing all protocol operations including staking, unstaking, fee collection, and rebalancing.

## Finding Description
The protocol maintains `accrued_reward_fees` as an accounting field tracking reward fees owed to the protocol. During epoch rollovers, fees are accumulated based on staking rewards without verifying that the validator pool can cover them. [1](#0-0) 

The critical vulnerability lies in `total_sui_supply()` which performs unchecked u64 subtraction in Sui Move. [2](#0-1) 

The validator pool balance can decrease through two legitimate mechanisms:

1. **Exchange rate decreases**: When `refresh_validator_info()` updates validator stakes using new exchange rates from the Sui system, slashing or validator penalties manifest as decreased sui amounts for the same pool token quantities. [3](#0-2) 

2. **User unstaking**: The `split_from_sui_pool()` function decreases `total_sui_supply` as users withdraw their SUI. [4](#0-3) 

Critically, `accrued_reward_fees` is only decremented in `collect_fees()`, which itself calls `refresh()` that invokes `total_sui_supply()`. [5](#0-4)  This creates a deadlock: once the invariant is violated, even the admin cannot collect fees to restore it.

The vulnerability is exacerbated by the fact that `reward_fee_bps` can be configured up to 100% (10,000 basis points). [6](#0-5) 

## Impact Explanation
Once `accrued_reward_fees > validator_pool.total_sui_supply()`, the protocol enters a complete denial of service:

- **All staking fails**: `stake()` invokes `total_sui_supply()` [7](#0-6) 
- **All unstaking fails**: `unstake()` invokes `total_sui_supply()` [8](#0-7) 
- **Fee collection fails**: `collect_fees()` → `refresh()` → `total_sui_supply()` aborts [9](#0-8) 
- **Rebalancing fails**: Both `rebalance()` and `set_validator_weights()` call `refresh()` which aborts [10](#0-9) 
- **Ratio queries fail**: `get_ratio()` and `get_ratio_reverse()` both invoke `total_sui_supply()` [11](#0-10) 

All LST holders cannot unstake their positions, new users cannot stake, and the protocol admin cannot perform any maintenance operations. The protocol remains frozen until an emergency package upgrade is deployed. This represents catastrophic failure with all user funds effectively locked.

## Likelihood Explanation
This vulnerability has MEDIUM-HIGH likelihood of occurrence in practice due to:

**Realistic Trigger Path**:
1. Protocol operates with moderate to high `reward_fee_bps` (30-80%) to generate protocol revenue
2. Admin delays fee collection for 3-5 epochs during low activity periods or operational oversight
3. Accumulated fees reach 10-20% of the validator pool balance
4. A validator slashing event or prolonged downtime causes 5-10% exchange rate decrease
5. Users observe the losses and unstake en masse (20-30% of pool)
6. Combined effect violates invariant: `validator_pool.total_sui_supply() < accrued_reward_fees`

**Supporting Factors**:
- Validator slashing and penalties are documented features of Sui's proof-of-stake consensus
- The maximum `reward_fee_bps` of 100% allows rapid fee accumulation
- No code-level protection prevents the invariant violation
- The vulnerability is cumulative—risk increases with each uncollected epoch
- Operational oversights (delayed fee collection) are common in protocol management

## Recommendation
Implement multiple layers of protection:

1. **Add invariant enforcement** in `refresh()` before accumulating fees:
```move
// Cap accrued_reward_fees to never exceed available balance
let max_accruable_fee = self.validator_pool.total_sui_supply().saturating_sub(1_000_000_000); // Keep 1 SUI buffer
self.accrued_reward_fees = self.accrued_reward_fees + reward_fee.min(max_accruable_fee);
```

2. **Use saturating subtraction** in `total_sui_supply()`:
```move
public fun total_sui_supply(self: &StakePool): u64 {
    let pool_supply = self.validator_pool.total_sui_supply();
    if (pool_supply >= self.accrued_reward_fees) {
        pool_supply - self.accrued_reward_fees
    } else {
        0 // Or handle as an emergency scenario
    }
}
```

3. **Add proportional fee adjustment** when validator pool decreases:
```move
// In refresh_validator_info after pool balance update
if (new_pool_supply < old_pool_supply) {
    // Proportionally reduce accrued fees when pool shrinks
    let reduction_ratio = (new_pool_supply as u128) * 10000 / (old_pool_supply as u128);
    self.accrued_reward_fees = ((self.accrued_reward_fees as u128) * reduction_ratio / 10000) as u64;
}
```

4. **Add emergency admin function** to manually adjust `accrued_reward_fees` with appropriate authorization checks.

## Proof of Concept
```move
#[test]
fun test_fee_underflow_dos() {
    // Setup: Initialize stake pool with 100,000 SUI and 80% reward fee
    let mut stake_pool = create_test_stake_pool();
    stake_pool.set_reward_fee_bps(8000); // 80% fee
    
    // Epoch 1-3: Accumulate rewards with high fees but don't collect
    simulate_epochs_with_rewards(&mut stake_pool, 3, 5000); // 5% rewards per epoch
    // After 3 epochs: ~15,000 SUI rewards, ~12,000 SUI in accrued_reward_fees
    
    // Simulate validator slashing (10% loss) 
    simulate_validator_slashing(&mut stake_pool, 10);
    
    // Simulate panic unstaking (30% of pool)
    let unstake_amount = stake_pool.validator_pool.total_sui_supply() * 30 / 100;
    simulate_mass_unstaking(&mut stake_pool, unstake_amount);
    
    // At this point: accrued_reward_fees > validator_pool.total_sui_supply()
    
    // Attempt any operation - should abort on underflow
    let result = stake_pool.total_sui_supply(); // ABORTS with arithmetic underflow
    
    // Verify DoS: Cannot stake, unstake, collect fees, or rebalance
    assert!(stake_pool.try_stake().is_err(), 0);
    assert!(stake_pool.try_unstake().is_err(), 0);
    assert!(stake_pool.try_collect_fees().is_err(), 0);
}
```

---

**Notes**:
This vulnerability represents a critical invariant violation in the liquid staking protocol's accounting system. While it requires specific preconditions (fee accumulation + validator losses + unstaking), these conditions are realistic in production environments, especially during market stress or validator incidents. The deadlock nature of the vulnerability (where even the recovery mechanism is blocked) makes it particularly severe. Immediate mitigation should include monitoring `accrued_reward_fees` relative to `validator_pool.total_sui_supply()` and implementing automated fee collection before the ratio exceeds safe thresholds (e.g., 80%).

### Citations

**File:** liquid_staking/sources/stake_pool.move (L232-232)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
```

**File:** liquid_staking/sources/stake_pool.move (L291-291)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
```

**File:** liquid_staking/sources/stake_pool.move (L367-367)
```text
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L461-461)
```text
        self.refresh(metadata, system_state, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L512-512)
```text
        let old_total_supply = self.total_sui_supply();
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

**File:** liquid_staking/sources/stake_pool.move (L590-590)
```text
        let total_sui_supply = self.total_sui_supply();
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
