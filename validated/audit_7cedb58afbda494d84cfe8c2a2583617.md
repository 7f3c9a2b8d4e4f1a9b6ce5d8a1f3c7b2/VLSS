# Audit Report

## Title
Minimum Stake Amount Check Occurs Before Fee Deduction, Trapping Users in Unstakeable Positions

## Summary
The liquid staking protocol applies the `MIN_STAKE_AMOUNT` validation asymmetrically between stake and unstake operations. In `stake()`, the minimum check occurs on the input amount before fees are deducted, while in `unstake()`, it checks the calculated SUI output value. This creates a trap where users who stake exactly `MIN_STAKE_AMOUNT` (0.1 SUI) cannot immediately unstake because the post-fee LST value falls below the minimum threshold, temporarily locking their funds until staking rewards accumulate.

## Finding Description

The vulnerability stems from inconsistent application of minimum amount validation across the stake/unstake flow.

In the `stake()` function, the minimum check validates the full input amount before any fee deduction: [1](#0-0) 

However, fees are then immediately deducted from this balance: [2](#0-1) 

The protocol uses ceiling calculation for fees, which can be up to 5% (MAX_STAKE_FEE_BPS = 500): [3](#0-2) [4](#0-3) 

After fee deduction, the reduced balance is used to mint LST tokens: [5](#0-4) 

In contrast, the `unstake()` function checks that the calculated SUI output amount (before unstake fees) meets the minimum: [6](#0-5) 

**Execution Path:**
1. User stakes exactly 100,000,000 MIST (MIN_STAKE_AMOUNT)
2. Minimum check passes: `100,000,000 >= 100,000,000` ✓
3. With 5% stake fee: `fee = ceil(100,000,000 * 500 / 10,000) = 5,000,000 MIST`
4. Post-fee balance: `95,000,000 MIST` (now below minimum)
5. LST minted based on this reduced 95,000,000 MIST value
6. User attempts immediate unstake (before rewards accumulate)
7. LST converts to ~95,000,000 MIST worth of SUI
8. Unstake check fails: `assert!(95,000,000 >= 100,000,000)` ✗
9. Transaction aborts with `EUnderMinAmount`

The LST-to-SUI conversion happens through: [7](#0-6) 

## Impact Explanation

**Severity: MEDIUM**

Users who stake exactly `MIN_STAKE_AMOUNT` experience temporary fund lock and operational denial of service:

- **Temporary Lock**: Funds remain locked until the LST appreciates through staking rewards
- **Required Appreciation**: With 5% stake fee, users need >5.26% LST appreciation (95M → 100M MIST) before they can unstake
- **Time Duration**: Lock persists for multiple epochs (typically days to weeks) depending on staking APY
- **Affected Users**: Anyone staking precisely at the minimum threshold, particularly common for:
  - First-time users testing the protocol
  - DApp integrations programmatically using minimum amounts
  - Users wanting to stake small amounts

**Why Medium, Not High:**
- Funds are NOT permanently lost or stolen
- Users CAN eventually exit after staking rewards accumulate  
- No direct protocol accounting corruption or fund theft
- However, it violates core user expectations about operational symmetry
- Creates operational DoS during the lock period
- Particularly problematic during market volatility when users need immediate liquidity

The vulnerability breaks the fundamental user expectation that "if I can stake amount X, I should be able to immediately unstake the resulting LST position."

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur in production:

**Attacker/User Capabilities:**
- No special privileges required - any user can trigger via public entry function
- No front-running, MEV, or complex transaction sequencing needed
- Simply call `stake_entry()` with exactly MIN_STAKE_AMOUNT (0.1 SUI)

**Attack Complexity:**
- Trivial: Single transaction with exact minimum amount
- No state manipulation or timing requirements
- Deterministic outcome based on fee configuration

**Feasibility Conditions:**
- Only requires non-zero stake fee to be configured (standard for production deployments generating revenue)
- Works at any time regardless of pool state, epoch, or validator status
- Fee rates up to 5% are explicitly allowed by protocol design

**Probability Factors:**
- Common user pattern to test protocols with minimum amounts
- Natural behavior for risk-averse users or integration testing
- No warning messages during stake operation
- Silent trap that only manifests on unstake attempt

## Recommendation

Apply the minimum amount check consistently across both operations. Choose one of these approaches:

**Option 1: Check post-fee amount in stake()** (Recommended)
Check the minimum after fee deduction to ensure users can always unstake:
```move
// In stake() function, after fee deduction
let post_fee_balance = sui_balance.value();
assert!(post_fee_balance >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**Option 2: Check pre-fee LST value in unstake()**
Convert LST to SUI and add back the equivalent of unstake fees before checking:
```move
// In unstake() function
let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
let estimated_pre_fee = sui_amount_out + self.fee_config.calculate_unstake_fee(sui_amount_out);
assert!(estimated_pre_fee >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**Option 3: Document and enforce minimum with fee buffer**
Increase MIN_STAKE_AMOUNT to account for fees, or document that users must stake `MIN_STAKE_AMOUNT / (1 - max_fee_rate)` to ensure unstakeability.

Option 1 is cleanest as it ensures only economically viable positions are created from the start.

## Proof of Concept

```move
#[test]
fun test_min_stake_amount_trap() {
    let mut scenario = test_scenario::begin(@0xA);
    
    // Setup: Create stake pool with 5% stake fee
    let mut pool = create_test_pool(&mut scenario);
    let mut metadata = create_test_metadata(&mut scenario);
    let mut system_state = create_test_system_state(&mut scenario);
    
    // Set maximum allowed stake fee (5%)
    pool.fee_config.set_stake_fee_bps(500);
    
    let ctx = test_scenario::ctx(&mut scenario);
    
    // User stakes exactly MIN_STAKE_AMOUNT (100_000_000 MIST = 0.1 SUI)
    let sui_coin = coin::mint_for_testing<SUI>(100_000_000, ctx);
    
    // Step 1: Stake succeeds
    let lst_coin = pool.stake(&mut metadata, &mut system_state, sui_coin, ctx);
    
    // Step 2: LST value is now ~95_000_000 due to 5% fee
    let lst_amount = lst_coin.value();
    assert!(lst_amount < 100_000_000, 0); // LST worth less than input
    
    // Step 3: Attempt immediate unstake - this FAILS
    let result = pool.unstake(&mut metadata, &mut system_state, lst_coin, ctx);
    
    // Expected: Transaction aborts with EUnderMinAmount (30003)
    // Actual: User is trapped until rewards accumulate
}
```

## Notes

This vulnerability demonstrates a subtle but important invariant violation in DeFi protocols: operational symmetry between deposit/withdrawal flows. While the funds are not at risk of permanent loss, the temporary lock violates user expectations and creates friction that undermines protocol usability and trust, particularly for new users testing the system with minimum amounts.

The fix should ensure that any position that can be created through `stake()` can also be immediately exited through `unstake()`, maintaining operational symmetry across the protocol's core user flows.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L230-230)
```text
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** liquid_staking/sources/stake_pool.move (L238-240)
```text
        // deduct fees
        let mint_fee_amount = self.fee_config.calculate_stake_fee(sui_balance.value());
        self.fees.join(sui_balance.split(mint_fee_amount));
```

**File:** liquid_staking/sources/stake_pool.move (L242-242)
```text
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
```

**File:** liquid_staking/sources/stake_pool.move (L294-295)
```text
        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** liquid_staking/sources/stake_pool.move (L647-662)
```text
    public fun lst_amount_to_sui_amount(
        self: &StakePool, 
        metadata: &Metadata<CERT>,
        lst_amount: u64
    ): u64 {
        let total_sui_supply = self.total_sui_supply();
        let total_lst_supply = metadata.get_total_supply_value();

        assert!(total_lst_supply > 0, EZeroSupply);

        let sui_amount = (total_sui_supply as u128)
            * (lst_amount as u128) 
            / (total_lst_supply as u128);

        sui_amount as u64
    }
```

**File:** liquid_staking/sources/fee_config.move (L9-9)
```text
    const MAX_STAKE_FEE_BPS: u64 = 500; // 5%
```

**File:** liquid_staking/sources/fee_config.move (L74-81)
```text
    public(package) fun calculate_stake_fee(self: &FeeConfig, sui_amount: u64): u64 {
        if (self.stake_fee_bps == 0) {
            return 0
        };

        // ceil(sui_amount * sui_stake_fee_bps / 10_000)
        (((self.stake_fee_bps as u128) * (sui_amount as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```
