### Title
Last Holder Exemption Enables Unfair Fee Extraction Through Account Splitting

### Summary
The unstake function's last holder condition exempts the final LST holder from paying redistribution fees while they benefit from all previous holders' redistribution payments. This asymmetry can be exploited by users splitting their holdings across multiple accounts, extracting approximately 0.25% additional value compared to single-account unstaking for typical fee configurations.

### Finding Description

The vulnerability exists in the `unstake()` function's redistribution fee calculation logic: [1](#0-0) 

When a user is the last LST holder (`total_lst_supply(metadata) == lst.value()`), the redistribution amount is set to zero. This means all of the `redeem_fee_amount` goes to protocol fees, with nothing returned to the pool. [2](#0-1) 

The redistribution fee mechanism is designed so that when users unstake, a portion of their fee goes back to the SUI pool, increasing the SUI/LST ratio and benefiting remaining LST holders. However, the last holder captures all previous redistribution benefits without reciprocating this payment. [3](#0-2) 

**Root Cause**: The conditional logic creates a unilateral advantage for the last holder position. While the intent may be to avoid redistributing when there are no beneficiaries, it creates an exploitable asymmetry in the fee structure.

**Why Existing Protections Fail**: 
- There are no restrictions on users splitting holdings across multiple accounts
- No minimum holder count requirements exist beyond the last holder check
- The ratio invariant checks focus on preventing value extraction from the pool itself, not on fee fairness [4](#0-3) 

### Impact Explanation

**Quantified Financial Advantage**:
For a user with total holdings of P SUI equivalent in LST, splitting into 2 accounts provides an additional extraction of approximately:
```
Advantage ≈ P × (1 - unstake_fee_bps/10000) × (unstake_fee_bps × unstake_fee_redistribution_bps / 200000000)
```

With realistic parameters (unstake_fee_bps = 100 (1%), unstake_fee_redistribution_bps = 5000 (50%)):
- 10,000 SUI position: ~24.75 SUI additional extraction (0.2475%)
- 100,000 SUI position: ~247.5 SUI additional extraction (0.2475%)

**Who Is Affected**:
- Early unstakers who pay redistribution fees that benefit later unstakers
- Protocol revenue is reduced (more goes to users, less to fees)
- The fee mechanism's intended fairness is violated

**Severity Justification**:
Medium severity because:
1. Requires coordination to become last holder (though feasible for large holders)
2. Percentage gain is relatively small but scales linearly with amount
3. Exploitable by rational actors without special privileges
4. Violates the fairness principle of the redistribution mechanism where all participants should contribute symmetrically

### Likelihood Explanation

**Attacker Capabilities**:
- Any user can create multiple accounts (no restrictions)
- Only requires standard unstaking operations via public entry functions
- No special privileges or trusted roles needed [5](#0-4) 

**Attack Complexity**: 
Low - The exploit path is straightforward:
1. User splits LST holdings across N accounts
2. Sequentially unstake from N-1 accounts (each pays redistribution)
3. Final account benefits from all redistribution but pays none

**Feasibility Conditions**:
- Attacker must orchestrate being the last holder (easier for large holders or during low adoption)
- Protocol must have `unstake_fee_redistribution_bps > 0` configured
- Minimal transaction costs make this economically viable for amounts > ~1,000 SUI

**Economic Rationality**:
The gain scales linearly with amount and requires only standard transaction fees as cost. For any substantial holding, the arbitrage is profitable.

### Recommendation

**Code-Level Mitigation**:
Modify the redistribution logic to ensure fair fee treatment for all unstakers, including the last holder:

```move
// Option 1: Always charge redistribution, redirect to protocol fees when last holder
let redistribution_amount = self.fee_config.calculate_unstake_fee_redistribution(redeem_fee_amount);
if(total_lst_supply(metadata) == lst.value()) {
    // Last holder: all fees go to protocol instead of pool
    self.fees.join(fee);
} else {
    // Normal case: split between protocol and redistribution
    let redistribution_fee = fee.split(redistribution_amount);
    self.fees.join(fee);
    self.join_to_sui_pool(redistribution_fee);
}

// Option 2: Track and enforce minimum redistribution contribution
// Add field to StakePool: accumulated_redistribution_debt
// Require final holder to pay accumulated debt before full exit
```

**Invariant Checks**:
Add validation that cumulative redistribution fees paid should be proportional to cumulative benefits received, preventing asymmetric extraction.

**Test Cases**:
1. Test scenario with 2 accounts splitting and sequential unstaking vs single account
2. Verify net extraction is equal in both cases
3. Add fuzzing tests with various fee configurations and holder counts

### Proof of Concept

**Initial State**:
- Pool: 200 SUI, 200 LST tokens
- User controls Account A (100 LST) and Account B (100 LST)
- Configuration: `unstake_fee_bps = 100` (1%), `unstake_fee_redistribution_bps = 5000` (50%)

**Attack Sequence**:

**Step 1 - Account A unstakes**:
- Calls `unstake_entry()` with 100 LST
- Receives 100 SUI (before fees)
- Pays 1 SUI fee, of which 0.5 SUI redistributed to pool
- Account A net: 99 SUI
- Pool state: 100.5 SUI, 100 LST (Account B only)
- New ratio: 1.005 SUI per LST

**Step 2 - Account B unstakes (last holder)**:
- Calls `unstake_entry()` with 100 LST
- Receives 100.5 SUI (benefits from improved ratio)
- Pays 1.005 SUI fee
- Redistribution amount = 0 (last holder condition triggered!)
- Account B net: 99.495 SUI
- Total received: 99 + 99.495 = 198.495 SUI

**Expected vs Actual Result**:

*Expected (fair fee structure)*: Single account unstaking 200 LST should receive 198 SUI (paying 2 SUI in fees)

*Actual (exploited)*: Same user via 2 accounts receives 198.495 SUI (effectively paying only 1.505 SUI in fees)

**Success Condition**: 
User extracts 0.495 SUI more than intended, representing half of the redistribution fee that Account A paid but Account B didn't reciprocate.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L267-278)
```text
    #[allow(lint(self_transfer))]
    public entry fun unstake_entry(
        self: &mut StakePool,
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        cert: Coin<CERT>,
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let sui = self.unstake(metadata, system_state, cert, ctx);
        transfer::public_transfer(sui, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L301-306)
```text
        let redistribution_amount = 
            if(total_lst_supply(metadata) == lst.value()) {
                0
            } else {
                self.fee_config.calculate_unstake_fee_redistribution(redeem_fee_amount)
            };
```

**File:** liquid_staking/sources/stake_pool.move (L308-312)
```text
        let mut fee = sui.split(redeem_fee_amount as u64);
        let redistribution_fee = fee.split(redistribution_amount);

        self.fees.join(fee);
        self.join_to_sui_pool(redistribution_fee);
```

**File:** liquid_staking/sources/stake_pool.move (L323-328)
```text
        // invariant: sui_out / lst_in <= old_sui_supply / old_lst_supply
        // -> sui_out * old_lst_supply <= lst_in * old_sui_supply
        assert!(
            (sui.value() as u128) * old_lst_supply <= (lst.value() as u128) * old_sui_supply,
            ERatio
        );
```

**File:** liquid_staking/sources/fee_config.move (L103-110)
```text
    public(package) fun calculate_unstake_fee_redistribution(self: &FeeConfig, sui_amount: u64): u64 {
        if (self.unstake_fee_redistribution_bps == 0) {
            return 0
        };

        // ceil(unstake_fee_amount * unstake_fee_redistribution_bps / 10_000)
        (((sui_amount as u128) * (self.unstake_fee_redistribution_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```
