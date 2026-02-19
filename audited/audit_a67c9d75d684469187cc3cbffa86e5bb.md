### Title
Irrecoverable Dust Funds in Suilend Staker After Full User Exit

### Summary
When all users withdraw from the Suilend reserve and liabilities drops to zero, the staker's `claim_fees` function permanently locks a minimum of 1 SUI due to a hardcoded buffer. Additionally, any dust amounts less than 1 SUI in the balances become irrecoverable. The protocol has no mechanism to extract these funds, resulting in permanent loss of staking rewards and residual balances.

### Finding Description

The vulnerability exists in the `claim_fees` function's excess calculation logic: [1](#0-0) 

When `liabilities = 0` (all users have exited), the formula `total_sui_supply - staker.liabilities - MIST_PER_SUI` creates two problems:

1. **Mandatory 1 SUI Buffer**: If `total_sui_supply > 1 SUI`, exactly 1 SUI is always left unclaimed
2. **Complete Lock Below Threshold**: If `total_sui_supply ≤ 1 SUI`, the entire amount is irrecoverable since `excess_sui = 0`

The comment "leave 1 SUI extra, just in case" suggests operational safety during normal operation, but provides no justification for this buffer when the staker is being wound down and all users have exited.

Additionally, the `rebalance` function contributes to dust accumulation: [2](#0-1) 

Any SUI below `MIN_DEPLOY_AMOUNT` (1 SUI) never gets staked and remains in `sui_balance` as dust.

The staker struct stores the `AdminCap` internally with no external access: [3](#0-2) 

All staker functions are `public(package)` only, providing no mechanism for emergency fund recovery or cleanup when winding down.

### Impact Explanation

**Direct Fund Loss**: Protocol funds (staking rewards and residual balances) become permanently locked with no recovery mechanism. The minimum loss is 1 SUI (≈$1-3 USD at typical prices), but can be higher:
- Mandatory 1 SUI buffer that remains after any claim when liabilities = 0
- Dust < 1 SUI in `sui_balance` from the MIN_DEPLOY_AMOUNT threshold
- Small LST positions that convert to < 1 SUI total

**Who is Affected**: The Suilend reserve protocol loses these funds, which represent:
- Staking rewards earned on idle SUI
- Rounding remainders from unstaking operations
- Final balances when users fully exit

**Concrete Scenario**: 
- Reserve has 1000 SUI staked with 998 SUI in liabilities
- All users withdraw over time until liabilities = 0  
- Staker has 2.5 SUI remaining (2 SUI rewards + 0.5 SUI dust)
- `claim_fees` can only extract 1.5 SUI (2.5 - 0 - 1.0)
- Remaining 1.0 SUI is permanently locked

This violates the custody invariant that all protocol-owned assets should be recoverable.

### Likelihood Explanation

**Realistic Scenario**: This occurs naturally during:
- Protocol migration or wind-down
- Mass user exodus from the lending market
- Market conditions causing full reserve drain

**No Attack Required**: This is a design flaw, not an attack. The issue manifests through normal user withdrawals when the reserve fully empties.

**Execution Path**: 
1. Users call standard Suilend withdraw/redeem functions
2. Reserve calls `staker::withdraw` which decrements liabilities
3. When liabilities reaches 0, `claim_fees` is called to recover remaining funds
4. The hardcoded buffer prevents full recovery

**Probability**: High during any protocol lifecycle event involving reserve migration or shutdown. While individual reserves may not fully drain during normal operations, protocol upgrades or migrations make this a realistic concern.

### Recommendation

**Immediate Fix**: Modify `claim_fees` to allow full withdrawal when liabilities = 0:

```move
let excess_sui = if (staker.liabilities == 0) {
    // Allow full withdrawal during wind-down
    total_sui_supply
} else if (total_sui_supply > staker.liabilities + MIST_PER_SUI) {
    // Normal operation: leave 1 SUI buffer
    total_sui_supply - staker.liabilities - MIST_PER_SUI
} else {
    0
};
```

**Additional Safeguard**: Add an emergency withdrawal function accessible by reserve admin for cleanup:

```move
public(package) fun emergency_withdraw_all<P: drop>(
    staker: &mut Staker<P>,
    system_state: &mut SuiSystemState,
    ctx: &mut TxContext,
): Balance<SUI> {
    assert!(staker.liabilities == 0, ELiabilitiesNotZero);
    
    // Unstake all LST
    if (staker.lst_balance.value() > 0) {
        let lst = staker.lst_balance.withdraw_all();
        let sui = liquid_staking::redeem(...);
        staker.sui_balance.join(sui.into_balance());
    }
    
    // Return all SUI
    staker.sui_balance.withdraw_all()
}
```

**Invariant Test**: Add test case verifying full fund recovery when liabilities = 0.

### Proof of Concept

**Initial State**:
- Suilend SUI reserve with staker initialized
- 1000 SUI deposited and staked
- 998 SUI borrowed by users (liabilities = 998)
- Staking rewards accrue 2 SUI over time

**Execution Steps**:
1. All users repay borrows and withdraw deposits
2. Reserve calls `staker::withdraw` repeatedly as users exit
3. Final state: `liabilities = 0`, `total_sui_supply = 2.5 SUI` (2 SUI rewards + 0.5 SUI dust)
4. Reserve calls `claim_fees` to recover remaining funds

**Expected Result**: 
Protocol recovers all 2.5 SUI

**Actual Result**:
- `excess_sui = 2.5 - 0 - 1.0 = 1.5 SUI`
- Only 1.5 SUI is claimed
- 1.0 SUI permanently locked in staker with no recovery mechanism

**Verification**:
Check staker state after claim_fees with liabilities = 0 shows non-zero `total_sui_supply()` that cannot be withdrawn through any existing function.

### Citations

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L106-108)
```text
        if (staker.sui_balance.value() < MIN_DEPLOY_AMOUNT) {
            return
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/staker.move (L141-145)
```text
        let excess_sui = if (total_sui_supply > staker.liabilities + MIST_PER_SUI) {
            total_sui_supply - staker.liabilities - MIST_PER_SUI
        } else {
            0
        };
```
