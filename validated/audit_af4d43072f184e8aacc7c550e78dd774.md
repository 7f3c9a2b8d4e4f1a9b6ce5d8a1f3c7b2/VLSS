### Title
Minimum Stake Amount Bypass Through Fee Exclusion in Limit Check

### Summary
The liquid staking module enforces a minimum stake amount of 0.1 SUI to prevent dust accumulation and ensure economic viability. However, the MIN_STAKE_AMOUNT check is performed on the amount before fee deduction in stake operations and after fee calculation but before fee deduction in unstake operations. This allows users to effectively stake or receive amounts below the minimum threshold, bypassing the protocol's dust protection mechanism.

### Finding Description

The external vulnerability involves a cap check performed on one value while a different (larger) value is actually used in the operation. The same vulnerability class exists in Volo's liquid staking module, but inverted: the minimum amount check is performed on an amount that includes fees, while the actual staked/withdrawn amount excludes fees.

**Stake Function Vulnerability:**

In `liquid_staking/sources/stake_pool.move`, the `stake()` function checks the minimum amount before fee deduction: [1](#0-0) 

However, the fee is then deducted from this amount: [2](#0-1) 

And the LST calculation uses the post-fee amount: [3](#0-2) 

The actual amount joined to the pool is after fee deduction: [4](#0-3) 

**Unstake Function Vulnerability:**

Similarly, in the `unstake()` function, the minimum check is performed on the calculated amount before fees: [5](#0-4) 

But fees are then deducted from this amount: [6](#0-5) 

The user receives the amount after fee deduction: [7](#0-6) 

**Root Cause:**

The MIN_STAKE_AMOUNT constant is defined as 0.1 SUI: [8](#0-7) 

The protocol allows fees up to 5% (500 basis points): [9](#0-8) 

**Exploit Path:**

1. For staking: User deposits exactly MIN_STAKE_AMOUNT (0.1 SUI)
2. Check passes: 0.1 SUI >= MIN_STAKE_AMOUNT ✓
3. Fee is calculated and deducted (e.g., 5% = 0.005 SUI)
4. Actual staked amount: 0.095 SUI < MIN_STAKE_AMOUNT
5. User receives LST based on 0.095 SUI, effectively staking below minimum

For unstaking: Similar bypass occurs where the check passes on the pre-fee amount but user receives post-fee amount below minimum.

**Why Current Protections Fail:**

The MIN_STAKE_AMOUNT check is positioned incorrectly relative to fee deduction, checking the gross amount rather than the net amount that actually enters/exits the protocol.

### Impact Explanation

This vulnerability allows circumvention of the minimum stake amount protection with concrete impacts:

1. **Protocol Invariant Violation**: The explicit 0.1 SUI minimum threshold can be bypassed, allowing effective stakes as low as 0.095 SUI (with 5% fees) or even lower with higher configured fees.

2. **Dust Accumulation**: The minimum stake amount exists to prevent dust accumulation in the protocol. Users can create numerous positions below the intended minimum, fragmenting protocol liquidity.

3. **Economic Inefficiency**: The minimum threshold ensures operations are economically viable relative to gas costs. Bypassing this can result in users losing value on gas-inefficient transactions.

4. **Spam Potential**: Attackers could create many tiny stakes below the minimum to spam the system and degrade performance.

### Likelihood Explanation

The vulnerability has high likelihood of exploitation:

1. **Public Access**: Both `stake()` and `unstake()` are public functions callable by any user through entry functions: [10](#0-9) [11](#0-10) 

2. **No Special Permissions**: No admin/operator capabilities required.

3. **Realistic Preconditions**: Only requires that fees are configured (stake_fee_bps > 0 or unstake_fee_bps > 0), which is the normal operating state of the protocol.

4. **Simple Execution**: User simply calls stake_entry() or unstake_entry() with amounts at or near MIN_STAKE_AMOUNT when fees are active.

### Recommendation

Modify the minimum stake amount checks to validate the net amount after fee deduction:

**For the stake function:**
Move the MIN_STAKE_AMOUNT check to after fee deduction:
```
// After line 240 (fee deduction), add:
assert!(sui_balance.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**For the unstake function:**
Check the final amount the user will receive after all fees:
```
// After line 312 (all fee deductions), add:
assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

Alternatively, implement a dual check: verify both the gross amount (current check) AND the net amount (new check) to ensure both input and actual staked amounts meet the minimum threshold.

### Proof of Concept

**Scenario 1: Stake Below Minimum**

Given:
- MIN_STAKE_AMOUNT = 100_000_000 (0.1 SUI)
- stake_fee_bps = 500 (5%)

Steps:
1. User calls `stake_entry()` with exactly 0.1 SUI
2. Check at line 230: `100_000_000 >= 100_000_000` ✓ passes
3. Fee calculated: `(100_000_000 * 500 + 9999) / 10_000 = 5_000_000` (0.05 SUI)
4. Fee deducted at line 240, remaining balance: 95_000_000 (0.095 SUI)
5. LST calculated based on 0.095 SUI at line 242
6. User receives LST representing only 0.095 SUI stake (< MIN_STAKE_AMOUNT)

**Scenario 2: Unstake Below Minimum**

Given:
- MIN_STAKE_AMOUNT = 100_000_000 (0.1 SUI)
- unstake_fee_bps = 500 (5%)
- User has LST representing exactly 0.1 SUI worth

Steps:
1. User calls `unstake_entry()` with their LST tokens
2. sui_amount_out calculated as 100_000_000 at line 294
3. Check at line 295: `100_000_000 >= 100_000_000` ✓ passes
4. Fee calculated: `(100_000_000 * 500 + 9999) / 10_000 = 5_000_000` (0.05 SUI)
5. Fee deducted at lines 308-312
6. User receives approximately 95_000_000 (0.095 SUI), which is < MIN_STAKE_AMOUNT

Both scenarios demonstrate successful bypass of the minimum stake amount constraint through fee-excluded limit checks.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L31-31)
```text
    const MIN_STAKE_AMOUNT: u64 = 1_00_000_000; // 0.1 SUI
```

**File:** liquid_staking/sources/stake_pool.move (L176-186)
```text
    public entry fun stake_entry(
        self: &mut StakePool, 
        metadata: &mut Metadata<CERT>,
        system_state: &mut SuiSystemState, 
        sui: Coin<SUI>, 
        ctx: &mut TxContext
    ) {
        self.manage.check_version();
        let cert = self.stake(metadata, system_state, sui, ctx);
        transfer::public_transfer(cert, ctx.sender());
    }
```

**File:** liquid_staking/sources/stake_pool.move (L230-230)
```text
        assert!(sui.value() >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** liquid_staking/sources/stake_pool.move (L239-240)
```text
        let mint_fee_amount = self.fee_config.calculate_stake_fee(sui_balance.value());
        self.fees.join(sui_balance.split(mint_fee_amount));
```

**File:** liquid_staking/sources/stake_pool.move (L242-242)
```text
        let lst_mint_amount = self.sui_amount_to_lst_amount(metadata, sui_balance.value());
```

**File:** liquid_staking/sources/stake_pool.move (L263-263)
```text
        self.join_to_sui_pool(sui_balance);
```

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

**File:** liquid_staking/sources/stake_pool.move (L294-295)
```text
        let sui_amount_out = self.lst_amount_to_sui_amount(metadata, lst.value());
        assert!(sui_amount_out >= MIN_STAKE_AMOUNT, EUnderMinAmount);
```

**File:** liquid_staking/sources/stake_pool.move (L300-312)
```text
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

**File:** liquid_staking/sources/stake_pool.move (L332-332)
```text
        coin::from_balance(sui, ctx)
```

**File:** liquid_staking/sources/fee_config.move (L8-9)
```text
    const MAX_UNSTAKE_FEE_BPS: u64 = 500; // 5%
    const MAX_STAKE_FEE_BPS: u64 = 500; // 5%
```
