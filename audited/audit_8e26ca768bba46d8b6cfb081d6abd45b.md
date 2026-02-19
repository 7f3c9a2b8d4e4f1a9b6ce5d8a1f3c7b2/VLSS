### Title
Inconsistent Fee Rounding Causes Protocol Fee Loss Through Floor Division

### Summary
The protocol uses floor division for fee calculations in vault deposits/withdrawals, flash loans, and liquid staking rewards, causing the protocol to lose fractional fee amounts on every transaction. This is inconsistent with the ceiling division explicitly implemented for stake/unstake fees in the same codebase, indicating developer awareness of the issue but incomplete application of the fix.

### Finding Description

The `safe_math` module only provides floor division with no ceiling division function: [1](#0-0) 

This floor division is used in multiple critical fee calculations:

**1. Vault Deposit Fee:** [2](#0-1) 

**2. Vault Withdraw Fee:** [3](#0-2) 

**3. Flash Loan Fees (to supplier and treasury):** [4](#0-3) 

Where FlashLoanMultiple equals 10,000: [5](#0-4) 

**4. Liquid Staking Reward Fee:** [6](#0-5) 

**However, the same codebase explicitly implements ceiling division for other fees**, proving developer awareness:

**Stake Fee (uses ceiling):** [7](#0-6) 

**Unstake Fee (uses ceiling):** [8](#0-7) 

**Unstake Fee Redistribution (uses ceiling):** [9](#0-8) 

The pattern `(amount * rate + 9999) / 10000` ensures ceiling division, collecting at least the stated fee rate. The inconsistent application of floor division elsewhere causes the protocol to undercollect fees.

### Impact Explanation

**Direct Protocol Fund Loss:**

For every transaction where `(amount * fee_rate) % denominator ≠ 0`, the protocol loses the fractional remainder:

- **Example 1** (Vault Deposit of 9,999 units at 10 bp = 0.1%):
  - Floor division: `9999 * 10 / 10000 = 99990 / 10000 = 9` units collected
  - Ceiling division: `(9999 * 10 + 9999) / 10000 = 109989 / 10000 = 10` units expected
  - **Loss: 1 unit (10% of intended fee)**

- **Example 2** (Small amount, 999 units at 10 bp):
  - Floor division: `999 * 10 / 10000 = 9990 / 10000 = 0` units collected
  - Ceiling division: Would collect 1 unit
  - **Loss: 1 unit (100% of intended fee)**

- **Example 3** (Flash loan 99,999 units, rate_to_supplier = 16):
  - Floor division: `99999 * 16 / 10000 = 159` units
  - Ceiling division: Would collect 160 units
  - **Loss: 1 unit per flash loan**

**Cumulative Impact:**
Over thousands of deposits, withdrawals, and flash loans, these fractional losses accumulate to significant amounts. The protocol systematically undercollects fees compared to the stated fee rates.

**Affected Parties:**
- Protocol treasury receives less fees than intended
- Liquidity suppliers in flash loans receive less than expected share
- All fee-dependent protocol operations affected

### Likelihood Explanation

**Certainty: HIGH - Occurs automatically on every fee-charging transaction**

- **Reachable Entry Points:** All public entry functions that charge fees
  - `deposit` operations in vault
  - `withdraw` operations in vault
  - Flash loan `loan()` function
  - Liquid staking reward collection

- **Feasible Preconditions:** None required - happens during normal protocol operation

- **Execution Practicality:** Guaranteed - every transaction with amount where `(amount * fee_rate)` is not perfectly divisible by the denominator (10,000) will lose precision

- **Frequency:** Extremely high - affects majority of transactions since most amounts don't divide evenly

- **Detection:** The inconsistency is evident in the codebase itself - ceiling division used for some fees proves this is a known issue that wasn't applied consistently

### Recommendation

**1. Add ceiling division function to safe_math.move:**
```move
public fun ceil_div(a: u256, b: u256): u256 {
    assert!(b > 0, SAFE_MATH_DIVISION_BY_ZERO);
    if (a == 0) return 0;
    ((a - 1) / b) + 1
}
```

**2. Update vault fee calculations to use ceiling division pattern:**

For deposit fee (line 830):
```move
let deposit_fee = ((coin_amount as u256) * (self.deposit_fee_rate as u256) + (RATE_SCALING - 1) as u256) / (RATE_SCALING as u256);
```

For withdraw fee (line 1040):
```move
let fee_amount = ((amount_to_withdraw as u256) * (self.withdraw_fee_rate as u256) + (RATE_SCALING - 1) as u256) / (RATE_SCALING as u256);
```

**3. Update flash loan fee calculations:**

Lines 152-153 should use:
```move
let to_supplier = (((_loan_amount as u256) * (cfg.rate_to_supplier as u256)) + 9999) / 10000;
let to_treasury = (((_loan_amount as u256) * (cfg.rate_to_treasury as u256)) + 9999) / 10000;
```

**4. Update liquid staking reward fee calculation:**

Line 94-96 should use:
```move
((after_balance - before_balance) as u128) * (self.reward_fee_bps() as u128) + 9999) / BPS_MULTIPLIER
```

**5. Add regression tests:**
Test fee calculations with amounts that produce non-zero remainders (e.g., 9999, 999, 99999) and verify ceiling behavior.

### Proof of Concept

**Initial State:**
- Vault deployed with default deposit fee rate of 10 bp (0.1%)
- RATE_SCALING = 10,000

**Transaction Sequence:**

1. User requests deposit of 9,999 principal coins
2. Operator executes deposit via `execute_deposit()`
3. Fee calculation at line 830: `9999 * 10 / 10000 = 9`
4. Protocol collects 9 units as fee
5. User receives shares for 9,990 units (9999 - 9)

**Expected vs Actual:**
- **Expected fee (at 0.1%):** 10 units (ceiling of 9.999)
- **Actual fee collected:** 9 units
- **Protocol loss:** 1 unit per transaction

**Success Condition:**
The discrepancy is verifiable by checking `deposit_withdraw_fee_collected` balance after the transaction - it will be 1 unit less than the ceiling-rounded amount for deposits with non-divisible amounts.

**Cumulative Impact:**
Execute 10,000 such transactions → Protocol loses up to 10,000 units in aggregate, representing 10% of intended fee revenue for these transactions.

### Citations

**File:** volo-vault/local_dependencies/protocol/math/sources/safe_math.move (L37-41)
```text
    public fun div(a: u256, b: u256): u256 {
         assert!(b > 0, SAFE_MATH_DIVISION_BY_ZERO);
         let c = a / b;
         return c
    }
```

**File:** volo-vault/sources/volo_vault.move (L830-830)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;
```

**File:** volo-vault/sources/volo_vault.move (L1040-1040)
```text
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L152-153)
```text
        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L16-16)
```text
    public fun FlashLoanMultiple(): u64 {10000}
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

**File:** liquid_staking/sources/fee_config.move (L83-90)
```text
    public(package) fun calculate_unstake_fee(self: &FeeConfig, sui_amount: u64): u64 {
        if (self.unstake_fee_bps == 0) {
            return 0
        };

        // ceil(sui_amount * unstake_fee_bps / 10_000)
        (((sui_amount as u128) * (self.unstake_fee_bps as u128) + 9999) / BPS_MULTIPLIER) as u64
    }
```

**File:** liquid_staking/sources/fee_config.move (L92-101)
```text
    public(package) fun calculate_reward_fee(self: &FeeConfig, before_balance: u64, after_balance: u64): u64 {
        let reward_fee = if (after_balance > before_balance) {
                ((after_balance - before_balance) as u128) 
                * (self.reward_fee_bps() as u128)
                / BPS_MULTIPLIER
            } else {
                0
            };
        reward_fee as u64
    }
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
