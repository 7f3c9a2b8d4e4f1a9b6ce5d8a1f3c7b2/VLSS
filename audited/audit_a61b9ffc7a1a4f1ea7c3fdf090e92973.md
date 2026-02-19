### Title
Arithmetic Underflow in total_sui_supply() Causes Complete Protocol DOS via Unchecked Fee Accounting

### Summary
The `total_sui_supply()` function performs unchecked subtraction that can underflow when `accrued_reward_fees` exceeds `validator_pool.total_sui_supply()`, causing all core protocol functions to abort. This occurs because reward fees accumulate over epochs but are only decremented during fee collection, while the validator pool's supply decreases during user unstaking operations, creating an accounting mismatch that permanently bricks the protocol.

### Finding Description

**Exact Code Location:**

The vulnerable subtraction occurs in the `total_sui_supply()` view function: [1](#0-0) 

**Root Cause:**

The vulnerability stems from an accounting invariant violation where two values that should maintain `validator_pool.total_sui_supply >= accrued_reward_fees` can become inverted:

1. **Fee Accumulation**: During epoch rollovers, `accrued_reward_fees` is incremented based on staking rewards: [2](#0-1) 

2. **Fee Decrement**: `accrued_reward_fees` is ONLY decremented in the admin-gated `collect_fees()` function: [3](#0-2) 

3. **Pool Supply Decrement**: During unstaking, `validator_pool.total_sui_supply` is decreased via `split_n_sui()`: [4](#0-3) 

Which calls `split_from_sui_pool()` that decrements the supply: [5](#0-4) 

**Critical Issue**: During the `unstake()` function, `validator_pool.total_sui_supply` decreases but `accrued_reward_fees` remains unchanged. There is no check preventing `accrued_reward_fees` from exceeding `validator_pool.total_sui_supply()`.

**Why Protections Fail:**

- No bounds check exists before the subtraction at line 560
- The reward fee can be configured up to 100% (10,000 bps): [6](#0-5) 

- The `unstake()` function calls `total_sui_supply()` but doesn't adjust `accrued_reward_fees`: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**

Once the underflow condition is triggered, the protocol suffers **complete operational failure**:

1. **Staking DOS**: `stake()` calls `total_sui_supply()` and aborts: [8](#0-7) 

2. **Unstaking DOS**: `unstake()` calls `total_sui_supply()` and aborts: [7](#0-6) 

3. **Fee Collection DOS**: `collect_fees()` calls `refresh()` which calls `total_sui_supply()`: [9](#0-8) 

4. **Ratio Calculation DOS**: All ratio and conversion functions abort: [10](#0-9) [11](#0-10) [12](#0-11) 

**Quantified Damage:**
- All user funds (entire `validator_pool.total_sui_supply`) become locked and inaccessible
- Protocol cannot collect accumulated fees
- No recovery possible without contract upgrade/migration
- All LST holders unable to redeem their tokens

**Affected Parties:**
- All LST token holders cannot unstake
- New users cannot stake
- Protocol administrators cannot collect fees or operate the system
- Entire protocol ecosystem is halted

### Likelihood Explanation

**Attacker Capabilities:** No malicious actor required - this occurs through normal protocol usage.

**Attack Complexity:** SIMPLE - requires only:
1. Time for fees to accumulate (happens naturally each epoch with rewards)
2. Large unstaking volume before admin calls `collect_fees()`

**Feasibility Conditions:**

The scenario unfolds naturally:
- **Initial State**: Protocol operates normally, earning staking rewards
- **Fee Accumulation**: Over N epochs, `accrued_reward_fees` grows to X SUI
- **Delayed Collection**: Admin doesn't call `collect_fees()` frequently (reasonable in normal operations)
- **Market Event**: Users unstake due to market volatility, better yields elsewhere, or protocol migration
- **Threshold Crossed**: When total unstaking exceeds `validator_pool.total_sui_supply - accrued_reward_fees`, the invariant breaks
- **Protocol Bricked**: Next call to any function using `total_sui_supply()` causes abort

**Probability Reasoning:**

HIGH likelihood because:
- Fees naturally accumulate during normal staking (no unusual conditions needed)
- Large unstaking events are common (market panic, competing protocols, liquidity needs)
- Admin may not call `collect_fees()` after every epoch
- The vulnerability window grows larger as fees accumulate
- Once triggered, recovery requires emergency upgrade

**Operational Constraints:**
- No detection mechanism exists to warn before the threshold
- Cannot be mitigated by pausing (functions still call `total_sui_supply()`)
- Admin cannot collect fees to fix the issue (fee collection also calls `total_sui_supply()`)

### Recommendation

**Immediate Fix:**

Add a bounds check in `total_sui_supply()` to prevent underflow:

```move
public fun total_sui_supply(self: &StakePool): u64 {
    let validator_supply = self.validator_pool.total_sui_supply();
    if (validator_supply <= self.accrued_reward_fees) {
        return 0
    };
    validator_supply - self.accrued_reward_fees
}
```

**Better Solution:**

Adjust `accrued_reward_fees` during unstaking operations to maintain the invariant:

```move
// In unstake() function, after line 297:
let sui_withdrawn = sui.value();
let fee_proportion = (sui_withdrawn as u128) * (self.accrued_reward_fees as u128) / (self.validator_pool.total_sui_supply() as u128);
self.accrued_reward_fees = self.accrued_reward_fees - (fee_proportion as u64);
```

**Invariant Checks:**

Add assertions in critical functions:
```move
assert!(
    self.validator_pool.total_sui_supply() >= self.accrued_reward_fees,
    E_FEE_EXCEEDS_SUPPLY
);
```

**Test Cases:**

1. Test unstaking when `accrued_reward_fees` is near `validator_pool.total_sui_supply`
2. Test consecutive epochs with high reward fees and delayed collection
3. Test mass unstaking scenarios with accumulated fees
4. Add invariant tests checking the relationship after every operation

### Proof of Concept

**Initial State:**
- Deploy protocol and stake 1,000,000 SUI
- Configure `reward_fee_bps = 1000` (10%)
- `validator_pool.total_sui_supply = 1,000,000`
- `accrued_reward_fees = 0`
- LST supply = 1,000,000

**Transaction Sequence:**

1. **Epochs 1-50**: Protocol earns staking rewards
   - Each epoch earns ~10,000 SUI (1% per epoch)
   - Each epoch adds ~1,000 SUI to `accrued_reward_fees` (10% fee)
   - After 50 epochs:
     - `validator_pool.total_sui_supply = 1,500,000`
     - `accrued_reward_fees = 50,000`
     - `total_sui_supply() = 1,450,000`

2. **Admin neglects fee collection** (realistic - waiting for optimal time)

3. **Mass unstaking event**: Users unstake 1,480,000 SUI
   - Multiple users call `unstake()` 
   - Each call reduces `validator_pool.total_sui_supply`
   - `accrued_reward_fees` remains at 50,000
   - After unstaking:
     - `validator_pool.total_sui_supply = 20,000`
     - `accrued_reward_fees = 50,000` (unchanged)

4. **Protocol DOS triggered**: Any user attempts to stake/unstake
   - Calls `total_sui_supply()`
   - Computes: 20,000 - 50,000 = **UNDERFLOW ABORT**
   - Transaction fails with arithmetic error

**Expected Result:** Protocol continues operating

**Actual Result:** Protocol permanently DOS'd, all operations abort, funds locked

**Success Condition:** The underflow causes transaction abort, proving complete protocol failure when `validator_pool.total_sui_supply < accrued_reward_fees`.

### Citations

**File:** liquid_staking/sources/stake_pool.move (L232-232)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
```

**File:** liquid_staking/sources/stake_pool.move (L291-291)
```text
        let old_sui_supply = (self.total_sui_supply() as u128);
```

**File:** liquid_staking/sources/stake_pool.move (L297-297)
```text
        let mut sui = self.validator_pool.split_n_sui(system_state, sui_amount_out, ctx);
```

**File:** liquid_staking/sources/stake_pool.move (L369-370)
```text
        let reward_fees = self.validator_pool.split_n_sui(system_state, self.accrued_reward_fees, ctx);
        self.accrued_reward_fees = self.accrued_reward_fees - reward_fees.value();
```

**File:** liquid_staking/sources/stake_pool.move (L512-512)
```text
        let old_total_supply = self.total_sui_supply();
```

**File:** liquid_staking/sources/stake_pool.move (L517-525)
```text
            let reward_fee = if (new_total_supply > old_total_supply) {
                (((new_total_supply - old_total_supply) as u128) 
                * (self.fee_config.reward_fee_bps() as u128) 
                / (BPS_MULTIPLIER as u128)) as u64
            } else {
                0
            };

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

**File:** liquid_staking/sources/stake_pool.move (L633-633)
```text
        let total_sui_supply = self.total_sui_supply();
```

**File:** liquid_staking/sources/stake_pool.move (L652-652)
```text
        let total_sui_supply = self.total_sui_supply();
```

**File:** liquid_staking/sources/validator_pool.move (L596-599)
```text
    fun split_from_sui_pool(self: &mut ValidatorPool, amount: u64): Balance<SUI> {
        self.total_sui_supply = self.total_sui_supply - amount;
        self.sui_pool.split(amount)
    }
```

**File:** liquid_staking/sources/fee_config.move (L6-6)
```text
    const MAX_BPS: u64 = 10_000; // 100%
```
