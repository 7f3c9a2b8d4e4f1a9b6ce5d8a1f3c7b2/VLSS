### Title
Silent Integer Truncation in LST Minting Calculation Causes User Fund Loss During Extreme Market Conditions

### Summary
The `sui_amount_to_lst_amount()` function performs u128 to u64 downcasting without overflow validation. When the liquid staking pool suffers catastrophic validator losses causing `total_sui_supply` to drop dramatically while `total_lst_supply` remains high, staking operations can overflow the u64 return value, silently truncating the LST amount and causing users to receive far fewer tokens than deserved.

### Finding Description

**Exact Location:** [1](#0-0) 

**Root Cause:**
The calculation `(total_lst_supply * sui_amount) / total_sui_supply` is performed in u128 arithmetic, but the result is cast directly to u64 without checking if it exceeds `u64::MAX` (18,446,744,073,709,551,615). In Move, such downcasts **truncate silently** by keeping only the lower 64 bits (`result % 2^64`), rather than aborting.

**Why Existing Protections Fail:**

1. The invariant check in the `stake()` function uses the already-truncated LST value: [2](#0-1) 

Since `lst.value()` is the truncated amount, the check `lst_out * old_sui_supply <= sui_in * old_lst_supply` passes with the incorrect truncated value.

2. The zero-mint check only prevents zero returns, not truncated values: [3](#0-2) 

**Contrast with Secure Pattern:**
The codebase's own `volo_v1/math.move` module demonstrates the correct pattern with explicit overflow checks: [4](#0-3) 

**Execution Path:**
1. User calls `stake_entry()` or `stake()` [5](#0-4) 
2. Function calls `sui_amount_to_lst_amount()` at line 242
3. Calculation overflows, truncation occurs silently
4. Truncated LST amount is minted and transferred to user
5. User receives far fewer tokens than deserved, losing the difference

### Impact Explanation

**Direct Fund Loss:**
When `total_sui_supply` drops to very low values (e.g., 1 SUI = 1e9 mist) while `total_lst_supply` remains high (e.g., 10 billion LST = 1e19 mist), a user staking 1,000 SUI (1e12 mist) should receive:
- Expected: (1e19 × 1e12) / 1e9 = 1e22 LST
- But u64::MAX ≈ 1.844e19
- Actual received: 1e22 % 2^64 ≈ value with lost higher-order bits

The user loses LST tokens worth potentially millions of dollars depending on stake size.

**Who Is Affected:**
- Any user staking during the vulnerable window after catastrophic validator losses
- No special permissions or exploiter needed - honest users are victims

**Protocol Damage:**
- Loss of user trust and funds
- Protocol insolvency if multiple users affected
- LST token loses credibility

**Severity:** Critical - Direct, quantifiable fund loss from normal operations.

### Likelihood Explanation

**Trigger Conditions:**
Validator losses causing `total_sui_supply` to become very small relative to `total_lst_supply`. This updates through the exchange rate mechanism during epoch refresh: [6](#0-5) 

**Realistic Scenarios:**
1. Multiple validators experience slashing simultaneously
2. Exchange rates reflect losses, drastically reducing `total_sui_supply`
3. Window exists between refresh and admin pause response
4. Users attempt to stake during this period (either unaware or attempting arbitrage)

**Attack Complexity:** Low - requires only calling public `stake()` function

**Detection Constraints:** 
The protocol has pause functionality but requires manual admin intervention: [7](#0-6) 

A rapid market crash could occur faster than admin response time.

**Probability:** Medium - requires extreme but not impossible market conditions (major validator slashing events do occur on blockchain networks)

### Recommendation

**Immediate Fix:**
Add explicit overflow check before downcasting in `sui_amount_to_lst_amount()`:

```move
public fun sui_amount_to_lst_amount(
    self: &StakePool, 
    metadata: &Metadata<CERT>,
    sui_amount: u64
): u64 {
    let total_sui_supply = self.total_sui_supply();
    let total_lst_supply = metadata.get_total_supply_value();

    if (total_sui_supply == 0 || total_lst_supply == 0) {
        return sui_amount
    };

    let lst_amount = (total_lst_supply as u128)
        * (sui_amount as u128)
        / (total_sui_supply as u128);

    // ADD THIS CHECK:
    const U64_MAX: u128 = 18_446_744_073_709_551_615;
    assert!(lst_amount <= U64_MAX, E_U64_OVERFLOW);
    
    lst_amount as u64
}
```

**Apply Same Fix To:**
1. `lst_amount_to_sui_amount()` at line 661 (same vulnerability in reverse direction) [8](#0-7) 

2. `get_sui_amount()` in validator_pool.move: [9](#0-8) 

**Additional Safeguards:**
- Add circuit breaker that auto-pauses when ratio exceeds safe bounds
- Emit warning events when approaching overflow conditions
- Add integration tests simulating extreme validator loss scenarios

**Test Cases:**
- Stake with `total_lst_supply = 1e19, total_sui_supply = 1e9, sui_amount = 1e12` (should abort)
- Verify unstake operations also handle overflow correctly
- Test edge cases at exactly `u64::MAX` boundary

### Proof of Concept

**Initial State:**
- Liquid staking pool has 10 billion SUI staked, 10 billion LST issued
- `total_sui_supply = 1e19 mist`
- `total_lst_supply = 1e19 mist`

**Catastrophic Event:**
- Validators suffer 99.9999% losses through slashing
- `refresh()` called, exchange rates update
- `total_sui_supply` drops to `1e9 mist` (1 SUI)
- `total_lst_supply` remains `1e19 mist` (existing LST holders still have tokens)

**Exploit Transaction:**
1. Attacker (or honest user) calls `stake_entry()` with 1,000 SUI (`1e12 mist`)
2. Calculation: `(1e19 × 1e12) / 1e9 = 1e22 LST`
3. Since `1e22 > u64::MAX (≈1.844e19)`, truncation occurs
4. User receives truncated value instead of `1e22 LST`

**Expected Result:** User receives 1e22 LST tokens (proportional to extreme ratio)

**Actual Result:** User receives truncated amount (keeping only lower 64 bits), losing massive value

**Success Condition:** Transaction completes without abort, user checks balance and finds far fewer LST tokens than the proper exchange rate would dictate.

### Citations

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

**File:** liquid_staking/sources/stake_pool.move (L227-227)
```text
        self.manage.check_not_paused();
```

**File:** liquid_staking/sources/stake_pool.move (L243-243)
```text
        assert!(lst_mint_amount > 0, EZeroMintAmount);
```

**File:** liquid_staking/sources/stake_pool.move (L257-261)
```text
        assert!(
            ((lst.value() as u128) * old_sui_supply <= (sui_balance.value() as u128) * old_lst_supply)
            || (old_sui_supply > 0 && old_lst_supply == 0), // special case
            ERatio
        );
```

**File:** liquid_staking/sources/stake_pool.move (L640-644)
```text
        let lst_amount = (total_lst_supply as u128)
            * (sui_amount as u128)
            / (total_sui_supply as u128);

        lst_amount as u64
```

**File:** liquid_staking/sources/stake_pool.move (L657-661)
```text
        let sui_amount = (total_sui_supply as u128)
            * (lst_amount as u128) 
            / (total_lst_supply as u128);

        sui_amount as u64
```

**File:** liquid_staking/sources/volo_v1/math.move (L14-19)
```text
    public fun mul_div(x: u64, y: u64, z: u64): u64 {
        assert!(z != 0, E_DIVIDE_BY_ZERO);
        let r = (x as u128) * (y as u128) / (z as u128);
        assert!(r <= U64_MAX, E_U64_OVERFLOW);
        (r as u64)
    }
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

**File:** liquid_staking/sources/validator_pool.move (L883-886)
```text
        let res = (exchange_rate.sui_amount() as u128)
                * (token_amount as u128)
                / (exchange_rate.pool_token_amount() as u128);
        res as u64
```
