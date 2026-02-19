### Title
Arithmetic Overflow in Compound Interest Calculation Causes DoS of Vault Operations and Reward Claims

### Summary
The `pow()` function in Suilend's decimal module can overflow during compound interest calculations when high APR reserves remain inactive for extended periods. This overflow causes transaction aborts that prevent Volo vault operations from completing and block Suilend reward claims, resulting in a DoS condition where withdrawals cannot be processed and rewards cannot be claimed.

### Finding Description

The vulnerability exists in the compound interest calculation flow that uses exponentiation by squaring without overflow protection. [1](#0-0) 

The `pow()` function performs repeated squaring operations via `mul()`: [2](#0-1) 

The multiplication `a.value * b.value` operates on `u256` values and can overflow when `cur_base` grows large during the squaring process. This occurs in the compound interest calculation: [3](#0-2) 

The base is `1 + APR/SECONDS_IN_YEAR` raised to the power of `time_elapsed_s`. With exponentiation by squaring, after k squaring operations, `cur_base = base^(2^k)`. Overflow occurs when `cur_base.value * cur_base.value > u256::MAX`, which happens when `cur_base.value > sqrt(u256::MAX) ≈ 2^128`.

**Mathematical breakdown:**
- For 10000% APR (100.0 as decimal): Overflow after ~194 days without updates
- For 1000% APR (10.0 as decimal): Overflow after ~8.5 years without updates  
- For 100% APR (1.0 as decimal): Overflow after ~68 years without updates

**Attack path:**

1. **Volo Vault Operations**: When updating Suilend position values, the adaptor calls `compound_interest`: [4](#0-3) 

2. **Operation Completion**: The vault must check value updates to complete operations: [5](#0-4) 

If `compound_interest` aborts, the operation cannot complete, leaving the vault stuck in `VAULT_DURING_OPERATION_STATUS`.

3. **Withdrawal Blocking**: Users cannot request withdrawals when vault is not in normal status: [6](#0-5) 

4. **Reward Claim Blocking**: Suilend reward claims also require `compound_interest`: [7](#0-6) 

### Impact Explanation

**Concrete impacts:**

1. **Vault DoS**: The Volo vault becomes stuck in `VAULT_DURING_OPERATION_STATUS`, unable to transition back to normal status. This prevents all new operations from starting since they require normal status. [8](#0-7) 

2. **Withdrawal Blocking**: Users with funds in the vault cannot create new withdrawal requests, effectively locking their funds until the issue is resolved administratively.

3. **Reward Claim Failure**: Users holding obligations in the affected Suilend reserve cannot claim their liquidity mining rewards due to the abort.

4. **Cascading Effects**: Any vault with a Suilend position on an affected reserve experiences these issues, potentially affecting multiple vaults and many users.

**Who is affected:**
- All Volo vault depositors when their vault has positions on affected reserves
- All Suilend users with obligations on high-APR inactive reserves
- Protocol operators unable to complete vault operations

**Severity justification:** HIGH - This creates a concrete DoS condition blocking user withdrawals and reward claims, with no easy recovery path short of emergency admin intervention or contract upgrades.

### Likelihood Explanation

**Attacker capabilities:** None required - this is a natural condition that occurs when reserves become inactive.

**Feasibility conditions:**
- High APR reserves (1000%+ which exist in DeFi during incentive programs or new pool launches)
- Extended periods without transactions on that specific reserve (months for extreme APRs)
- The Volo vault has borrowed Suilend positions on such reserves

**Probability assessment:**
- **Moderate** for high-APR scenarios (10000% APR + 6 months inactivity): Possible during new protocol launches or incentive campaigns
- **Low** for typical APRs (100% APR would require decades): Most active DeFi reserves have regular transactions

**Key factors:**
- Popular reserves naturally receive regular transactions that call `compound_interest`, mitigating the issue
- Inactive or deprecated reserves with residual high APR configurations are vulnerable
- The vulnerability is more likely during market downturns when some reserves see reduced activity

The prompt specifically asks about "high APY" scenarios, making this a relevant concern despite the time requirements.

### Recommendation

**Immediate mitigation:**

1. Add overflow protection to the `pow()` function with early termination or capping:

```move
public fun pow(b: Decimal, mut e: u64): Decimal {
    // Cap exponent to prevent overflow
    const MAX_SAFE_EXPONENT: u64 = 10_000_000; // ~115 days at 1 second intervals
    if (e > MAX_SAFE_EXPONENT) {
        e = MAX_SAFE_EXPONENT;
    };
    
    let mut cur_base = b;
    let mut result = from(1);
    
    while (e > 0) {
        if (e % 2 == 1) {
            result = mul(result, cur_base);
        };
        cur_base = mul(cur_base, cur_base);
        e = e / 2;
    };
    
    result
}
```

2. Add a maximum time delta check in `compound_interest`:

```move
public(package) fun compound_interest<P>(reserve: &mut Reserve<P>, clock: &Clock) {
    let cur_time_s = clock::timestamp_ms(clock) / 1000;
    let time_elapsed_s = cur_time_s - reserve.interest_last_update_timestamp_s;
    if (time_elapsed_s == 0) {
        return
    };
    
    // Cap time elapsed to prevent overflow (e.g., 30 days)
    const MAX_TIME_ELAPSED: u64 = 30 * 24 * 60 * 60;
    let safe_time_elapsed = if (time_elapsed_s > MAX_TIME_ELAPSED) {
        MAX_TIME_ELAPSED
    } else {
        time_elapsed_s
    };
    
    // Use safe_time_elapsed in calculation
    // ...
}
```

3. Add APR bounds checking in reserve configuration to prevent extremely high APR values.

**Test cases:**
- Test `pow()` with high bases and large exponents (simulate years of inactivity)
- Test vault operation completion with stale Suilend positions
- Test reward claims on reserves with large time deltas
- Verify graceful degradation when overflow conditions are detected

### Proof of Concept

**Initial state:**
1. Suilend reserve configured with 10000% APR (extreme but possible for new incentive programs)
2. Volo vault has borrowed a Suilend position on this reserve via `operation_start_op`
3. Reserve becomes inactive - no transactions for 194+ days

**Exploitation sequence:**

**Transaction 1** (Day 0): Operator starts vault operation
- Calls `operation_start_op` borrowing Suilend position
- Vault enters `VAULT_DURING_OPERATION_STATUS`
- Success

**Transaction 2** (Day 194+): Operator attempts to finish operation
- Calls `operation_finish_for_check_value_update`
- Internally calls `suilend_compound_interest`
- `compound_interest` calculates: `pow(1.00000317, 16,761,600)` (194 days in seconds)
- During exponentiation by squaring (iteration 24): `cur_base.value * cur_base.value` exceeds `u256::MAX`
- **Transaction ABORTS with arithmetic overflow**

**Expected vs Actual:**
- **Expected**: Operation completes, vault returns to `VAULT_NORMAL_STATUS`
- **Actual**: Transaction aborts, vault remains stuck in `VAULT_DURING_OPERATION_STATUS`

**Transaction 3**: User attempts withdrawal
- Calls `user_entry::withdraw()`
- `request_withdraw()` checks `assert_normal()` at line 905
- **Transaction ABORTS** - vault not in normal status

**Success condition:** Vault permanently stuck, withdrawals blocked until admin intervention or contract upgrade.

### Notes

The vulnerability is exacerbated by the fact that Suilend's `compound_interest` is called from multiple critical paths including vault operations, deposits, withdrawals, borrows, and reward claims. While the likelihood depends on specific APR and activity levels, the impact when it occurs is severe and affects fundamental protocol operations. The audit prompt's specific focus on "high APY" scenarios makes this particularly relevant, as DeFi protocols do experience temporary periods of extreme APRs during launches or incentive programs.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L71-75)
```text
    public fun mul(a: Decimal, b: Decimal): Decimal {
        Decimal {
            value: (a.value * b.value) / WAD,
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/decimal.move (L83-96)
```text
    public fun pow(b: Decimal, mut e: u64): Decimal {
        let mut cur_base = b;
        let mut result = from(1);

        while (e > 0) {
            if (e % 2 == 1) {
                result = mul(result, cur_base);
            };
            cur_base = mul(cur_base, cur_base);
            e = e / 2;
        };

        result
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L603-614)
```text
        // I(t + n) = I(t) * (1 + apr()/SECONDS_IN_YEAR) ^ n
        let utilization_rate = calculate_utilization_rate(reserve);
        let compounded_borrow_rate = pow(
            add(
                decimal::from(1),
                div(
                    calculate_apr(config(reserve), utilization_rate),
                    decimal::from(365 * 24 * 60 * 60)
                )
            ),
            time_elapsed_s
        );
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L91-102)
```text
fun suilend_compound_interest<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
) {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());
    let reserve_array_indices = get_reserve_array_indicies(obligation);

    reserve_array_indices.do_ref!(|reserve_array_index| {
        lending_market.compound_interest(*reserve_array_index, clock);
    });
}
```

**File:** volo-vault/sources/operation.move (L72-75)
```text
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
```

**File:** volo-vault/sources/operation.move (L353-365)
```text
    let total_usd_value_before = total_usd_value;
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };

```

**File:** volo-vault/sources/volo_vault.move (L904-906)
```text
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1273-1274)
```text
        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_id);
        reserve::compound_interest(reserve, clock);
```
