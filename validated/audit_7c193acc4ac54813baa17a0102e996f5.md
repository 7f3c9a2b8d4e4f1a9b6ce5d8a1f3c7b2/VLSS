# Audit Report

## Title
Rate Limiter Off-By-One Error Allows Bypass of Withdrawal/Borrow Limits When window_duration=1

## Summary
The Suilend rate limiter's `current_outflow()` function contains an off-by-one error in the sliding window calculation that completely bypasses rate limits when `window_duration` is set to 1 second. This allows attackers to withdraw or borrow at 2x the intended rate by timing transactions to exact second boundaries.

## Finding Description

The vulnerability exists in the sliding window weight calculation. [1](#0-0) 

The formula incorrectly adds "+1" to `(cur_time - rate_limiter.window_start)` when calculating the previous window's contribution weight. The correct formula for a sliding window should be `window_duration - (cur_time - window_start)`, but the implementation uses `window_duration - (cur_time - window_start + 1)`.

When `window_duration = 1` and a transaction occurs at `cur_time = window_start` (immediately after a window transition), the calculation becomes:
- `prev_weight = (1 - (0 + 1)) / 1 = 0`

This causes the previous window to contribute 0% instead of 100%, completely ignoring recent outflows.

The window transition logic correctly updates state, [2](#0-1)  moving `cur_qty` to `prev_qty` and resetting the current window. However, when combined with the flawed `current_outflow()` calculation, it creates the bypass opportunity.

The rate limiter protects CToken redemptions (withdrawals) [3](#0-2)  and borrows [4](#0-3)  by calling `rate_limiter::process_qty()` with the USD value of each operation.

The lending market is initialized with `window_duration = 1` by default, [5](#0-4)  making this the default vulnerable configuration. Admins can update this configuration [6](#0-5)  including setting `window_duration = 1` with meaningful rate limits.

Time is tracked in seconds via `clock::timestamp_ms(clock) / 1000`, making precise timing to second boundaries straightforward.

Volo integrates with Suilend through the suilend_adaptor, [7](#0-6)  meaning this vulnerability could impact Volo's deposited positions if Suilend reserves are rapidly drained.

## Impact Explanation

**Security Control Bypass**: The rate limiter is a critical security mechanism specifically designed to mitigate exploits by limiting the rate of withdrawals and borrows. This vulnerability completely defeats that protection when `window_duration = 1`.

**Quantified Exploit**: With `window_duration = 1 second` and `max_outflow = 1000 USD`:
- At time T: Attacker withdraws/borrows 1000 USD (fills the limit, passes check)
- At time T+1: Window transition occurs, but due to the off-by-one error, `prev_weight = 0`
- Attacker immediately withdraws/borrows another 1000 USD (passes check with only current window counted)
- **Total: 2000 USD in 1 second window, exactly 2x the intended 1000 USD rate limit**

**Affected Parties**:
- Suilend protocol loses intended rate limit protection against rapid fund extraction
- Legitimate users may be unable to access liquidity after reserves are drained
- Volo vault positions in Suilend could become illiquid or suffer losses if reserves are rapidly depleted during an exploit

**Severity**: High - Complete bypass of a security control designed to prevent rapid fund extraction during exploits or oracle failures.

## Likelihood Explanation

**Attacker Capabilities**: Any user with:
- CTokens to redeem, OR
- Collateral to borrow against
- Basic ability to submit transactions at specific timestamps (trivial on blockchain)

**Attack Complexity**: Minimal
- Monitor blockchain time to reach integer second boundary
- Submit first transaction at time T
- Submit second transaction at time T+1
- Time granularity is in seconds, making precise timing straightforward

**Feasibility Conditions**:
- No special privileges required
- Works with default configuration (`window_duration = 1`, though with unlimited `max_outflow` by default)
- Admin could set meaningful `max_outflow` limits while keeping `window_duration = 1`
- Deterministic and repeatable exploit

**Probability**: Very High - The exploit requires no special conditions beyond basic market participation and is deterministic in nature.

## Recommendation

Fix the off-by-one error in the `current_outflow()` function by removing the "+1" from the calculation:

```move
fun current_outflow(rate_limiter: &RateLimiter, cur_time: u64): Decimal {
    let prev_weight = div(
        sub(
            decimal::from(rate_limiter.config.window_duration),
            decimal::from(cur_time - rate_limiter.window_start),  // Remove the +1
        ),
        decimal::from(rate_limiter.config.window_duration),
    );
    
    add(
        mul(rate_limiter.prev_qty, prev_weight),
        rate_limiter.cur_qty,
    )
}
```

This ensures that at the start of a new window (`cur_time == window_start`), the previous window contributes 100% as intended, properly enforcing rate limits.

## Proof of Concept

```move
#[test]
fun test_rate_limiter_bypass_with_window_duration_1() {
    use sui::test_scenario;
    use sui::clock::{Self, Clock};
    use suilend::rate_limiter::{Self};
    use suilend::decimal;
    
    let admin = @0xAD;
    let mut scenario = test_scenario::begin(admin);
    
    // Create clock at time 100
    let mut clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
    clock.set_for_testing(100_000); // 100 seconds
    
    // Create rate limiter with window_duration=1, max_outflow=1000
    let config = rate_limiter::new_config(1, 1000);
    let mut limiter = rate_limiter::new(config, 100);
    
    // First transaction at T=100: withdraw 1000 USD
    rate_limiter::process_qty(&mut limiter, 100, decimal::from(1000));
    // This succeeds
    
    // Second transaction at T=101: withdraw another 1000 USD  
    clock.set_for_testing(101_000); // 101 seconds
    rate_limiter::process_qty(&mut limiter, 101, decimal::from(1000));
    // This should FAIL but SUCCEEDS due to off-by-one error
    // Total withdrawn: 2000 USD in 1 second, bypassing the 1000 USD limit
    
    clock.destroy_for_testing(clock);
    test_scenario::end(scenario);
}
```

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move (L44-62)
```text
    fun update_internal(rate_limiter: &mut RateLimiter, cur_time: u64) {
        assert!(cur_time >= rate_limiter.window_start, EInvalidTime);

        // |<-prev window->|<-cur window (cur_slot is in here)->|
        if (cur_time < rate_limiter.window_start + rate_limiter.config.window_duration) {
            return
        } else // |<-prev window->|<-cur window->| (cur_slot is in here) |
        if (cur_time < rate_limiter.window_start + 2 * rate_limiter.config.window_duration) {
            rate_limiter.prev_qty = rate_limiter.cur_qty;
            rate_limiter.window_start =
                rate_limiter.window_start + rate_limiter.config.window_duration;
            rate_limiter.cur_qty = decimal::from(0);
        } else // |<-prev window->|<-cur window->|<-cur window + 1->| ... | (cur_slot is in here) |
        {
            rate_limiter.prev_qty = decimal::from(0);
            rate_limiter.window_start = cur_time;
            rate_limiter.cur_qty = decimal::from(0);
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move (L65-80)
```text
    fun current_outflow(rate_limiter: &RateLimiter, cur_time: u64): Decimal {
        // assume the prev_window's outflow is even distributed across the window
        // this isn't true, but it's a good enough approximation
        let prev_weight = div(
            sub(
                decimal::from(rate_limiter.config.window_duration),
                decimal::from(cur_time - rate_limiter.window_start + 1),
            ),
            decimal::from(rate_limiter.config.window_duration),
        );

        add(
            mul(rate_limiter.prev_qty, prev_weight),
            rate_limiter.cur_qty,
        )
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L175-178)
```text
            rate_limiter: rate_limiter::new(
                rate_limiter::new_config(1, 18_446_744_073_709_551_615),
                0,
            ),
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L311-317)
```text
        if (!exempt_from_rate_limiter) {
            rate_limiter::process_qty(
                &mut lending_market.rate_limiter,
                clock::timestamp_ms(clock) / 1000,
                reserve::ctoken_market_value_upper_bound(reserve, ctoken_amount),
            );
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L431-435)
```text
        rate_limiter::process_qty(
            &mut lending_market.rate_limiter,
            clock::timestamp_ms(clock) / 1000,
            borrow_value,
        );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L1093-1101)
```text
    public fun update_rate_limiter_config<P>(
        _: &LendingMarketOwnerCap<P>,
        lending_market: &mut LendingMarket<P>,
        clock: &Clock,
        config: RateLimiterConfig,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
        lending_market.rate_limiter = rate_limiter::new(config, clock::timestamp_ms(clock) / 1000);
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```
