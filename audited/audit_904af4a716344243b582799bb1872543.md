### Title
Rate Limiter State Reset Allows Bypass of Reduced Outflow Limits

### Summary
When an admin reduces `max_outflow` via `update_rate_limiter_config`, the system creates a fresh rate limiter that resets `cur_qty` and `prev_qty` to zero, completely erasing existing outflow tracking. This allows users to immediately borrow or redeem up to the new limit, even if the previous tracked outflows exceeded the new limit, effectively bypassing rate limit protections during config updates.

### Finding Description

The vulnerability exists in the `update_rate_limiter_config` function: [1](#0-0) 

This function replaces the entire rate limiter by calling `rate_limiter::new()`, which creates a fresh instance with zeroed tracking state: [2](#0-1) 

The rate limiter tracks outflows through `cur_qty` and `prev_qty` fields to enforce limits via `process_qty`: [3](#0-2) 

These limits are enforced during borrows: [4](#0-3) 

And redemptions (unless exempted): [5](#0-4) 

**Root Cause**: The config update unconditionally resets outflow tracking instead of preserving or capping existing values when `max_outflow` is reduced.

**Why Protections Fail**: No validation exists to handle the case where existing tracked outflows (`cur_qty` or `prev_qty`) exceed the new `max_outflow`. The reset behavior assumes a fresh start is appropriate, but this defeats the purpose of rate limiting during critical config changes.

### Impact Explanation

**Direct Fund Impact**: Users can extract significantly more funds than intended when rate limits are tightened. For example:
- Initial state: `max_outflow = 1,000,000 USD`, `cur_qty = 800,000 USD`
- Admin reduces to: `max_outflow = 100,000 USD` (e.g., detecting exploit risk)
- After reset: `cur_qty = 0`, allowing immediate extraction of another 100,000 USD
- Users who borrowed 800,000 USD before the update can immediately borrow 100,000 USD more

**Who is Affected**: 
- Liquidity providers whose funds are protected by rate limits
- Protocol integrity when responding to suspicious activity
- All lending market users relying on rate limiting as an exploit mitigation

**Severity Justification**: HIGH - Rate limiters are critical security controls designed to prevent rapid fund extraction exploits. Bypassing them during config updates undermines this protection precisely when admins are attempting to tighten security in response to detected risks.

### Likelihood Explanation

**Attacker Capabilities**: Any user with an obligation can call the public `borrow` or `redeem_ctokens_and_withdraw_liquidity` functions immediately after observing an admin's rate limit reduction.

**Attack Complexity**: LOW
1. Monitor mempool or chain for `update_rate_limiter_config` transactions
2. Submit borrow/redeem transactions immediately after the update
3. Extract funds up to the new limit despite previous high outflows

**Feasibility Conditions**:
- Admin reduces `max_outflow` (reasonable operational action)
- Existing `cur_qty` or `prev_qty` are non-zero (normal state during market activity)
- User has borrowing capacity or ctokens to redeem

**Detection Constraints**: The reset is immediate and atomic. Users can exploit it in the same block or immediately after without special privileges.

**Probability**: HIGH - Admins may need to reduce rate limits in response to:
- Market volatility requiring tighter controls
- Detection of suspicious borrowing patterns
- Protocol risk management adjustments
- Response to exploits in similar protocols

### Recommendation

**Code-Level Mitigation**:

Replace the unconditional reset in `update_rate_limiter_config` with logic that preserves outflow tracking:

```move
public fun update_rate_limiter_config<P>(
    _: &LendingMarketOwnerCap<P>,
    lending_market: &mut LendingMarket<P>,
    clock: &Clock,
    config: RateLimiterConfig,
) {
    assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);
    
    // Update internal state to current time before config change
    let cur_time = clock::timestamp_ms(clock) / 1000;
    rate_limiter::update_internal(&mut lending_market.rate_limiter, cur_time);
    
    // Update only the config, preserving cur_qty and prev_qty
    rate_limiter::update_config(&mut lending_market.rate_limiter, config);
}
```

**Invariant Checks to Add**:

In `rate_limiter.move`, add a new function:
```move
public fun update_config(rate_limiter: &mut RateLimiter, config: RateLimiterConfig) {
    // If reducing max_outflow, cap existing quantities to new limit
    if (config.max_outflow < rate_limiter.config.max_outflow) {
        let new_max = decimal::from(config.max_outflow);
        if (gt(rate_limiter.cur_qty, new_max)) {
            rate_limiter.cur_qty = new_max;
        };
        if (gt(rate_limiter.prev_qty, new_max)) {
            rate_limiter.prev_qty = new_max;
        };
    }
    rate_limiter.config = config;
}
```

**Test Cases**:
1. Reduce `max_outflow` while `cur_qty > new_max_outflow` → verify `cur_qty` is capped
2. Reduce `max_outflow` while `prev_qty > new_max_outflow` → verify `prev_qty` is capped
3. Attempt to borrow after config reduction → verify rate limit still enforced based on preserved state
4. Verify window transitions work correctly after config update without reset

### Proof of Concept

**Initial State**:
- Lending market with rate limiter: `max_outflow = 1,000,000 USD`, `cur_qty = 800,000 USD`, `prev_qty = 500,000 USD`
- Attacker has obligation with sufficient collateral

**Transaction Sequence**:

1. **T0**: Attacker borrows 200,000 USD (remaining capacity)
   - `cur_qty` increases to 1,000,000 USD (at limit)
   - Transaction succeeds

2. **T1**: Admin calls `update_rate_limiter_config` with `max_outflow = 100,000 USD`
   - Current implementation: `rate_limiter = rate_limiter::new(config, current_time)`
   - Result: `cur_qty = 0`, `prev_qty = 0`, `max_outflow = 100,000`

3. **T2**: Attacker immediately borrows 100,000 USD
   - Check: `current_outflow() = 0 + 0 = 0` (due to reset)
   - Validation: `0 <= 100,000` ✓ passes
   - Transaction succeeds

**Expected vs Actual Result**:
- **Expected**: After reducing limit to 100,000 USD, further borrows should be blocked since 1,000,000 USD was already borrowed
- **Actual**: Attacker successfully borrows additional 100,000 USD immediately after config update
- **Total Extracted**: 300,000 USD in quick succession when admin intended 100,000 USD maximum

**Success Condition**: Attacker extracts funds exceeding the new `max_outflow` limit by exploiting the rate limiter reset during config updates.

### Citations

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move (L8-18)
```text
    public struct RateLimiter has copy, drop, store {
        /// configuration parameters
        config: RateLimiterConfig,
        // state
        /// prev qty is the sum of all outflows from [window_start - config.window_duration, window_start)
        prev_qty: Decimal,
        /// time when window started
        window_start: u64,
        /// cur qty is the sum of all outflows from [window_start, window_start + config.window_duration)
        cur_qty: Decimal,
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move (L35-42)
```text
    public fun new(config: RateLimiterConfig, cur_time: u64): RateLimiter {
        RateLimiter {
            config,
            prev_qty: decimal::from(0),
            window_start: cur_time,
            cur_qty: decimal::from(0),
        }
    }
```
