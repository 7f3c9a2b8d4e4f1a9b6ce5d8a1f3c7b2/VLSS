### Title
Off-By-One Error in Rate Limiter Sliding Window Calculation Allows Excess Outflows at Window Boundaries

### Summary
The `current_outflow()` function in the Suilend rate limiter contains an off-by-one error in its sliding window weight calculation. When `cur_time` equals `window_start` exactly (at window boundaries), the formula incorrectly under-weights the previous window by `1/window_duration`, allowing users to exceed the configured `max_outflow` limit by up to `max_outflow / window_duration` at each window transition.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The `current_outflow()` function calculates a weighted sum of previous and current window outflows to approximate a sliding window rate limit. At line 71, the formula adds `+ 1` to the time difference: [2](#0-1) 

This causes an off-by-one error. When `cur_time == window_start` (exactly at a window boundary after `update_internal()` transitions):
- `cur_time - window_start + 1 = 0 + 1 = 1`
- `prev_weight = (window_duration - 1) / window_duration`

**Correct behavior should be:**
- Without the `+ 1`, when `cur_time == window_start`: `prev_weight = window_duration / window_duration = 1.0`
- At the exact window start, the sliding lookback window `[cur_time - window_duration, cur_time]` should include 100% of the previous window

**Why protections fail:**
The bug systematically under-weights `prev_qty` by exactly `1/window_duration` at every window boundary. The rate limiter is called in critical paths: [3](#0-2)  and [4](#0-3) 

### Impact Explanation

**Concrete Harm:**
The rate limiter is designed to prevent rapid asset drainage from Suilend (protecting against exploits and oracle attacks). This bug weakens that protection by allowing excess outflows at predictable window boundaries.

**Quantified Impact:**
At each window transition, users can collectively withdraw an additional:
- **Excess allowance = max_outflow / window_duration**

Example scenarios:
- If `window_duration = 86400` (1 day) and `max_outflow = $1,000,000`:
  - Excess per boundary = $1,000,000 / 86,400 ≈ **$11.57**
  - If exploited at every daily boundary over a year: $11.57 × 365 ≈ **$4,223**

- If `window_duration = 3600` (1 hour) and `max_outflow = $10,000,000`:
  - Excess per boundary = $10,000,000 / 3,600 ≈ **$2,778**
  - 24 boundaries per day: $2,778 × 24 ≈ **$66,667 daily**

**Who is affected:**
- Suilend protocol and Volo vault users are exposed to faster-than-intended outflow rates
- The rate limiter's security guarantee is weakened by a factor of `(window_duration - 1) / window_duration`

**Severity:** Medium - The impact scales inversely with `window_duration`. Smaller windows result in larger relative bypass percentages.

### Likelihood Explanation

**Reachable Entry Points:**
Any user calling `borrow()` or `redeem_ctokens_and_withdraw_liquidity()` triggers the rate limiter via `process_qty()`: [5](#0-4) 

**Exploitation Feasibility:**
1. **Window boundaries are deterministic** - Users can calculate when `window_start` will advance based on `window_duration`
2. **No special privileges required** - Any user making normal borrow/redeem transactions at window boundaries triggers the bug
3. **Automatic occurrence** - The first transaction(s) at or after `window_start + window_duration` automatically benefit from the miscalculation

**Attack Complexity:**
- LOW - The bug triggers naturally at predictable times
- Users don't need precise timestamp control; transactions occurring within the same timestamp as the boundary all share the under-weighted calculation
- Multiple users can collectively consume the excess allowance

**Economic Rationality:**
The attack is economically viable when the excess (`max_outflow / window_duration`) exceeds transaction costs, which is highly likely for DeFi protocols with substantial limits.

### Recommendation

**Code-level Fix:**
Remove the `+ 1` from line 71 in `current_outflow()`:

```move
let prev_weight = div(
    sub(
        decimal::from(rate_limiter.config.window_duration),
        decimal::from(cur_time - rate_limiter.window_start), // Remove + 1
    ),
    decimal::from(rate_limiter.config.window_duration),
);
```

**Invariant Check:**
Add assertion to verify at window boundaries (`cur_time == window_start`):
```move
assert!(prev_weight == decimal::from(1), EInvalidWeight);
```

**Regression Test:**
Create test case that:
1. Sets `window_duration = 100` and `max_outflow = 100`
2. Fills `prev_qty` to 99
3. Advances to exact window boundary (`cur_time == new window_start`)
4. Verifies `current_outflow()` returns exactly 99 (not ~98.01)
5. Verifies only 1 unit can be added, not ~2 units

### Proof of Concept

**Initial State:**
- Rate limiter configured: `window_duration = 86400`, `max_outflow = 1000000`
- `window_start = 1000`, `prev_qty = 0`, `cur_qty = 0`

**Exploitation Steps:**

**Transaction 1 (Time = 86399):**
- User borrows asset worth $990,000
- `update_internal()`: window still current (`86399 < 1000 + 86400`)
- `process_qty()`: `cur_qty = 990000`
- `current_outflow()` = `0 + 990000 = 990000` ✓ Passes

**Transaction 2 (Time = 86400 - exact boundary):**
- Window transitions in `update_internal()`:
  - `prev_qty = 990000`
  - `window_start = 86400`
  - `cur_qty = 0`
- User attempts to borrow $15,000
- `current_outflow()` calculates:
  - `prev_weight = (86400 - 1) / 86400 = 0.999988426...`
  - Estimated outflow = `0.999988426 × 990000 + 0 = 989,988.54`
  - Remaining = `1000000 - 989988.54 = 11.46` ❌
  
**Expected Result (without bug):**
- `prev_weight = 1.0`
- Estimated outflow = `1.0 × 990000 = 990000`
- Remaining = `1000000 - 990000 = 10000`
- Transaction should fail or require reduction to $10,000

**Actual Result (with bug):**
- User can withdraw approximately $11.46 more than intended
- Over time at each boundary, cumulative excess accumulates
- Rate limiter protection is weakened by ~0.0012% per window

### Citations

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/rate_limiter.move (L83-95)
```text
    public fun process_qty(rate_limiter: &mut RateLimiter, cur_time: u64, qty: Decimal) {
        update_internal(rate_limiter, cur_time);

        rate_limiter.cur_qty = add(rate_limiter.cur_qty, qty);

        assert!(
            le(
                current_outflow(rate_limiter, cur_time),
                decimal::from(rate_limiter.config.max_outflow),
            ),
            ERateLimitExceeded,
        );
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L312-316)
```text
            rate_limiter::process_qty(
                &mut lending_market.rate_limiter,
                clock::timestamp_ms(clock) / 1000,
                reserve::ctoken_market_value_upper_bound(reserve, ctoken_amount),
            );
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L431-435)
```text
        rate_limiter::process_qty(
            &mut lending_market.rate_limiter,
            clock::timestamp_ms(clock) / 1000,
            borrow_value,
        );
```
