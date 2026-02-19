### Title
Stale Oracle Prices Accepted During Critical Price Deviation Events

### Summary
When major or critical price deviations are detected between primary and secondary oracle sources, `update_single_price()` stops updating prices as a safety mechanism. However, the old price remains valid for up to 30 seconds (default `update_interval`), allowing lending operations to execute with stale prices during extreme market volatility when accurate pricing is most critical.

### Finding Description

In `update_single_price()`, when price deviation severity is detected as major or critical, the function returns early without updating the oracle price: [1](#0-0) 

The severity levels are defined as: [2](#0-1) 

When severity is major (1) or critical (0), line 118 returns early, preventing the price update at line 164. The old price remains in PriceOracle with its original timestamp.

The staleness check in `oracle::get_token_price()` only invalidates prices after `update_interval` has elapsed: [3](#0-2) 

The default `update_interval` is 30 seconds: [4](#0-3) 

Lending operations use `calculator::calculate_value()` which asserts on price validity: [5](#0-4) 

However, this only checks the boolean returned by `get_token_price()`, which remains true for 30 seconds after the last update, even during critical price deviations.

Critical lending operations like health factor calculations use these potentially stale prices: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**
- Users can borrow against overvalued collateral during flash crashes (e.g., ETH crashes from $3000 to $2000, but oracle shows $3000 for up to 30 seconds)
- Incorrect liquidations may execute, either liquidating healthy positions or failing to liquidate unhealthy ones
- Protocol insolvency risk if significant borrowing occurs against inflated collateral values

**Quantified Damage:**
During a 50% flash crash with a 30-second stale price window, an attacker could:
- Borrow up to 75% LTV against collateral valued at 2x its real price
- Effective LTV becomes 150%, immediately creating bad debt
- For a $1M collateral position: $750K borrowed against $500K actual value = $250K loss

**Affected Parties:**
- Lending protocol suffers bad debt
- Legitimate lenders lose funds as protocol becomes undercollateralized
- Liquidators may execute incorrect liquidations

**Severity:** HIGH - Direct fund loss during predictable market conditions (high volatility events when oracle sources disagree).

### Likelihood Explanation

**Attacker Capabilities:**
- Requires monitoring for oracle price deviations (publicly observable via events)
- Needs automated execution within 30-second window (standard for MEV bots)
- No special privileges required - any user can borrow/withdraw

**Attack Complexity:** MODERATE
- Market volatility causes legitimate price deviations between oracle sources
- Flash crashes, oracle manipulation attacks, or network delays trigger major/critical severity
- Automated bots can easily monitor PriceRegulation events and execute within 30 seconds

**Feasibility Conditions:**
- Primary and secondary oracle sources must disagree significantly (natural during volatility)
- Attacker must have pre-existing account with collateral
- Must execute before 30-second staleness window expires

**Economic Rationality:**
- Profitable during any >10% price movement in 30-second window
- Gas costs minimal compared to potential arbitrage profits
- Risk-free if timed correctly (borrow at inflated value, repay at market value)

**Probability:** MEDIUM-HIGH during market volatility events, which occur regularly in crypto markets.

### Recommendation

**Immediate Mitigations:**

1. **Reduce update_interval** to 5 seconds or less in `oracle.move`: [8](#0-7) 

2. **Add emergency halt on critical severity**: Modify `update_single_price()` to set a global pause flag when critical severity is detected: [9](#0-8) 

Add: `config::set_emergency_pause(oracle_config, feed_address, true)` before returning, and check this flag in lending operations.

3. **Implement stricter staleness checks during volatility**: Track consecutive failed updates and exponentially reduce the acceptable staleness window.

4. **Add volatility-aware validation**: In `calculator::calculate_value()`, check if any major/critical events occurred within the last update_interval and reject prices during this period.

**Test Cases:**
- Verify lending operations abort immediately when major/critical severity detected
- Confirm reduced update_interval prevents stale price acceptance
- Test that consecutive failed updates trigger emergency procedures
- Validate health factor calculations reject prices during known volatility windows

### Proof of Concept

**Initial State:**
- ETH price: $3000 (last updated at t=0)
- User has 10 ETH collateral ($30,000 value)
- LTV: 75%, user can borrow up to $22,500

**Exploit Sequence:**

1. **t=20s**: Flash crash - market ETH price drops to $2000
2. **t=20s**: Oracle keeper calls `update_single_price()`
   - Primary oracle: $2000 (current market)
   - Secondary oracle: $3000 (lagging)
   - Deviation: 50% exceeds threshold2
   - Severity: CRITICAL (0)
   - Function returns at line 118 without updating price

3. **t=25s**: Attacker calls lending protocol borrow function
   - `get_token_price()` checks: `25000ms - 0ms = 25000ms < 30000ms` (update_interval)
   - Returns: `(valid=true, price=$3000, decimal=18)`
   - `calculator::calculate_value()` accepts $3000 price
   - Health factor calculated using $30,000 collateral value (should be $20,000)
   - Borrow limit: $22,500 (should be $15,000)

4. **t=25s**: Attacker borrows $22,500 USDC against 10 ETH
   - Actual collateral value: $20,000
   - Actual LTV: 112.5% (immediately unhealthy)
   - Protocol now has $2,500 bad debt

5. **t=55s**: Price becomes stale (55s - 0s > 30s)
   - Future operations abort with `ERR_PRICE_NOT_UPDATED`
   - Attacker already executed exploit with $2,500 profit

**Expected Result:** Operations should halt when critical severity detected
**Actual Result:** User can borrow for 30 seconds using stale overvalued prices

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L104-120)
```text
            let severity = strategy::validate_price_difference(primary_price, secondary_price, price_diff_threshold1, price_diff_threshold2, current_timestamp, max_duration_within_thresholds, diff_threshold2_timer);
            if (severity != constants::level_normal()) {
                emit (PriceRegulation {
                    level: severity,
                    config_address: config_address,
                    feed_address: feed_address,
                    price_diff_threshold1: price_diff_threshold1,
                    price_diff_threshold2: price_diff_threshold2,
                    current_time: current_timestamp,
                    diff_threshold2_timer: diff_threshold2_timer,
                    max_duration_within_thresholds: max_duration_within_thresholds,
                    primary_price: primary_price,
                    secondary_price: secondary_price,
                });
                if (severity != constants::level_warning()) { return };
                start_or_continue_diff_threshold2_timer = true;
            };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L3-12)
```text
    // Critical level: it is issued when the price difference exceeds x2
    public fun level_critical(): u8 { 0 }

    // Major level: it is issued when the price difference exceeds x1 and does not exceed x2, but it lasts too long
    public fun level_major(): u8 { 1 }

    // Warning level: it is issued when the price difference exceeds x1 and does not exceed x2 and the duration is within an acceptable range
    public fun level_warning(): u8 { 2 }

    public fun level_normal(): u8 { 3 }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L30-30)
```text
    public fun default_update_interval(): u64 {30000} // 30s
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L85-88)
```text
        version_verification(price_oracle);
        assert!(update_interval > 0, error::invalid_value());
        price_oracle.update_interval = update_interval;
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-469)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L475-480)
```text
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```
