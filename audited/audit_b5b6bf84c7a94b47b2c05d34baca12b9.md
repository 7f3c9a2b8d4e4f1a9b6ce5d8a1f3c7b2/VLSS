### Title
Oracle Price Divergence Exploitation During Warning Level Allows Overleveraged Positions and Protocol Insolvency

### Summary
The oracle system accepts potentially divergent prices when severity equals `level_warning` (10-20% price difference between primary and secondary oracles), continuing execution with only the primary price for up to 10 seconds. During market stress when legitimate price divergence occurs, attackers can exploit inflated or deflated oracle prices to create overleveraged lending positions, potentially causing protocol insolvency and bad debt.

### Finding Description

The vulnerability exists in the dual-oracle price validation system used by the Navi lending protocol. When both primary and secondary oracle prices are fresh but divergent, the system calculates a severity level: [1](#0-0) 

The critical issue occurs in the price update logic when severity equals `level_warning`: [2](#0-1) 

When the price difference is between `threshold1` (default 1000 = 10%) and `threshold2` (default 2000 = 20%), the function:
1. Emits a `PriceRegulation` event but continues execution
2. Sets `start_or_continue_diff_threshold2_timer = true`
3. Stores the **primary price only** into the oracle [3](#0-2) 

The stored divergent price is then used in Navi lending health factor calculations: [4](#0-3) [5](#0-4) 

The health factor check allows borrowing as long as the calculated health factor (using the potentially divergent price) meets the threshold, creating overleveraged positions when prices are inflated.

### Impact Explanation

**Direct Protocol Insolvency Risk:**

During market volatility (common in cryptocurrency markets), oracle price feeds legitimately diverge by 10-20% due to:
- Different update frequencies between Pyth and Supra
- Network latency differences
- Flash crash events
- Cross-exchange arbitrage opportunities

**Concrete Attack Scenario:**

1. ETH price drops from $2000 to $1800 (10% decline)
2. Supra (primary) lags at $2000, Pyth (secondary) updates to $1800
3. System accepts $2000 price at warning level
4. Attacker with 10 ETH collateral:
   - Inflated collateral value: 10 × $2000 = $20,000
   - Real collateral value: 10 × $1800 = $18,000
   - Can borrow up to ~$15,000 (75% LTV on inflated value)
   - Should only borrow ~$13,500 (75% LTV on real value)
   - **Excess borrowing: $1,500 (11% overleveraged)**

5. When prices converge or escalate to major level, position becomes underwater
6. Protocol absorbs the bad debt

**Quantified Impact:**
- **Per-position**: 10-20% overleveraging on borrowed amounts
- **Protocol-wide**: During black swan events affecting all positions simultaneously, cumulative bad debt could exceed protocol reserves
- **Affected parties**: All vault depositors and lending protocol users suffer losses

### Likelihood Explanation

**High Likelihood During Market Stress:**

1. **Permissionless Oracle Updates**: `update_single_price` is a public function callable by anyone with no capability requirement [6](#0-5) 

2. **Realistic Preconditions**: 10-20% price divergence is **common** during:
   - Flash crashes (e.g., May 2021 crypto crash: 30% drops in minutes)
   - Major liquidation cascades
   - Cross-exchange arbitrage windows
   - Network congestion causing oracle delays

3. **Sufficient Exploitation Window**: Default `max_duration_within_thresholds` is 10,000ms (10 seconds) [7](#0-6) 

   On Sui, atomic transactions execute in <1 second, providing ample time to:
   - Update oracle price
   - Execute borrow operation
   - Extract value

4. **No Trusted Role Required**: Any user with collateral can exploit this - no admin compromise or special capabilities needed

5. **Economic Rationality**: 
   - Attack cost: Gas fees only
   - Attack profit: 10-20% additional borrowing capacity
   - Risk: Minimal if executed during genuine market stress (appears legitimate)

### Recommendation

**Immediate Mitigation:**

Modify the warning-level handling to use a conservative price instead of blindly accepting the primary price:

```move
// In oracle_pro.move, lines 100-120
if (is_primary_price_fresh && is_secondary_price_fresh) {
    let severity = strategy::validate_price_difference(...);
    if (severity != constants::level_normal()) {
        if (severity == constants::level_warning()) {
            // Use the MORE CONSERVATIVE price (lower for collateral, higher for debt)
            // Or use the average/median of both prices
            final_price = math::min(primary_price, secondary_price); // Conservative approach
            start_or_continue_diff_threshold2_timer = true;
        } else {
            // Critical or major level - reject update
            return
        }
    }
}
```

**Alternative Approaches:**

1. **Reduce Warning Threshold**: Set `price_diff_threshold1` to 200-500 (2-5%) instead of 1000 (10%)
2. **Shorten Time Window**: Reduce `max_duration_within_thresholds` to 2-3 seconds instead of 10 seconds
3. **Use Weighted Average**: Combine primary and secondary prices proportionally based on staleness/confidence

**Required Invariant Checks:**

Add health factor validation using BOTH oracle prices:
```move
// Before accepting borrow
let hf_with_primary = calculate_health_factor_with_price(primary_price);
let hf_with_secondary = calculate_health_factor_with_price(secondary_price);
let min_hf = math::min(hf_with_primary, hf_with_secondary);
assert!(min_hf >= required_hf, error::insufficient_health_factor());
```

**Test Cases:**

1. Test borrowing with 10% price divergence at warning level - should use conservative price
2. Test rapid price movements causing timer to exceed 10 seconds - should escalate to major
3. Test concurrent borrows during warning period - should maintain protocol solvency
4. Stress test with multiple assets simultaneously in warning state

### Proof of Concept

**Initial State:**
- User has 10 ETH collateral deposited in Navi
- ETH market price: $2000
- Both oracles show $2000
- User has zero debt

**Attack Sequence:**

1. **Market Event**: ETH price drops to $1800 on exchanges
2. **Oracle Divergence**: 
   - Pyth (secondary) updates to $1800 
   - Supra (primary) lags at $2000
   - Divergence: (2000-1800)/1800 = 11.1% → Warning level

3. **Attacker Transaction**:
   ```
   Call update_single_price(clock, oracle_config, price_oracle, supra_holder, pyth_info, eth_feed)
   → Severity = level_warning
   → Oracle stores $2000 (primary price)
   → Timer starts
   ```

4. **Exploit Borrow**:
   ```
   Call execute_borrow(10,000 USDC) // Attempting to borrow $10,000
   → Health factor calculated with $2000 ETH price
   → Collateral value: 10 ETH × $2000 = $20,000
   → LTV: $10,000 / $20,000 = 50%
   → Health factor: (20,000 × 0.75) / 10,000 = 1.5 ✓ PASSES
   → Borrow succeeds
   ```

**Expected vs Actual:**

**Expected (with $1800 real price):**
- Collateral value: 10 ETH × $1800 = $18,000
- Max safe borrow: $18,000 × 0.75 = $13,500
- Attempting $10,000 borrow should succeed but is close to limit

**Actual (with $2000 divergent price):**
- Collateral value: 10 ETH × $2000 = $20,000 (inflated by 11%)
- Max safe borrow: $20,000 × 0.75 = $15,000
- **User can borrow up to $15,000 instead of $13,500**
- **$1,500 additional borrowing capacity from price manipulation**

**Success Condition:**
When prices converge to $1800:
- Real collateral: 10 × $1800 = $18,000
- Real debt: $10,000
- Real health factor: (18,000 × 0.75) / 10,000 = 1.35

If user borrowed the full $15,000:
- Real health factor: (18,000 × 0.75) / 15,000 = 0.9 → **UNDERCOLLATERALIZED**
- Protocol has $15,000 debt backed by only $13,500 safe collateral
- **Bad debt: $1,500 per position**

**Notes**

The vulnerability is particularly severe because:

1. **Systemic Risk**: During market crashes, ALL positions may experience this simultaneously, multiplying the bad debt across the entire protocol

2. **Legitimate Appearance**: The exploit uses genuine market conditions (price divergence during volatility) making it indistinguishable from normal activity

3. **No Manipulation Required**: Unlike oracle manipulation attacks, this requires NO attack on the oracle infrastructure itself - just waiting for natural market conditions

4. **Time-Critical Defense**: The protocol has only 10 seconds to detect and respond before positions become underwater, insufficient for manual intervention

5. **Implementation Note**: While the question references `oracle_dynamic_getter.move`, the actual vulnerability is in `oracle_pro.move` which is the actively used implementation. The `get_dynamic_single_price()` function in `oracle_dynamic_getter.move` has identical logic but appears unused in the codebase.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L9-20)
```text
    public fun validate_price_difference(primary_price: u256, secondary_price: u256, threshold1: u64, threshold2: u64, current_timestamp: u64, max_duration_within_thresholds: u64, ratio2_usage_start_time: u64): u8 {
        let diff = utils::calculate_amplitude(primary_price, secondary_price);

        if (diff < threshold1) { return constants::level_normal() };
        if (diff > threshold2) { return constants::level_critical() };

        if (ratio2_usage_start_time > 0 && current_timestamp > max_duration_within_thresholds + ratio2_usage_start_time) {
            return constants::level_major()
        } else {
            return constants::level_warning()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-56)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
        config::version_verification(oracle_config);
        assert!(!config::is_paused(oracle_config), error::paused());
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L100-120)
```text
        if (is_primary_price_fresh && is_secondary_price_fresh) { // if 2 price sources are fresh, validate price diff
            let (price_diff_threshold1, price_diff_threshold2) = (config::get_price_diff_threshold1_from_feed(price_feed), config::get_price_diff_threshold2_from_feed(price_feed));
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds_from_feed(price_feed);
            let diff_threshold2_timer = config::get_diff_threshold2_timer_from_feed(price_feed);
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L156-165)
```text
        if (start_or_continue_diff_threshold2_timer) {
            config::start_or_continue_diff_threshold2_timer(price_feed, current_timestamp)
        } else {
            config::reset_diff_threshold2_timer(price_feed)
        };
        // update the history price to price feed
        config::keep_history_update(price_feed, final_price, clock::timestamp_ms(clock)); 
        // update the final price to PriceOracle
        oracle::update_price(clock, price_oracle, oracle_id, final_price); 
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-100)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L148-155)
```text
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/oracle/tests/oracle_pro/oracle_config_manage_test.move (L69-70)
```text
            let max_duration_within_thresholds = config::get_max_duration_within_thresholds(&oracle_config ,feed_id);
            assert!(max_duration_within_thresholds == 10000, 0);
```
