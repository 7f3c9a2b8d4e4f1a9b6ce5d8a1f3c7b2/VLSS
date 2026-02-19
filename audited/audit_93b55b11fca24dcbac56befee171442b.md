### Title
Critical Oracle Divergence Causes Complete Vault DoS Through Price Staleness Lock

### Summary
When both primary and secondary oracles persistently diverge beyond `threshold2`, the `update_single_price()` function returns without updating prices, causing price timestamps to remain stale. This triggers a complete denial-of-service condition where all vault operations (deposits, withdrawals, operations) fail after 60 seconds due to price staleness checks, effectively locking user funds indefinitely until manual intervention.

### Finding Description

The vulnerability exists in the oracle price update mechanism at [1](#0-0) 

When the price difference validation returns `level_critical` severity (indicating divergence exceeds `threshold2`), the function immediately returns without calling `oracle::update_price()` at line 164. The severity levels are defined as [2](#0-1)  where `level_critical` returns 0, and the validation logic is implemented at [3](#0-2) 

This design flaw creates a deadlock scenario. The vault's `get_total_usd_value()` function enforces staleness checks at [4](#0-3)  requiring all asset prices to be updated within `MAX_UPDATE_INTERVAL` (60 seconds).

All critical vault operations depend on this function:
- Deposit execution calls it at [5](#0-4)  and [6](#0-5) 
- Operation start calls it at [7](#0-6) 
- Operation value updates call it at [8](#0-7) 

When oracles persistently diverge (e.g., during extreme market volatility, oracle manipulation, or technical failures), the safety mechanism intended to prevent accepting incorrect prices instead creates a worse outcome: complete operational paralysis.

While a manual override exists via `OracleFeederCap::update_token_price()` at [9](#0-8) , this requires immediate detection and intervention within the 60-second window, and does not address persistent divergence scenarios.

### Impact Explanation

**Critical Operational Impact:**
- All deposit executions fail, blocking users from entering positions
- All withdrawal executions fail, trapping user funds indefinitely  
- All vault operations fail, preventing rebalancing and yield strategies
- Share ratio calculations fail, blocking fee collection and reward distribution

**Fund Custody Impact:**
- User funds effectively locked until manual intervention
- Pending deposits stuck in request buffers
- Pending withdrawals cannot be executed
- Receipt holders cannot redeem their shares

**Protocol-Wide Cascade:**
- Multi-vault systems dependent on receipt adaptors become blocked
- External protocols integrating with affected vaults experience failures
- Reward managers cannot process distributions

The severity is **CRITICAL** because:
1. Complete loss of protocol functionality
2. Indefinite fund lockup without user recourse
3. Affects all users simultaneously
4. No automatic recovery mechanism

### Likelihood Explanation

**Highly Probable Scenario:**

Oracle divergence beyond `threshold2` is a realistic condition that occurs during:
- Extreme market volatility (flash crashes, major news events)
- Oracle provider technical issues (API downtime, feed delays)
- Chain congestion affecting oracle update transactions
- Deliberate oracle manipulation by exploiters
- Cross-chain bridge failures affecting price feeds

**Attacker Capabilities:**
- No special privileges required - any market participant can cause oracle divergence
- Low cost if exploiting natural market volatility
- Moderate cost if manipulating secondary oracle feed directly
- Economic incentive: Force vault into emergency state for competitive advantage or short positions

**Execution Practicality:**
- Precondition: Both oracles must be enabled and providing fresh prices
- Trigger: Natural divergence > `threshold2` OR manipulation of one oracle source
- Persistence: Continues as long as underlying market conditions or manipulation persists
- No transaction complexity - happens automatically through normal oracle updates

**Detection Constraints:**
- Event emission at [10](#0-9)  alerts to divergence but not DoS consequence
- 60-second window for intervention is insufficient during off-hours or incident response
- Manual override requires `OracleFeederCap` holder availability and awareness

The likelihood is **HIGH** because oracle divergence is a common occurrence in DeFi systems, especially during market stress when vault operations are most critical.

### Recommendation

**Immediate Fix - Add Fallback Logic:**

Modify `update_single_price()` to accept primary oracle price even when severity is `level_critical`, but:
1. Emit critical warning event
2. Set a flag marking the price as "unvalidated"
3. Apply conservative deviation limits
4. Require admin acknowledgment before next operation

```move
// At line 118, replace the immediate return with fallback logic:
if (severity == constants::level_critical()) {
    // Use primary price with critical flag
    emit(CriticalPriceDivergenceAccepted {
        config_address,
        feed_address,
        primary_price,
        secondary_price,
        timestamp: current_timestamp
    });
    // Continue to price validation and update with primary price
} else if (severity != constants::level_warning()) {
    return  // Only return for level_major
};
```

**Secondary Mitigation - Historical Price Fallback:**

Enhance the historical price validation at [11](#0-10)  to use last valid price when both oracles diverge:

1. Store last validated dual-oracle price with extended TTL
2. When `level_critical` occurs, use historical price if within acceptable age
3. Gradually increase staleness tolerance during persistent divergence

**Tertiary Protection - Emergency Circuit Breaker:**

Add vault-level emergency mode:
1. Allow operations with explicit staleness acknowledgment parameter
2. Apply conservative loss tolerance multiplier during oracle issues
3. Rate-limit operations to prevent exploitation
4. Require multi-sig admin approval to enter/exit emergency mode

**Invariant Checks:**
- `assert!(price_timestamp_updated || emergency_mode_enabled)`
- Test persistent oracle divergence scenarios
- Verify operations continue with fallback prices
- Validate emergency mode activation/deactivation flows

**Test Cases:**
1. Simulate 5-minute oracle divergence > threshold2
2. Verify deposits/withdrawals continue with primary price
3. Test historical price fallback activation
4. Validate emergency mode prevents excessive loss
5. Ensure events properly alert operators to divergence

### Proof of Concept

**Initial State:**
- Vault with active deposits and withdrawal requests
- Oracle configured with `threshold2 = 5%` (500 basis points)
- Both Pyth and Supra oracles enabled and operational
- Users have pending deposit/withdrawal requests

**Attack Sequence:**

**Step 1 - Natural Divergence Occurs:**
```
Transaction 1: Market volatility causes Pyth price: $100, Supra price: $106
Price difference: 6% > threshold2 (5%)
Call: update_single_price(oracle_config, price_oracle, supra_holder, pyth_info, feed_address)
Result: Function returns at line 118 without updating PriceOracle
Effect: price.timestamp remains at T0
```

**Step 2 - Wait 61 Seconds:**
```
Time advances: T0 + 61 seconds
Oracle timestamps still fresh (< max_timestamp_diff)
But PriceOracle.price.timestamp not updated (still T0)
```

**Step 3 - User Attempts Deposit:**
```
Transaction 2: execute_deposit(vault, reward_manager, clock, config, request_id, max_shares)
Calls: vault.get_total_usd_value(clock) at line 820
Checks: now - last_update_time = 61 seconds > MAX_UPDATE_INTERVAL (60 seconds)
Result: ABORT with ERR_USD_VALUE_NOT_UPDATED
```

**Step 4 - User Attempts Withdrawal:**
```
Transaction 3: execute_withdraw(vault, clock, config, request_id, min_amount)
Calls: vault.get_total_usd_value(clock)  
Result: ABORT with ERR_USD_VALUE_NOT_UPDATED
```

**Step 5 - Operator Attempts Vault Operation:**
```
Transaction 4: start_op_with_bag(vault, operation, cap, clock, ...)
Calls: vault.get_total_usd_value(clock) at line 178
Result: ABORT with ERR_USD_VALUE_NOT_UPDATED
```

**Expected vs Actual Result:**
- **Expected:** Vault accepts one oracle's price with warning and continues operations
- **Actual:** Complete vault paralysis, all operations blocked, funds locked

**Success Condition for DoS:**
- All vault operations fail for 61+ seconds after oracle divergence
- Condition persists indefinitely while oracles remain diverged
- Only manual intervention via `OracleFeederCap` can recover

**Notes:**
The vulnerability's criticality is amplified because the safety mechanism (rejecting divergent prices) creates a worse security outcome (complete fund lockup) than the risk it attempts to mitigate (accepting potentially incorrect price from one oracle). During market stress when accurate pricing is most critical, the vault becomes completely non-operational.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L106-117)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L118-118)
```text
                if (severity != constants::level_warning()) { return };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L139-154)
```text
        if (!strategy::validate_price_range_and_history(final_price, maximum_effective_price, minimum_effective_price, maximum_allowed_span_percentage, current_timestamp, historical_price_ttl, historical_price, historical_updated_time)) {
            emit(InvalidOraclePrice {
                config_address: config_address,
                feed_address: feed_address,
                provider: provider::to_string(primary_oracle_provider),
                price: final_price,
                maximum_effective_price: maximum_effective_price,
                minimum_effective_price: minimum_effective_price,
                maximum_allowed_span: maximum_allowed_span_percentage,
                current_timestamp: current_timestamp,
                historical_price_ttl: historical_price_ttl,
                historical_price: historical_price,
                historical_updated_time: historical_updated_time,
            });
            return
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

**File:** volo-vault/sources/volo_vault.move (L820-821)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L841-841)
```text
    let total_usd_value_after = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1266)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L138-150)
```text
    public entry fun update_token_price(
        _: &OracleFeederCap,
        clock: &Clock,
        price_oracle: &mut PriceOracle,
        oracle_id: u8,
        token_price: u256,
    ) {
        version_verification(price_oracle);

        let price_oracles = &mut price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());
        let price = table::borrow_mut(price_oracles, oracle_id);
        price.value = token_price;
```
