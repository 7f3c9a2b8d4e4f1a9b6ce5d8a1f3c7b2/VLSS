### Title
Missing Pyth Confidence Interval Validation Allows Inaccurate Prices to Break Vault Risk Calculations

### Summary
The `get_price_unsafe_to_target_decimal()` function in the Pyth oracle adaptor does not validate Pyth's confidence interval before converting and returning prices. This allows prices with wide confidence bands to be accepted and used in vault USD valuations, share ratio calculations, and loss tolerance checks, enabling value extraction through mispriced deposits/withdrawals and bypassing risk management controls.

### Finding Description

**Root Cause:**
The `get_price_unsafe_to_target_decimal()` function extracts only the price magnitude, exponent, and timestamp from Pyth's `PriceInfoObject` without checking the confidence interval that indicates price quality. [1](#0-0) 

The function calls `get_price_unsafe_native()` which retrieves price data but never accesses the confidence field available via `price::get_conf()`. [2](#0-1) 

**Contrast with Proper Implementation:**
The Suilend module in the codebase demonstrates the correct approach - it validates that the confidence interval must be less than 10% of the price magnitude, returning `option::none()` if the check fails. [3](#0-2) 

**Execution Path:**
1. `oracle_pro::update_single_price()` calls `get_price_from_adaptor()` which invokes the vulnerable function: [4](#0-3) 

2. The unchecked price flows into vault valuation functions that calculate USD values for share ratio determination: [5](#0-4) [6](#0-5) 

3. These USD values drive share calculations in deposit execution: [7](#0-6) 

4. And loss tolerance enforcement in operations: [8](#0-7) [9](#0-8) 

**Why Existing Protections Fail:**
While the oracle system includes price difference validation, range checks, and staleness checks, none of these validate Pyth's confidence interval: [10](#0-9) [11](#0-10) 

These checks can pass even when confidence is wide because:
- Price difference validation only helps with dual sources (both could have wide confidence)
- Range validation uses configured bounds that may be wider than confidence indicates
- Historical price comparison doesn't detect sudden confidence degradation
- Staleness only checks timestamp, not price quality

### Impact Explanation

**Direct Fund Impact:**
When Pyth reports a price with wide confidence (e.g., $100 ± $30), the actual price could range from $70-$130, but the vault accepts $100 as accurate. Users can exploit this:

1. **Deposit Exploitation**: If actual value is $130 but reported as $100, depositing principal valued at actual $130 yields shares calculated at $100, granting 30% excess shares
2. **Withdrawal Exploitation**: If actual value is $70 but reported as $100, withdrawing shares burns them at $100 calculation but extracts assets worth actual $70, draining 30% excess value
3. **Compounding Effect**: Multiple assets with wide confidence bands amplify mispricing

**Loss Tolerance Bypass:**
Incorrect USD valuations can cause operations to incorrectly pass or fail loss tolerance checks, allowing operations that should be blocked or blocking legitimate operations.

**Affected Parties:**
- Vault depositors suffer dilution when others exploit mispriced entries
- Existing shareholders lose value when mispriced withdrawals extract excess funds
- Protocol incurs unrealized losses that exceed configured tolerance

**Severity Justification:**
High severity - enables direct value extraction from vault through normal user operations, undermines core risk management invariant (accurate pricing), and affects all vault assets using Pyth pricing.

### Likelihood Explanation

**Attacker Capabilities:**
No special capabilities required - any user can deposit/withdraw during periods of wide confidence. The attacker simply needs to:
1. Monitor Pyth confidence intervals (publicly available on-chain)
2. Execute standard vault operations (deposit/withdraw) when confidence is wide

**Attack Complexity:**
Low complexity - requires only:
- Monitoring Pyth price feeds for wide confidence events
- Executing normal vault transactions during these windows
- No protocol manipulation or special access needed

**Feasibility Conditions:**
Wide confidence intervals occur naturally during:
- Low liquidity periods in underlying markets
- High volatility events (market crashes, news events)
- Oracle network disruptions or update delays
- Cross-chain bridge issues affecting price feed data
- Thin orderbook conditions

These are realistic market conditions that occur regularly in DeFi, not attacker-controlled scenarios.

**Detection/Operational Constraints:**
- Wide confidence is visible on-chain but not monitored by vault
- Exploit transactions appear as legitimate deposits/withdrawals
- No rate limiting or monitoring prevents exploitation during confidence degradation
- Multi-asset vault increases attack surface (more assets to monitor)

**Probability:**
High - Pyth confidence intervals regularly widen during normal market stress, providing frequent exploitation windows. The lack of confidence validation is a systematic gap affecting all Pyth price updates.

### Recommendation

**Code-Level Mitigation:**

1. **Add Confidence Validation** in `adaptor_pyth.move`:

Modify `get_price_unsafe_to_target_decimal()` to extract and validate confidence:

```move
public fun get_price_unsafe_to_target_decimal(pyth_price_info: &PriceInfoObject, target_decimal: u8): (u256, u64) {
    let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);
    
    let i64_price = price::get_price(&pyth_price_info_unsafe);
    let price_mag = i64::get_magnitude_if_positive(&i64_price);
    let conf = price::get_conf(&pyth_price_info_unsafe);
    
    // Validate confidence interval (conf must be < 10% of price)
    const MIN_CONFIDENCE_RATIO: u64 = 10;
    assert!(conf * MIN_CONFIDENCE_RATIO <= price_mag, ERROR_WIDE_CONFIDENCE_INTERVAL);
    
    let i64_expo = price::get_expo(&pyth_price_info_unsafe);
    let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000;
    let expo = i64::get_magnitude_if_negative(&i64_expo);
    
    let decimal_price = utils::to_target_decimal_value_safe((price_mag as u256), expo, (target_decimal as u64));
    (decimal_price, timestamp)
}
```

2. **Alternative Graceful Handling**:

Return `Option<(u256, u64)>` instead of aborting, allowing oracle system to fall back to secondary price or reject the update gracefully:

```move
public fun get_price_unsafe_to_target_decimal_safe(pyth_price_info: &PriceInfoObject, target_decimal: u8): Option<(u256, u64)>
```

3. **Configuration Parameter**:

Add configurable `MAX_CONFIDENCE_RATIO` per asset in `OracleConfig` to allow different confidence requirements for different asset volatility profiles.

**Invariant Checks:**
- Add confidence ratio check: `confidence ≤ price / MIN_CONFIDENCE_RATIO`
- Emit event when confidence validation fails for monitoring
- Consider circuit breaker if multiple assets fail confidence checks

**Test Cases:**
1. Test price update with confidence = 15% (should fail with MIN_CONFIDENCE_RATIO=10)
2. Test price update with confidence = 5% (should succeed)
3. Test fallback to secondary oracle when primary fails confidence
4. Test deposit/withdrawal cannot exploit wide confidence prices
5. Fuzz test with various confidence ratios during market volatility scenarios

### Proof of Concept

**Initial State:**
- Vault has $1,000,000 total USD value
- Total shares: 1,000,000 (share ratio = $1.00)
- User has $100,000 USDC to deposit
- Asset XYZ actual market price: $100

**Attack Sequence:**

1. **Confidence Degradation**: Pyth oracle for XYZ experiences thin liquidity, reports:
   - Price: $70
   - Confidence: ±$35 (50% confidence band)
   - Timestamp: Fresh (within staleness threshold)

2. **Oracle Update**: Operator calls `update_single_price()`:
   - `get_price_unsafe_to_target_decimal()` returns $70 without checking confidence
   - No secondary oracle or secondary also affected
   - Range check passes (within max/min effective prices)
   - Historical check passes (if configured span > 30%)
   - Price accepted and stored

3. **Exploit Deposit**: User deposits $100,000 USDC:
   - Vault values XYZ holdings at $70 (30% undervalued)
   - Total vault USD value incorrectly calculated as lower
   - Share ratio incorrectly calculated at ~$0.93
   - User receives ~107,527 shares instead of 100,000 shares
   - User gains 7,527 shares (~$7,527 value) at expense of existing shareholders

4. **Price Recovery**: When confidence narrows and price returns to $100:
   - User's 107,527 shares now worth $107,527
   - User can withdraw for $7,527 profit
   - Existing shareholders absorbed the loss

**Expected vs Actual Result:**
- **Expected**: Confidence validation rejects $70 price with ±$35 confidence, oracle update fails, deposit uses last valid price
- **Actual**: $70 price accepted, user exploits mispricing for guaranteed profit

**Success Condition:**
User successfully extracts value by depositing during wide confidence period and withdrawing after price/confidence stabilizes, proven by share count exceeding fair value allocation.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L27-37)
```text
    public fun get_price_unsafe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
        let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);

        let i64_price = price::get_price(&pyth_price_info_unsafe);
        let i64_expo = price::get_expo(&pyth_price_info_unsafe);
        let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000; // timestamp from pyth in seconds, should be multiplied by 1000
        let price = i64::get_magnitude_if_positive(&i64_price);
        let expo = i64::get_magnitude_if_negative(&i64_expo);

        (price, expo, timestamp)
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L48-53)
```text
    public fun get_price_unsafe_to_target_decimal(pyth_price_info: &PriceInfoObject, target_decimal: u8): (u256, u64) {
        let (price, decimal, timestamp) = get_price_unsafe_native(pyth_price_info);
        let decimal_price = utils::to_target_decimal_value_safe((price as u256), decimal, (target_decimal as u64));

        (decimal_price, timestamp)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L31-38)
```text
        let conf = price::get_conf(&price);

        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L176-179)
```text
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L838-850)
```text
    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1101-1128)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );

    let principal_asset_type = type_name::get<PrincipalCoinType>().into_string();

    finish_update_asset_value(
        self,
        principal_asset_type,
        principal_usd_value,
        clock.timestamp_ms(),
    );
}
```

**File:** volo-vault/sources/volo_vault.move (L1130-1154)
```text
public fun update_coin_type_asset_value<PrincipalCoinType, CoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();
    assert!(
        type_name::get<CoinType>() != type_name::get<PrincipalCoinType>(),
        ERR_INVALID_COIN_ASSET_TYPE,
    );

    let asset_type = type_name::get<CoinType>().into_string();
    let now = clock.timestamp_ms();

    let coin_amount = self.assets.borrow<String, Balance<CoinType>>(asset_type).value() as u256;
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);

    finish_update_asset_value(self, asset_type, coin_usd_value, now);
}
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/strategy.move (L23-53)
```text
    public fun validate_price_range_and_history(
        price: u256,
        maximum_effective_price: u256,
        minimum_effective_price: u256,
        maximum_allowed_span_percentage: u64,
        current_timestamp: u64,
        historical_price_ttl: u64,
        historical_price: u256,
        historical_updated_time: u64,
    ): bool {
        // check if the price is greater than the maximum configuration value
        if (maximum_effective_price > 0 && price > maximum_effective_price) {
            return false
        };

        // check if the price is less than the minimum configuration value
        if (price < minimum_effective_price) {
            return false
        };

        // check the final price and the history price range is smaller than the acceptable range
        if (current_timestamp - historical_updated_time < historical_price_ttl) {
            let amplitude = utils::calculate_amplitude(historical_price, price);

            if (amplitude > maximum_allowed_span_percentage) {
                return false
            };
        };

        return true
    }
```
