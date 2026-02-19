### Title
Critical Oracle Misconfiguration: Incorrect Decimals Parameter Enables Massive Fund Theft Through Price Manipulation

### Summary
The `add_switchboard_aggregator` function accepts an unconstrained `decimals` parameter with no validation, allowing an admin to accidentally configure incorrect decimal precision for price feeds. This causes `get_normalized_asset_price` to apply incorrect scaling factors (multiplying or dividing by powers of 10), resulting in USD valuations that can be orders of magnitude too high or too low. Users can exploit admin misconfigurations to receive 1000x more shares on deposit or withdraw 1000x more assets, enabling direct theft of vault funds.

### Finding Description
The vulnerability exists in the oracle configuration flow where price feed decimals are stored without validation. [1](#0-0) 

The admin provides a `decimals: u8` parameter that gets stored directly in the `PriceInfo` struct without any validation against the actual coin's decimal precision or Switchboard feed format: [2](#0-1) 

This stored decimals value is later used by `get_normalized_asset_price` to scale prices relative to a 9-decimal reference point: [3](#0-2) 

**Root Cause**: When `decimals` is incorrect, the scaling logic produces massively wrong prices:
- If actual coin has 9 decimals but admin sets `decimals=6`: price is multiplied by 10³ (1000x inflation)
- If actual coin has 6 decimals but admin sets `decimals=9`: price is divided by 10⁰ while it should be multiplied by 10³ (1000x deflation)

These incorrect prices flow into all USD value calculations: [4](#0-3) 

And directly affect deposit share calculations: [5](#0-4) 

The share ratio calculation uses total USD value, which includes the incorrectly priced assets: [6](#0-5) 

### Impact Explanation
**Direct Fund Theft Scenario:**

1. Vault holds 100 SUI (9 decimals) correctly valued at $200 total ($2/SUI), with 100 shares outstanding
2. Admin mistakenly configures SUI aggregator with `decimals=6` instead of `decimals=9`
3. `get_normalized_asset_price` multiplies the price by 10³, making it $2,000 per SUI
4. Attacker deposits 1 SUI ($2 actual value):
   - Vault calculates it as $2,000 value (1000x inflated)
   - Share ratio before deposit = $200 / 100 = $2 per share (still correct based on old valuation)
   - New total USD = $200 + $2,000 = $2,200
   - Attacker receives shares = $2,000 / $2 = 1,000 shares
   - Attacker should receive = $2 / $2 = 1 share
5. Attacker now owns 1,000 shares out of 1,100 total (90.9%)
6. Attacker immediately withdraws, stealing ~91 SUI for their 1 SUI deposit

**Quantified Impact:**
- 100 SUI vault (~$200) can be drained with a 1 SUI deposit (~$2)
- Attack cost: $2, Gain: $180, ROI: 9000%
- Affects all existing shareholders proportionally
- Works for any decimal mismatch magnitude (10x, 100x, 1000x, etc.)

**Additional Impacts:**
- Loss tolerance checks become meaningless (can hide real losses or trigger false alarms)
- Receipt valuations for nested vaults become incorrect
- Operation value update validation fails to detect actual losses

### Likelihood Explanation
**Attack Feasibility:** HIGH

**Attacker Capabilities Required:**
- Monitor oracle configuration transactions for decimal mismatches
- Execute standard deposit transaction
- No special permissions needed - any user can exploit

**Attack Preconditions:**
- Admin makes configuration error (decimals parameter mismatch)
- Common scenario: Multi-asset vaults with coins of different decimals (SUI=9, USDC=6, BTC=8)
- High probability of human error without validation

**Detection Difficulty:**
- Silent failure - no error messages
- USD values appear in events but may not be obviously wrong to casual observers
- Can be disguised as normal market volatility if magnitude is smaller

**Economic Viability:**
- Attack cost: Single deposit transaction (~$2 in example)
- Profit potential: Up to total vault value
- No ongoing costs or complex setup required
- Immediate execution - can frontrun correction transactions

**Real-World Likelihood:**
The vulnerability does NOT require malicious admin behavior - honest configuration mistakes are sufficient and highly probable because:
1. No validation feedback during configuration
2. Different coins have different decimals (6, 8, 9, 18)
3. Switchboard documentation may be unclear about expected format
4. Testing might not catch edge cases with multiple decimal precisions

### Recommendation
**Immediate Mitigation:**

1. **Add CoinMetadata validation in `add_switchboard_aggregator`:**
```move
public(package) fun add_switchboard_aggregator<CoinType>(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
    coin_metadata: &CoinMetadata<CoinType>,
) {
    // Validate decimals matches actual coin decimals
    assert!(decimals == coin_metadata::get_decimals(coin_metadata), ERR_INVALID_DECIMALS);
    
    // existing logic...
}
```

2. **Add sanity checks on normalized prices:**
```move
public fun get_normalized_asset_price(...): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;
    
    // Sanity check: normalized price should be within reasonable bounds
    // e.g., between $0.000001 and $10,000,000 per smallest unit
    assert!(price > MIN_REASONABLE_PRICE && price < MAX_REASONABLE_PRICE, ERR_PRICE_OUT_OF_BOUNDS);
    
    // existing normalization logic...
}
```

3. **Add admin function to safely update decimals with validation:**
```move
public(package) fun update_aggregator_decimals<CoinType>(
    config: &mut OracleConfig,
    asset_type: String,
    new_decimals: u8,
    coin_metadata: &CoinMetadata<CoinType>,
) {
    assert!(new_decimals == coin_metadata::get_decimals(coin_metadata), ERR_INVALID_DECIMALS);
    let price_info = &mut config.aggregators[asset_type];
    price_info.decimals = new_decimals;
}
```

4. **Add integration tests covering:**
    - Multiple coins with different decimals in same vault
    - Attempting to add aggregator with wrong decimals
    - Deposit/withdrawal calculations with various decimal precisions

### Proof of Concept

**Initial State:**
- Deploy vault with SUI as principal coin (9 decimals)
- 100 SUI deposited by honest users at $2/SUI = $200 total value
- 100 shares minted to honest users
- Admin configures Switchboard aggregator with `decimals=6` (WRONG, should be 9)

**Attack Steps:**

Transaction 1 - Admin Misconfiguration:
```move
vault_manage::add_switchboard_aggregator(
    admin_cap,
    oracle_config,
    clock,
    type_name::get<SUI>().into_string(),
    6, // WRONG! Should be 9
    sui_aggregator
);
```

Transaction 2 - Attacker Deposits:
```move
// Attacker deposits 1 SUI
vault::request_deposit(vault, clock, receipt, 1_000_000_000); // 1 SUI = 10^9 smallest units

// Operator executes deposit
vault::execute_deposit(vault, clock, oracle_config, request_id, max_shares);
```

**Expected Result:**
- Attacker receives ~1 share for 1 SUI deposit
- Total shares = 101
- Attacker owns ~1% of vault

**Actual Result:**
- `get_normalized_asset_price` returns 2 * 10^21 (1000x inflated)
- `update_free_principal_value` calculates: (101 * 10^9 * 2 * 10^21) / 10^18 = 202 * 10^12
- New USD value deposited = 202,000 * 10^9 - 200 * 10^9 = 201,800 * 10^9
- Attacker receives shares = 201,800 * 10^9 / 2 * 10^9 = 100,900 shares
- Total shares = 100,900 + 100 = 101,000 shares
- Attacker owns 99.9% of vault

Transaction 3 - Attacker Withdraws:
```move
vault::request_withdraw(vault, clock, receipt_id, 100_900_shares);
vault::execute_withdraw(vault, clock, oracle_config, request_id, max_amount);
// Attacker receives ~99.9 SUI, gaining ~98.9 SUI profit
```

**Success Condition:**
Attacker extracts significantly more value than deposited due to inflated share valuation from incorrect decimal configuration.

### Citations

**File:** volo-vault/sources/manage.move (L99-108)
```text
public fun add_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    oracle_config.add_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}
```

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** volo-vault/sources/oracle.move (L158-184)
```text
public(package) fun add_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,
    aggregator: &Aggregator,
) {
    config.check_version();

    assert!(!config.aggregators.contains(asset_type), ERR_AGGREGATOR_ALREADY_EXISTS);
    let now = clock.timestamp_ms();

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = PriceInfo {
        aggregator: aggregator.id().to_address(),
        decimals,
        price: init_price,
        last_updated: now,
    };
    config.aggregators.add(asset_type, price_info);

    emit(SwitchboardAggregatorAdded {
        asset_type,
        aggregator: aggregator.id().to_address(),
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L839-844)
```text
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1297-1317)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
```
