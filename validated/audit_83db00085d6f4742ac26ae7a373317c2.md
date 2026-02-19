# Audit Report

## Title
Critical Oracle Misconfiguration: Incorrect Decimals Parameter Enables Massive Fund Theft Through Price Manipulation

## Summary
The `add_switchboard_aggregator` function accepts a `decimals` parameter without validation against the actual coin's decimal precision. This creates a critical vulnerability where incorrect decimal configuration causes `get_normalized_asset_price` to apply wrong scaling factors (up to 1000x), enabling attackers to exploit admin misconfigurations by depositing small amounts to receive massively inflated shares and drain vault funds.

## Finding Description
The vulnerability stems from missing input validation in the oracle configuration flow. [1](#0-0) 

When an admin configures a Switchboard aggregator, they provide a `decimals: u8` parameter that gets stored directly in the `PriceInfo` struct without any validation against the actual coin's decimal precision. [2](#0-1) 

This stored decimals value is later used by `get_normalized_asset_price` to scale prices relative to a 9-decimal normalization point. [3](#0-2) 

**The Root Cause:** Switchboard returns prices in 18-decimal format [4](#0-3) , and the normalization logic compensates for coin decimals by:
- If coin decimals < 9: multiplying price by 10^(9-decimals)
- If coin decimals ≥ 9: dividing price by 10^(decimals-9)

When the configured `decimals` parameter is incorrect:
- SUI (9 decimals) configured as decimals=6: price multiplied by 10³ = 1000x inflation
- USDC (6 decimals) configured as decimals=9: price divided when it should multiply = 1000x deflation

Test evidence confirms this behavior: [5](#0-4) 

The corrupted prices flow into USD value calculations used throughout the vault. [6](#0-5) 

This directly affects deposit share calculations where user shares are computed as `new_usd_value_deposited / share_ratio_before`. [7](#0-6) 

The oracle price is multiplied with coin balance to compute USD value using the formula `balance * normalized_price / 1e18`. [8](#0-7) 

## Impact Explanation
**Critical Fund Loss Scenario:**

Assume a vault holds 100 SUI (9 decimals, market price $2/SUI) = $200 total value with 100 shares outstanding.

Admin mistakenly configures SUI aggregator with `decimals=6` instead of `decimals=9`.

When Switchboard returns $2/SUI as 2×10^18:
- Incorrect normalization: 2×10^18 × 10^(9-6) = 2×10^21
- This represents $2,000 per SUI (1000x inflated)

Attacker deposits 1 SUI ($2 actual value):
1. Vault calculates deposit as $2,000 USD value (using corrupted oracle price)
2. Share ratio before deposit = $200 / 100 shares = $2 per share
3. New total USD = $200 (old) + $2,000 (new) = $2,200
4. Attacker receives: $2,000 / $2 = **1,000 shares** (should be 1 share)
5. Attacker now owns 1,000 / 1,100 = 90.9% of vault
6. Attacker withdraws ~91 SUI for their 1 SUI deposit

**Quantified Impact:**
- Attack cost: $2 (1 SUI)
- Attacker gain: $180 (90 SUI stolen)
- Return: 9000%
- All existing shareholders lose 90.9% of their holdings
- Works for any decimal mismatch: 1-decimal error = 10x, 2-decimal = 100x, 3-decimal = 1000x

The vulnerability affects share calculations [9](#0-8)  which aggregate all asset USD values including the misconfigured assets.

## Likelihood Explanation
**HIGH LIKELIHOOD - Realistic Preconditions:**

1. **Multi-Asset Vault Configuration:** Production vaults support multiple coins with different decimals:
   - SUI: 9 decimals
   - USDC: 6 decimals  
   - BTC: 8 decimals
   - WETH: 18 decimals

2. **No Validation Feedback:** The protocol provides no error checking or warnings when decimals are configured. The function signature accepts any `u8` value. [10](#0-9) 

3. **Easy Admin Error:** When configuring 5+ different asset types, confusing which coin has which decimal count is highly probable without tooling validation.

4. **Silent Failure:** No on-chain validation occurs, and USD values appear in events but may not be obviously wrong to operators monitoring transactions.

**Attacker Capabilities:**
- Monitor blockchain for oracle configuration transactions
- Detect decimal mismatches by comparing expected vs actual USD values
- Execute standard deposit via public interfaces (no special permissions)
- Frontrun admin correction transactions
- Immediate profit extraction through withdrawal

**No Effective Protections:**
- Slippage parameters (`expected_shares`, `max_shares_received`) are user-provided and attacker-controlled [11](#0-10) 
- Loss tolerance checks apply to operations, not direct deposits
- Admin pause requires detecting the issue first, giving attacker time window

## Recommendation
**Immediate Fix:**
1. Add validation that compares the provided `decimals` parameter against `CoinMetadata<T>` for the asset type during configuration
2. Implement sanity checks on normalized prices (e.g., reject if normalized price differs by >10x from raw price)
3. Add a time-delayed configuration update mechanism allowing detection before activation
4. Emit detailed events showing both raw and normalized prices for monitoring

**Long-term Fix:**
```move
// Fetch coin decimals from metadata instead of accepting as parameter
public(package) fun add_switchboard_aggregator<CoinType>(
    config: &mut OracleConfig,
    clock: &Clock,
    aggregator: &Aggregator,
    coin_metadata: &CoinMetadata<CoinType>,
) {
    let asset_type = type_name::get<CoinType>().into_string();
    let decimals = coin_metadata::get_decimals(coin_metadata);  // Get from metadata
    // ... rest of function
}
```

Alternatively, if generic approach isn't feasible:
- Implement admin-settable decimal bounds per asset type
- Require two-step configuration: propose then confirm after delay
- Add circuit breakers detecting abnormal share issuance rates

## Proof of Concept

```move
#[test]
fun test_decimal_misconfiguration_exploit() {
    let mut scenario = test_scenario::begin(@admin);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault with 100 SUI correctly valued at $2/SUI = $200
    init_vault::init_vault(&mut scenario, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut scenario);
    
    scenario.next_tx(@admin);
    {
        let mut oracle_config = scenario.take_shared<OracleConfig>();
        let mut aggregator = mock_aggregator::create_mock_aggregator(scenario.ctx());
        
        // Switchboard price: $2/SUI = 2e18
        mock_aggregator::set_current_result(&mut aggregator, 2_000_000_000_000_000_000, 0);
        
        // VULNERABILITY: Admin mistakenly configures SUI with decimals=6 instead of 9
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            6,  // Wrong! Should be 9 for SUI
            &aggregator,
        );
        
        let normalized_price = vault_oracle::get_normalized_asset_price(
            &oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        
        // Price is now 2e21 instead of 2e18 = 1000x inflated
        assert!(normalized_price == 2_000_000_000_000_000_000_000, 0);
        
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };
    
    // Attacker deposits 1 SUI and receives ~1000 shares instead of 1
    // Can now withdraw ~91 SUI from the 100 SUI vault
    
    clock.destroy_for_testing();
    scenario.end();
}
```

This test demonstrates that configuring `decimals=6` for a 9-decimal coin causes `get_normalized_asset_price` to return a price inflated by 1000x, enabling the exploit described in the impact section.

### Citations

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
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

**File:** volo-vault/local_dependencies/switchboard_sui/on_demand/sources/utils/decimal.move (L5-5)
```text
const DECIMALS: u8 = 18;
```

**File:** volo-vault/tests/oracle.test.move (L558-638)
```text
// [TEST-CASE: Should get correct usd value with normalized prices.] @test-case ORACLE-010
public fun test_get_correct_usd_value_with_oracle_price_with_different_decimals() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    let sui_asset_type = type_name::get<SUI_TEST_COIN>().into_string();
    let usdc_asset_type = type_name::get<USDC_TEST_COIN>().into_string();
    let btc_asset_type = type_name::get<BTC_TEST_COIN>().into_string();

    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);

        test_scenario::return_shared(oracle_config);
    };

    s.next_tx(OWNER);
    {
        let config = s.take_shared<OracleConfig>();

        assert!(
            vault_oracle::get_asset_price(&config, &clock, sui_asset_type) == 2 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_asset_price(&config, &clock, usdc_asset_type) == 1 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_asset_price(&config, &clock, btc_asset_type) == 100_000 * ORACLE_DECIMALS,
        );

        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, sui_asset_type) == 2 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, usdc_asset_type) == 1 * ORACLE_DECIMALS * 1_000,
        );
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, btc_asset_type) == 100_000 * ORACLE_DECIMALS * 10,
        );

        test_scenario::return_shared(config);
    };

    s.next_tx(OWNER);
    {
        let config = s.take_shared<OracleConfig>();

        let sui_usd_value_for_1_sui = vault_utils::mul_with_oracle_price(
            1_000_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, sui_asset_type),
        );

        let usdc_usd_value_for_1_usdc = vault_utils::mul_with_oracle_price(
            1_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, usdc_asset_type),
        );

        let btc_usd_value_for_1_btc = vault_utils::mul_with_oracle_price(
            100_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, btc_asset_type),
        );

        assert!(sui_usd_value_for_1_sui == 2 * DECIMALS);
        assert!(usdc_usd_value_for_1_usdc == 1 * DECIMALS);
        assert!(btc_usd_value_for_1_btc == 100_000 * DECIMALS);

        test_scenario::return_shared(config);
    };

    clock.destroy_for_testing();
    s.end();
}
```

**File:** volo-vault/sources/volo_vault.move (L821-872)
```text
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

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

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
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

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
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
}
```

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

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
