# Audit Report

## Title
Decimal Mismatch Vulnerability in Oracle Aggregator Switching Leads to Incorrect Asset Valuations

## Summary
The `change_switchboard_aggregator()` function fails to update the `decimals` field when switching oracle aggregators, causing massive valuation errors that corrupt vault accounting, share pricing, and bypass loss tolerance enforcement when the new aggregator reports prices in a different decimal format.

## Finding Description

The vulnerability exists in the oracle aggregator switching mechanism. When an admin switches to a new Switchboard aggregator, the `change_switchboard_aggregator()` function updates the aggregator address, price, and timestamp but critically omits updating the stored `decimals` field. [1](#0-0) 

The `decimals` field is stored in the `PriceInfo` struct and is essential for correct price normalization to the protocol's standard 9-decimal format. [2](#0-1) 

When vault operations call `get_normalized_asset_price()` to value assets, the function retrieves the stored `decimals` field and uses it in the normalization formula. [3](#0-2)  If this field doesn't match the actual decimal format of the current aggregator, the normalization produces completely incorrect results.

**Execution Flow:**

1. Admin legitimately calls `change_switchboard_aggregator()` through the management interface [4](#0-3) 

2. The function updates aggregator address and price but NOT decimals

3. Vault operations call `update_free_principal_value()` or `update_coin_type_asset_value()` which fetch normalized prices using the wrong decimals [5](#0-4) [6](#0-5) 

4. Loss tolerance checks compare `total_usd_value_before` and `total_usd_value_after`, but with wrong valuations, actual losses appear negligible [7](#0-6) 

5. The tolerance enforcement fails to detect real losses when valuations are inflated [8](#0-7) 

## Impact Explanation

**Direct Fund Impact:**
- **Incorrect Share Pricing:** Share ratios calculated using total USD value will be wrong. Users receive incorrect share amounts during deposits or wrong principal amounts during withdrawals.
- **Quantified Damage:** If decimals differ by n (e.g., switching from 18 to 9 decimals), valuations are off by a factor of 10^n. A vault with 1000 SUI reporting prices at 1_000_000_000 (9 decimals, $1) could be incorrectly normalized to 1 if the stored decimals is 18, making the vault appear worth $0.001 instead of $1000, causing share calculations to be 1 billion times wrong.

**Security Mechanism Bypass:**
- **Loss Tolerance Bypass:** With inflated or deflated valuations, actual losses appear negligible or gains appear enormous, failing to trigger protection limits. This allows operators to bypass loss constraints designed to protect user funds.

**Affected Parties:**
- All vault depositors receive massively incorrect share amounts
- Protocol loses ability to enforce risk management
- Entire vault accounting becomes corrupted until aggregator is fixed

## Likelihood Explanation

**High Likelihood:**

1. **Legitimate Operational Scenario:** Admins routinely switch oracle aggregators for valid reasons (better data feeds, upgrading infrastructure, redundancy). This is normal operations, not an attack.

2. **Feasible Preconditions:** The system explicitly supports different decimal formats. The `add_switchboard_aggregator()` function accepts a `decimals` parameter, and test cases demonstrate assets with 9, 6, and 18 decimals being used. [9](#0-8) [10](#0-9) 

3. **No Safeguards:** There are no validation checks ensuring decimal compatibility when switching aggregators. No warnings or events indicate a potential mismatch.

4. **Silent Failure:** The bug doesn't cause immediate transaction failure. USD values will be wrong but transactions succeed, allowing damage to accumulate before detection.

5. **Single Transaction:** Only requires one legitimate admin transaction.

## Recommendation

Update the `change_switchboard_aggregator()` function to accept a `decimals` parameter and update the `PriceInfo.decimals` field:

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // Add decimals parameter
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);
    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.decimals = decimals;  // Update decimals field
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

Also update the management wrapper in `manage.move` to pass the decimals parameter.

## Proof of Concept

```move
#[test]
public fun test_decimal_mismatch_vulnerability_poc() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Add aggregator with 18 decimals, price represents $1
        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, 0);
        
        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            18,  // 18 decimals
            &aggregator,
        );
        
        // Verify correct normalization: 1_000_000_000_000_000_000 / 10^9 = 1_000_000_000 ($1 normalized)
        let price1 = oracle_config.get_normalized_asset_price(
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        assert!(price1 == 1_000_000_000);
        
        test_scenario::return_shared(oracle_config);
        aggregator::destroy_aggregator(aggregator);
    };
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        let admin_cap = s.take_from_sender<AdminCap>();
        
        // Switch to new aggregator with 9 decimals (but decimals field NOT updated)
        let mut new_aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut new_aggregator, 1_000_000_000, 0);  // $1 with 9 decimals
        
        vault_manage::change_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            &new_aggregator,
        );
        
        // BUG: Normalized price now wrong!
        // Expected: 1_000_000_000 ($1 normalized)
        // Actual: 1_000_000_000 / 10^9 = 1 ($0.000000001 normalized)
        // Price is 1 BILLION times too small!
        let price2 = oracle_config.get_normalized_asset_price(
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        assert!(price2 == 1);  // Should be 1_000_000_000 but is 1!
        
        // If vault has 1000 SUI, it's now valued at $0.001 instead of $1000
        // Share calculations will be catastrophically wrong
        
        test_scenario::return_shared(oracle_config);
        s.return_to_sender(admin_cap);
        aggregator::destroy_aggregator(new_aggregator);
    };
    
    clock::destroy_for_testing(clock);
    s.end();
}
```

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

**File:** volo-vault/sources/oracle.move (L198-220)
```text
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let init_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];

    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });

    price_info.aggregator = aggregator.id().to_address();
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**File:** volo-vault/sources/manage.move (L118-126)
```text
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, aggregator);
}
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

**File:** volo-vault/sources/operation.move (L353-364)
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

**File:** volo-vault/tests/oracle.test.move (L479-555)
```text
public fun test_get_normalized_price_for_different_decimals() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut oracle_config = s.take_shared<OracleConfig>();

        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, 0);

        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            9,
            &aggregator,
        );

        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);

        aggregator::destroy_aggregator(aggregator);
    };

    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut oracle_config = s.take_shared<OracleConfig>();

        let mut aggregator = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator, 1_000_000_000_000_000_000, 0);

        vault_oracle::add_switchboard_aggregator(
            &mut oracle_config,
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
            6,
            &aggregator,
        );

        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);

        aggregator::destroy_aggregator(aggregator);
    };

    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let oracle_config = s.take_shared<OracleConfig>();

        let normalized_sui_price = oracle_config.get_normalized_asset_price(
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        assert!(normalized_sui_price == 1_000_000_000_000_000_000);

        let normalized_usdc_price = oracle_config.get_normalized_asset_price(
            &clock,
            type_name::get<USDC_TEST_COIN>().into_string(),
        );
        assert!(normalized_usdc_price == 1_000_000_000_000_000_000_000);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
    };

    clock::destroy_for_testing(clock);
    s.end();
}
```
