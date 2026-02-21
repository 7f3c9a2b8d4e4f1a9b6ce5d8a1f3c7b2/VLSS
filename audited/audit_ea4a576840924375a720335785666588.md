# Audit Report

## Title
Decimal Mismatch Vulnerability in Oracle Aggregator Switching Leads to Incorrect Asset Valuations

## Summary
The `change_switchboard_aggregator()` function allows admins to switch Switchboard oracle aggregators but critically fails to update the stored `decimals` field in `PriceInfo`. When the new aggregator reports prices in a different decimal format than the old one, all subsequent price normalizations use incorrect decimal values, resulting in massively wrong USD valuations that corrupt vault accounting, share pricing, and loss tolerance enforcement.

## Finding Description

The vulnerability exists in the oracle aggregator management flow. When an admin switches to a new Switchboard aggregator, the function updates the aggregator address, price, and timestamp but **critically fails to update the `decimals` field**. [1](#0-0) 

The `decimals` field is stored in the `PriceInfo` struct and is essential for correct price normalization. [2](#0-1) 

When `get_normalized_asset_price()` retrieves prices for asset valuation, it uses the stored `decimals` field to normalize prices to a standard 9-decimal format. [3](#0-2)  If the `decimals` field doesn't match the actual decimal format of the current aggregator, the normalization formula produces completely incorrect results.

**Execution Flow:**

1. Admin calls `change_switchboard_aggregator()` through the management interface. [4](#0-3) 

2. The function updates aggregator address and price but NOT decimals.

3. When vault operations call `update_free_principal_value()` or `update_coin_type_asset_value()`, they fetch normalized prices using the wrong decimals. [5](#0-4) [6](#0-5) 

4. These incorrect prices are used in USD value calculations via `mul_with_oracle_price()`. [7](#0-6) 

5. Wrong USD values propagate to share ratio calculations used in deposits/withdrawals. [8](#0-7) 

6. Loss tolerance checks compare incorrect before/after values, failing to detect actual losses. [9](#0-8) 

## Impact Explanation

**Direct Fund Impact:**
- **Incorrect Share Pricing:** Share ratios calculated using total USD value will be catastrophically wrong, causing users to receive incorrect share amounts during deposits or wrong principal amounts during withdrawals.
- **Quantified Damage:** If decimals differ by n (e.g., switching from 9 to 18 decimals), valuations are off by a factor of 10^n. A vault with 1000 SUI worth $2000 could be valued at $2 trillion (10^9 times wrong), making shares nearly worthless or enabling massive over-withdrawal.

**Security Mechanism Bypass:**
- **Loss Tolerance Bypass:** The loss tolerance mechanism compares `total_usd_value_before` and `total_usd_value_after`. With inflated valuations, actual losses appear negligible and fail to trigger protection limits, allowing operators to bypass loss constraints.

**Affected Parties:**
- All vault depositors receive incorrect share amounts
- Protocol loses ability to enforce risk management (loss tolerance)
- Entire vault accounting becomes corrupted

## Likelihood Explanation

**High Likelihood Because:**

1. **Legitimate Operational Scenario:** Admins routinely switch oracle aggregators for valid reasons (better data feeds, upgrading oracle infrastructure, redundancy). This is not an attack but normal operations.

2. **Feasible Preconditions:** Different Switchboard aggregators can report prices in different decimal formats. The `add_switchboard_aggregator()` function explicitly accepts a `decimals` parameter, indicating that different aggregators use different formats. [10](#0-9) 

3. **No Safeguards:** There are no validation checks to ensure decimal compatibility when switching aggregators. No warnings or events indicate a potential mismatch.

4. **Silent Failure:** The bug doesn't cause immediate transaction failure. USD values will be wrong but may not trigger obvious errors until users attempt deposits/withdrawals, potentially after significant damage has occurred.

5. **Single Transaction:** Only requires one admin transaction to trigger the vulnerability.

## Recommendation

Add a `decimals` parameter to the `change_switchboard_aggregator()` function and update the stored decimals field when switching aggregators:

**In oracle.move:**
```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // ADD THIS PARAMETER
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
    price_info.decimals = decimals;  // ADD THIS LINE
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**In manage.move:**
```move
public fun change_switchboard_aggregator(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // ADD THIS PARAMETER
    aggregator: &Aggregator,
) {
    oracle_config.change_switchboard_aggregator(clock, asset_type, decimals, aggregator);
}
```

## Proof of Concept

```move
#[test]
fun test_decimal_mismatch_vulnerability() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        let admin_cap = s.take_from_sender<AdminCap>();
        
        // Add initial aggregator with 9 decimals
        let mut aggregator1 = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator1, 2_000_000_000, 0); // $2 in 9 decimals
        
        vault_manage::add_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            9,
            &aggregator1,
        );
        
        // Get normalized price (should be correct)
        let price1 = oracle_config.get_normalized_asset_price(
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        assert!(price1 == 2_000_000_000); // Correct: $2 in 9 decimals
        
        // Switch to aggregator with 18 decimals (decimals field NOT updated!)
        let mut aggregator2 = mock_aggregator::create_mock_aggregator(s.ctx());
        mock_aggregator::set_current_result(&mut aggregator2, 2_000_000_000_000_000_000, 0); // $2 in 18 decimals
        
        vault_manage::change_switchboard_aggregator(
            &admin_cap,
            &mut oracle_config,
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
            &aggregator2,
        );
        
        // Get normalized price (will be WRONG - still using decimals=9!)
        let price2 = oracle_config.get_normalized_asset_price(
            &clock,
            type_name::get<SUI_TEST_COIN>().into_string(),
        );
        
        // Expected: 2_000_000_000 (correct $2 in 9 decimals)
        // Actual: 2_000_000_000_000_000_000 (10^9 times too large!)
        assert!(price2 == 2_000_000_000_000_000_000); // VULNERABILITY DEMONSTRATED
        
        aggregator::destroy_aggregator(aggregator1);
        aggregator::destroy_aggregator(aggregator2);
        test_scenario::return_shared(oracle_config);
        s.return_to_sender(admin_cap);
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

**File:** volo-vault/sources/utils.move (L68-76)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}

// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/sources/operation.move (L353-377)
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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```
