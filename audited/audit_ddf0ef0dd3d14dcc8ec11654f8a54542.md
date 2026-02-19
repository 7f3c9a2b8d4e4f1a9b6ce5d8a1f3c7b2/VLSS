### Title
Missing Aggregator Characteristic Validation in change_switchboard_aggregator Enables Vault Misvaluation

### Summary
The `change_switchboard_aggregator` function does not validate that the new aggregator has the same characteristics (specifically decimals) as the old one, and does not accept a decimals parameter to update this critical field. This allows an admin error (providing wrong aggregator reference) or configuration mistake to result in catastrophic vault misvaluation, as the stored decimals field is used for price normalization but never updated or validated during aggregator replacement.

### Finding Description
The vulnerability exists in the `change_switchboard_aggregator` function implementation: [1](#0-0) 

When an aggregator is initially added via `add_switchboard_aggregator`, a decimals parameter is required and stored in the PriceInfo struct: [2](#0-1) 

The decimals field is critical because it's used in `get_normalized_asset_price` to normalize prices to 9 decimals for consistent USD valuation: [3](#0-2) 

However, when changing aggregators, the function:
1. Does NOT accept a decimals parameter
2. Does NOT validate the new aggregator is for the correct asset
3. Does NOT update the decimals field
4. Simply preserves the old decimals value

The normalized prices are then used throughout vault valuations: [4](#0-3) [5](#0-4) 

### Impact Explanation
**Catastrophic Vault Misvaluation:**

If an admin accidentally provides the wrong aggregator reference (e.g., providing BTC aggregator when intending to change SUI aggregator), the consequences are severe:

1. **Wrong Asset Pricing**: The vault would use BTC prices ($100,000) for SUI holdings, or vice versa
2. **Decimal Mismatch**: Even for the same asset, if decimals differ (stored: 18, actual: 9), price normalization would be off by 10^9, making values 1 billion times smaller or 1000x larger
3. **Share Calculation Errors**: All deposit/withdraw share calculations use total_usd_value, which would be completely wrong
4. **Fund Loss**: Users depositing when vault is overvalued receive fewer shares; users withdrawing when vault is undervalued drain funds

**Example Scenario:**
- SUI aggregator configured with decimals=9
- Admin calls change_switchboard_aggregator for SUI but accidentally provides USDC aggregator reference (decimals should be 6)
- Stored decimals remain 9, but USDC prices (≈$1) are now used for SUI
- If USDC aggregator returns 1e18 ($1), normalized with decimals=9: stays at 1e18
- But SUI price should be ≈$2, so vault undervalues SUI by 2x
- All SUI holdings misvalued, affecting $millions in TVL

Worse decimal mismatch: If old aggregator had decimals=18 and new one is effectively using 9 decimals but the function doesn't update the stored decimals field, normalization would divide by 10^9 when it shouldn't, making prices 1 billion times smaller.

### Likelihood Explanation
**High Likelihood - Admin Error Scenario:**

This is not a malicious attack but a realistic operational risk:

1. **Reachable Entry Point**: Admin can call via `vault_manage::change_switchboard_aggregator`: [6](#0-5) 

2. **Feasible Preconditions**: 
   - Admin needs to change an aggregator (routine operational task)
   - Admin accidentally provides wrong aggregator address reference
   - No validation catches this mistake

3. **Realistic Scenarios**:
   - Multiple aggregators tracked off-chain, admin uses wrong address
   - Copy-paste error in deployment scripts
   - Confusion about which aggregator is for which asset
   - Oracle provider changes aggregator format/configuration

4. **No Economic Barriers**: This is an admin configuration error, not an economic attack

The lack of validation makes this error catastrophic when it's easily preventable with proper checks.

### Recommendation

**1. Add decimals parameter and validation to change_switchboard_aggregator:**

```move
public(package) fun change_switchboard_aggregator(
    config: &mut OracleConfig,
    clock: &Clock,
    asset_type: String,
    decimals: u8,  // ADD THIS
    aggregator: &Aggregator,
) {
    config.check_version();
    assert!(config.aggregators.contains(asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &mut config.aggregators[asset_type];
    
    // VALIDATE decimals match if they shouldn't change
    // OR allow explicit decimals update if configuration changed
    assert!(price_info.decimals == decimals, ERR_DECIMALS_MISMATCH);
    
    let init_price = get_current_price(config, clock, aggregator);
    
    emit(SwitchboardAggregatorChanged {
        asset_type,
        old_aggregator: price_info.aggregator,
        new_aggregator: aggregator.id().to_address(),
    });
    
    price_info.aggregator = aggregator.id().to_address();
    price_info.decimals = decimals;  // UPDATE THIS
    price_info.price = init_price;
    price_info.last_updated = clock.timestamp_ms();
}
```

**2. Add validation that new aggregator provides reasonable price range:**
Check that the new aggregator's initial price is within reasonable bounds of the old price (e.g., not 1000x different) to catch obvious mistakes.

**3. Update the manage.move wrapper:** [6](#0-5) 

Add decimals parameter to the public interface.

**4. Add integration tests:**
Test changing aggregators with wrong decimals to ensure validation catches the error.

### Proof of Concept

**Initial State:**
- Vault has SUI aggregator configured: asset_type="SUI", decimals=9, aggregator=AGGREGATOR_SUI
- SUI price = $2 (2e18 in oracle format)
- Vault holds 1,000,000 SUI (1,000,000e9 = 1e15)
- Expected value: 1e15 * 2e18 / 1e18 = 2,000,000e9 = $2,000,000

**Attack/Error Steps:**

1. Admin calls `change_switchboard_aggregator` for SUI but accidentally provides BTC aggregator reference
2. Function accepts it without validation (no decimals check, no asset type validation)
3. BTC price = $100,000 (1e23 in oracle format)
4. Decimals remain 9 (from SUI configuration)

**Result:**
- Vault now thinks SUI price is $100,000
- SUI holdings valued at: 1e15 * 1e23 / 1e18 = 1e20 = $100,000,000,000
- Vault overvalued by 50,000x

**Alternative Decimal Mismatch:**
1. Initial: SUI aggregator with decimals=18 stored
2. Admin changes to aggregator expecting decimals=9
3. New aggregator returns 2e18 (meaning $2)
4. But normalization uses stored decimals=18: 2e18 / 10^(18-9) = 2e18 / 1e9 = 2e9
5. Normalized price becomes 2e9 instead of 2e18 (1 billion times smaller)
6. All SUI valuations off by 1 billion times

Both scenarios demonstrate how the missing validation enables catastrophic vault misvaluation.

### Citations

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
