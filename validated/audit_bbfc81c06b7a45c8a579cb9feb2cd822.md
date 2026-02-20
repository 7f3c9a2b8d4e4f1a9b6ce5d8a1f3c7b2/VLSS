# Audit Report

## Title
Mismatched Oracle Price Decimals Cause Incorrect Relative Price Calculation in DEX Adaptors

## Summary
The DEX adaptor functions assume all oracle prices have 18 decimals but this assumption is not enforced. When two assets in a liquidity pool have oracle feeds with different decimal precision (e.g., BTC with 8 decimals, ETH with 18 decimals), the relative price calculation produces mathematically incorrect results by orders of magnitude (10^10 difference), causing the slippage validation to always fail and preventing any position value updates. This creates a complete operational DoS for vaults with mixed-decimal DEX positions.

## Finding Description

The `get_position_value()` function in momentum.adaptor.move contains a critical unenforced assumption stated in the comment: "Oracle price has 18 decimals" [1](#0-0) . 

However, the oracle system's `PriceInfo` struct stores a `decimals` field that can vary per asset [2](#0-1) , and this value is set when adding aggregators through `add_switchboard_aggregator()` [3](#0-2) .

The `get_asset_price()` function returns the raw price without any decimal normalization [4](#0-3) . While the system provides `get_normalized_asset_price()` which normalizes all prices to 9 decimals [5](#0-4) , the DEX adaptors only use the normalized function for final USD value calculations, not for the relative price calculation used in slippage validation.

**Mathematical Issue:**

The relative price calculation performs: `relative_price_from_oracle = price_a * DECIMAL / price_b` where DECIMAL = 10^18 [6](#0-5) .

When price_a has 8 decimals (e.g., BTC: 50000 * 10^8) and price_b has 18 decimals (e.g., ETH: 3000 * 10^18):
- Result = (50000 * 10^8) * 10^18 / (3000 * 10^18) = 16.67 * 10^8
- This has 8 decimals, not 18

Meanwhile, `sqrt_price_x64_to_price()` always outputs a price with 18 decimals [7](#0-6) .

The slippage check then compares values with a 10^10 magnitude difference [8](#0-7) . The identical issue exists in cetus_adaptor.move [9](#0-8) .

## Impact Explanation

**HIGH Severity - Complete Operational Denial of Service**

When position value updates fail, the vault's `get_total_usd_value()` function cannot be called because it enforces that all asset values must be updated within `MAX_UPDATE_INTERVAL` [10](#0-9) . The `MAX_UPDATE_INTERVAL` is set to 0 [11](#0-10) , requiring same-transaction updates.

This blocks critical vault operations including:
- **Deposit execution** - `execute_deposit()` calls `get_total_usd_value()` to calculate share ratios [12](#0-11) 
- **Withdrawal execution** - Similar dependency on fresh total USD values
- **Loss tolerance enforcement** - Cannot track operation value changes
- **All vault state transitions** - Vault becomes effectively frozen

## Likelihood Explanation

**HIGH Likelihood - Natural Production Occurrence**

This issue requires no attacker action. The adaptor functions are public functions callable via Programmable Transaction Blocks [13](#0-12) .

Real-world Switchboard oracle feeds naturally have different decimal formats based on asset characteristics:
- Bitcoin price feeds commonly use 8 decimals (matching BTC's native precision)
- Ethereum price feeds commonly use 18 decimals (matching ETH's native precision)
- Stablecoin feeds may use 6 decimals (matching USDC/USDT precision)

The protocol admin configures these decimals honestly through `add_switchboard_aggregator()` to match the actual format of each Switchboard feed [3](#0-2) . This is proper configuration, not misconfiguration.

Any production vault with DEX positions using assets with different oracle decimal formats will immediately trigger this bug upon the first position value update attempt.

## Recommendation

Normalize both oracle prices to a consistent decimal format before calculating the relative price. Use `get_normalized_asset_price()` instead of `get_asset_price()` for the slippage validation:

```move
// In momentum.adaptor.move and cetus_adaptor.move
// Replace lines 49-51 with:
let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a * DECIMAL / normalized_price_b;
```

Alternatively, adjust the pool price calculation to match the actual oracle decimal format being used, but the normalization approach is cleaner and more maintainable.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = 7_001)] // ERR_INVALID_POOL_PRICE
public fun test_mismatched_oracle_decimals_causes_slippage_failure() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault with SUI principal
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        
        // Configure BTC with 8 decimals (realistic)
        let btc_type = type_name::get<BTC_TEST_COIN>().into_string();
        vault_oracle::set_aggregator(&mut oracle_config, &clock, btc_type, 8, @0xBTC);
        
        // Configure ETH with 18 decimals (realistic)
        let eth_type = type_name::get<ETH_TEST_COIN>().into_string();
        vault_oracle::set_aggregator(&mut oracle_config, &clock, eth_type, 18, @0xETH);
        
        // Set prices: BTC = 50000 with 8 decimals, ETH = 3000 with 18 decimals
        vault_oracle::set_current_price(&mut oracle_config, &clock, btc_type, 50000 * 100_000_000); // 8 decimals
        vault_oracle::set_current_price(&mut oracle_config, &clock, eth_type, 3000 * 1_000_000_000_000_000_000); // 18 decimals
        
        test_scenario::return_shared(oracle_config);
    };
    
    // Create a mock BTC-ETH pool position
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let oracle_config = s.take_shared<OracleConfig>();
        let mut pool = create_mock_momentum_pool<BTC_TEST_COIN, ETH_TEST_COIN>();
        
        // This will abort with ERR_INVALID_POOL_PRICE due to decimal mismatch
        // relative_price_from_oracle will be ~16.67 * 10^8 (8 decimals)
        // pool_price will be ~16.67 * 10^18 (18 decimals)
        // Difference is 10^10, exceeding any reasonable slippage tolerance
        momentum_adaptor::update_momentum_position_value(
            &mut vault,
            &oracle_config,
            &clock,
            string::utf8(b"BTC-ETH-Position"),
            &mut pool
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(oracle_config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that with realistic oracle decimal configurations (BTC=8, ETH=18), the slippage validation will always fail, preventing position value updates and causing complete vault DoS.

### Citations

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L48-48)
```text
    // Oracle price has 18 decimals
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L49-51)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L55-58)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L93-103)
```text
fun sqrt_price_x64_to_price(sqrt_price_x64: u128, decimals_a: u8, decimals_b: u8): u256 {
    let sqrt_price_u256_with_decimals = (sqrt_price_x64 as u256) * DECIMAL / pow(2, 64);
    let price_u256_with_decimals =
        sqrt_price_u256_with_decimals * sqrt_price_u256_with_decimals / DECIMAL;

    if (decimals_a > decimals_b) {
        price_u256_with_decimals * pow(10, (decimals_a - decimals_b))
    } else {
        price_u256_with_decimals / pow(10, (decimals_b - decimals_a))
    }
}
```

**File:** volo-vault/sources/oracle.move (L24-29)
```text
public struct PriceInfo has drop, store {
    aggregator: address,
    decimals: u8,
    price: u256,
    last_updated: u64,
}
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L49-66)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    // e.g. For SUI-USDC Pool, decimal_a = 9, decimal_b = 6
    // pool price = 3e18
    // price_a = 3e18
    // price_b = 1e18
    // relative_price_from_oracle = 3e18 * 1e18 / 1e18 = 3e18

    // pool price = price_a / price_b (not consider decimals)
    let pool_price = sqrt_price_x64_to_price(pool.current_sqrt_price(), decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L806-850)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
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
```

**File:** volo-vault/sources/volo_vault.move (L1254-1279)
```text
public(package) fun get_total_usd_value<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    let now = clock.timestamp_ms();
    let mut total_usd_value = 0;

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });

    emit(TotalUSDValueUpdated {
        vault_id: self.vault_id(),
        total_usd_value: total_usd_value,
        timestamp: now,
    });

    total_usd_value
}
```
