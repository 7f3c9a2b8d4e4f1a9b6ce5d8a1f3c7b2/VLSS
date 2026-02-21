# Audit Report

## Title
Pyth Price Confidence Interval Bypass Enables Unreliable Oracle Data Injection Leading to Vault Position Liquidation

## Summary
The Pyth oracle adaptor's `get_price_unsafe_native()` function fails to validate confidence intervals, allowing prices with extremely wide confidence bands to be injected into Navi's PriceOracle. This creates an oracle mismatch where the vault values its Navi positions using Switchboard oracle while Navi's liquidation logic uses the compromised PriceOracle, enabling unfair liquidations of vault positions.

## Finding Description

The vulnerability exists in the Pyth price extraction logic. The `get_price_unsafe_native()` function extracts only price, exponent, and timestamp without calling `price::get_conf()` to retrieve or validate the confidence band: [1](#0-0) 

In contrast, Suilend's oracle implementation properly validates confidence intervals, rejecting prices where confidence exceeds 10% of the price magnitude: [2](#0-1) 

The unsafe adaptor is invoked when Pyth is configured as the price provider: [3](#0-2) 

The `update_single_price()` function is publicly accessible without capability requirements, using shared objects (`OracleConfig` and `PriceOracle`) that anyone can borrow in a Programmable Transaction Block: [4](#0-3) [5](#0-4) [6](#0-5) 

The manipulated PriceOracle is used by Navi's liquidation logic for health calculations and liquidation decisions: [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

The vault maintains Navi positions that can be liquidated by external actors: [11](#0-10) 

While the vault values its Navi positions using its own Switchboard-based oracle: [12](#0-11) [13](#0-12) 

This creates a dangerous oracle mismatch: the vault believes its positions are healthy based on reliable Switchboard prices, but Navi can liquidate these positions based on unreliable Pyth prices with wide confidence bands.

## Impact Explanation

**Direct Fund Loss**: The vault's leveraged Navi positions (supply collateral, borrow debt) can be unfairly liquidated when unreliable Pyth prices are injected. A concrete scenario:
- Vault has 10,000 SUI supplied to Navi, borrowing 15,000 USDC  
- Switchboard shows SUI = $4.00, net position value = $25,000 (healthy)
- Attacker injects Pyth price SUI = $2.00 ± $1.00 (50% confidence band that should be rejected per Suilend's standard)
- Navi's view: collateral = $20,000, debt = $15,000, health factor drops below threshold
- Liquidators seize vault's collateral at discounted liquidation bonus rates
- Vault loses significant value despite position being genuinely healthy

**Affected Parties**: All vault shareholders lose funds proportionally as the vault's share value decreases from unfair liquidations.

**Severity Justification**: HIGH - Direct theft of vault funds through oracle manipulation, exploitable by any untrusted user, affects all vault shareholders, no recovery mechanism.

## Likelihood Explanation

**Attacker Capabilities**: Any user can construct a Programmable Transaction Block to call `update_single_price()` since it requires no capabilities and uses shared objects. The attacker only needs:
1. Access to on-chain Pyth `PriceInfoObject` (publicly available)
2. Knowledge of oracle configuration (on-chain)
3. Ability to compose PTB transactions

**Attack Complexity**: LOW
1. Monitor Pyth for prices with wide confidence bands (occurs naturally during volatile markets)
2. Compose PTB calling `update_single_price()` with low-quality Pyth data
3. Oracle protections are insufficient: secondary oracle validation only works if both oracles are fresh; price range checks require proper admin configuration; confidence is never checked
4. Either wait for liquidators or execute liquidation directly

**Feasibility Conditions**: All realistic in normal operation
- Pyth naturally provides prices with confidence bands exceeding 10% during market volatility
- Oracle configuration has Pyth enabled as primary/secondary provider
- Vault maintains active leveraged positions in Navi
- No on-chain mechanism distinguishes confidence-bypassed updates

**Probability**: HIGH - Exploitable whenever Pyth experiences normal market conditions producing wide confidence bands. No special market manipulation required.

## Recommendation

Add confidence interval validation to the Pyth adaptor, following Suilend's implementation pattern:

```move
public fun get_price_safe_native(pyth_price_info: &PriceInfoObject): (u64, u64, u64) {
    let pyth_price_info_unsafe = pyth::get_price_unsafe(pyth_price_info);
    
    let i64_price = price::get_price(&pyth_price_info_unsafe);
    let i64_expo = price::get_expo(&pyth_price_info_unsafe);
    let timestamp = price::get_timestamp(&pyth_price_info_unsafe) * 1000;
    let price = i64::get_magnitude_if_positive(&i64_price);
    let expo = i64::get_magnitude_if_negative(&i64_expo);
    
    // Add confidence validation
    let conf = price::get_conf(&pyth_price_info_unsafe);
    let min_confidence_ratio = 10; // 10% threshold like Suilend
    assert!(conf * min_confidence_ratio <= price, error::confidence_too_wide());
    
    (price, expo, timestamp)
}
```

Replace the usage in `oracle_pro.move` to call the safe version, or add the confidence check directly in `get_price_unsafe_to_target_decimal`.

## Proof of Concept

```move
#[test]
fun test_pyth_confidence_bypass_liquidation() {
    // 1. Setup vault with Navi position (10,000 SUI collateral, 15,000 USDC borrow)
    // 2. Switchboard price: SUI = $4.00 (healthy: $40,000 collateral vs $15,000 debt)
    // 3. Attacker obtains Pyth PriceInfoObject with SUI = $2.00 ± $1.00 (50% confidence)
    // 4. Call update_single_price() via PTB with bad Pyth data
    // 5. PriceOracle now shows SUI = $2.00
    // 6. Navi view: $20,000 collateral vs $15,000 debt (health factor < 1)
    // 7. Execute liquidation - vault loses funds
    // 8. Verify vault's Navi position was liquidated despite being healthy per Switchboard
}
```

**Notes**

The core issue is the reliance on an external oracle system (Navi's PriceOracle) that can be manipulated through missing validation in the Pyth adaptor. The vault cannot protect itself because it doesn't control Navi's liquidation logic, which uses the shared PriceOracle object. This architectural dependency combined with the missing confidence validation creates a critical vulnerability where vault funds can be stolen through unfair liquidations triggered by unreliable oracle data.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/adaptor_pyth.move (L26-37)
```text
    // get_price_unsafe_native: return the price(uncheck timestamp)/decimal(expo)/timestamp from pyth oracle
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

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L54-54)
```text
    public fun update_single_price(clock: &Clock, oracle_config: &mut OracleConfig, price_oracle: &mut PriceOracle, supra_oracle_holder: &OracleHolder, pyth_price_info: &PriceInfoObject, feed_address: address) {
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L175-180)
```text
        if (provider == provider::pyth_provider()) {
            let pyth_pair_id = oracle::adaptor_pyth::get_identifier_to_vector(pyth_price_info);
            assert!(sui::address::from_bytes(pyth_pair_id) == sui::address::from_bytes(pair_id), error::pair_not_match());
            let (price, timestamp) = oracle::adaptor_pyth::get_price_unsafe_to_target_decimal(pyth_price_info, target_decimal);
            return (price, timestamp)
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L203-203)
```text
        transfer::share_object(cfg);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L53-58)
```text
        transfer::share_object(PriceOracle {
            id: object::new(ctx),
            version: version::this_version(),
            price_oracles: table::new(ctx),
            update_interval: constants::default_update_interval(),
        });
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L212-212)
```text
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L359-361)
```text
    public fun is_health(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, user: address): bool {
        user_health_factor(clock, storage, oracle, user) >= ray_math::ray()
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L379-391)
```text
    public fun user_health_factor(clock: &Clock, storage: &mut Storage, oracle: &PriceOracle, user: address): u256 {
        // 
        let health_collateral_value = user_health_collateral_value(clock, oracle, storage, user); // 202500000000000
        let dynamic_liquidation_threshold = dynamic_liquidation_threshold(clock, storage, oracle, user); // 650000000000000000000000000
        let health_loan_value = user_health_loan_value(clock, oracle, storage, user); // 49500000000
        if (health_loan_value > 0) {
            // H = TotalCollateral * LTV * Threshold / TotalBorrow
            let ratio = ray_math::ray_div(health_collateral_value, health_loan_value);
            ray_math::ray_mul(ratio, dynamic_liquidation_threshold)
        } else {
            address::max()
        }
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-480)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }

    /**
     * Title: get the number of collaterals the user has in given asset.
     * Returns: USD amount.
     */
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
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
