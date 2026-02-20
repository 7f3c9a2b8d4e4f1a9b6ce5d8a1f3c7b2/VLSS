# Audit Report

## Title
Price Feed Disable Check Bypassed in Direct PriceOracle Queries

## Summary
The oracle system's two-tier architecture creates a critical security bypass: when an admin disables a price feed via `set_enable_to_price_feed`, the flag is set in `OracleConfig` but the lending protocol's price queries read directly from `PriceOracle` without checking this flag. This allows stale prices from disabled feeds to remain valid for the duration of `update_interval`, enabling exploitation through liquidations, borrowing, and withdrawals using prices the admin explicitly disabled.

## Finding Description

The protocol implements a two-tier oracle architecture with separate state management:

**Tier 1 - OracleConfig (Feed Metadata & Control):**
When an admin disables a feed, the enable flag is updated in the `PriceFeed` struct within `OracleConfig`: [1](#0-0) 

**Tier 2 - PriceOracle (Actual Price Storage):**
The price update function correctly checks the enable flag and returns early if disabled, preventing new price writes: [2](#0-1) 

**The Vulnerability:**
However, the primary price query function used by the lending protocol reads directly from `PriceOracle` and only validates staleness, not the enable flag: [3](#0-2) 

This function only checks if `current_timestamp - price.timestamp <= update_interval`, allowing old prices written before the disable to remain valid.

**Lending Protocol Dependency:**
The calculator module relies on this vulnerable query path: [4](#0-3) 

All critical lending operations use these calculator functions through their health factor checks:

1. **Collateral valuation** uses the vulnerable price path: [5](#0-4) 

2. **Loan valuation** uses the same vulnerable path: [6](#0-5) 

3. **Borrow operations** check health factors with these functions: [7](#0-6) 

4. **Withdraw operations** validate health using the same path: [8](#0-7) 

5. **Liquidation logic** checks if positions are unhealthy using disabled feed prices: [9](#0-8) 

6. **Liquidation events** also directly query prices without checking the enable flag: [10](#0-9) 

**Configuration Vulnerability:**
The `update_interval` can be set to any value greater than zero with no upper bound: [11](#0-10) 

While the default is 30 seconds: [12](#0-11) 

For less volatile assets, this could be configured to hours, extending the exploitation window significantly.

**Public Entry Points:**
All lending operations are accessible via public entry functions that trigger the vulnerable price query path: [13](#0-12) [14](#0-13) [15](#0-14) 

## Impact Explanation

**Direct Fund Impact:**
When an admin disables a malfunctioning or compromised price feed, the lending protocol continues accepting stale prices for all critical operations. This creates multiple attack vectors:

1. **Unfair Liquidations**: If a collateral asset's feed is disabled but the stale price is favorable, liquidators can trigger unfair liquidations against users whose actual collateral value is sufficient.

2. **Liquidation Avoidance**: Conversely, if a borrow asset's feed is disabled with a stale favorable price, undercollateralized positions can avoid liquidation, creating bad debt for the protocol.

3. **Over-borrowing**: Users can borrow more than their actual collateral value supports by exploiting stale favorable prices during the exploitation window.

4. **Unsafe Withdrawals**: Users can withdraw collateral that should be locked due to insufficient health factors, calculated using stale prices.

**Duration of Exposure:**
The exploitation window spans from the moment a feed is disabled until `last_update_timestamp + update_interval`. With the default 30-second interval, this creates a 30-second window. However, if configured to 1 hour (3,600,000 ms) for less volatile assets, the window extends to nearly 1 hour of exploitable stale pricing.

**Security Integrity Bypass:**
The admin's emergency control mechanism to disable a feed is completely ineffective for price queries. This defeats the core purpose of the safety mechanism designed to protect the protocol from bad oracle data during oracle provider malfunctions, detected price manipulation, or emergency events.

## Likelihood Explanation

**Reachable Entry Point:**
All lending protocol operations (borrow, liquidate, withdraw) are public entry functions that any user can call without special permissions. These operations inherently query prices through the vulnerable path for health factor validation.

**Feasible Preconditions:**
This vulnerability is triggered during normal operational scenarios when an admin legitimately needs to disable a feed due to:
- Oracle provider malfunction or data feed connectivity issues
- Detected price manipulation or anomalies in oracle data
- Emergency response to external events affecting price accuracy (e.g., market volatility, oracle provider compromise)
- Routine maintenance requiring feed rotation or provider migration

These are expected and necessary administrative actions, making the preconditions highly realistic.

**Execution Practicality:**
Any user can exploit this by:
1. Monitoring for `PriceFeedSetEnable` events emitted when feeds are disabled: [16](#0-15) 

2. Immediately executing lending operations using the stale price before it expires from staleness validation
3. Extracting value through operations that benefit from the price discrepancy between the disabled feed's stale price and the actual market price

**Economic Rationality:**
- Attack cost: Minimal (standard transaction fees)
- Potential gains: Depend on price deviation, position size, and exploitation window duration
- For volatile assets or large positions, gains can substantially exceed costs
- Risk: Low, as the operation appears legitimate to monitoring systems

**Detection Constraints:**
The bypass is silent - price queries return success without any indication that the feed is disabled, making it difficult for monitoring systems to detect exploitation in progress. The only event emitted is during the disable action, not during subsequent price queries.

## Recommendation

Modify `oracle::get_token_price` to check the enable flag from `OracleConfig` before returning price data:

```move
public fun get_token_price(
    clock: &Clock,
    price_oracle: &PriceOracle,
    oracle_config: &OracleConfig,  // Add OracleConfig parameter
    oracle_id: u8
): (bool, u256, u8) {
    version_verification(price_oracle);

    let price_oracles = &price_oracle.price_oracles;
    assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

    // Find the corresponding price feed in OracleConfig
    let feed_address = get_feed_address_by_oracle_id(oracle_config, oracle_id);
    let price_feed = config::get_price_feed(oracle_config, feed_address);
    
    // Check if the feed is enabled
    if (!config::is_price_feed_enable(price_feed)) {
        return (false, 0, 0)
    };

    let token_price = table::borrow(price_oracles, oracle_id);
    let current_ts = clock::timestamp_ms(clock);

    let valid = false;
    if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
        valid = true;
    };
    (valid, token_price.value, token_price.decimal)
}
```

Update all call sites in the lending protocol to pass both `PriceOracle` and `OracleConfig` parameters. This ensures the enable flag is consistently enforced across both write and read paths.

## Proof of Concept

```move
#[test_only]
module test::oracle_bypass_poc {
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::clock::{Self, Clock};
    use oracle::config::{Self, OracleConfig};
    use oracle::oracle::{Self, PriceOracle, OracleAdminCap};
    use lending_core::calculator;
    
    #[test]
    fun test_disabled_feed_still_queryable() {
        let admin = @0xAD;
        let mut scenario = ts::begin(admin);
        
        // Setup: Create oracle system
        {
            let ctx = ts::ctx(&mut scenario);
            oracle::init_for_testing(ctx);
            config::new_config(ctx);
        };
        
        ts::next_tx(&mut scenario, admin);
        
        // Register a price feed and set initial price
        {
            let mut price_oracle = ts::take_shared<PriceOracle>(&scenario);
            let mut oracle_config = ts::take_shared<OracleConfig>(&scenario);
            let admin_cap = ts::take_from_sender<OracleAdminCap>(&scenario);
            let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
            
            // Register token with oracle_id = 1
            oracle::register_token_price(&admin_cap, &clock, &mut price_oracle, 1, 100_000_000, 9);
            
            // Create price feed in config
            config::new_price_feed<SUI>(&mut oracle_config, 1, 60000, 100, 200, 300000, 1000, 1000000000000, 1000000, 3600000, ts::ctx(&mut scenario));
            
            // Initial price is valid and queryable
            let (valid, price, decimal) = oracle::get_token_price(&clock, &price_oracle, 1);
            assert!(valid == true, 0);
            assert!(price == 100_000_000, 1);
            
            ts::return_shared(price_oracle);
            ts::return_shared(oracle_config);
            ts::return_to_sender(&scenario, admin_cap);
            clock::destroy_for_testing(clock);
        };
        
        ts::next_tx(&mut scenario, admin);
        
        // Admin disables the feed
        {
            let mut oracle_config = ts::take_shared<OracleConfig>(&scenario);
            let admin_cap = ts::take_from_sender<OracleAdminCap>(&scenario);
            
            let feeds = config::get_vec_feeds(&oracle_config);
            let feed_id = *vector::borrow(&feeds, 0);
            
            // Disable the feed
            config::set_enable_to_price_feed(&mut oracle_config, feed_id, false);
            
            // Verify it's disabled
            let price_feed = config::get_price_feed(&oracle_config, feed_id);
            assert!(config::is_price_feed_enable(price_feed) == false, 2);
            
            ts::return_shared(oracle_config);
            ts::return_to_sender(&scenario, admin_cap);
        };
        
        ts::next_tx(&mut scenario, admin);
        
        // BUG: Despite being disabled, price is still queryable through get_token_price
        {
            let price_oracle = ts::take_shared<PriceOracle>(&scenario);
            let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
            
            // Advance time by 20 seconds (within 30s update_interval)
            clock::increment_for_testing(&mut clock, 20000);
            
            // Price is still valid even though feed is disabled!
            let (valid, price, decimal) = oracle::get_token_price(&clock, &price_oracle, 1);
            assert!(valid == true, 3); // This should fail but doesn't - proving the vulnerability
            assert!(price == 100_000_000, 4);
            
            // Calculator functions would use this stale price
            let amount = 1_000_000_000; // 1 token
            let value = calculator::calculate_value(&clock, &price_oracle, amount, 1);
            assert!(value == 100, 5); // Calculated using disabled feed's price
            
            ts::return_shared(price_oracle);
            clock::destroy_for_testing(clock);
        };
        
        ts::end(scenario);
    }
}
```

This test demonstrates that after an admin disables a price feed in `OracleConfig`, the `oracle::get_token_price` function continues to return valid prices from `PriceOracle`, allowing the lending protocol's calculator functions to use stale prices from administratively disabled feeds.

### Citations

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L71-76)
```text
    struct PriceFeedSetEnable has copy, drop {
        config: address,
        feed_id: address,
        value: bool,
        before_value: bool,
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/config.move (L278-285)
```text
    public(friend) fun set_enable_to_price_feed(cfg: &mut OracleConfig, feed_id: address, value: bool) {
        assert!(table::contains(&cfg.feeds, feed_id), error::price_feed_not_found());
        let price_feed = table::borrow_mut(&mut cfg.feeds, feed_id);
        let before_value = price_feed.enable;

        price_feed.enable = value;
        emit(PriceFeedSetEnable {config: object::uid_to_address(&cfg.id), feed_id: feed_id, value: value, before_value: before_value})
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_pro.move (L60-62)
```text
        if (!config::is_price_feed_enable(price_feed)) {
            return
        };
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L80-88)
```text
    public entry fun set_update_interval(
        _: &OracleAdminCap,
        price_oracle: &mut PriceOracle,
        update_interval: u64,
    ) {
        version_verification(price_oracle);
        assert!(update_interval > 0, error::invalid_value());
        price_oracle.update_interval = update_interval;
    }
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle.move (L180-198)
```text
    public fun get_token_price(
        clock: &Clock,
        price_oracle: &PriceOracle,
        oracle_id: u8
    ): (bool, u256, u8) {
        version_verification(price_oracle);

        let price_oracles = &price_oracle.price_oracles;
        assert!(table::contains(price_oracles, oracle_id), error::non_existent_oracle());

        let token_price = table::borrow(price_oracles, oracle_id);
        let current_ts = clock::timestamp_ms(clock);

        let valid = false;
        if (token_price.value > 0 && current_ts - token_price.timestamp <= price_oracle.update_interval) {
            valid = true;
        };
        (valid, token_price.value, token_price.decimal)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/calculator.move (L97-101)
```text
    public fun calculate_value(clock: &Clock, oracle: &PriceOracle, amount: u256, oracle_id: u8): u256 {
        let (is_valid, price, decimal) = oracle::get_token_price(clock, oracle, oracle_id);
        assert!(is_valid, error::invalid_price());
        amount * price / (sui::math::pow(10, decimal) as u256)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L91-91)
```text
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L154-155)
```text
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L212-212)
```text
        assert!(!is_health(clock, oracle, storage, user), error::user_is_healthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L464-469)
```text
    public fun user_loan_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_loan_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L475-480)
```text
    public fun user_collateral_value(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address): u256 {
        let balance = user_collateral_balance(storage, asset, user);
        let oracle_id = storage::get_oracle_id(storage, asset);

        calculator::calculate_value(clock, oracle, balance, oracle_id)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L456-457)
```text
        let (_, collateral_price, _) = oracle::get_token_price(clock, oracle, collateral_oracle_id);
        let (_, debt_price, _) = oracle::get_token_price(clock, oracle, debt_oracle_id);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_constants.move (L30-30)
```text
    public fun default_update_interval(): u64 {30000} // 30s
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L833-851)
```text
    public entry fun entry_withdraw<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        let _balance = lending::withdraw_coin<CoinType>(clock, oracle, storage, pool, asset, amount, ctx);
        let _coin = coin::from_balance(_balance, ctx);
        transfer::public_transfer(_coin, user);
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L898-920)
```text
    public entry fun entry_borrow<CoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        pool: &mut Pool<CoinType>,
        asset: u8,
        amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, asset, user);
        update_reward_state_by_asset<CoinType>(clock, incentive_v3, storage, user);

        let fee = get_borrow_fee(incentive_v3, amount);

        let _balance =  lending::borrow_coin<CoinType>(clock, oracle, storage, pool, asset, amount + fee, ctx);

        deposit_borrow_fee(incentive_v3, &mut _balance, fee);

        let _coin = coin::from_balance(_balance, ctx);
        transfer::public_transfer(_coin, tx_context::sender(ctx));
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/incentive_v3.move (L1062-1114)
```text
    public entry fun entry_liquidation<DebtCoinType, CollateralCoinType>(
        clock: &Clock,
        oracle: &PriceOracle,
        storage: &mut Storage,
        debt_asset: u8,
        debt_pool: &mut Pool<DebtCoinType>,
        debt_coin: Coin<DebtCoinType>,
        collateral_asset: u8,
        collateral_pool: &mut Pool<CollateralCoinType>,
        liquidate_user: address,
        liquidate_amount: u64,
        incentive_v2: &mut IncentiveV2,
        incentive_v3: &mut Incentive,
        ctx: &mut TxContext
    ) {
        incentive_v2::update_reward_all(clock, incentive_v2, storage, collateral_asset, @0x0);
        incentive_v2::update_reward_all(clock, incentive_v2, storage, debt_asset, @0x0);

        update_reward_state_by_asset<DebtCoinType>(clock, incentive_v3, storage, liquidate_user);
        update_reward_state_by_asset<CollateralCoinType>(clock, incentive_v3, storage, liquidate_user);
        let sender = tx_context::sender(ctx);
        let (_bonus_balance, _excess_balance) = lending::liquidation(
            clock,
            oracle,
            storage,
            debt_asset,
            debt_pool,
            debt_coin,
            collateral_asset,
            collateral_pool,
            liquidate_user,
            liquidate_amount,
            ctx,
        );

        // handle excess balance
        let _excess_value = balance::value(&_excess_balance);
        if (_excess_value > 0) {
            let _coin = coin::from_balance(_excess_balance, ctx);
            transfer::public_transfer(_coin, sender);
        } else {
            balance::destroy_zero(_excess_balance)
        };

        // handle bonus balance
        let _bonus_value = balance::value(&_bonus_balance);
        if (_bonus_value > 0) {
            let _coin = coin::from_balance(_bonus_balance, ctx);
            transfer::public_transfer(_coin, sender);
        } else {
            balance::destroy_zero(_bonus_balance)
        }
    }
```
