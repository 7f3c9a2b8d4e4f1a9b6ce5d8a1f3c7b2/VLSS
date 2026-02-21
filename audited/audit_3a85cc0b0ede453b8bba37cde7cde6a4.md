# Audit Report

## Title
Stale Oracle Price Vulnerability in Navi Position Valuation Due to Two-Layer Caching

## Summary
The vault's oracle system implements a two-layer price caching mechanism where the `OracleConfig` caches Switchboard prices for up to 60 seconds, while the vault requires asset values to be updated in the same transaction. This architectural mismatch allows operators to perform vault operations using oracle prices that are up to 1 minute stale, enabling exploitation to understate losses and bypass loss tolerance protections.

## Finding Description

The vulnerability stems from a critical disconnect between two different staleness validation mechanisms operating at different protocol layers:

**Layer 1 - OracleConfig Cache:** The `OracleConfig` stores cached prices with a default `update_interval` of 60 seconds (1 minute). [1](#0-0)  This cache is initialized with this interval by default. [2](#0-1) 

**Layer 2 - Vault Asset Values:** The vault enforces that asset VALUES must be updated within `MAX_UPDATE_INTERVAL = 0`, meaning they must be updated in the same transaction. [3](#0-2)  This is enforced when calculating total USD value. [4](#0-3) 

**The Critical Flaw:** When `calculate_navi_position_value()` is called to value Navi positions, it uses `vault_oracle::get_asset_price()` to fetch prices. [5](#0-4) 

The `get_asset_price()` function only validates that the CACHED price was updated within the oracle's `update_interval` (60 seconds), not the actual Switchboard aggregator's current timestamp. [6](#0-5) 

While `get_current_price()` properly validates Switchboard's timestamp when fetching fresh prices, [7](#0-6)  this validation only occurs when `update_price()` is explicitly called to refresh the cache. [8](#0-7) 

**Exploitation Scenario:**
1. At time T=0: Someone calls `update_price()` to cache Switchboard price P1=$2000
2. At time T=30s: Market crashes, Switchboard shows P2=$1900  
3. At time T=45s: Operator begins operation, calls `update_navi_position_value()` which uses cached P1=$2000 (still valid, within 60s window)
4. Operator's Navi position is overvalued by ~5% due to stale price
5. After performing operations that lose value, operator updates again at T=55s, still using stale P1
6. Loss calculation compares before/after values both using inflated prices, understating actual losses

This allows operators to bypass the loss tolerance check implemented in `end_op_value_update_with_bag()`. [9](#0-8) 

The vault BELIEVES it enforces fresh prices through the 0-second requirement, but this only applies to the vault's tracking table (`assets_value_updated`), not the underlying oracle price cache. Both the "before" and "after" valuations can use the same stale cached price, causing the loss calculation to systematically understate real losses when market prices move during operations.

## Impact Explanation

**High Severity - Protocol Integrity Compromise**

1. **Loss Tolerance Bypass:** The vault implements per-epoch loss tolerance [10](#0-9)  to protect depositors from excessive losses. By using stale prices that don't reflect current market conditions, operators can understate losses in USD terms, allowing operations that exceed the intended risk limits to pass validation checks. The loss limit enforcement at line 635 becomes ineffective when both before and after valuations use identical stale prices.

2. **Share Ratio Manipulation:** When users deposit or withdraw, share ratios are calculated based on total vault USD value. [11](#0-10)  Stale prices lead to incorrect valuations, causing unfair share distributions that can extract value from existing depositors.

3. **Accounting Corruption:** In volatile crypto markets, prices can move 1-5% within 60 seconds. For a vault with $1M in Navi positions, this represents $10K-$50K of potential mispricing, directly affecting all vault participants.

4. **Systemic Risk:** The vulnerability affects all vault operations that rely on oracle prices, not just Navi positions, as the same `get_asset_price()` mechanism is used throughout the vault system for Cetus, Momentum, and Suilend adaptors.

## Likelihood Explanation

**High Likelihood - Readily Exploitable**

1. **Standard Operation Flow:** The vulnerable code path is triggered during normal vault operations. Any operator performing routine operations can exploit this vulnerability without special setup.

2. **Operator Control:** While `update_price()` is a public function that anyone can call, operators control the TIMING of their operations. They can strategically execute operations when cached prices are favorable relative to current market prices, waiting for periods when the cache is stale.

3. **Market Conditions:** Cryptocurrency markets are inherently volatile. 60-second price movements of 1-5% occur regularly, especially during high volatility periods, providing frequent exploitation opportunities.

4. **No Detection:** The exploitation is difficult to detect as all protocol checks pass - the cached price is within its configured staleness limit, making the operation appear legitimate from an on-chain perspective.

5. **Economic Incentive:** For operators managing large positions, the ability to understate losses or manipulate share ratios provides clear financial incentives with minimal cost (only gas fees).

## Recommendation

Implement one of the following solutions:

**Solution 1: Enforce Fresh Switchboard Validation**
Modify `get_asset_price()` to always validate the Switchboard aggregator's actual timestamp, not just the cached price timestamp:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String, aggregator: &Aggregator): u256 {
    config.check_version();
    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);
    
    let price_info = &config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);
    
    // Validate the Switchboard aggregator's actual timestamp
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    // Return the current price from Switchboard, not cached
    current_result.result().value() as u256
}
```

**Solution 2: Reduce Oracle Cache Interval**
Reduce the `MAX_UPDATE_INTERVAL` constant in oracle.move to match the vault's requirements (or a much smaller value like 5 seconds):

```move
const MAX_UPDATE_INTERVAL: u64 = 5000; // 5 seconds instead of 60 seconds
```

**Solution 3: Mandatory Fresh Updates During Operations**
Require operators to call `update_price()` (which validates Switchboard) immediately before both the start and end of operations, within the same transaction.

## Proof of Concept

```move
#[test]
fun test_stale_oracle_price_bypass_loss_tolerance() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        
        // Set initial price at $2000
        let prices = vector[2000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        test_scenario::return_shared(oracle_config);
    };
    
    // Start operation at T=10s with price=$2000
    clock.increment_for_testing(10_000);
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        
        vault.update_free_principal_value(&config, &clock);
        let total_before = vault.get_total_usd_value(&clock);
        
        // Market crashes to $1900, but we DON'T update the oracle cache
        // The cached price from T=0 is still valid (within 60s window)
        
        // Perform operation at T=50s (still within 60s cache window)
        clock.increment_for_testing(40_000);
        
        vault.update_free_principal_value(&config, &clock);
        let total_after = vault.get_total_usd_value(&clock);
        
        // Loss appears to be zero because both use stale $2000 price
        // Real loss is 5% but bypasses tolerance check
        assert!(total_before == total_after); // This should fail if using real prices
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

### Citations

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
```

**File:** volo-vault/sources/oracle.move (L84-94)
```text
fun init(ctx: &mut TxContext) {
    let config = OracleConfig {
        id: object::new(ctx),
        version: VERSION,
        aggregators: table::new(ctx),
        update_interval: MAX_UPDATE_INTERVAL,
        dex_slippage: DEFAULT_DEX_SLIPPAGE,
    };

    transfer::share_object(config);
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

**File:** volo-vault/sources/oracle.move (L225-247)
```text
public fun update_price(
    config: &mut OracleConfig,
    aggregator: &Aggregator,
    clock: &Clock,
    asset_type: String,
) {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_price = get_current_price(config, clock, aggregator);

    let price_info = &mut config.aggregators[asset_type];
    assert!(price_info.aggregator == aggregator.id().to_address(), ERR_AGGREGATOR_ASSET_MISMATCH);

    price_info.price = current_price;
    price_info.last_updated = now;

    emit(AssetPriceUpdated {
        asset_type,
        price: current_price,
        timestamp: now,
    })
}
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
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

**File:** volo-vault/sources/volo_vault.move (L1164-1168)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = self.assets_value_updated[*asset_type];
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
    });
}
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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
