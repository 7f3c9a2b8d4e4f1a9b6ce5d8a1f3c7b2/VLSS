### Title
Stale Oracle Price Vulnerability in Navi Position Valuation Due to Two-Layer Caching

### Summary
The `calculate_navi_position_value()` function uses `get_asset_price()` which validates only the staleness of cached prices in OracleConfig (up to 1 minute old), not the actual Switchboard aggregator's current price timestamp. This allows vault operations to use oracle prices that are up to 1 minute stale, enabling operators to exploit favorable stale prices for position valuations and potentially bypass loss tolerance checks.

### Finding Description

The vulnerability exists in a two-layer price caching mechanism with mismatched staleness validation:

**Layer 1 - Switchboard Aggregator**: The actual oracle price source with its own timestamp.

**Layer 2 - OracleConfig Cache**: A cached copy of Switchboard prices in the vault's oracle configuration.

The critical flaw is at line 63 of `navi_adaptor.move` where `vault_oracle::get_asset_price()` is called: [1](#0-0) 

This function only validates the cached price staleness, not the Switchboard aggregator's actual timestamp: [2](#0-1) 

The cached price is updated via `update_price()` which calls `get_current_price()` to fetch from Switchboard: [3](#0-2) [4](#0-3) 

**The Key Issue**: The oracle's `update_interval` defaults to 60 seconds (1 minute): [5](#0-4) 

While the vault enforces that asset VALUES must be updated within `MAX_UPDATE_INTERVAL = 0` (same transaction): [6](#0-5) [7](#0-6) 

This creates a disconnect: asset values are updated in the same transaction, but the PRICES used can be up to 1 minute stale from the cached OracleConfig.

### Impact Explanation

**Direct Security Integrity Impact**:
1. **Incorrect Position Valuations**: Navi positions can be valued using prices up to 1 minute stale, leading to inaccurate total vault USD calculations during operations.

2. **Loss Tolerance Bypass**: During vault operations, if the stale price is favorable, an operator can understate losses or overstate gains, potentially bypassing the per-epoch loss tolerance checks that protect the vault.

3. **Unfair Value Distribution**: The `end_op_value_update_with_bag()` flow compares `total_usd_value_before` with `total_usd_value_after` to calculate losses. Stale prices can manipulate this comparison.

4. **Share Ratio Manipulation**: Since share ratios depend on total USD value calculations, stale prices during deposit/withdraw operations can lead to unfair share pricing.

**Quantified Impact**: In volatile markets, cryptocurrency prices can move 1-5% within one minute. For a vault with $1M in Navi positions, this represents potential mispricing of $10K-$50K.

**Affected Parties**: All vault depositors are affected as their share values depend on accurate position valuations.

### Likelihood Explanation

**High Likelihood - Practical Exploitation**:

1. **Reachable Entry Point**: The `update_navi_position_value()` function is called during standard vault operations. Any operator performing operations can trigger this code path.

2. **Feasible Preconditions**: 
   - Operator role is required but this is the expected user for vault operations
   - No special market conditions needed beyond normal crypto volatility
   - The vulnerability is inherent in the design, not dependent on race conditions

3. **Execution Practicality**:
   - Time T: Anyone calls `update_price()` (public function) to cache Switchboard price
   - Time T+30s: Switchboard price updates due to market movement
   - Time T+50s: Operator executes vault operation
   - `get_asset_price()` returns stale cached price (still within 1-minute window)
   - Position valued at outdated price

4. **Economic Rationality**: 
   - No attack cost beyond normal operation gas fees
   - Operator can strategically time operations when cached prices are favorable
   - While anyone can call `update_price()`, operators control operation timing

5. **Detection Difficulty**: The exploit is difficult to detect as all checks pass - the cached price is within its staleness limit, making the operation appear legitimate.

### Recommendation

**Immediate Fix**: Modify `get_asset_price()` to validate the actual Switchboard aggregator's timestamp, not just the cached price timestamp.

Add a new function to fetch and validate current Switchboard price:

```move
public fun get_fresh_asset_price(
    config: &OracleConfig, 
    clock: &Clock,
    aggregator: &Aggregator,
    asset_type: String
): u256 {
    // Validate Switchboard timestamp is fresh
    let current_price = get_current_price(config, clock, aggregator);
    
    // Update cache
    let price_info = &mut config.aggregators[asset_type];
    price_info.price = current_price;
    price_info.last_updated = clock.timestamp_ms();
    
    current_price
}
```

**Alternative Fix**: Require `update_price()` to be called in the same transaction before position valuation during operations, by adding a transaction-level freshness check that cannot be satisfied by stale cached prices.

**Invariant to Enforce**: During vault operations with status `VAULT_DURING_OPERATION_STATUS`, all oracle prices used must be fetched directly from Switchboard aggregators with freshness validation, not from cache.

**Test Cases**:
1. Test that operations fail when using cached prices older than the operation transaction
2. Test that rapid price movements within 1 minute are properly reflected in valuations
3. Test that operators cannot exploit timing between cache updates and operations

### Proof of Concept

**Initial State**:
- Vault has Navi position with supplied/borrowed assets
- OracleConfig has cached prices for relevant assets
- Current time: T

**Attack Sequence**:

1. **T+0s**: Alice (or anyone) calls `vault_oracle::update_price()` with Switchboard aggregator
   - Switchboard price: $100 per token
   - Price cached in OracleConfig with `last_updated = T`

2. **T+30s**: Market moves significantly
   - Switchboard aggregator updates to $105 per token (5% increase)
   - OracleConfig cache still shows $100 (not updated)

3. **T+50s**: Operator Bob executes vault operation calling `update_navi_position_value()`
   - Calls `calculate_navi_position_value()` at line 31
   - At line 63: `get_asset_price()` is called
   - Returns cached price of $100 (within 1-minute staleness limit)
   - Position valued at $100 instead of actual $105
   - 5% undervaluation

4. **Expected Result**: Position should be valued at current Switchboard price of $105
   **Actual Result**: Position valued at stale cached price of $100

**Success Condition**: The operation completes with stale pricing, and total vault USD value is calculated incorrectly, potentially allowing Bob to:
- Understate losses to stay within loss tolerance
- Manipulate pre/post operation value comparisons
- Extract value through mispriced positions

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-63)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**File:** volo-vault/sources/oracle.move (L12-12)
```text
const MAX_UPDATE_INTERVAL: u64 = 1000 * 60; // 1 minute
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
