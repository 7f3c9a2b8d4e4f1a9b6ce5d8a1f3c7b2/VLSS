### Title
Mismatched Oracle Price Decimals Cause Incorrect Relative Price Calculation in DEX Adaptors

### Summary
The `get_position_value()` function in momentum.adaptor.move (and identically in cetus_adaptor.move) assumes all oracle prices have 18 decimals, but this assumption is not enforced. When two assets in a pool have oracle price feeds with different decimal formats, the relative price calculation produces incorrect results, causing the slippage validation to fail and preventing legitimate position value updates.

### Finding Description

**Location:** [1](#0-0) 

The code calculates the relative price between two assets using their raw oracle prices: [1](#0-0) 

The comment states "Oracle price has 18 decimals", but this is an undocumented assumption that is not enforced anywhere in the codebase.

**Root Cause:**

The oracle system stores a `decimals` field in `PriceInfo` that represents the decimal format of each asset's oracle price feed: [2](#0-1) 

This decimals value is set when adding aggregators and can be any value: [3](#0-2) 

The `get_asset_price()` function returns the raw price with its original decimal format (whatever was stored in PriceInfo): [4](#0-3) 

Note that the system DOES provide `get_normalized_asset_price()` which normalizes prices to 9 decimals: [5](#0-4) 

However, the momentum and cetus adaptors use `get_asset_price()` (non-normalized) for the relative price calculation, while using `get_normalized_asset_price()` only for the final USD value calculation: [6](#0-5) 

**Why Protections Fail:**

There is no validation enforcing that all oracle price feeds use the same decimal format. Different Switchboard price feeds naturally have different decimal formats based on the asset type (e.g., BTC feeds commonly use 8 decimals, ETH uses 18, etc.).

**Concrete Example:**

Assume Asset A (e.g., ETH) has an oracle price with 18 decimals: `price_a = 2000 * 10^18`
Assume Asset B (e.g., BTC) has an oracle price with 8 decimals: `price_b = 40000 * 10^8`

The relative price calculation becomes:
```
relative_price_from_oracle = price_a * DECIMAL / price_b
                          = (2000 * 10^18) * (10^18) / (40000 * 10^8)
                          = 2000 * 10^18 * 10^18 / (40000 * 10^8)
                          = 0.05 * 10^28
                          = 5 * 10^26
```

But the pool_price from `sqrt_price_x64_to_price()` will have 18 decimals (correctly calculated), so it would be approximately `0.05 * 10^18`.

The slippage check compares a value with 26 decimals to a value with 18 decimals - a difference of 10^8, causing the assertion to always fail even when prices are actually aligned.

### Impact Explanation

**Harm:**
- **Denial of Service**: The vault cannot update Momentum or Cetus position values when the two coins in a pool have oracle feeds with different decimal formats
- Position value updates will always fail the slippage assertion check at: [7](#0-6) 
- Without updated position values, the vault cannot accurately track its total USD value
- This prevents proper operation of the vault, including deposits, withdrawals, and operations that depend on accurate valuation

**Affected Parties:**
- Vault users cannot interact with the vault when position values are stale
- Vault operators cannot perform operations
- The entire protocol becomes unusable for pools with mismatched oracle decimals

**Severity Justification:**
HIGH - This causes a complete operational DoS for affected pools, preventing all vault functionality that depends on accurate position valuation. The issue affects critical vault operations and has no workaround once triggered.

### Likelihood Explanation

**Reachability:**
The vulnerable function is called through the public entry point `update_momentum_position_value()`: [8](#0-7) 

**Preconditions:**
- Two assets with different oracle price decimal formats are used in a Momentum or Cetus pool
- This is a NATURAL occurrence, not a malicious configuration
- Real-world Switchboard and other oracle providers use different decimal formats for different asset types (BTC commonly uses 8 decimals, ETH uses 18, stablecoins may use 6, etc.)

**Execution:**
No attacker action is required. Once the system is configured with diverse oracle feeds (which is expected in production), any attempt to update position values will trigger the bug.

**Probability:**
HIGH - This will occur in any production deployment that includes assets with different oracle decimal formats, which is the standard case for multi-asset vaults integrating with real oracle providers.

### Recommendation

**Primary Fix:**
Use `get_normalized_asset_price()` instead of `get_asset_price()` for the relative price calculation to ensure both prices have the same decimal format (9 decimals):

```move
// In momentum.adaptor.move line 49-51 (and similarly in cetus_adaptor.move)
// Replace:
let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = price_a * DECIMAL / price_b;

// With:
let normalized_price_a_temp = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b_temp = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a_temp * vault_utils::decimals() / normalized_price_b_temp;
```

Note: Adjust the DECIMAL constant used to match the 9-decimal format of normalized prices.

**Additional Fix:**
The `sqrt_price_x64_to_price()` function appears to use oracle price decimals where it should use actual coin decimals. Consider adding a separate field to track coin decimals or documenting the required relationship between oracle decimals and coin decimals.

**Validation:**
Add assertions when adding aggregators to enforce that all oracle price feeds use a consistent decimal format, or properly handle mixed decimals throughout the codebase.

**Test Cases:**
1. Test with two assets having different oracle decimal formats (e.g., 18 and 8)
2. Verify that relative price calculation produces correct results
3. Test the slippage check with various price scenarios
4. Add integration tests that mirror real Switchboard feed configurations

### Proof of Concept

**Initial State:**
1. Vault is deployed and operational
2. Asset A (ETH) is added with oracle decimals = 18, oracle price = 2000 * 10^18
3. Asset B (BTC) is added with oracle decimals = 8, oracle price = 40000 * 10^8  
4. A Momentum pool exists with these two assets
5. The vault holds a position in this pool

**Exploitation Steps:**
1. Operator calls `update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(vault, config, clock, asset_type, pool)`
2. Function calls `get_position_value()` internally
3. Line 49-50: Retrieves price_a = 2000 * 10^18 and price_b = 40000 * 10^8
4. Line 51: Calculates relative_price_from_oracle = 2000 * 10^18 * 10^18 / (40000 * 10^8) = 5 * 10^26 (incorrect!)
5. Line 53: Calculates pool_price ≈ 0.05 * 10^18 (correct)
6. Line 55-58: Slippage check compares 10^26 scale to 10^18 scale
7. Transaction aborts with `ERR_INVALID_POOL_PRICE`

**Expected vs Actual:**
- Expected: Position value update succeeds with valid prices
- Actual: Transaction reverts, DoS of vault operations

**Success Condition:**
The vulnerability is confirmed when attempting to update position values for any pool where the two assets have oracle feeds with different decimal formats causes transaction failure, even when actual prices are within acceptable slippage.

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L48-52)
```text
    // Oracle price has 18 decimals
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-66)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);

    value_a + value_b
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

**File:** volo-vault/sources/oracle.move (L158-178)
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
```
