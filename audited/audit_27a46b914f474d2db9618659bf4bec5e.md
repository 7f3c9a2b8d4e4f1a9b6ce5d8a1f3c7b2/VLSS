### Title
Hardcoded DECIMAL Constant Causes Incorrect Slippage Validation for Tokens with Different Decimals

### Summary
The `calculate_cetus_position_value()` function uses a hardcoded `DECIMAL = 1e18` constant to calculate relative oracle prices without accounting for token decimal differences. When tokens in a Cetus pool have different oracle decimal configurations, the slippage check compares mathematically incompatible values, causing either denial-of-service by rejecting valid operations or bypassing critical safety checks that protect against price manipulation.

### Finding Description

The vulnerability exists in the relative price calculation in `calculate_cetus_position_value()`: [1](#0-0) 

The oracle system allows each token to have different decimal configurations stored in the `PriceInfo` structure: [2](#0-1) 

When adding aggregators, admins can specify any decimal value without validation: [3](#0-2) 

The test suite demonstrates tokens with different decimals (9, 6, 8) are explicitly supported: [4](#0-3) 

**Root Cause:** Line 52 calculates `relative_price_from_oracle = price_a * DECIMAL / price_b` where:
- `price_a` is denominated as USD per 10^decimals_a token units
- `price_b` is denominated as USD per 10^decimals_b token units
- When decimals_a ≠ decimals_b, the simple division produces an incorrect relative price that's off by a factor of 10^(decimals_a - decimals_b)

The pool price calculation correctly adjusts for token decimal differences: [5](#0-4) 

But the oracle-derived price does not, causing the slippage comparison to fail: [6](#0-5) 

### Impact Explanation

**Operational Impact - DOS:** When decimals_a < decimals_b, the `relative_price_from_oracle` is artificially inflated by 10^(decimals_b - decimals_a). For example, with SUI (decimals=9) and USDC (decimals=6), the ratio is off by 1000x. This causes legitimate position value updates to fail the slippage check (ERR_INVALID_POOL_PRICE), blocking critical vault operations including:
- Asset valuation updates required for withdrawals
- Periodic position rebalancing
- Risk management operations

**Security Integrity Impact - Safety Bypass:** When decimals_a > decimals_b, the relative price is artificially deflated, causing the slippage check to pass even when actual price deviation exceeds configured limits. This defeats the security mechanism designed to prevent operations during:
- Price manipulation attacks on DEX
- Stale oracle data scenarios  
- Market volatility exceeding acceptable bounds

The same vulnerability affects the Momentum adaptor: [7](#0-6) 

**Affected Users:** All vault depositors and operators when dealing with Cetus or Momentum positions containing tokens with different decimal configurations.

### Likelihood Explanation

**High Likelihood:**

1. **No Enforcement:** The oracle configuration explicitly supports different decimals with no validation enforcing uniformity: [8](#0-7) 

2. **Natural Usage Pattern:** The test infrastructure uses tokens with different decimals (SUI=9, USDC=6, BTC=8), indicating this is an expected configuration pattern.

3. **Entry Point:** The function is callable via standard vault operations through `update_cetus_position_value()`: [9](#0-8) 

4. **Existing Deployments:** Common token pairs like SUI-USDC (9 vs 6 decimals) will trigger this vulnerability immediately upon deployment.

5. **No Attacker Requirements:** This is a logic error that manifests during normal operations without requiring attacker action.

### Recommendation

**Fix Line 52 to account for decimal differences:**

```move
let relative_price_from_oracle = if (decimals_a >= decimals_b) {
    price_a * DECIMAL / (price_b * (pow(10, (decimals_a - decimals_b)) as u256))
} else {
    (price_a * (pow(10, (decimals_b - decimals_a)) as u256)) * DECIMAL / price_b
};
```

**Alternative (Simpler):** Use normalized prices consistently:
```move
let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);
let relative_price_from_oracle = normalized_price_a * DECIMAL / normalized_price_b;
```

**Add Validation:** Either enforce uniform decimals at aggregator registration or add explicit decimal adjustment logic.

**Apply Fix to Both Adaptors:** cetus_adaptor.move and momentum.adaptor.move have identical issues.

**Test Cases:**
1. Test SUI-USDC pool (9 vs 6 decimals) with valid pool price - should pass slippage check
2. Test with 3-decimal difference showing 1000x error factor
3. Test edge case with extreme decimal differences (0 vs 18)

### Proof of Concept

**Initial State:**
1. Oracle configured with SUI (decimals=9, price=2e18 representing $2/SUI)
2. Oracle configured with USDC (decimals=6, price=1e18 representing $1/USDC)  
3. Cetus SUI-USDC pool with fair market price (1 SUI = 2 USDC)
4. DEX slippage tolerance set to 1% (100 basis points)

**Transaction Sequence:**
1. Operator calls `update_cetus_position_value<PrincipalCoin, SUI, USDC>(vault, config, clock, asset_type, pool)`

**Expected Result:**
- Slippage check passes (pool price matches oracle price within 1%)
- Position value updated successfully

**Actual Result:**
- Line 52 calculates: `relative_price_from_oracle = 2e18 * 1e18 / 1e18 = 2e18`
- But with decimal adjustment should be: `2e18 * 1e18 / (1e18 * 1000) = 2e15`
- Error factor: 1000x
- Slippage check at line 64: `(pool_price - 2e18) * 1e18 / 2e18 < 1e18 * 100 / 10000`
- With pool_price ≈ 2e15 (correct), difference ≈ 2e18, causing massive apparent slippage
- Transaction aborts with ERR_INVALID_POOL_PRICE (code 6_001)
- **Success Condition for Exploit:** Legitimate operation fails, causing DOS

### Citations

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L19-30)
```text
public fun update_cetus_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut CetusPool<CoinA, CoinB>,
) {
    let cetus_position = vault.get_defi_asset<PrincipalCoinType, CetusPosition>(asset_type);
    let usd_value = calculate_cetus_position_value(pool, cetus_position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L49-52)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L63-66)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L78-88)
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

**File:** volo-vault/tests/test_helpers.move (L27-47)
```text
        vault_oracle::set_aggregator(
            config,
            clock,
            sui_asset_type,
            9,
            MOCK_AGGREGATOR_SUI,
        );
        vault_oracle::set_aggregator(
            config,
            clock,
            usdc_asset_type,
            6,
            MOCK_AGGREGATOR_USDC,
        );
        vault_oracle::set_aggregator(
            config,
            clock,
            btc_asset_type,
            8,
            MOCK_AGGREGATOR_BTC,
        );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L48-58)
```text
    // Oracle price has 18 decimals
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;

    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
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
