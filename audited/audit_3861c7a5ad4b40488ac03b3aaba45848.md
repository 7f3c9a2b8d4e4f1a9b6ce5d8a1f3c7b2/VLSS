### Title
Momentum Adaptor Lacks Version Compatibility Checks for sqrt_price Format Changes

### Summary
The momentum adaptor hardcodes the assumption that MomentumPool's `sqrt_price` is in Q64.64 fixed-point format without any version compatibility checking. If MomentumPool is upgraded to use a different fixed-point precision, the adaptor would either cause vault operation failures (DoS) or produce incorrect position valuations, potentially bypassing loss tolerance checks.

### Finding Description

The momentum adaptor's `sqrt_price_x64_to_price` function hardcodes a Q64.64 format assumption by dividing the sqrt_price by `pow(2, 64)`: [1](#0-0) 

The adaptor directly calls `pool.sqrt_price()` to retrieve the raw u128 value and converts it using this hardcoded divisor: [2](#0-1) 

**Root Cause:** The adaptor has no mechanism to verify or adapt to different sqrt_price formats. The mmt_v3 module includes a Version object with major/minor version tracking: [3](#0-2) 

However, the momentum adaptor functions do not accept or check this Version parameter, unlike the trade operations which do require version verification.

**Why Existing Protections Fail:**

The only protection is the oracle price sanity check: [4](#0-3) 

This check compares the pool price (calculated from sqrt_price) against the oracle price within a configurable slippage tolerance (default 1%): [5](#0-4) 

If the sqrt_price format changes, this check would likely abort with `ERR_INVALID_POOL_PRICE`, causing DoS. However, if the format change is subtle or slippage tolerance is increased, incorrect valuations could pass through.

**Execution Path:** During vault operations, MomentumPosition assets are borrowed, used, and their values must be updated before operation completion: [6](#0-5) 

The value update uses the adaptor which would fail or produce wrong values after an mmt_v3 upgrade: [7](#0-6) 

### Impact Explanation

**Primary Impact - Operational DoS:**
If MomentumPool changes sqrt_price from Q64.64 to a different precision (e.g., Q128.128), the calculated pool_price would be severely incorrect. The oracle price check would detect this deviation and abort with `ERR_INVALID_POOL_PRICE`. This would make all vault operations involving Momentum positions fail, effectively freezing those assets in the vault until the adaptor is updated.

**Secondary Impact - Loss Tolerance Bypass:**
If the format change is subtle enough to pass the slippage check, positions would be incorrectly valued. The operation value update process calculates total_usd_value_after using these values: [8](#0-7) 

Overvalued positions could allow operations that should fail loss tolerance checks to pass, potentially exposing the vault to greater losses than intended. Undervalued positions could incorrectly block valid operations.

**Affected Parties:**
- Vault depositors: Operations with Momentum positions become unusable (DoS) or loss protection is compromised (incorrect valuation)
- Operators: Cannot execute planned strategies involving Momentum positions
- Protocol: Vault becomes partially non-functional until emergency adaptor updates

### Likelihood Explanation

**Trigger Condition:** This issue manifests when MomentumPool (mmt_v3) is upgraded with a different sqrt_price calculation method. The mmt_v3 module is in local_dependencies, suggesting potential shared control, but protocol upgrades are a normal part of DeFi operations.

**Execution Path:** No attacker action is required. Normal vault operations (start_op_with_bag → update_momentum_position_value → end_op_value_update_with_bag) would automatically trigger the incompatibility once mmt_v3 is upgraded.

**Detection Constraints:** 
- Most likely: Oracle price check immediately catches the error → DoS
- Less likely: Subtle format changes or high slippage tolerance → incorrect valuation passes through

**Probability Assessment:** While this depends on mmt_v3 upgrade practices, the lack of any compatibility safeguards makes this a real architectural risk. The severity is MEDIUM because:
1. Not an active exploit but a compatibility failure
2. Impact ranges from DoS (certain) to loss tolerance bypass (possible)
3. Requires external protocol upgrade (not fully under Volo control)
4. No emergency mitigation mechanism exists

### Recommendation

**1. Add Version Compatibility Checking:**
Modify adaptor functions to accept and validate the mmt_v3 Version object:

```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
    version: &Version,  // Add this parameter
) {
    version.assert_supported_version();  // Add version check
    // ... rest of function
}
```

**2. Make sqrt_price Format Configurable:**
Add a configuration parameter for the fixed-point divisor instead of hardcoding `pow(2, 64)`, allowing adaptability to format changes without code upgrades.

**3. Enhanced Validation:**
Consider adding explicit format validation by checking expected sqrt_price ranges or comparing multiple calculation methods as a sanity check.

**4. Test Cases:**
- Test adaptor behavior with different sqrt_price formats
- Verify DoS prevention when format changes
- Validate oracle check catches format mismatches
- Test graceful degradation paths

### Proof of Concept

**Initial State:**
- Vault has MomentumPosition assets
- Adaptor expects sqrt_price in Q64.64 format (divisor = 2^64)
- Oracle prices are correctly configured

**Scenario 1 - DoS (Most Likely):**
1. mmt_v3 is upgraded to use Q128.128 format (divisor = 2^128)
2. Operator calls `start_op_with_bag` to borrow MomentumPosition
3. After operation, operator calls `update_momentum_position_value`
4. Adaptor calculates: `sqrt_price_u256_with_decimals = (sqrt_price_x64 as u256) * DECIMAL / pow(2, 64)` (wrong divisor)
5. If actual value should be divided by 2^128, this produces price ~2^64 times too high
6. Oracle check: `pool_price` vs `relative_price_from_oracle` fails slippage check
7. Transaction aborts with `ERR_INVALID_POOL_PRICE`
8. All subsequent operations with Momentum positions fail

**Scenario 2 - Incorrect Valuation (Less Likely):**
1. mmt_v3 makes a subtle format change that doesn't drastically alter values
2. OR slippage tolerance is configured high (e.g., 10%)
3. Incorrect valuation passes oracle check
4. Position is overvalued in `total_usd_value_after`
5. Loss tolerance check passes when it should fail
6. Vault accepts operation that exceeds intended loss limits

**Expected:** Adaptor should detect version mismatch and fail gracefully with informative error
**Actual:** Either DoS (transaction aborts) or incorrect valuation passes through

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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L53-58)
```text
    let pool_price = sqrt_price_x64_to_price(sqrt_price, decimals_a, decimals_b);
    let slippage = config.dex_slippage();
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L69-91)
```text
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();

    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
    (amount_a, amount_b, sqrt_price)
}
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/version.move (L1-44)
```text
module mmt_v3::version {

    public struct Version has key, store {
        id: UID,
        major_version: u64,
        minor_version: u64
    }

    public struct VersionCap has key, store {
        id: UID
    }

    fun init(ctx: &mut TxContext) {
        abort 0
    }

    // ======= version control ==========
    
    public fun value_major(v: &Version): u64 { abort 0 }
    public fun value_minor(v: &Version): u64 { abort 0 }

    public fun upgrade_major(v: &mut Version, _: &VersionCap) {
        abort 0
    }

    public fun upgrade_minor(v: &mut Version, val: u64, _: &VersionCap) {
        abort 0
    }

    public fun set_version(v: &mut Version, _: &VersionCap, major: u64, minor: u64) {
        abort 0
    }

    public fun is_supported_major_version(v: &Version): bool {
        abort 0
    }

    public fun is_supported_minor_version(v: &Version): bool {
        abort 0
    }

    public fun assert_supported_version(v: &Version) {
        abort 0
    }
```

**File:** volo-vault/sources/oracle.move (L14-14)
```text
const DEFAULT_DEX_SLIPPAGE: u256 = 100; // 1%
```

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
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
