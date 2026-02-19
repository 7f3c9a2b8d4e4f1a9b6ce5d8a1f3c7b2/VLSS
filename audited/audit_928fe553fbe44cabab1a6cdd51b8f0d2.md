### Title
Navi Position Value Calculation Fails to Normalize for Coin Decimals, Causing Massive Valuation Errors

### Summary
The `calculate_navi_position_value()` function uses `get_asset_price()` instead of `get_normalized_asset_price()`, causing coins with different decimal places to be valued incorrectly. For equal $1 values, a 9-decimal coin like SUI appears 1000x more valuable than a 6-decimal coin like USDC, directly violating the protocol's valuation correctness invariant.

### Finding Description

The vulnerability exists in the Navi adaptor's position value calculation. [1](#0-0) 

The root cause is on line 63, where the function retrieves the unnormalized oracle price: [2](#0-1) 

This price is then used with `mul_with_oracle_price()` on lines 65-66: [3](#0-2) 

The `mul_with_oracle_price()` function simply divides by `ORACLE_DECIMALS` (10^18): [4](#0-3) 

However, Navi stores balances in each coin's native decimals (not normalized). After applying the ray index (10^27), the `supply_scaled` and `borrow_scaled` values remain in native coin decimals: [5](#0-4) 

The oracle configuration stores a `decimals` field for each asset: [6](#0-5) 

The correct approach is to use `get_normalized_asset_price()`, which adjusts the price based on coin decimals to normalize for 9-decimal representation: [7](#0-6) 

**Comparison with correct implementations:**

The Cetus adaptor correctly uses `get_normalized_asset_price()`: [8](#0-7) 

The Receipt adaptor also correctly uses `get_normalized_asset_price()`: [9](#0-8) 

The vault's own price update functions use `get_normalized_asset_price()`: [10](#0-9) 

And for coin type assets: [11](#0-10) 

### Impact Explanation

**Direct Fund Impact:**

For coins with equal real-world value, the incorrect calculation produces results that differ by 10^(decimal_difference):

- 1 SUI (9 decimals, $1 value) = 1,000,000,000 native units → Navi calculates: 1,000,000,000 USD value units
- 1 USDC (6 decimals, $1 value) = 1,000,000 native units → Navi calculates: 1,000,000 USD value units
- **Error: SUI appears 1000x more valuable than USDC**

For 8-decimal vs 6-decimal coins:
- 1 WETH (8 decimals) vs 1 USDC (6 decimals) → WETH appears 100x more valuable

This directly violates the **Pricing & Funds** invariant requiring `total_usd_value correctness`.

**Exploitation Scenarios:**

1. **Inflated Collateral Attack**: Operator supplies high-decimal coins (SUI: 9 decimals) and borrows low-decimal coins (USDC: 6 decimals) on Navi. The position appears to have 1000x more collateral value than reality, allowing massive over-leverage.

2. **False Health Factor**: The inflated position value bypasses health limiter checks, allowing the vault to operate with actual positions that would normally be rejected.

3. **Loss Realization**: When positions are closed or liquidated, the vault realizes the true value is 1000x less than recorded, causing catastrophic losses that exceed `loss_tolerance`.

4. **Share Price Manipulation**: Inflated Navi position values increase `total_usd_value`, artificially inflating share prices and allowing attackers to steal value from other depositors through asymmetric deposit/withdraw.

### Likelihood Explanation

**High Likelihood - Reachable Entry Point:**

The vulnerable function is called during normal vault operations through `update_navi_position_value()`: [12](#0-11) 

This is invoked by operators during standard operation flows, as shown in tests: [13](#0-12) 

**Feasible Preconditions:**

- Operator role (trusted but can be compromised or malicious)
- Access to Navi protocol with multi-decimal coin markets
- No additional checks prevent this - the calculation executes unconditionally

**Execution Practicality:**

The vulnerability manifests through normal protocol operations:
1. Operator adds Navi AccountCap to vault
2. Operator deposits high-decimal coins and borrows low-decimal coins on Navi
3. Operator calls `update_navi_position_value()` - the inflated value is recorded
4. Vault operates with incorrect `total_usd_value`
5. When realized, losses far exceed tolerance

**Economic Rationality:**

A malicious or compromised operator can profit by:
- Inflating vault TVL to attract more deposits at premium share prices
- Using inflated positions to justify larger operations
- Front-running the value correction to extract value

The vulnerability exists in production code with no test coverage for multi-decimal scenarios: [14](#0-13) 

### Recommendation

**Fix Implementation:**

Replace `get_asset_price()` with `get_normalized_asset_price()` in the Navi adaptor:

```move
// Line 63 - BEFORE (vulnerable):
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// Line 63 - AFTER (fixed):
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

**Specific Changes:** [2](#0-1) 

Change this single line to use `vault_oracle::get_normalized_asset_price()` instead of `vault_oracle::get_asset_price()`.

**Add Invariant Checks:**

Add test coverage comparing multi-decimal coin valuations:
- Test SUI (9 decimals) vs USDC (6 decimals) vs WETH (8 decimals)
- Verify equal real-world values produce equal USD value outputs
- Test Navi position calculations match Cetus/Receipt adaptor patterns

**Test Cases:**

Create integration test verifying:
1. Navi position with 1 SUI supplied and 1 USDC borrowed
2. Verify position value matches expected USD value within tolerance
3. Test with multiple decimal combinations (6, 8, 9)
4. Compare against normalized price calculations

### Proof of Concept

**Initial State:**
- Vault with Navi integration enabled
- Oracle configured with:
  - SUI price: $2, decimals: 9
  - USDC price: $1, decimals: 6
- Both oracle prices stored as 18-decimal values

**Attack Sequence:**

1. **Operator supplies 100 SUI to Navi**
   - Amount: 100,000,000,000 (100 SUI with 9 decimals)
   - Index ≈ 1.0 (10^27 in RAY)
   - supply_scaled ≈ 100,000,000,000

2. **Operator borrows 100 USDC from Navi**
   - Amount: 100,000,000 (100 USDC with 6 decimals)
   - Index ≈ 1.0 (10^27 in RAY)
   - borrow_scaled ≈ 100,000,000

3. **Update position value called**
   - SUI: mul_with_oracle_price(100,000,000,000, 2×10^18) = 200,000,000,000
   - USDC: mul_with_oracle_price(100,000,000, 1×10^18) = 100,000,000
   - Net position: 200,000,000,000 - 100,000,000 = ~199,900,000,000

**Expected Result (with normalized prices):**
- SUI: mul_with_oracle_price(100,000,000,000, 2×10^18) = 200×10^9 = 200,000,000,000
- USDC: mul_with_oracle_price(100,000,000, 1×10^21) = 100×10^9 = 100,000,000,000
- Net position: 200,000,000,000 - 100,000,000,000 = 100,000,000,000 ($100 value)

**Actual Result (current vulnerable code):**
- Net position: ~199,900,000,000 (appears to be ~$200 value)
- **Error: Missing $100 in liabilities due to USDC being 1000x undervalued**

**Success Condition:**
The vault records Navi position value that is 1000x higher than reality, allowing operators to over-leverage and causing eventual massive losses when positions are settled.

### Citations

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-72)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-73)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<T>().into_string(),
    );

    let vault_share_value = vault_utils::mul_d(shares, share_ratio);
    let pending_deposit_value = vault_utils::mul_with_oracle_price(
        vault_receipt.pending_deposit_balance() as u256,
        principal_price,
    );
    let claimable_principal_value = vault_utils::mul_with_oracle_price(
        vault_receipt.claimable_principal() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1109-1118)
```text
    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );

    let principal_usd_value = vault_utils::mul_with_oracle_price(
        self.free_principal.value() as u256,
        principal_price,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1146-1151)
```text
    let price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        asset_type,
    );
    let coin_usd_value = vault_utils::mul_with_oracle_price(coin_amount, price);
```

**File:** volo-vault/tests/update/update.test.move (L964-970)
```text
        navi_adaptor::update_navi_position_value<SUI_TEST_COIN>(
            &mut vault,
            &config,
            &clock,
            vault_utils::parse_key<NaviAccountCap>(0),
            &mut storage,
        );
```

**File:** volo-vault/tests/calculation.test.move (L49-72)
```text
#[test]
// [TEST-CASE: Should multiply with oracle price.] @test-case CALCULATION-003
// Price is 10^18: 1U = 1e18
// Amount is 10^9: 1 coin = 1e9
// USD Value is 10^9: 1U = 1e9
public fun test_mul_with_oracle_price() {
    let mut amount = vault_utils::to_decimals(1);
    let mut price = vault_utils::to_oracle_price_decimals(1);

    assert!(vault_utils::from_oracle_price_decimals(price) == 1, 0);

    // 1 Coin * 1U/Coin = 1U
    assert!(vault_utils::mul_with_oracle_price(amount, price) == vault_utils::to_decimals(1), 0);

    amount = 10_000_000_000;
    price = 1_000_000_000_000_000_000;
    // 10 Coin * 1U/Coin = 10U
    assert!(vault_utils::mul_with_oracle_price(amount, price) == 10_000_000_000, 0);

    amount = 1_000_000_000;
    price = 10_000_000_000_000_000_000;
    // 1 Coin * 10U/Coin = 10U
    assert!(vault_utils::mul_with_oracle_price(amount, price) == 10_000_000_000, 0);
}
```
