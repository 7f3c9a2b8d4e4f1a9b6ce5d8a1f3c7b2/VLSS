### Title
Navi Adaptor Decimal Mismatch Causes Massive Position Misvaluation (10^9x Inflation for 18-Decimal Assets)

### Summary
The `calculate_navi_position_value()` function in the Navi adaptor uses raw, non-normalized oracle prices when calculating USD values, causing severe valuation errors that scale with the coin's decimal difference from 9. Assets with 6 decimals (USDC) are valued 1000x too low, while hypothetical 18-decimal assets (like wrapped ETH) would be valued 1 billion times (10^9x) too high, enabling massive vault share manipulation and fund theft.

### Finding Description

The vulnerability exists in the Navi adaptor's price handling mechanism: [1](#0-0) 

The adaptor fetches the raw oracle price using `vault_oracle::get_asset_price()` instead of `vault_oracle::get_normalized_asset_price()`. This raw price is then used directly with `mul_with_oracle_price()`, which always divides by `ORACLE_DECIMALS = 10^18`: [2](#0-1) 

The oracle system stores each asset with a `decimals` field representing the coin's native decimal precision: [3](#0-2) 

The correct pattern requires using normalized prices, as shown in the Cetus adaptor: [4](#0-3) 

And the Momentum adaptor: [5](#0-4) 

And the vault's own coin value update function: [6](#0-5) 

The normalization function adjusts prices based on coin decimals to ensure consistent USD calculations: [7](#0-6) 

Test cases explicitly demonstrate that normalized prices are required for correct multi-decimal asset valuation: [8](#0-7) 

### Impact Explanation

**Direct Fund Theft via Share Manipulation:**
- For USDC (6 decimals): 1000 USDC position calculated as $1 instead of $1000 (1000x undervalued)
- For BTC (8 decimals): 1 BTC position calculated as $10,000 instead of $100,000 (10x undervalued)
- For hypothetical 18-decimal token: 1 token worth $2000 calculated as $2000 * 10^9 (1 billion times overvalued)

**Exploitation Scenario:**
1. Attacker deposits large amount of an 18-decimal token to Navi (if supported)
2. Calls `update_navi_position_value()` to update vault's asset values
3. Vault's total USD value inflated by 10^9x for that position
4. Attacker deposits minimal principal to vault, receives shares based on inflated total value
5. Attacker immediately withdraws, draining nearly all vault funds from legitimate users

Even without 18-decimal tokens, the undervaluation of USDC/BTC positions corrupts the vault's total USD value calculation, causing incorrect share pricing that enables gradual fund extraction through deposit/withdrawal arbitrage.

**Affected Parties:**
- All vault depositors lose funds when share calculations use incorrect total USD values
- Protocol suffers complete loss of depositor trust
- Estimated impact: Total vault drain possible with 18-decimal tokens; 10-1000x pricing errors with existing tokens

### Likelihood Explanation

**Reachability:**
The vulnerable function is called through the public `update_navi_position_value()` entry point during normal vault operations: [9](#0-8) 

**Attack Complexity:** LOW
- Attacker only needs to deposit assets with non-9 decimal counts to Navi
- No special privileges required
- No complex timing or state manipulation needed
- Standard DeFi user actions (deposit to Navi, trigger vault update)

**Feasibility:** HIGH
- USDC (6 decimals) and BTC (8 decimals) are commonly used in tests and likely in production
- If any 18-decimal token is added to Navi support, immediate critical exploitation
- The bug is deterministic and always present

**Current Conditions:**
- Test suite confirms USDC (6 decimals) and BTC (8 decimals) are supported assets
- Any Navi position with these assets will have incorrect valuations
- Only SUI (9 decimals) escapes the bug due to normalization being identity transformation

### Recommendation

**Immediate Fix:**
Replace line 63 in `navi_adaptor.move` to use normalized prices:

```move
// Change from:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// To:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
``` [10](#0-9) 

**Invariant Check:**
Add assertion to verify normalized prices are used in all adaptors that call `mul_with_oracle_price()`.

**Regression Test:**
Add test case similar to the oracle test that validates Navi position values for USDC (6 decimals), BTC (8 decimals), and SUI (9 decimals) assets, verifying correct USD calculations: [11](#0-10) 

### Proof of Concept

**Setup:**
1. Configure oracle with USDC at 6 decimals, price = 1 * 10^18
2. User deposits 1000 USDC to Navi (1000_000000 in base units)
3. Vault contains 1000 shares, each worth $1

**Exploitation Steps:**

**Transaction 1: Update Navi Position Value**
- Call `update_navi_position_value()` for USDC position
- Current buggy calculation:
  - `supply_scaled = 1000_000000` (after ray_mul with index ≈ 1.0)
  - `price = get_asset_price() = 1 * 10^18` (raw, not normalized)
  - `usd_value = mul_with_oracle_price(1000_000000, 1 * 10^18)`
  - `= 1000_000000 * 1 * 10^18 / 10^18 = 1000_000000`
  - Result: $0.001 USD (should be $1000 USD)

**Expected Result (with fix):**
- `price = get_normalized_asset_price() = 1 * 10^21` (normalized for 6 decimals)
- `usd_value = mul_with_oracle_price(1000_000000, 1 * 10^21)`
- `= 1000_000000 * 1 * 10^21 / 10^18 = 1000 * 10^9`
- Result: $1000 USD ✓

**Actual Result:**
- Vault's total USD value corrupted by 1000x undervaluation
- Share price calculations broken
- Attacker can exploit pricing discrepancy to extract ~1000x value through deposit/withdrawal cycles

**Success Condition:**
Position value should equal `1000 * DECIMALS` where `DECIMALS = 10^9`, but instead equals `1000_000000` (0.001 * 10^9), confirming 1000x undervaluation.

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
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

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-72)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-64)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
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

**File:** volo-vault/tests/oracle.test.move (L558-638)
```text
// [TEST-CASE: Should get correct usd value with normalized prices.] @test-case ORACLE-010
public fun test_get_correct_usd_value_with_oracle_price_with_different_decimals() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    let sui_asset_type = type_name::get<SUI_TEST_COIN>().into_string();
    let usdc_asset_type = type_name::get<USDC_TEST_COIN>().into_string();
    let btc_asset_type = type_name::get<BTC_TEST_COIN>().into_string();

    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);

        test_scenario::return_shared(oracle_config);
    };

    s.next_tx(OWNER);
    {
        let config = s.take_shared<OracleConfig>();

        assert!(
            vault_oracle::get_asset_price(&config, &clock, sui_asset_type) == 2 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_asset_price(&config, &clock, usdc_asset_type) == 1 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_asset_price(&config, &clock, btc_asset_type) == 100_000 * ORACLE_DECIMALS,
        );

        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, sui_asset_type) == 2 * ORACLE_DECIMALS,
        );
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, usdc_asset_type) == 1 * ORACLE_DECIMALS * 1_000,
        );
        assert!(
            vault_oracle::get_normalized_asset_price(&config, &clock, btc_asset_type) == 100_000 * ORACLE_DECIMALS * 10,
        );

        test_scenario::return_shared(config);
    };

    s.next_tx(OWNER);
    {
        let config = s.take_shared<OracleConfig>();

        let sui_usd_value_for_1_sui = vault_utils::mul_with_oracle_price(
            1_000_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, sui_asset_type),
        );

        let usdc_usd_value_for_1_usdc = vault_utils::mul_with_oracle_price(
            1_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, usdc_asset_type),
        );

        let btc_usd_value_for_1_btc = vault_utils::mul_with_oracle_price(
            100_000_000,
            vault_oracle::get_normalized_asset_price(&config, &clock, btc_asset_type),
        );

        assert!(sui_usd_value_for_1_sui == 2 * DECIMALS);
        assert!(usdc_usd_value_for_1_usdc == 1 * DECIMALS);
        assert!(btc_usd_value_for_1_btc == 100_000 * DECIMALS);

        test_scenario::return_shared(config);
    };

    clock.destroy_for_testing();
    s.end();
}
```
