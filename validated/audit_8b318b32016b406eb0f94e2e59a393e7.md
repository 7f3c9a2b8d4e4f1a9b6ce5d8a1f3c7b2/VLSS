# Audit Report

## Title
Navi Adaptor Oracle Decimal Mismatch Causes Massive USD Value Miscalculation for Non-9-Decimal Assets

## Summary
The Navi adaptor uses `get_asset_price()` instead of `get_normalized_asset_price()` when calculating USD values of lending positions. This causes assets with decimals other than 9 (e.g., USDC with 6 decimals, BTC with 8 decimals) to be severely undervalued (up to 1000x), leading to incorrect share minting during deposits and enabling direct fund theft from existing vault shareholders.

## Finding Description

The vulnerability exists in the Navi adaptor's USD value calculation. The adaptor incorrectly uses the raw oracle price without decimal normalization, causing a fundamental mismatch in how asset values are computed.

**The Buggy Implementation:**

The Navi adaptor calls `vault_oracle::get_asset_price()` to obtain prices for Navi position assets, then passes these raw prices directly to `vault_utils::mul_with_oracle_price()`. [1](#0-0) 

**The Oracle Design:**

The vault oracle system is explicitly designed to normalize prices based on coin decimals. The `get_normalized_asset_price()` function adjusts the raw price by multiplying by 10^(9-decimals) for coins with fewer than 9 decimals, or dividing by 10^(decimals-9) for coins with more than 9 decimals. [2](#0-1) 

**The Utils Module Expectation:**

The `mul_with_oracle_price()` function expects 18-decimal normalized prices (ORACLE_DECIMALS = 10^18). It calculates USD value as `balance * price / 10^18`. [3](#0-2) 

**Correct Implementations:**

Both the Cetus and Momentum adaptors correctly use `get_normalized_asset_price()` when calculating USD values: [4](#0-3) [5](#0-4) 

**Protocol Test Confirmation:**

The protocol's own test suite explicitly demonstrates the normalization requirement. For USDC (6 decimals) with a raw price of 1e18, the normalized price must be 1e21 (1000x multiplier). For BTC (8 decimals), the multiplier is 10x. [6](#0-5) 

**Mathematical Impact:**

For USDC (6 decimals) with oracle price 1e18:
- **Correct calculation**: normalized_price = 1e21 → USD_value = balance * 1e21 / 1e18 = balance * 1000
- **Buggy calculation**: raw_price = 1e18 → USD_value = balance * 1e18 / 1e18 = balance
- **Result**: USD value undervalued by 1000x

For BTC (8 decimals): 10x undervaluation
For SUI (9 decimals): No impact (10^0 = 1)

## Impact Explanation

This vulnerability enables direct theft of vault funds through share manipulation.

**Execution Flow:**

1. The Navi adaptor's incorrect USD calculation feeds into the vault's total USD value aggregation. [7](#0-6) 

2. During deposit execution, shares are minted based on the ratio between deposited value and the pre-deposit share ratio. The share ratio is calculated as `total_usd_value / total_shares`. [8](#0-7) 

3. When the total USD value is artificially lowered by the Navi adaptor bug, the share ratio becomes artificially low, causing the vault to mint exponentially more shares than deserved.

**Attack Scenario:**

Consider a vault with:
- $900,000 in Navi USDC positions (calculated as $900 due to bug)
- $100,000 in SUI positions (calculated correctly)
- Total calculated: $100,900 instead of $1,000,000

When an attacker deposits $10,000:
- Expected shares: ~1% of total (based on true $1,000,000 value)
- Actual shares received: ~9.9% of total (based on buggy $100,900 value)
- After valuation correction or asset rebalancing, attacker withdraws with correct ratio
- **Theft: ~$89,000 stolen from existing shareholders**

**Severity Justification:**

- **Direct fund loss**: Immediate theft from existing vault shareholders
- **No mitigation**: No slippage protection can prevent this (the bug is in pre-calculation)
- **Common scenario**: USDC is the most prevalent stablecoin; Navi is a major Sui protocol
- **Scalable exploit**: Larger deposits = larger theft amounts

## Likelihood Explanation

This vulnerability has extremely high likelihood of exploitation:

**Reachable Entry Point:**

The exploit uses standard public vault operations accessible to any user - no special permissions required.

**Preconditions:**

1. Vault operates with Navi adaptor (standard configuration)
2. Navi positions contain non-9-decimal assets (USDC with 6 decimals is ubiquitous)
3. No operator intervention can prevent the exploit

**Economic Viability:**

- **Attack cost**: Only the deposit principal (fully recoverable with profit)
- **Expected return**: Up to 1000x profit multiplier for USDC-heavy positions
- **Risk**: Minimal - appears as normal deposit in transaction logs
- **Timing**: No race conditions or special timing required

**Practicality:**

An attacker simply:
1. Monitors on-chain vault state for favorable conditions (Navi holding USDC)
2. Submits standard deposit request
3. Waits for operator to execute deposit (standard flow)
4. Receives massively inflated shares due to miscalculated share ratio
5. Later withdraws at correct valuation, extracting profit from other users

**Real-World Context:**

- USDC is the dominant stablecoin on Sui ecosystem
- Navi Protocol is a widely-used lending platform
- Vault strategies naturally diversify into stable lending yields
- The bug is systematic (always active when conditions met), not requiring market manipulation or timing

## Recommendation

Replace `get_asset_price()` with `get_normalized_asset_price()` in the Navi adaptor:

```move
// In navi_adaptor.move, line 63:
// Change from:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// To:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This aligns the Navi adaptor with the correct implementation pattern used by Cetus and Momentum adaptors.

## Proof of Concept

```move
#[test]
fun test_navi_adaptor_decimal_mismatch_vulnerability() {
    let mut scenario = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup vault and oracle with USDC (6 decimals)
    init_vault::init_vault(&mut scenario, &mut clock);
    let mut oracle_config = scenario.take_shared<OracleConfig>();
    
    // Configure USDC with 6 decimals and price 1e18 (1 USD)
    let usdc_type = type_name::get<USDC_TEST_COIN>().into_string();
    oracle_config.set_aggregator(&clock, usdc_type, 6, @0x123);
    oracle_config.set_current_price(&clock, usdc_type, 1_000_000_000_000_000_000);
    
    // Get prices
    let raw_price = oracle_config.get_asset_price(&clock, usdc_type);
    let normalized_price = oracle_config.get_normalized_asset_price(&clock, usdc_type);
    
    // Demonstrate the bug: normalized should be 1000x raw for 6-decimal coins
    assert!(raw_price == 1_000_000_000_000_000_000, 0);
    assert!(normalized_price == 1_000_000_000_000_000_000_000, 1); // 1e21
    
    // Calculate USD value for 1,000,000 USDC (1e12 base units)
    let balance = 1_000_000_000_000_u256; // 1M USDC in base units
    
    // Correct calculation (what Cetus/Momentum do)
    let correct_usd = vault_utils::mul_with_oracle_price(balance, normalized_price);
    
    // Buggy calculation (what Navi does)
    let buggy_usd = vault_utils::mul_with_oracle_price(balance, raw_price);
    
    // Prove 1000x undervaluation
    assert!(correct_usd == 1_000_000_000_000_000, 2); // $1M in 1e9 decimals
    assert!(buggy_usd == 1_000_000_000_000, 3);       // $1K in 1e9 decimals
    assert!(correct_usd / buggy_usd == 1000, 4);      // 1000x discrepancy!
    
    test_scenario::return_shared(oracle_config);
    clock.destroy_for_testing();
    scenario.end();
}
```

## Notes

This vulnerability is particularly critical because:

1. **Confirmed by Protocol Tests**: The protocol's own test suite at lines 597-631 of `oracle.test.move` explicitly validates the normalization requirement, proving the design intent.

2. **Inconsistent Implementation**: Only the Navi adaptor has this bug - Cetus, Momentum, and Suilend adaptors all correctly use normalized prices, indicating this is an implementation oversight rather than a design decision.

3. **Immediate Exploitability**: Unlike vulnerabilities requiring specific market conditions or timing, this bug is always active whenever the vault holds Navi positions with non-9-decimal assets.

4. **No Effective Mitigation**: The `expected_shares` slippage protection in deposit execution cannot prevent this exploit because the miscalculation occurs in the share ratio calculation itself, not in the final minting step.

5. **Ecosystem Impact**: Given USDC's prevalence and Navi's popularity on Sui, this vulnerability poses a systemic risk to any vault utilizing Navi lending strategies.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
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

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
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

**File:** volo-vault/tests/oracle.test.move (L597-631)
```text
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
```

**File:** volo-vault/sources/volo_vault.move (L820-853)
```text
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

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;
```

**File:** volo-vault/sources/volo_vault.move (L1254-1278)
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
```
