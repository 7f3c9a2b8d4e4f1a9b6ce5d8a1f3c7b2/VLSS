# Audit Report

## Title
Decimal Conversion Error in Navi Adaptor Causes 1000x Undervaluation of Non-9-Decimal Assets and Loss Tolerance Bypass

## Summary
The Navi adaptor uses raw oracle prices without decimal normalization when calculating USD values for lending positions, causing assets with 6 decimals (USDC) to be undervalued by 1000x. This breaks vault accounting and enables operators to drain funds exceeding loss tolerance limits without triggering safeguards.

## Finding Description

The `calculate_navi_position_value` function in the Navi adaptor uses `get_asset_price()` to retrieve oracle prices and passes them directly to `mul_with_oracle_price()` for valuation calculations. [1](#0-0) 

This contrasts with the **correct pattern** used by all other adaptors (Cetus, Momentum, Receipt), which call `get_normalized_asset_price()` instead: [2](#0-1) [3](#0-2) [4](#0-3) 

**Root Cause:** The `get_normalized_asset_price()` function adjusts prices based on asset decimals stored in the oracle config. For assets with decimals < 9, it multiplies the price by 10^(9-decimals) to normalize to 9-decimal precision. [5](#0-4) 

The `mul_with_oracle_price()` utility divides by 1e18 (ORACLE_DECIMALS), expecting the price to already account for asset decimal differences. [6](#0-5) 

**Concrete Example - USDC (6 decimals):**
- Amount: 1,000,000 USDC = 1e12 units (1e6 USDC × 1e6 decimals)
- Raw oracle price: 1e18 (representing $1 with 18 decimals)
- **Without normalization (Navi):** 1e12 × 1e18 / 1e18 = **1e12** (≈$1,000 in 9-decimal format)
- **With normalization (correct):** 1e12 × (1e18 × 1000) / 1e18 = **1e15** (≈$1,000,000 in 9-decimal format)
- **Undervaluation factor: 1000x**

**Exploit Execution Path:**
1. Vault holds $1M USDC in Navi lending positions + $100K SUI
2. Reported total value: $1K (USDC undervalued) + $100K = **$101K** (actual: $1.1M)
3. Loss tolerance: 0.1% of $101K = **$101**
4. Operator starts operation and borrows NaviAccountCap [7](#0-6) 
5. Operator withdraws $10,000 USDC from Navi and keeps it
6. Operator returns cap and calls `update_navi_position_value`, which calculates new undervalued position
7. Value update triggers loss check: reported loss ≈ $10 (still undervalued) < $101 tolerance → **PASSES** [8](#0-7) 
8. Actual loss is $10,000 but loss tolerance enforcement fails [9](#0-8) 

The vault aggregates all asset values to calculate total USD value and share ratios. [10](#0-9)  Undervalued Navi positions corrupt these calculations, breaking fundamental vault invariants.

## Impact Explanation

**CRITICAL - Direct Fund Theft via Loss Tolerance Bypass**

The loss tolerance mechanism is designed to prevent operators from causing excessive losses during operations. However, with Navi positions severely undervalued:

1. **Baseline understatement:** When loss tolerance resets, `cur_epoch_loss_base_usd_value` is set from the undervalued total, creating an artificially LOW baseline. [11](#0-10) 

2. **Loss calculation bypass:** Operators can drain actual funds (correctly valued assets or DeFi positions) while the reported loss remains within the understated tolerance limit.

3. **Quantified impact:** For a vault with $1M USDC in Navi (reported as $1K):
   - Loss tolerance at 0.1% allows $101 reported loss
   - Operator can drain $100,000+ in actual value while staying under the false limit
   - Protocol's primary operator safeguard is completely bypassed

4. **Multi-asset attack vector:** Attacker deposits correctly-valued 9-decimal assets, operator uses them as collateral to borrow undervalued 6-decimal assets via Navi, then drains the correctly-valued assets while the vault appears healthy.

## Likelihood Explanation

**HIGH - Automatically Triggered in Normal Operations**

1. **No special permissions:** Any vault configured to use Navi lending with USDC, USDT, or other non-9-decimal stablecoins triggers the bug. Operator role is trusted but scoped - this vulnerability enables loss tolerance bypass which violates their authorization scope.

2. **Standard DeFi configuration:** USDC has 6 decimals on most chains and is a primary stablecoin for lending protocols. The test infrastructure already configures USDC with 6 decimals, confirming this is an expected use case. [12](#0-11) 

3. **Public entry point:** `update_navi_position_value` is called during normal vault operation flows, not requiring any special access beyond standard operator capabilities. [13](#0-12) 

4. **No protective validation:** The vault trusts adaptor calculations without verifying decimal normalization. Once values are stored in `assets_value`, they're used directly in all downstream calculations.

5. **Realistic economic incentive:** With default 0.1% loss tolerance, an operator could extract hundreds of thousands of dollars from a multi-million dollar vault before detection.

## Recommendation

Change the Navi adaptor to use `get_normalized_asset_price()` instead of `get_asset_price()`, matching the pattern used by all other adaptors:

**In `volo-vault/sources/adaptors/navi_adaptor.move`, line 63, replace:**
```move
let price = vault_oracle::get_asset_price(config, clock, coin_type);
```

**With:**
```move
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This single-line change ensures all assets are valued consistently regardless of their native decimal precision, maintaining vault accounting invariants and proper loss tolerance enforcement.

## Proof of Concept

```move
#[test]
fun test_navi_decimal_undervaluation() {
    use sui::test_scenario;
    use sui::clock;
    use volo_vault::navi_adaptor;
    use volo_vault::vault_oracle::{Self, OracleConfig};
    use volo_vault::vault_utils;
    
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    let mut clock = clock::create_for_testing(scenario.ctx());
    
    // Setup oracle with USDC at 6 decimals
    vault_oracle::init_for_testing(scenario.ctx());
    scenario.next_tx(owner);
    let mut config = scenario.take_shared<OracleConfig>();
    
    vault_oracle::set_aggregator(
        &mut config,
        &clock,
        std::ascii::string(b"USDC"),
        6, // 6 decimals like real USDC
        @0xDEAD
    );
    
    // Set USDC price to $1 (1e18 in oracle format)
    vault_oracle::set_current_price(
        &mut config,
        &clock,
        std::ascii::string(b"USDC"),
        1_000_000_000_000_000_000 // $1 with 18 decimals
    );
    
    // Calculate value of 1,000,000 USDC (1e12 units)
    let usdc_amount: u256 = 1_000_000_000_000; // 1M USDC with 6 decimals
    
    // Using get_asset_price (VULNERABLE - what Navi does)
    let raw_price = vault_oracle::get_asset_price(&config, &clock, std::ascii::string(b"USDC"));
    let wrong_value = vault_utils::mul_with_oracle_price(usdc_amount, raw_price);
    
    // Using get_normalized_asset_price (CORRECT - what other adaptors do)
    let normalized_price = vault_oracle::get_normalized_asset_price(&config, &clock, std::ascii::string(b"USDC"));
    let correct_value = vault_utils::mul_with_oracle_price(usdc_amount, normalized_price);
    
    // Demonstrate 1000x undervaluation
    assert!(wrong_value == 1_000_000_000_000, 0); // $1K (wrong)
    assert!(correct_value == 1_000_000_000_000_000, 1); // $1M (correct)
    assert!(correct_value / wrong_value == 1000, 2); // 1000x factor
    
    test_scenario::return_shared(config);
    clock::destroy_for_testing(clock);
    scenario.end();
}
```

This test demonstrates that the Navi adaptor's approach produces a valuation 1000x lower than the correct approach for 6-decimal USDC, directly proving the vulnerability and its exploitation potential for loss tolerance bypass.

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

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L59-69)
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

**File:** volo-vault/sources/volo_vault.move (L608-624)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
}
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

**File:** volo-vault/sources/volo_vault.move (L1154-1167)
```text
}

public fun validate_total_usd_value_updated<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
) {
    self.check_version();

    let now = clock.timestamp_ms();

    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = self.assets_value_updated[*asset_type];
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
    });
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

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/tests/test_helpers.move (L34-40)
```text
        vault_oracle::set_aggregator(
            config,
            clock,
            usdc_asset_type,
            6,
            MOCK_AGGREGATOR_USDC,
        );
```
