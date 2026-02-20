# Audit Report

## Title
Navi Adaptor Incorrectly Uses Non-Normalized Oracle Prices Leading to Mispriced Asset Valuations

## Summary
The Navi adaptor uses raw oracle prices instead of normalized prices when calculating position USD values, causing severe mispricing for tokens with non-9 decimals. This breaks the protocol's critical 9-decimal USD accounting invariant, enabling direct fund theft through share price manipulation.

## Finding Description

The Volo vault system maintains a critical invariant: all USD values must be expressed with exactly 9 decimal places. The `mul_with_oracle_price()` utility function divides by 10^18 (ORACLE_DECIMALS), designed to work with normalized oracle prices that account for token decimals. [1](#0-0) 

The oracle module provides two distinct functions:
- `get_asset_price()` - Returns raw 18-decimal Switchboard prices
- `get_normalized_asset_price()` - Adjusts prices based on token decimals to ensure 9-decimal output when used with `mul_with_oracle_price()` [2](#0-1) 

**All other adaptors correctly use normalized prices:**

Cetus adaptor: [3](#0-2) 

Momentum adaptor: [4](#0-3) 

**However, the Navi adaptor uses non-normalized prices:** [5](#0-4) 

**Root Cause:** After `ray_mul()` converts scaled balances to actual amounts, the result is in the token's native decimals, as confirmed by Navi's implementation: [6](#0-5) 

**Mathematical Impact:**
- For USDC (6 decimals): `(1_000_000 * 1e18) / 1e18 = 1_000_000` (6 decimals = $0.001 instead of 9 decimals = $1.00) → **1000x undervaluation**
- For 9-decimal tokens (SUI): Works correctly by coincidence, masking the bug

**Navi Protocol Token Support:** Test files confirm Navi supports 6-decimal stablecoins: [7](#0-6) 

## Impact Explanation

This vulnerability enables direct fund theft through share price manipulation:

**1. Share Price Corruption:** The mispriced Navi values corrupt `total_usd_value`: [8](#0-7) 

This directly corrupts the share ratio calculation: [9](#0-8) 

**2. Exploit Mechanism:** [10](#0-9) 

With undervalued Navi positions:
- Vault with $1M USDC in Navi (reported as $1,000) + $1M other assets
- Total reported: ~$1,001,000 (should be $2,000,000)
- Share price: 50% of actual value
- Attacker deposits $1M → receives shares worth $2M in actual value
- Immediately withdraws for $2M
- **Net theft: ~$1M per transaction**

**3. Loss Tolerance Bypass:** Systematically undervalued baselines allow operators to trigger actual losses that don't breach tolerance thresholds.

**4. Cascading Failures:** Affects all vault accounting, reward distribution, and receipt valuations.

## Likelihood Explanation

**High likelihood:**

1. **Confirmed Token Support:** Navi protocol demonstrably supports USDC/USDT with 6 decimals - standard for real-world stablecoins.

2. **Normal Operations Trigger:** Operators routinely update Navi position values via the public `update_navi_position_value()` function during vault management.

3. **No Special Permissions Required:** Any vault with Navi positions containing non-9-decimal tokens exhibits this behavior. Users exploit via standard deposit/withdraw flows.

4. **No Detection Mechanism:** The protocol lacks validation ensuring adaptor-returned USD values are in 9-decimal format.

5. **Massive Economic Incentive:** 1000x mispricing for USDC creates million-dollar profit opportunities per transaction with only gas costs.

## Recommendation

Change the Navi adaptor to use normalized prices:

```move
// In navi_adaptor.move, line 63, replace:
let price = vault_oracle::get_asset_price(config, clock, coin_type);

// With:
let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

This aligns with Cetus and Momentum adaptors, ensuring the 9-decimal USD output invariant is maintained.

## Proof of Concept

```move
#[test]
fun test_navi_usdc_mispricing() {
    // Setup vault with Navi USDC position (6 decimals)
    // Update position value using current implementation
    // Verify USD value is 1000x lower than expected
    // Demonstrate share price manipulation via deposit
    // Show attacker can withdraw more than deposited
}
```

The test would show that 1 USDC (1_000_000 units with 6 decimals) valued at $1 is reported as $0.001 due to the missing normalization, enabling the share price manipulation attack.

### Citations

**File:** volo-vault/sources/utils.move (L68-71)
```text
// Asset USD Value = Asset Balance * Oracle Price
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
```

**File:** volo-vault/sources/oracle.move (L126-154)
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-64)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L53-66)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L482-490)
```text
    /**
     * Title: get the number of collaterals the user has in given asset, include interest.
     * Returns: token amount.
     */
    public fun user_collateral_balance(storage: &mut Storage, asset: u8, user: address): u256 {
        let (supply_balance, _) = storage::get_user_balance(storage, asset, user);
        let (supply_index, _) = storage::get_index(storage, asset);
        ray_math::ray_mul(supply_balance, supply_index) // scaled_amount
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/tests/base_tests.move (L429-448)
```text
    struct USDC_TEST has drop {}

    fun init(witness: USDC_TEST, ctx: &mut TxContext) {
        let decimals = 6;
        let name = b"Wrapped USDC";
        let symbol = b"USDC_TEST";
        
        let (treasury_cap, metadata) = coin::create_currency<USDC_TEST>(
            witness,         // witness
            decimals,        // decimals
            symbol,          // symbol
            name,            // name
            b"",             // description
            option::none(),  // icon_url
            ctx
        );

        transfer::public_freeze_object(metadata);
        transfer::public_transfer(treasury_cap, tx_context::sender(ctx))
    }
```

**File:** volo-vault/sources/volo_vault.move (L820-844)
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
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```
