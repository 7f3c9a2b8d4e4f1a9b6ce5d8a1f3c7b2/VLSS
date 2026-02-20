# Audit Report

## Title
Missing Zero-Denominator Validation in Vault Division Operations Causing Temporary Denial of Service

## Summary
The Volo vault's mathematical utility functions `div_d()` and `div_with_oracle_price()` lack zero-denominator validation, unlike the protocol's `safe_math` and `ray_math` modules. When share ratios reach zero (due to zero vault valuation with existing shares) or oracle prices return zero (due to oracle failures), deposit and withdrawal execution operations abort with arithmetic errors, temporarily blocking these operations until conditions normalize.

## Finding Description

The `vault_utils` module defines division functions without zero-denominator validation: [1](#0-0) [2](#0-1) 

This contrasts with the protocol's defensive math libraries that enforce zero checks: [3](#0-2) [4](#0-3) 

**Exploit Path 1 - Deposit DoS via Zero Share Ratio:**

When `get_share_ratio()` calculates the share ratio, it can return zero if `total_usd_value == 0` while `total_shares > 0`: [5](#0-4) 

The `execute_deposit()` function then uses this share ratio as a denominator: [6](#0-5) 

When `share_ratio_before == 0`, the division `div_d(new_usd_value_deposited, 0)` causes an arithmetic abort.

**Exploit Path 2 - Withdraw DoS via Zero Oracle Price:**

The `execute_withdraw()` function divides by the oracle price: [7](#0-6) 

The oracle validation only checks timestamp freshness, not zero values: [8](#0-7) [9](#0-8) 

When oracle price is zero, `div_with_oracle_price(usd_value, 0)` causes an arithmetic abort.

## Impact Explanation

**Temporary Denial of Service on Core Vault Operations:**

- **Deposit DoS**: When share_ratio becomes zero, deposit execution fails. Users' principal remains in `deposit_coin_buffer` but can be retrieved via cancellation after the `locking_time_for_cancel_request` timeout elapses.

- **Withdrawal DoS**: When oracle price is zero, withdrawal execution fails. Users' shares remain in pending withdraw requests but can be cancelled after the timeout period.

Both scenarios temporarily block legitimate user operations until either: (1) oracle prices recover to non-zero values, or (2) users cancel their requests after the locking timeout. This is a **temporary availability disruption**, not permanent fund loss, as recovery mechanisms exist through request cancellation and oracle price restoration.

## Likelihood Explanation

**Medium Likelihood - Requires Specific Conditions:**

1. **Zero Share Ratio Path**: Requires all vault assets to simultaneously report zero prices while `total_shares > 0`. This can occur during:
   - Multi-asset oracle infrastructure failures
   - Extreme market events causing multiple assets to become near-worthless
   - Oracle feed delistings for deprecated assets

2. **Zero Oracle Price Path**: Requires the principal coin's oracle to return zero, which can happen due to:
   - Switchboard aggregator failures
   - Delisted or deprecated asset feeds
   - Oracle infrastructure issues

While these conditions are realistic and don't require attacker intervention or key compromise, they represent edge cases rather than common scenarios. The oracle system includes freshness checks but explicitly allows zero prices, as evidenced by test utilities that set prices to zero without validation. [10](#0-9) 

## Recommendation

Add zero-denominator validation to the division functions in `vault_utils`:

```move
// div with decimals
public fun div_d(v1: u256, v2: u256): u256 {
    assert!(v2 != 0, ERR_DIVISION_BY_ZERO);
    v1 * DECIMALS / v2
}

// Asset Balance = Asset USD Value / Oracle Price
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    assert!(v2 != 0, ERR_DIVISION_BY_ZERO);
    v1 * ORACLE_DECIMALS / v2
}
```

Additionally, consider adding oracle price validation to reject zero prices:

```move
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    // ... existing checks ...
    let price = price_info.price;
    assert!(price > 0, ERR_INVALID_ORACLE_PRICE);
    price
}
```

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = /* arithmetic error code */)]
public fun test_deposit_dos_via_zero_share_ratio() {
    // 1. Initialize vault and create initial deposit (creates shares)
    // 2. Set all oracle prices to 0 → total_usd_value becomes 0
    // 3. Request new deposit
    // 4. Execute deposit → aborts with div_d(value, 0)
    // Expected: Arithmetic error due to division by zero share ratio
}

#[test]
#[expected_failure(abort_code = /* arithmetic error code */)]
public fun test_withdraw_dos_via_zero_oracle_price() {
    // 1. Initialize vault and create deposit
    // 2. Request withdrawal
    // 3. Set principal coin oracle price to 0
    // 4. Execute withdrawal → aborts with div_with_oracle_price(value, 0)
    // Expected: Arithmetic error due to division by zero oracle price
}
```

## Notes

This vulnerability represents a defensive programming gap where critical division operations lack the same zero-validation that exists in the protocol's general-purpose math libraries. While the impact is mitigated by request cancellation mechanisms and oracle recovery paths, adding explicit zero checks provides defense-in-depth and clearer error messaging for these edge cases.

### Citations

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/utils.move (L74-76)
```text
public fun div_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * ORACLE_DECIMALS / v2
}
```

**File:** volo-vault/local_dependencies/protocol/math/sources/safe_math.move (L37-41)
```text
    public fun div(a: u256, b: u256): u256 {
         assert!(b > 0, SAFE_MATH_DIVISION_BY_ZERO);
         let c = a / b;
         return c
    }
```

**File:** volo-vault/local_dependencies/protocol/math/sources/ray_math.move (L85-92)
```text
    public fun ray_div(a: u256, b: u256): u256 {
        assert!(b != 0, RAY_MATH_DIVISION_BY_ZERO);
        let halfB = b / 2;

        assert!(a <= (address::max() - halfB) / RAY, RAY_MATH_MULTIPLICATION_OVERFLOW);

        (a * RAY + halfB) / b
    }
```

**File:** volo-vault/sources/volo_vault.move (L821-844)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1006-1022)
```text
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1304-1309)
```text
    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
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

**File:** volo-vault/sources/oracle.move (L304-312)
```text
    let price_info = PriceInfo {
        aggregator: aggregator,
        decimals,
        price: 0,
        last_updated: clock.timestamp_ms(),
    };

    config.aggregators.add(asset_type, price_info);
}
```
