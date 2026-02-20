# Audit Report

## Title
Stale Pyth Prices Can Be Used to Manipulate Vault Share Ratios Through Suilend Position Mispricing

## Summary
The Suilend adaptor's price freshness validation contains a critical flaw where the 60-second Pyth oracle staleness window is incompatible with the reserve's 0-second freshness check. An attacker can exploit this by refreshing stale Pyth prices into reserves and immediately updating the vault's Suilend position value, causing share ratio manipulation that enables value extraction from other vault users.

## Finding Description

The vulnerability stems from a two-layer staleness validation system with mismatched thresholds that creates a time-based oracle manipulation vector.

**Layer 1 - Pyth Oracle (60-second tolerance):**

The Suilend oracle accepts Pyth price data that is up to 60 seconds old via the `MAX_STALENESS_SECONDS` constant. [1](#0-0) 

The staleness validation in `get_pyth_price_and_identifier()` compares the current Sui timestamp against the Pyth price's embedded timestamp with this 60-second threshold. [2](#0-1) 

**Layer 2 - Reserve Cache (0-second tolerance):**

The Suilend reserve enforces a 0-second staleness threshold via `PRICE_STALENESS_THRESHOLD_S`. [3](#0-2) 

The freshness check in `is_price_fresh()` validates when the reserve cache was last updated, not the age of the underlying Pyth data. [4](#0-3) 

**The Critical Disconnect:**

When `parse_suilend_obligation()` calculates position values, it validates price freshness using `assert_price_is_fresh()` on both deposits and borrows. [5](#0-4) [6](#0-5) 

However, this only checks the reserve's cache timestamp, not the underlying Pyth data age.

**Public Attack Surface:**

Both critical functions are public and callable by anyone:
- `refresh_reserve_price()` caches Pyth prices into reserves [7](#0-6) 
- `update_suilend_position_value()` updates the vault's USD valuation [8](#0-7) 

**Root Cause:**

When `update_price()` is called, it sets `price_last_update_timestamp_s` to the current time regardless of the actual Pyth data age. [9](#0-8) 

This allows stale Pyth data (up to 60 seconds old) to pass the 0-second freshness check immediately after caching.

**Attack Flow:**
1. Attacker identifies stale Pyth price data on-chain (e.g., 50 seconds old) during market volatility
2. Calls `refresh_reserve_price()` to cache the stale price (sets timestamp to NOW)
3. Immediately calls `update_suilend_position_value()` in the same transaction
4. The freshness check passes because the reserve was "just updated"
5. Suilend position is mispriced using 50-second-old data
6. Vault's `total_usd_value` is corrupted via `finish_update_asset_value()` [10](#0-9) 
7. Share ratio calculation uses the corrupted total value [11](#0-10) 
8. Attacker extracts value through withdrawal at inflated share ratio [12](#0-11) 

## Impact Explanation

**Direct Fund Theft:**

The mispriced Suilend position directly corrupts the vault's total USD value calculation, which aggregates all asset values to compute the share ratio. [13](#0-12) 

This corrupted share ratio is then used in withdrawal operations, enabling value extraction. [14](#0-13) 

**Concrete Attack Scenario:**
- Vault holds $1M total value with 1M shares (ratio = $1.00/share)
- Vault has $100K Suilend position with SUI collateral
- Market crash: SUI drops from $2.00 to $1.60 in 30 seconds (20% drop)
- Pyth price on-chain is 50 seconds old, showing $2.00 (within 60-second limit)
- Attacker refreshes stale price then updates vault's Suilend position value
- Position valued at $100K instead of actual $80K (overvalued by $20K)
- Vault's total_usd_value becomes $1,020,000 instead of actual $1,000,000
- Share ratio inflated to $1.02/share
- Attacker with 100K shares withdraws and receives $102,000 worth instead of $100,000
- **Net theft: $2,000 from remaining vault users**

The magnitude scales with vault size, position size, and price movement percentage. During flash crashes (10-20% moves in under 60 seconds), the potential loss becomes substantial.

**Affected Parties:**
- Remaining vault shareholders suffer dilution from overvalued withdrawals
- New depositors receive fewer shares when positions are undervalued
- Protocol integrity is compromised as the fundamental share accounting becomes unreliable

## Likelihood Explanation

**Highly Feasible Attack:**

1. **Reachable Entry Points:** Both `refresh_reserve_price()` and `update_suilend_position_value()` are public functions with no access control restrictions.

2. **Realistic Preconditions:**
   - Crypto market volatility is extremely common (flash crashes, breaking news, liquidation cascades)
   - Pyth prices naturally lag behind spot prices during periods of high volatility
   - Network congestion can delay Pyth updates, making stale prices more common
   - The 60-second window is substantial in crypto markets where prices can move 10-20% in under a minute

3. **Execution Simplicity:**
   - Single transaction with two function calls
   - No complex timing requirements beyond same-second execution
   - No special privileges or vault positions needed
   - Any address can execute the attack

4. **Economic Rationality:**
   - Attack cost is minimal (only gas fees)
   - Profit is deterministic when conditions align (market moving faster than Pyth updates)
   - Attacker can monitor price feeds off-chain to identify favorable windows
   - Risk is extremely low as attacker can abort transaction if conditions change before submission

5. **Detection/Prevention Difficulty:**
   - Legitimate price updates are indistinguishable from malicious ones on-chain
   - No on-chain signals differentiate attack transactions from normal operations
   - Slippage protection mechanisms cannot prevent this as the vault's internal state is already corrupted before user interactions

**Probability Assessment:**
Crypto markets frequently experience 5-10% price moves within 60-second windows during volatile periods. Given that Pyth updates can lag during network congestion and high volatility, the conditions for exploitation occur regularly - potentially multiple times per week during volatile market conditions.

## Recommendation

**Immediate Fix:**

The `update_price()` function should validate that the Pyth price data itself is fresh, not just accept any data within the 60-second window. The reserve's `price_last_update_timestamp_s` should reflect the actual Pyth data timestamp, not the cache update time:

```move
public(package) fun update_price<P>(
    reserve: &mut Reserve<P>, 
    clock: &Clock,
    price_info_obj: &PriceInfoObject
) {
    let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
    assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
    assert!(option::is_some(&price_decimal), EInvalidPrice);

    reserve.price = option::extract(&mut price_decimal);
    reserve.smoothed_price = ema_price_decimal;
    
    // FIX: Use the Pyth data's actual timestamp, not the current time
    let price_info = price_info::get_price_info_from_price_info_object(price_info_obj);
    let price_feed = price_info::get_price_feed(&price_info);
    let price = price_feed::get_price(price_feed);
    reserve.price_last_update_timestamp_s = price::get_timestamp(&price);
}
```

**Alternative Fix:**

Reduce the `MAX_STALENESS_SECONDS` to match the reserve's `PRICE_STALENESS_THRESHOLD_S` of 0, ensuring both layers enforce the same freshness requirement.

## Proof of Concept

A complete proof of concept would require:
1. Deploy a test vault with a Suilend position
2. Deploy a mock Pyth price feed with controllable timestamps
3. Submit a Pyth price update with a 50-second-old timestamp (within 60-second limit)
4. Call `refresh_reserve_price()` to cache the stale price
5. Immediately call `update_suilend_position_value()` in the same transaction
6. Observe that the freshness check passes despite using 50-second-old data
7. Call `get_share_ratio()` and observe the corrupted ratio
8. Execute a withdrawal and observe excess value extraction

The test would demonstrate that the two-layer staleness validation with mismatched thresholds allows stale prices to corrupt the vault's share ratio accounting.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L42-48)
```text
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L242-246)
```text
    public(package) fun is_price_fresh<P>(reserve: &Reserve<P>, clock: &Clock): bool {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;

        cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-593)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
        reserve.price_last_update_timestamp_s = clock::timestamp_ms(clock) / 1000;
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L68-68)
```text
        borrow_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-211)
```text
    public fun refresh_reserve_price<P>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
        price_info: &PriceInfoObject,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        reserve::update_price<P>(reserve, clock, price_info);
    }
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

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
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
