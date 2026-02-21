# Audit Report

## Title
Pyth Oracle Failure Causes Complete Vault DoS Due to Missing Fallback Implementation in Suilend Integration

## Summary
The Suilend oracle module's `get_pyth_price_and_identifier()` function is designed to return `None` for invalid Pyth prices to allow graceful fallback handling. However, the actual callers immediately abort on `None`, creating a cascading failure that blocks all Volo vault operations when any Suilend-integrated asset experiences Pyth oracle issues (confidence intervals >10% or staleness >60 seconds).

## Finding Description

The vulnerability stems from a critical mismatch between documented design intent and actual implementation:

**Root Cause - Broken Design Promise:**

The `get_pyth_price_and_identifier()` function explicitly documents that it "returns None instead of aborting so the caller can handle invalid prices gracefully by eg falling back to a different oracle." [1](#0-0) 

The function returns `None` when confidence checks fail [2](#0-1)  or staleness checks fail [3](#0-2) . The code even acknowledges "timestamps... may get out of sync, but that's why we have a fallback oracle."

**Critical Implementation Flaw:**

Despite this documented design, both `create_reserve()` [4](#0-3)  and `update_price()` [5](#0-4)  immediately abort with `EInvalidPrice` when receiving `None`, completely contradicting the stated graceful handling design.

**Cascading Failure Chain:**

1. The public entry point `refresh_reserve_price()` calls the aborting `update_price()` function [6](#0-5) 

2. The Suilend adaptor's `parse_suilend_obligation()` requires fresh prices via `assert_price_is_fresh()` [7](#0-6) [8](#0-7) 

3. Price freshness requires same-transaction updates since `PRICE_STALENESS_THRESHOLD_S = 0` [9](#0-8) [10](#0-9) 

4. The vault's `get_total_usd_value()` requires all assets updated within `MAX_UPDATE_INTERVAL = 0` [11](#0-10) [12](#0-11) 

5. All critical vault operations depend on `get_total_usd_value()`:
   - `start_op_with_bag()` [13](#0-12) 
   - `end_op_value_update_with_bag()` [14](#0-13) 
   - `execute_deposit()` [15](#0-14) 
   - `execute_withdraw()` via `get_share_ratio()` [16](#0-15) [17](#0-16) 

## Impact Explanation

**Complete Operational Freeze:**

When Pyth oracle returns invalid prices for ANY Suilend reserve used by the vault, ALL vault operations become permanently blocked until the oracle recovers. This affects:
- All deposit executions requiring updated total USD values
- All withdrawal executions requiring share ratio calculations
- All vault operations requiring value updates before and after execution
- All users with pending requests who cannot complete their transactions

**High Severity Assessment:**

1. **No Attacker Required**: Natural oracle degradation triggers complete DoS
2. **Realistic Triggering**: Pyth confidence intervals commonly exceed 10% (MIN_CONFIDENCE_RATIO = 10) during market volatility; 60-second staleness occurs during network congestion
3. **Total Impact**: ALL vault operations blocked, not just specific functions
4. **No Recovery Mechanism**: No emergency override, manual price setting, or alternative oracle path exists
5. **Broken Promise**: Code comments explicitly state fallback handling should exist but it doesn't

## Likelihood Explanation

**HIGH Likelihood:**

**Realistic Triggering Conditions:**
- Confidence interval > 10% of price: Common during flash crashes, major news events, or low liquidity periods
- Staleness > 60 seconds: Occurs during network congestion, validator issues, or Pyth feed delays
- Clock timestamp desynchronization between Sui and Pyth networks

**No Workarounds:**
- Same-transaction price update mandated by `PRICE_STALENESS_THRESHOLD_S = 0` and `MAX_UPDATE_INTERVAL = 0`
- No alternative oracle source implemented despite code comments suggesting one should exist
- No emergency admin function to bypass price checks
- No manual price override capability

**Historical Precedent:**
Oracle failures are well-documented across DeFi protocols during extreme volatility (March 2020, May 2021, November 2022). The 60-second staleness threshold and 10% confidence requirement make this triggering scenario highly realistic.

## Recommendation

Implement the promised fallback oracle mechanism:

1. **Add Secondary Oracle**: Integrate a secondary oracle (e.g., Switchboard, Pyth EMA, or manual admin override) that can be used when primary Pyth feed fails validation

2. **Graceful Degradation in Callers**: Modify `create_reserve()` and `update_price()` to handle `None` gracefully by attempting fallback oracle, rather than immediately aborting

3. **Emergency Price Override**: Add admin-controlled emergency price setting function for critical situations

4. **Relaxed Staleness During Degradation**: Consider allowing slightly stale prices (e.g., 5 minutes) during oracle degradation with appropriate risk warnings

## Proof of Concept

```move
// Triggering scenario:
// 1. Deploy vault with Suilend obligation asset
// 2. Wait for Pyth oracle to have >10% confidence interval or >60s staleness
//    (naturally occurs during market volatility or network congestion)
// 3. Attempt to execute any vault operation:
//    - execute_deposit() 
//    - execute_withdraw()
//    - start_op_with_bag()
//    - end_op_value_update_with_bag()
// 
// Result: Transaction aborts at refresh_reserve_price() with EInvalidPrice
// All vault operations blocked until Pyth oracle recovers
```

**Notes:**
This vulnerability is particularly severe because:
- The code explicitly promises graceful fallback handling that was never implemented
- Zero staleness thresholds make same-transaction updates mandatory
- No emergency recovery mechanism exists
- Natural oracle degradation (not attack) triggers complete protocol DoS

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-18)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
    /// return type: (spot price, ema price, price identifier)
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L36-38)
```text
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L43-48)
```text
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L167-168)
```text
        let (mut price_decimal, smoothed_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L242-246)
```text
    public(package) fun is_price_fresh<P>(reserve: &Reserve<P>, clock: &Clock): bool {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;

        cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-588)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-210)
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
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L68-68)
```text
        borrow_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L820-820)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1006)
```text
    let ratio = self.get_share_ratio(clock);
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

**File:** volo-vault/sources/volo_vault.move (L1308-1308)
```text
    let total_usd_value = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```
