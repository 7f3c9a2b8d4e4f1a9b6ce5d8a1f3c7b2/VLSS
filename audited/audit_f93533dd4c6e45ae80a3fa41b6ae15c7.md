### Title
No Protocol-Controlled Oracle Staleness Checks for Suilend Position Valuation

### Summary
The Volo vault system lacks protocol-controlled oracle staleness checks when valuing Suilend lending positions. It relies entirely on Suilend's hardcoded 0-second staleness threshold, preventing Volo from configuring acceptable price age limits or implementing fallback mechanisms. This creates a denial-of-service vulnerability where vault operations involving Suilend positions can fail due to timing issues, leaving funds locked in operational status.

### Finding Description
The vulnerability exists in Volo's Suilend adaptor integration. When updating Suilend position values during vault operations, Volo calls Suilend's `assert_price_is_fresh()` function which enforces a hardcoded 0-second staleness threshold that Volo cannot configure or override. [1](#0-0) 

The adaptor's `parse_suilend_obligation()` function calls `assert_price_is_fresh()` on each reserve (lines 56, 68), which internally checks against Suilend's hardcoded threshold: [2](#0-1) [3](#0-2) 

The staleness check `cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S` with threshold=0 requires prices to be updated within the exact same second. Volo has no ability to configure this parameter or implement fallback logic.

The exploit path follows the vault operation lifecycle: [4](#0-3) 

As documented, operators must call `lending_market::refresh_reserve_price()` separately before `update_suilend_position_value()`. If these calls occur in different seconds due to network delays, block time variations, or separate transactions, the staleness check fails and aborts the transaction with `EPriceStale` error, preventing completion of the vault operation. [5](#0-4) 

Unlike Volo's own oracle system which has configurable staleness: [6](#0-5) [7](#0-6) 

The Suilend integration completely delegates staleness control to the external dependency without protocol-level checks or fallback mechanisms.

### Impact Explanation
**Severity: Medium-High**

1. **Denial of Service**: Vault operations involving Suilend positions can fail consistently if timing requirements cannot be met, preventing operators from completing legitimate operations
2. **Funds Locked**: During failed operations, the vault remains in "operation status", potentially blocking other vault activities until resolved
3. **No Protocol Control**: Volo governance cannot adjust staleness thresholds based on market volatility, network conditions, or risk parameters
4. **No Fallback**: When Suilend's check fails, there is no alternative oracle or graceful degradation path - the transaction simply aborts
5. **Operational Fragility**: The 0-second threshold is extremely strict, requiring perfect timing coordination that may be impossible to guarantee in production

### Likelihood Explanation
**Likelihood: Medium-High**

1. **Realistic Trigger**: Operators performing normal vault operations with Suilend positions must coordinate multiple on-chain calls with precise timing
2. **Network Variability**: Block time variations, transaction ordering, and network congestion can easily cause >1 second delays between price refresh and usage
3. **Multi-Transaction Flow**: The documented pattern requires separate calls to `refresh_reserve_price` and `update_suilend_position_value`, increasing likelihood of timing issues
4. **No Attacker Required**: This vulnerability can trigger naturally during legitimate operations without malicious intent
5. **Production Reality**: In live environments with multiple operators, concurrent transactions, and varying network conditions, the strict 0-second requirement becomes a significant operational risk

### Recommendation
Implement protocol-controlled staleness checks for Suilend position valuation:

1. **Add configurable staleness threshold**: Create a `suilend_price_staleness_threshold` parameter in `OracleConfig` that Volo governance can adjust
2. **Pre-validation check**: Before calling `parse_suilend_obligation()`, verify that reserve prices were updated within Volo's acceptable threshold
3. **Fallback mechanism**: If Suilend price freshness check fails, implement graceful handling such as:
   - Attempting to refresh the price atomically within the same transaction
   - Using Volo's own oracle prices as a fallback validation
   - Providing clear error messages to operators about required price refresh timing
4. **Atomic operation wrapper**: Consider creating a wrapper function that atomically calls `refresh_reserve_price()` followed by `update_suilend_position_value()` within the same transaction to guarantee timing requirements are met
5. **Documentation**: Clearly document timing requirements and provide operator tooling to ensure price freshness before attempting position updates

### Proof of Concept

**Setup:**
1. Vault has an active Suilend lending position (ObligationOwnerCap stored as defi asset)
2. Operator initiates vault operation borrowing the Suilend position

**Exploit Steps:**
1. At time T (second S), operator calls `lending_market::refresh_reserve_price()` for all reserves used by the Suilend obligation
2. Suilend updates `reserve.price_last_update_timestamp_s = S`
3. Due to network delay or transaction in next block, operator calls `update_suilend_position_value()` at time T+1 (second S+1)
4. Inside `parse_suilend_obligation()`, Suilend calls `assert_price_is_fresh(clock)` for each reserve
5. Check calculates: `(S+1) - S = 1 > 0 (PRICE_STALENESS_THRESHOLD_S)`
6. Suilend aborts with `EPriceStale` error (error code 0)
7. Vault operation fails to complete, vault remains in "operation status"
8. Operator cannot complete the operation without perfectly timing both calls within the same second

**Expected Result:** Transaction aborts, vault operation incomplete, funds remain locked in operational state

**Root Cause:** Volo has no control over Suilend's hardcoded 0-second staleness threshold and no fallback mechanism when the external check fails

### Notes
This vulnerability is distinct from Volo's own Switchboard oracle integration, which correctly implements protocol-controlled staleness checks with configurable `update_interval` parameters. The issue specifically affects the Suilend adaptor path where Volo delegates staleness validation entirely to an external dependency with no ability to configure thresholds or implement fallback logic, exactly mirroring the vulnerability class described in the external report.

### Citations

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L12-19)
```text
// @dev Need to update the price of the reserve before calling this function
//      Update function: lending_market::refresh_reserve_price
//          public fun refresh_reserve_price<P>(
//              lending_market: &mut LendingMarket<P>,
//              reserve_array_index: u64,
//              clock: &Clock,
//              price_info: &PriceInfoObject,
//           )
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L42-89)
```text
public(package) fun parse_suilend_obligation<ObligationType>(
    obligation_cap: &SuilendObligationOwnerCap<ObligationType>,
    lending_market: &LendingMarket<ObligationType>,
    clock: &Clock,
): u256 {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());

    let mut total_deposited_value_usd = 0;
    let mut total_borrowed_value_usd = 0;
    let reserves = lending_market.reserves();

    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);

        let cumulative_borrow_rate = borrow.cumulative_borrow_rate();
        let new_cumulative_borrow_rate = reserve::cumulative_borrow_rate(borrow_reserve);

        let new_borrowed_amount = borrow
            .borrowed_amount()
            .mul(new_cumulative_borrow_rate.div(cumulative_borrow_rate));

        let market_value = reserve::market_value(
            borrow_reserve,
            new_borrowed_amount,
        );

        total_borrowed_value_usd = total_borrowed_value_usd + market_value.to_scaled_val();
    });

    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L238-246)
```text
    public fun assert_price_is_fresh<P>(reserve: &Reserve<P>, clock: &Clock) {
        assert!(is_price_fresh(reserve, clock), EPriceStale);
    }

    public(package) fun is_price_fresh<P>(reserve: &Reserve<P>, clock: &Clock): bool {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;

        cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S
    }
```

**File:** volo-vault/sources/oracle.move (L35-36)
```text
    update_interval: u64,
    dex_slippage: u256, // Pool price and oracle price slippage parameter (used in adaptors related to DEX)
```

**File:** volo-vault/sources/oracle.move (L250-262)
```text
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();

    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();

    let max_timestamp = current_result.max_timestamp_ms();

    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    current_result.result().value() as u256
}
```
