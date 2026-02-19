### Title
Suilend Oracle Failure Bricks All Vault Operations Due to Missing Fallback Implementation

### Summary
The `get_pyth_price_and_identifier()` function returns `None` for invalid prices with a comment suggesting "caller can handle invalid prices gracefully by eg falling back to a different oracle," but the actual callers in `reserve.move` immediately abort when receiving `None`. This causes a cascading failure that permanently blocks all vault operations (deposits, withdrawals, and operations) whenever the Pyth oracle returns invalid prices for any Suilend reserve used by the vault. [1](#0-0) 

### Finding Description

**Root Cause:**

The `get_pyth_price_and_identifier()` function can return `None` for the spot price under two conditions: [2](#0-1) [3](#0-2) 

However, the callers in `reserve.move` do NOT implement any fallback mechanism. Both `create_reserve()` and `update_price()` immediately abort when receiving `None`: [4](#0-3) [5](#0-4) 

**Cascading Failure Chain:**

1. `refresh_reserve_price()` (public function) calls `reserve::update_price()`: [6](#0-5) 

2. When Pyth returns `None`, the transaction aborts with `EInvalidPrice`, preventing price updates

3. The Suilend adaptor requires updated prices before operations: [7](#0-6) 

4. Without updated prices, `parse_suilend_obligation()` aborts on staleness check: [8](#0-7) [9](#0-8) [10](#0-9) 

5. Without updated Suilend asset values, `get_total_usd_value()` aborts: [11](#0-10) [12](#0-11) 

6. All critical operations require `get_total_usd_value()`: [13](#0-12) [14](#0-13) [15](#0-14) [16](#0-15) [17](#0-16) 

### Impact Explanation

**Complete Operational Freeze:**

When Pyth oracle returns `None` for any Suilend reserve used by the vault, ALL vault operations become permanently blocked:
- **Cannot start operations**: `start_op_with_bag()` requires `get_total_usd_value()` 
- **Cannot end operations**: `end_op_value_update_with_bag()` requires `get_total_usd_value()`
- **Cannot execute deposits**: `execute_deposit()` requires `get_total_usd_value()` twice
- **Cannot execute withdrawals**: `execute_withdraw()` requires `get_share_ratio()` which calls `get_total_usd_value()`

**Who is Affected:**
- All vault users with pending deposit/withdrawal requests
- All operators unable to perform any vault operations
- All funds remain locked in the vault until oracle recovers

**Severity Justification:**
This is a **CRITICAL** denial-of-service vulnerability because:
1. It requires no attacker action - natural oracle degradation triggers it
2. Pyth oracle can realistically return `None` when confidence intervals widen (>10%) or during network issues (>60s staleness)
3. Recovery requires oracle to return valid prices, which may not happen for extended periods during market volatility
4. There is NO emergency override or alternative price source
5. Comment in code falsely implies fallback exists, indicating design intent was not implemented

### Likelihood Explanation

**HIGH Likelihood:**

**Triggering Conditions (Realistic):**
- Confidence interval exceeds 10% of price (common during high volatility)
- Oracle price becomes stale (>60 seconds old) due to network congestion or validator issues
- No attacker action required - natural market/network conditions

**No Workarounds Available:**
- No alternative oracle implementation exists in Suilend module despite comment mentioning it
- No emergency functions to bypass price checks
- No manual price override capability
- `PRICE_STALENESS_THRESHOLD_S = 0` means same-transaction price updates are mandatory

**Attack Complexity:** NONE (passive failure, not an attack)

**Detection:** Immediate - all affected operations will abort with error codes

**Probability:** Medium-to-High during:
- Market volatility (confidence intervals widen)
- Network congestion (oracle updates delayed)
- Sui validator set changes (temporary clock/timestamp issues)

### Recommendation

**Immediate Fix - Add Fallback Mechanism:**

1. In `reserve.move::update_price()`, use EMA price as fallback when spot price is None:
```move
let (price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);

// Use EMA price as fallback if spot price unavailable
let final_price = if (option::is_some(&price_decimal)) {
    option::extract(&mut price_decimal)
} else {
    ema_price_decimal  // Fallback to EMA price
};

reserve.price = final_price;
reserve.smoothed_price = ema_price_decimal;
```

2. Add validation that EMA price itself is not stale/invalid

3. Consider implementing Switchboard oracle integration as secondary fallback as originally intended per module comment

**Alternative - Grace Period:**
- Increase `PRICE_STALENESS_THRESHOLD_S` from 0 to allow some staleness tolerance (e.g., 300 seconds)
- This gives time for oracle to recover without bricking operations

**Test Cases:**
- Simulate Pyth returning None during deposit execution
- Simulate Pyth returning None during operation start/end
- Verify fallback to EMA price maintains system integrity
- Test recovery when Pyth returns valid prices after using fallback

### Proof of Concept

**Initial State:**
1. Vault has Suilend position with USDC reserve
2. User submits deposit request
3. Operator attempts to execute deposit

**Exploitation Steps:**

**Transaction 1 - Update Prices (Fails):**
```
1. Call refresh_reserve_price(lending_market, reserve_index, clock, pyth_price_info)
2. Pyth oracle returns None due to confidence > 10% or staleness > 60s
3. Transaction aborts with EInvalidPrice (error code 4)
```

**Transaction 2 - Execute Deposit (Fails):**
```
1. Call execute_deposit(vault, request_id, ...)
2. Function calls get_total_usd_value(clock)
3. Suilend asset value was not updated (due to Transaction 1 failure)
4. Transaction aborts with ERR_USD_VALUE_NOT_UPDATED (error code 5_007)
```

**Transaction 3 - Start Operation (Fails):**
```
1. Call start_op_with_bag(vault, ...)
2. Function calls get_total_usd_value(clock) at line 178
3. Transaction aborts with ERR_USD_VALUE_NOT_UPDATED
```

**Expected Result:** Operations should use fallback oracle or EMA price

**Actual Result:** All vault operations permanently blocked until Pyth recovers

**Success Condition:** Pyth oracle must return valid prices with confidence <10% and staleness <60s before any operation can proceed

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-18)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
    /// return type: (spot price, ema price, price identifier)
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L33-38)
```text
        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L40-48)
```text
        // check current sui time against pythnet publish time. there can be some issues that arise because the
        // timestamps are from different sources and may get out of sync, but that's why we have a fallback oracle
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L167-168)
```text
        let (mut price_decimal, smoothed_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L238-240)
```text
    public fun assert_price_is_fresh<P>(reserve: &Reserve<P>, clock: &Clock) {
        assert!(is_price_fresh(reserve, clock), EPriceStale);
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-588)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
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

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L820-820)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L841-841)
```text
    let total_usd_value_after = self.get_total_usd_value(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1006)
```text
    let ratio = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1266)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
```

**File:** volo-vault/sources/operation.move (L355-355)
```text
    let total_usd_value_after = vault.get_total_usd_value(
```
