### Title
Unchecked Power Operation in Pyth Price Parsing Causes Arithmetic Overflow DoS

### Summary
The `parse_price_to_decimal()` function computes `std::u64::pow(10, expo_magnitude)` without validating that `expo_magnitude <= 18`. Since 10^19 exceeds u64::MAX, any Pyth price feed with an exponent magnitude of 19 or greater will cause an arithmetic overflow abort, resulting in a complete denial of service for all Suilend reserve operations that depend on price updates.

### Finding Description

The vulnerability exists in the `parse_price_to_decimal()` function [1](#0-0) 

**Root Cause:**
The function performs two unchecked power operations:
1. When the exponent is negative: `std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))` [2](#0-1) 
2. When the exponent is positive: `std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))` [3](#0-2) 

**Mathematical Boundary:**
- u64::MAX = 18,446,744,073,709,551,615
- 10^18 = 1,000,000,000,000,000,000 (fits in u64)
- 10^19 = 10,000,000,000,000,000,000 (exceeds u64::MAX)

Therefore, any `expo_magnitude >= 19` causes arithmetic overflow and transaction abort.

**Why Existing Protections Fail:**
The function only validates price confidence and staleness [4](#0-3)  but never validates the exponent magnitude bounds before the power operation. The exponent is cast from i64 magnitude to u8 (range 0-255), meaning values from 19 to 255 are all accepted but will cause overflow.

**Execution Path:**
This function is called during:
1. Reserve creation via `get_pyth_price_and_identifier()` [5](#0-4) 
2. Price updates via `update_price()` [6](#0-5) 

### Impact Explanation

**Concrete Harm:**
When a Pyth price feed provides an exponent with magnitude >= 19, all transactions calling `parse_price_to_decimal()` will abort due to arithmetic overflow. This completely disables:
1. New reserve creation - unable to initialize reserves with the malformed price feed
2. Price updates for existing reserves - `update_price()` calls will fail
3. All lending operations dependent on accurate prices - borrowing, liquidations, interest calculations

**Severity Justification:**
This is a HIGH severity operational DoS vulnerability because:
- The entire Suilend reserve system becomes non-functional for affected assets
- No funds can be borrowed or liquidated when prices cannot update
- Users cannot interact with reserves using the malformed price feed
- The DoS persists until the oracle feed is corrected or replaced

**Affected Parties:**
All users and liquidity providers interacting with Suilend reserves that use Pyth price feeds with malformed exponents.

### Likelihood Explanation

**Feasibility Conditions:**
- Typical Pyth exponents are 4-7 decimals based on codebase usage patterns
- However, NO validation exists in the protocol to enforce this
- The code accepts any u8 value (0-255) for the exponent magnitude
- If Pyth provides malformed data, wrong price feed is configured, or there's a bug in the Pyth oracle system, the overflow occurs automatically

**Attacker Capabilities:**
While an attacker cannot directly control Pyth price feeds, this vulnerability can be triggered by:
- Oracle misconfiguration (using wrong price feed ID)
- Pyth oracle bugs or data corruption
- Edge cases in Pyth's price formatting
- Protocol integration errors when adding new assets

**Attack Complexity:**
Low - no complex transaction sequences needed. The overflow happens automatically when the malformed price data is processed.

**Probability Assessment:**
Medium likelihood - while typical operation uses safe exponent values, the lack of validation means any deviation from expected data format causes immediate DoS with no recovery mechanism.

### Recommendation

**Immediate Fix:**
Add exponent bounds validation before the power operation in `parse_price_to_decimal()`:

```move
fun parse_price_to_decimal(price: Price): Decimal {
    let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
    let expo = price::get_expo(&price);
    
    // Add validation
    const MAX_SAFE_EXPONENT: u8 = 18;
    
    if (i64::get_is_negative(&expo)) {
        let expo_mag = i64::get_magnitude_if_negative(&expo);
        assert!(expo_mag <= MAX_SAFE_EXPONENT, E_EXPONENT_TOO_LARGE);
        div(
            decimal::from(price_mag),
            decimal::from(std::u64::pow(10, (expo_mag as u8))),
        )
    } else {
        let expo_mag = i64::get_magnitude_if_positive(&expo);
        assert!(expo_mag <= MAX_SAFE_EXPONENT, E_EXPONENT_TOO_LARGE);
        mul(
            decimal::from(price_mag),
            decimal::from(std::u64::pow(10, (expo_mag as u8))),
        )
    }
}
```

**Alternative Approach:**
Use the iterative decimal conversion method from the protocol oracle adaptor [7](#0-6)  which avoids the power operation entirely through incremental multiplication/division.

**Test Cases:**
1. Test with `expo_magnitude = 18` (should succeed)
2. Test with `expo_magnitude = 19` (should fail gracefully with clear error)
3. Test with `expo_magnitude = 255` (maximum u8 value, should fail)
4. Test boundary transition between valid and invalid exponents

### Proof of Concept

**Initial State:**
- Suilend lending market deployed
- Attempting to create a reserve or update prices

**Exploit Sequence:**
1. Pyth price feed provides price data with exponent magnitude >= 19 (e.g., expo = -19 representing 10^-19 precision)
2. User or protocol calls `update_price()` or reserve creation function
3. Function calls `get_pyth_price_and_identifier()` which calls `parse_price_to_decimal()`
4. Code executes `std::u64::pow(10, 19)` 
5. Arithmetic overflow occurs: 10^19 = 10,000,000,000,000,000,000 > 18,446,744,073,709,551,615

**Expected Result:**
Price parsed successfully with proper decimal conversion

**Actual Result:**
Transaction aborts with arithmetic overflow error, preventing all reserve operations

**Success Condition:**
Any call to `parse_price_to_decimal()` with `expo_magnitude >= 19` causes immediate transaction abort, demonstrating the DoS vulnerability.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L33-48)
```text
        // confidence interval check
        // we want to make sure conf / price <= x%
        // -> conf * (100 / x )<= price
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };

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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L54-70)
```text
    fun parse_price_to_decimal(price: Price): Decimal {
        // suilend doesn't support negative prices
        let price_mag = i64::get_magnitude_if_positive(&price::get_price(&price));
        let expo = price::get_expo(&price);

        if (i64::get_is_negative(&expo)) {
            div(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_negative(&expo) as u8))),
            )
        } else {
            mul(
                decimal::from(price_mag),
                decimal::from(std::u64::pow(10, (i64::get_magnitude_if_positive(&expo) as u8))),
            )
        }
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L167-167)
```text
        let (mut price_decimal, smoothed_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-586)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
```

**File:** volo-vault/local_dependencies/protocol/oracle/sources/oracle_utils.move (L9-22)
```text
    public fun to_target_decimal_value_safe(value: u256, decimal: u64, target_decimal: u64): u256 {
        // zero check to prevent stack overflow
        while (decimal != target_decimal && value != 0) {
            if (decimal < target_decimal) {
                value = value * 10;
                decimal = decimal + 1;
            } else {
                value = value / 10;
                decimal = decimal - 1;
            };
        };

        value
    }
```
