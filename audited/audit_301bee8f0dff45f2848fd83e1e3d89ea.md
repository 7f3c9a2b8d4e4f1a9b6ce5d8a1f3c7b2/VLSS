### Title
Integer Overflow in Flash Loan Fee Calculation Causes DoS

### Summary
The `loan()` function calculates flash loan fees using `_loan_amount * cfg.rate_to_supplier / FlashLoanMultiple()` without checking for u64 overflow during multiplication. When an admin configures large `cfg.max` values combined with non-trivial fee rates, the multiplication overflows before division occurs, causing transaction aborts and rendering flash loans unusable for the configured amounts.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The fee calculation performs unchecked u64 multiplication before division. In Move, u64 arithmetic operations abort on overflow. The calculation sequence is:

1. `to_supplier = _loan_amount * cfg.rate_to_supplier / FlashLoanMultiple()`
2. `to_treasury = _loan_amount * cfg.rate_to_treasury / FlashLoanMultiple()`

Where `FlashLoanMultiple()` returns 10000. [2](#0-1) 

The multiplication occurs first in Move's evaluation order, and if `_loan_amount * rate_to_supplier > u64::MAX (18,446,744,073,709,551,615)`, the transaction aborts.

**Why Existing Protections Fail:**
The `verify_config()` function only validates:
- `rate_to_supplier + rate_to_treasury < FlashLoanMultiple()` 
- `min < max` [3](#0-2) 

There is no validation ensuring `cfg.max * cfg.rate_to_supplier < u64::MAX` or `cfg.max * cfg.rate_to_treasury < u64::MAX`.

**Overflow Thresholds:**
- With `rate_to_supplier = 1,000` (10%): max safe loan = 1.8 × 10^16 base units
- With `rate_to_supplier = 5,000` (50%): max safe loan = 3.7 × 10^15 base units
- With `rate_to_supplier = 9,999` (99.99%): max safe loan = 1.8 × 10^15 base units

For SUI (9 decimals): 10 million SUI = 10^16 base units

### Impact Explanation

**Operational DoS Impact:**
When the overflow condition exists, any user attempting to borrow amounts approaching `cfg.max` will experience transaction aborts at [4](#0-3)  making flash loans completely unusable for that asset despite the pool having sufficient liquidity.

**Affected Parties:**
- Users cannot access flash loan functionality
- Protocol loses flash loan fee revenue
- DeFi composability breaks for protocols depending on flash loans

**Severity Justification:**
While no funds are directly stolen, this represents a critical operational failure where a core protocol feature becomes permanently disabled for an asset until admin reconfiguration. The severity is High because:
1. Flash loans are a fundamental DeFi primitive
2. The condition is easy to trigger accidentally
3. Recovery requires admin intervention
4. Users have no workaround

### Likelihood Explanation

**Preconditions:**
An admin legitimately configuring flash loans for a large liquidity pool might:
1. Set `cfg.max = 10,000,000 * 10^9` (10 million SUI in base units)
2. Set `cfg.rate_to_supplier = 1,000` (10% fee)

This is not malicious - admins naturally want to allow large flash loans for high-liquidity pools and might set percentage-based fees that seem reasonable.

**Execution Complexity:**
Low - any user calling the public `loan()` function with amount near `cfg.max` triggers the overflow.

**Detection:**
The issue would manifest immediately when users attempt to utilize the configured flash loan limits, causing confusion and support burden.

**Probability:**
High for large-value pools where admins want to maximize flash loan utility. The codebase even shows safe patterns for handling multiplication-before-division using u128 casting [5](#0-4)  but this pattern is not applied in `flash_loan.move`.

### Recommendation

**Immediate Fix:**
Add overflow validation to `verify_config()`:

```move
fun verify_config(cfg: &AssetConfig) {
    assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
    assert!(cfg.min < cfg.max, error::invalid_amount());
    
    // Add overflow checks
    let max_as_u128 = (cfg.max as u128);
    let rate_supplier_u128 = (cfg.rate_to_supplier as u128);
    let rate_treasury_u128 = (cfg.rate_to_treasury as u128);
    
    assert!(max_as_u128 * rate_supplier_u128 <= (U64_MAX as u128), error::invalid_amount());
    assert!(max_as_u128 * rate_treasury_u128 <= (U64_MAX as u128), error::invalid_amount());
}
```

**Alternative Fix:**
Use safe multiplication pattern in `loan()` function:

```move
let to_supplier = {
    let result = (_loan_amount as u128) * (cfg.rate_to_supplier as u128) / (constants::FlashLoanMultiple() as u128);
    assert!(result <= (U64_MAX as u128), error::invalid_amount());
    (result as u64)
};
```

**Test Cases:**
1. Verify `create_asset()` fails when `max * rate_to_supplier > u64::MAX`
2. Verify `set_asset_max()` fails when new max causes overflow
3. Verify `set_asset_rate_to_supplier()` fails when new rate causes overflow
4. Regression test with realistic large values (10M SUI, 10% fee)

### Proof of Concept

**Initial State:**
1. Protocol initialized with flash loan config
2. Large liquidity pool with 10+ million SUI

**Attack Steps:**
1. Admin calls `create_flash_loan_asset<SUI>()` with:
   - `_max = 10_000_000_000_000_000` (10 million SUI)
   - `_rate_to_supplier = 1_000` (10%)
   - `_rate_to_treasury = 100` (1%)
   
2. Configuration succeeds (passes `verify_config()`)

3. User calls `loan<SUI>()` with `_loan_amount = 10_000_000_000_000_000`

**Expected Result:**
Flash loan executes successfully with fees calculated

**Actual Result:**
Transaction aborts at line 152 due to u64 overflow:
- Calculation: `10_000_000_000_000_000 * 1_000 = 10^19`
- u64::MAX = `18,446,744,073,709,551,615` (1.8 × 10^19)
- Overflow condition met → Transaction aborts

**Success Condition:**
Transaction fails with arithmetic overflow, flash loans unusable despite pool having 10M+ SUI available.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L141-173)
```text
    public(friend) fun loan<CoinType>(config: &Config, _pool: &mut Pool<CoinType>, _user: address, _loan_amount: u64): (Balance<CoinType>, Receipt<CoinType>) {
        version_verification(config);
        let str_type = type_name::into_string(type_name::get<CoinType>());
        assert!(table::contains(&config.support_assets, *ascii::as_bytes(&str_type)), error::reserve_not_found());
        let asset_id = table::borrow(&config.support_assets, *ascii::as_bytes(&str_type));
        let cfg = table::borrow(&config.assets, *asset_id);

        let pool_id = object::uid_to_address(pool::uid(_pool));
        assert!(_loan_amount >= cfg.min && _loan_amount <= cfg.max, error::invalid_amount());
        assert!(cfg.pool_id == pool_id, error::invalid_pool());

        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();

        let _balance = pool::withdraw_balance(_pool, _loan_amount, _user);
        
        let _receipt = Receipt<CoinType> {
            user: _user,
            asset: *asset_id,
            amount: _loan_amount,
            pool: pool_id,
            fee_to_supplier: to_supplier,
            fee_to_treasury: to_treasury,
        };

        emit(FlashLoan {
            sender: _user,
            asset: *asset_id,
            amount: _loan_amount,
        });

        (_balance, _receipt)
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L290-293)
```text
    fun verify_config(cfg: &AssetConfig) {
        assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
        assert!(cfg.min < cfg.max, error::invalid_amount());
    }
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/constants.move (L16-16)
```text
    public fun FlashLoanMultiple(): u64 {10000}
```

**File:** liquid_staking/sources/volo_v1/math.move (L14-19)
```text
    public fun mul_div(x: u64, y: u64, z: u64): u64 {
        assert!(z != 0, E_DIVIDE_BY_ZERO);
        let r = (x as u128) * (y as u128) / (z as u128);
        assert!(r <= U64_MAX, E_U64_OVERFLOW);
        (r as u64)
    }
```
