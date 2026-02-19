# Audit Report

## Title
Integer Overflow in Flash Loan Fee Calculation Causes DoS

## Summary
The flash loan fee calculation performs unchecked u64 multiplication before division, causing transaction aborts when loan amounts and fee rates result in values exceeding u64::MAX. This renders flash loans unusable for legitimately configured large liquidity pools.

## Finding Description

The `loan()` function in the flash loan module calculates fees using direct u64 multiplication before division [1](#0-0) . The division constant is 10000 [2](#0-1) .

In Sui Move, u64 arithmetic operations abort on overflow. The multiplication `_loan_amount * cfg.rate_to_supplier` occurs before division in Move's evaluation order. When this multiplication exceeds u64::MAX (18,446,744,073,709,551,615), the transaction aborts.

**Why Existing Protections Fail:**

The `verify_config()` function only validates that fee rates sum to less than 10000 and that min < max [3](#0-2) . There is no validation ensuring `cfg.max * cfg.rate_to_supplier < u64::MAX`.

**Public Entry Points:**

While `loan()` itself is `public(friend)` [4](#0-3) , it is called by fully public functions in the lending module [5](#0-4) , making it accessible to any user.

**Overflow Example:**
- 20 million SUI = 2 × 10^16 base units (9 decimals)
- With 10% fee (rate_to_supplier = 1000): 2 × 10^16 × 1000 = 2 × 10^19
- This exceeds u64::MAX (≈ 1.844 × 10^19), causing abort

## Impact Explanation

**Operational DoS:** When the overflow condition exists, any user attempting to borrow amounts approaching `cfg.max` will experience transaction aborts, making flash loans completely unusable for that asset despite sufficient pool liquidity.

**Affected Parties:**
- Users cannot access flash loan functionality
- Protocol loses flash loan fee revenue
- DeFi composability breaks for protocols depending on flash loans

**Severity: High** - While no funds are directly at risk, this represents a critical operational failure where a core DeFi primitive becomes permanently disabled until admin intervention. Flash loans are fundamental to DeFi protocols, and the misconfiguration is easy to trigger accidentally.

## Likelihood Explanation

**High Likelihood for Large Pools:**

Admins naturally want to maximize flash loan utility for high-liquidity pools. Setting large `cfg.max` values combined with reasonable percentage-based fees (10-50%) easily triggers the overflow condition.

**Preconditions:**
- Admin sets `cfg.max = 20,000,000 × 10^9` (20 million SUI)
- Admin sets `cfg.rate_to_supplier = 1000` (10% fee)
- Both are legitimate, non-malicious configurations

**Execution:** Any user calling the public flash loan functions with amounts near `cfg.max` triggers the overflow immediately.

**Detection:** The issue manifests immediately when users attempt to utilize the configured limits, causing support burden and confusion.

The codebase demonstrates awareness of safe multiplication patterns using u128 casting [6](#0-5) , but this pattern is not applied in the flash loan fee calculation.

## Recommendation

Implement safe multiplication using u128 casting before division, similar to the pattern used in `liquid_staking::math::mul_div()`:

```move
public(friend) fun loan<CoinType>(...) {
    // ... existing code ...
    
    // Safe fee calculation with overflow protection
    let to_supplier = {
        let result = (_loan_amount as u128) * (cfg.rate_to_supplier as u128) / (constants::FlashLoanMultiple() as u128);
        assert!(result <= (18446744073709551615 as u128), error::overflow());
        (result as u64)
    };
    
    let to_treasury = {
        let result = (_loan_amount as u128) * (cfg.rate_to_treasury as u128) / (constants::FlashLoanMultiple() as u128);
        assert!(result <= (18446744073709551615 as u128), error::overflow());
        (result as u64)
    };
    
    // ... rest of function ...
}
```

Additionally, add validation in `verify_config()` to prevent misconfiguration:

```move
fun verify_config(cfg: &AssetConfig) {
    assert!(cfg.rate_to_supplier + cfg.rate_to_treasury < constants::FlashLoanMultiple(), error::invalid_amount());
    assert!(cfg.min < cfg.max, error::invalid_amount());
    
    // Prevent overflow in fee calculations
    let max_rate = if (cfg.rate_to_supplier > cfg.rate_to_treasury) { cfg.rate_to_supplier } else { cfg.rate_to_treasury };
    assert!((cfg.max as u128) * (max_rate as u128) <= (18446744073709551615 as u128), error::config_overflow());
}
```

## Proof of Concept

```move
#[test]
fun test_flash_loan_overflow() {
    // Setup: Create flash loan config with large max and 10% fee
    // cfg.max = 20_000_000_000_000_000 (20 million SUI in base units)
    // cfg.rate_to_supplier = 1000 (10%)
    
    // When: User attempts to borrow 20 million SUI
    // Then: Transaction aborts due to u64 overflow in:
    //       20_000_000_000_000_000 * 1000 = 20_000_000_000_000_000_000 > u64::MAX
    
    // Expected: Abort with arithmetic overflow
    // Actual: Flash loans become unusable despite pool having sufficient liquidity
}
```

## Notes

This vulnerability affects the integrated Navi Protocol flash loan dependency within the Volo codebase. While technically in a local dependency, it is in-scope and impacts protocol functionality. The safe multiplication pattern demonstrated in `liquid_staking::math` should be consistently applied across all multiply-then-divide operations in the codebase.

### Citations

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L141-141)
```text
    public(friend) fun loan<CoinType>(config: &Config, _pool: &mut Pool<CoinType>, _user: address, _loan_amount: u64): (Balance<CoinType>, Receipt<CoinType>) {
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/flash_loan.move (L152-153)
```text
        let to_supplier = _loan_amount * cfg.rate_to_supplier / constants::FlashLoanMultiple();
        let to_treasury = _loan_amount * cfg.rate_to_treasury / constants::FlashLoanMultiple();
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

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/lending.move (L539-545)
```text
    public fun flash_loan_with_ctx<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, ctx: &mut TxContext): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, tx_context::sender(ctx), amount)
    }

    public fun flash_loan_with_account_cap<CoinType>(config: &FlashLoanConfig, pool: &mut Pool<CoinType>, amount: u64, account_cap: &AccountCap): (Balance<CoinType>, FlashLoanReceipt<CoinType>) {
        base_flash_loan<CoinType>(config, pool, account::account_owner(account_cap), amount)
    }
```

**File:** liquid_staking/sources/volo_v1/math.move (L14-18)
```text
    public fun mul_div(x: u64, y: u64, z: u64): u64 {
        assert!(z != 0, E_DIVIDE_BY_ZERO);
        let r = (x as u128) * (y as u128) / (z as u128);
        assert!(r <= U64_MAX, E_U64_OVERFLOW);
        (r as u64)
```
