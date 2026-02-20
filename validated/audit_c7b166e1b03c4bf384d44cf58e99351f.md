# Audit Report

## Title
Division by Zero in `div_d()` Causes Complete Vault DoS When Share Ratio Reaches Zero

## Summary
The `div_d()` utility function lacks zero-divisor validation, creating a critical DoS vulnerability. When vault lending positions become underwater during market stress, adaptors return zero values, causing `get_share_ratio()` to return zero. Subsequent `execute_deposit()` calls panic with division by zero, completely blocking all deposit operations and trapping user funds in the request buffer.

## Finding Description

The vulnerability exists across a critical execution path in the vault's deposit mechanism:

**Root Cause**: The `div_d()` function performs division without zero-divisor validation. [1](#0-0)  Unlike other math utilities in the codebase that include explicit checks, [2](#0-1)  `div_d()` directly performs `v1 * DECIMALS / v2` without validating that `v2 != 0`.

**Critical Path Component 1**: The `get_share_ratio()` function has an early return when `total_shares == 0`, [3](#0-2)  but when `total_shares > 0` and `total_usd_value == 0`, it calculates `div_d(total_usd_value, total_shares)` which returns `0 * DECIMALS / total_shares = 0`. [4](#0-3) 

**Critical Path Component 2**: In `execute_deposit()`, this zero share_ratio is captured before processing the deposit, [5](#0-4)  and subsequently used as a divisor to calculate user shares. [6](#0-5)  When `share_ratio_before = 0`, this triggers a runtime division by zero panic before the assertion on line 848 can execute.

**Why Total USD Value Reaches Zero**: Both Navi and Suilend adaptors explicitly return zero when lending positions become underwater (borrows exceed collateral value):

- Navi adaptor returns 0 when total supply value falls below total borrow value. [7](#0-6) 
- Suilend adaptor returns 0 when total deposited value falls below total borrowed value. [8](#0-7) 

When all vault assets are in underwater positions, `get_total_usd_value()` sums these zero values. [9](#0-8) 

**Entry Point**: Operators call `execute_deposit()` with an OperatorCap to process pending deposit requests. [10](#0-9) 

## Impact Explanation

**Severity: CRITICAL - Complete Protocol DoS**

This vulnerability causes complete denial of service for the vault's core deposit functionality:

1. **Immediate Impact**: All `execute_deposit()` calls abort with runtime panic when share_ratio is zero, preventing any deposit execution
2. **Funds Locked**: Users with pending deposit requests cannot have them executed; their principal coins remain locked in the deposit buffer with no way to retrieve them except through cancellation (which has time-lock restrictions)
3. **No Recovery Path**: The vault remains stuck in this state - no automatic recovery mechanism exists, and new deposits cannot help recover underwater positions
4. **Protocol Inoperability**: The core value proposition (accepting deposits to deploy capital) becomes completely unavailable

**Affected Parties**:
- New depositors: Cannot execute pending deposit requests
- Existing shareholders: Cannot add capital to help recover underwater vault positions
- Protocol operators: Must implement emergency procedures or wait for market recovery

The severity is CRITICAL because:
- Core protocol functionality (deposits) becomes completely unavailable
- Occurs at runtime panic level (not graceful error handling that could be caught)
- No built-in recovery mechanism
- Can happen through natural market conditions without malicious activity

## Likelihood Explanation

**Likelihood: MEDIUM-to-HIGH - Natural Market Conditions**

This vulnerability triggers under realistic DeFi operating conditions:

1. **Feasible Preconditions**:
   - Vault has existing deposits (`total_shares > 0`) from previous operations - common state
   - Vault has deployed most/all funds to Navi/Suilend lending protocols - normal vault strategy
   - Market volatility causes collateral values to drop below borrowed amounts
   - Lending positions become underwater - documented DeFi risk

2. **No Malicious Activity Required**: This occurs through normal market dynamics and price movements, not attacker manipulation

3. **Historical Precedent**: DeFi lending positions frequently go underwater during market crashes (March 2020 COVID crash, May 2021 crash, November 2022 FTX collapse, etc.)

4. **Reachable Execution Path**: Operators routinely call `execute_deposit()` for pending requests using their OperatorCap - this is expected protocol operation, not a rare edge case

5. **No Warning System**: No checks prevent the vault from reaching this state; the panic occurs immediately on the first deposit execution attempt after positions go underwater

The likelihood is rated MEDIUM-to-HIGH because while it requires all positions to be underwater simultaneously (a severe scenario), this can realistically occur during major market downturns, especially for vaults with concentrated positions or aggressive leverage strategies.

## Recommendation

Add zero-divisor validation to the `div_d()` function to match the pattern used in other math libraries within the codebase:

```move
const ERR_DIVISION_BY_ZERO: u64 = 9001;

public fun div_d(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * DECIMALS / v2
}
```

Alternatively, add a specific check in `execute_deposit()` before using `share_ratio_before` as a divisor:

```move
let share_ratio_before = self.get_share_ratio(clock);
assert!(share_ratio_before > 0, ERR_ZERO_SHARE_RATIO);
```

The first approach (fixing `div_d()`) is recommended as it protects all call sites and follows the defensive programming pattern already established in the `safe_math` module.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = DIVISION_BY_ZERO)] // Sui runtime abort code
fun test_deposit_dos_when_underwater() {
    // Setup vault with initial deposits (total_shares > 0)
    let mut vault = create_test_vault();
    let clock = create_test_clock();
    
    // Execute initial deposit to establish shares
    execute_test_deposit(&mut vault, &clock, 1000);
    assert!(vault.total_shares() > 0);
    
    // Simulate all positions going underwater by:
    // 1. Deploy all free principal to lending
    // 2. Set adaptor values to return 0 (underwater)
    deploy_all_to_lending(&mut vault);
    set_all_positions_underwater(&mut vault);
    
    // Verify total_usd_value is 0 but total_shares > 0
    let total_value = get_total_usd_value_without_update(&vault);
    assert!(total_value == 0);
    assert!(vault.total_shares() > 0);
    
    // Verify get_share_ratio returns 0
    let share_ratio = get_share_ratio(&vault, &clock);
    assert!(share_ratio == 0);
    
    // Attempt to execute new deposit - should panic with division by zero
    // This demonstrates complete DoS of deposit functionality
    execute_test_deposit(&mut vault, &clock, 500); // PANICS HERE
}
```

## Notes

This vulnerability demonstrates a critical gap in defensive programming where a utility function lacks basic input validation that could prevent catastrophic protocol failure during market stress events. The issue is particularly severe because:

1. **Silent Zero Propagation**: The `get_share_ratio()` function silently returns 0 instead of failing fast, allowing the zero value to propagate to a division operation
2. **Inconsistent Safety**: Other math libraries in the same codebase (`safe_math`, `ray_math`) include proper zero-divisor checks
3. **Market-Driven Trigger**: Unlike vulnerabilities requiring attacker action, this can be triggered purely by external market conditions
4. **No Escape Hatch**: Once triggered, there's no graceful degradation or recovery path - the vault is stuck until positions recover above water or emergency admin intervention

The recommended fix is straightforward and follows established patterns in the codebase, making this a high-priority issue to address before production deployment.

### Citations

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
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

**File:** volo-vault/sources/volo_vault.move (L806-814)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L820-821)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1304-1306)
```text
    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };
```

**File:** volo-vault/sources/volo_vault.move (L1308-1309)
```text
    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L85-87)
```text
    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
```
