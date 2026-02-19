# Audit Report

## Title
Division by Zero in `div_d()` Causes Complete Vault DoS When Share Ratio Reaches Zero

## Summary
The `div_d()` utility function lacks zero-divisor validation [1](#0-0) , and `get_share_ratio()` can legitimately return zero when the vault has outstanding shares but all asset values are zero. This causes `execute_deposit()` to panic with division by zero at the critical share calculation step [2](#0-1) , completely blocking all deposit operations and rendering the vault inoperable.

## Finding Description

**Root Cause:**

The `div_d()` function performs division without any zero-divisor check [1](#0-0) . When called with a zero divisor, it causes a runtime panic.

**Critical Execution Path:**

1. The `get_share_ratio()` function calculates share ratio using `div_d(total_usd_value, total_shares)` [3](#0-2) . When `total_shares > 0` (bypassing the early return at line 1304-1306), but `total_usd_value = 0`, the calculation returns: `(0 * DECIMALS) / total_shares = 0`.

2. In `execute_deposit()`, this zero share_ratio is retrieved [4](#0-3)  and then used as the divisor for calculating user shares [2](#0-1) .

3. The division `div_d(new_usd_value_deposited, 0)` triggers a runtime panic **before** the zero-share assertion at line 848 can execute.

**Why Total USD Value Can Reach Zero:**

Both Navi and Suilend adaptors explicitly return zero when lending positions become underwater (borrows exceed collateral):

- **Navi adaptor**: Returns 0 when `total_supply_usd_value < total_borrow_usd_value` [5](#0-4) 

- **Suilend adaptor**: Returns 0 when `total_deposited_value_usd < total_borrowed_value_usd` [6](#0-5) 

When all vault assets are deployed to underwater positions, `get_total_usd_value()` sums these zero values and returns 0 [7](#0-6) .

**Entry Point:**

Operators execute deposits through the public `operation::execute_deposit()` function [8](#0-7) , which calls the vulnerable vault function.

## Impact Explanation

**Critical Operational Impact - Complete Vault DoS:**

- All `execute_deposit()` calls abort with division by zero panic when share_ratio is zero
- The vault cannot accept any new deposits, even with valid user funds
- Users with pending deposit requests cannot have them executed; their funds remain locked in the request buffer
- Existing shareholders cannot add more capital to potentially recover the vault from underwater positions
- Protocol operators must implement emergency procedures to restore functionality
- No automatic recovery mechanism exists in the protocol

**Severity Justification:**

This is **CRITICAL** because:
1. It causes complete protocol unavailability for core deposit functionality
2. The condition occurs naturally through market volatility without requiring malicious actions
3. The failure happens at runtime panic level rather than graceful error handling
4. No protective guards prevent the zero-divisor scenario before the panic
5. The vault becomes permanently stuck until external administrative intervention

The zero-share assertion exists at line 848 but is unreachable due to the panic occurring first at line 844 [9](#0-8) .

## Likelihood Explanation

**High Likelihood - Natural Market Conditions:**

The vulnerability triggers under realistic DeFi conditions that do not require attacker manipulation:

1. **Reachable Entry Point**: Standard vault operations allow execution through operator capabilities [8](#0-7) 

2. **Feasible Preconditions**:
   - Vault deploys funds to Navi/Suilend lending protocols (normal vault strategy)
   - Market volatility causes collateral value to drop below borrowed value
   - Lending positions become underwater (well-documented DeFi risk)
   - Adaptors legitimately return zero per their design logic [5](#0-4) [6](#0-5) 

3. **No Privileged Actions Required**: Occurs through market conditions combined with normal operator deposit execution

4. **Historical Precedent**: DeFi lending positions commonly go underwater during market crashes (March 2020, May 2021, November 2022 crypto market events)

5. **Detection Difficulty**: No warning mechanism exists; the first deposit attempt post-condition results in immediate panic

The vault status checks pass normally [10](#0-9) , and the early return in `get_share_ratio()` only triggers when `total_shares == 0` [11](#0-10) , not when share_ratio becomes zero.

## Recommendation

Add zero-divisor validation to `div_d()` and/or add pre-division validation in share calculation contexts:

**Option 1: Fix `div_d()` function:**
```move
public fun div_d(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERROR_DIVISION_BY_ZERO);
    v1 * DECIMALS / v2
}
```

**Option 2: Add pre-validation in `execute_deposit()`:**
```move
let share_ratio_before = self.get_share_ratio(clock);
assert!(share_ratio_before > 0, ERR_ZERO_SHARE_RATIO);
let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**Option 3: Prevent zero total_usd_value condition:**
```move
// In get_share_ratio()
let total_usd_value = self.get_total_usd_value(clock);
if (total_usd_value == 0) {
    // Handle zero value case - perhaps disable deposits or return default ratio
    return vault_utils::to_decimals(1)
};
```

The most robust solution combines Options 1 and 2 to provide defense-in-depth against division by zero scenarios.

## Proof of Concept

```move
#[test]
fun test_division_by_zero_dos_when_underwater() {
    // Setup: Create vault with initial depositor
    let mut scenario = test_scenario::begin(ADMIN);
    let (vault, operator_cap, oracle_config, clock) = setup_vault_with_initial_deposit(&mut scenario);
    
    // Step 1: Deploy all funds to Navi lending position
    deploy_to_navi_lending(&mut vault, &operator_cap, &mut scenario);
    
    // Step 2: Simulate market crash - collateral drops below borrows
    // This causes Navi adaptor to return 0 (underwater position)
    simulate_underwater_position(&mut vault, &oracle_config, &clock);
    
    // Step 3: New user requests deposit
    let new_depositor = @0xBEEF;
    let deposit_coin = coin::mint_for_testing<SUI>(1000, scenario.ctx());
    let request_id = user_entry::deposit_with_auto_transfer(
        &mut vault,
        &mut reward_manager,
        deposit_coin,
        1000,
        1, // expected_shares
        option::none(),
        &clock,
        scenario.ctx()
    );
    
    // Step 4: Operator attempts to execute deposit
    // Expected: Transaction aborts with division by zero panic
    // Actual: assert!(share_ratio == 0) AND div_d(amount, 0) panics
    operation::execute_deposit(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &oracle_config,
        request_id,
        10000, // max_shares_received
    ); // <-- PANIC: division by zero in div_d()
}
```

**Notes:**
- The vulnerability is directly reachable through standard vault operations when market conditions create underwater lending positions
- Both Navi and Suilend adaptors are designed to return 0 for underwater positions, making this scenario realistic
- The panic occurs before any graceful error handling can execute
- Recovery requires administrative intervention to either restore asset values or implement emergency procedures

### Citations

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/volo_vault.move (L813-814)
```text
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L821-821)
```text
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L844-850)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
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

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
```
