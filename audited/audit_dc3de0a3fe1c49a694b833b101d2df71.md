# Audit Report

## Title
Division by Zero in `div_d()` Causes Complete Vault DoS When Share Ratio Reaches Zero

## Summary
The vault's `div_d()` utility function performs division without zero-divisor validation. When vault lending positions become underwater through natural market conditions, adaptors return zero values, causing `get_share_ratio()` to return zero. Subsequent `execute_deposit()` calls trigger a runtime division by zero panic, completely blocking all deposit operations and locking user funds in the request buffer.

## Finding Description

This vulnerability exists across a critical execution path in the vault's deposit mechanism, composed of several interconnected components:

**Root Cause**: The `div_d()` function performs division without zero-divisor validation [1](#0-0) , calculating `v1 * DECIMALS / v2` with no check for `v2 == 0`.

**Critical Path Component 1**: The `get_share_ratio()` function only has an early return when `total_shares == 0` [2](#0-1) . However, when `total_shares > 0` and `total_usd_value == 0`, it proceeds to calculate the ratio [3](#0-2) , which returns `0 * DECIMALS / total_shares = 0`.

**Critical Path Component 2**: In `execute_deposit()`, the zero share_ratio is retrieved [4](#0-3)  and then used as a divisor to calculate user shares [5](#0-4) . When `share_ratio_before = 0`, this triggers a runtime division by zero panic that aborts execution before the zero-share assertion [6](#0-5)  can execute.

**Why Total USD Value Reaches Zero**: Both external lending adaptors explicitly return zero when positions become underwater:

- Navi adaptor returns 0 when `total_supply_usd_value < total_borrow_usd_value` [7](#0-6) 

- Suilend adaptor returns 0 when `total_deposited_value_usd < total_borrowed_value_usd` [8](#0-7) 

When all vault assets are deployed to underwater lending positions, `get_total_usd_value()` sums these zero values [9](#0-8)  and returns 0.

**Entry Point**: Operators call `execute_deposit()` with an OperatorCap to process pending deposit requests [10](#0-9) , which is expected protocol operation. The vault only validates that it's in normal status [11](#0-10) , with no checks preventing zero share_ratio.

## Impact Explanation

**Severity: CRITICAL - Complete Protocol DoS**

This vulnerability causes complete denial of service for the vault's core deposit functionality:

1. **Immediate Impact**: All `execute_deposit()` calls abort with runtime panic when share_ratio is zero, as the Move VM immediately aborts on arithmetic division by zero before any subsequent assertions can execute.

2. **Funds Locked**: Users with pending deposit requests cannot have them executed; their coins remain locked in the vault's request buffer with no automatic recovery mechanism.

3. **No Recovery Path**: The vault remains stuck in this state. Unlike graceful error handling, runtime panics provide no recovery path. New capital cannot enter to help recover underwater positions, creating a deadlock.

4. **Protocol Inoperability**: The core value proposition (accepting deposits) becomes unavailable, effectively rendering the vault non-functional.

The severity is CRITICAL because:
- Core protocol functionality becomes completely unavailable
- Occurs at runtime panic level (not graceful error handling)
- No built-in recovery mechanism exists in the protocol
- Can happen through natural market conditions without malicious activity
- Affects all pending and future deposits until emergency intervention

## Likelihood Explanation

**Likelihood: HIGH - Natural Market Conditions**

This vulnerability triggers under realistic DeFi operating conditions without requiring any attacker:

1. **Feasible Preconditions**:
   - Vault has existing deposits (`total_shares > 0`) from previous operations
   - Vault has deployed funds to Navi/Suilend lending protocols (normal yield strategy)
   - Market volatility causes collateral values to drop below borrowed amounts
   - Lending positions become underwater (common DeFi risk during market crashes)

2. **No Malicious Activity Required**: This occurs through normal market dynamics. Historical DeFi events (March 2020 COVID crash, May 2021 crypto crash, November 2022 FTX collapse) demonstrate that lending positions frequently go underwater during market stress.

3. **Reachable Execution Path**: Operators routinely call `execute_deposit()` to process pending requests using their OperatorCap - this is expected protocol operation, not a privileged attack vector.

4. **No Warning System**: No checks prevent the vault from reaching this state. The panic occurs immediately on the first deposit execution attempt after positions go underwater, with no gradual degradation or warning.

The combination of natural market triggers, feasible preconditions, and lack of protective mechanisms makes this a HIGH likelihood vulnerability.

## Recommendation

Implement zero-divisor validation in the `div_d()` function and add protective checks in `get_share_ratio()`:

**Option 1 - Add assertion in div_d()**:
```move
public fun div_d(v1: u256, v2: u256): u256 {
    assert!(v2 > 0, ERR_DIVISION_BY_ZERO);
    v1 * DECIMALS / v2
}
```

**Option 2 - Add check in get_share_ratio()** (preferred):
```move
public fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    
    // Prevent division by zero when total value is zero but shares exist
    assert!(total_usd_value > 0, ERR_ZERO_TOTAL_VALUE);
    
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
    // ... rest of function
}
```

**Option 3 - Emergency pause mechanism** (additional protection):
Add automatic vault status change to disabled when total_usd_value reaches zero with existing shares, preventing further operations until admin intervention.

## Proof of Concept

```move
#[test]
fun test_division_by_zero_dos_on_underwater_positions() {
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Setup: Create vault and initial deposit
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let admin_cap = vault::test_create_admin_cap(ctx);
        vault::create_vault<SUI>(&admin_cap, ctx);
        transfer::public_transfer(admin_cap, ADMIN);
    };
    
    test_scenario::next_tx(&mut scenario, ADMIN);
    
    // User makes initial deposit (total_shares = 100, total_usd_value = 100)
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        let config = create_test_oracle_config(test_scenario::ctx(&mut scenario));
        
        let deposit_coin = coin::mint_for_testing<SUI>(100, test_scenario::ctx(&mut scenario));
        let request_id = vault.request_deposit(deposit_coin, &clock, 100, receipt_id, USER1);
        vault.execute_deposit(&clock, &config, request_id, 100);
        
        // Vault now has: total_shares = 100, total_usd_value = 100
        assert!(vault.total_shares() == 100, 0);
        
        test_scenario::return_shared(vault);
        clock::destroy_for_testing(clock);
    };
    
    test_scenario::next_tx(&mut scenario, OPERATOR);
    
    // Simulate market crash: Deploy funds to Navi, then positions go underwater
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let mut navi_storage = test_scenario::take_shared<Storage>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        let config = create_test_oracle_config(test_scenario::ctx(&mut scenario));
        
        // Deploy all funds to Navi (borrow and supply)
        // ... [Navi integration code] ...
        
        // Simulate market crash: Update oracle prices so position becomes underwater
        // borrows_value > collateral_value
        // ... [Oracle price update] ...
        
        // Update Navi position value - adaptor returns 0 for underwater position
        navi_adaptor::update_navi_position_value(&mut vault, &config, &clock, asset_type, &mut navi_storage);
        
        // Now: total_shares = 100, but total_usd_value = 0 (underwater)
        assert!(vault.total_shares() == 100, 1);
        assert!(vault.get_total_usd_value_without_update() == 0, 2);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(navi_storage);
        clock::destroy_for_testing(clock);
    };
    
    test_scenario::next_tx(&mut scenario, USER2);
    
    // New user attempts deposit - this will PANIC with division by zero
    {
        let mut vault = test_scenario::take_shared<Vault<SUI>>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        let config = create_test_oracle_config(test_scenario::ctx(&mut scenario));
        
        let deposit_coin = coin::mint_for_testing<SUI>(50, test_scenario::ctx(&mut scenario));
        let request_id = vault.request_deposit(deposit_coin, &clock, 50, receipt_id_2, USER2);
        
        // This call will PANIC with division by zero at execute_deposit line 844
        // share_ratio_before = div_d(0, 100) = 0
        // user_shares = div_d(50, 0) = PANIC!
        vault.execute_deposit(&clock, &config, request_id, 100); // ABORTS HERE
        
        test_scenario::return_shared(vault);
        clock::destroy_for_testing(clock);
    };
    
    test_scenario::end(scenario);
}
```

## Notes

This vulnerability is particularly severe because:

1. **Natural Trigger**: Requires no attacker - underwater lending positions occur naturally during market stress, as demonstrated repeatedly in DeFi history.

2. **No Graceful Degradation**: The panic is a runtime arithmetic abort, not a handled error condition, providing no opportunity for recovery or fallback logic.

3. **Systemic Risk**: Once triggered, ALL pending and future deposits are blocked, potentially during the exact moment when the vault needs fresh capital most (to recover from underwater positions).

4. **Design Flaw**: The adaptors' design decision to return 0 for underwater positions (rather than using signed integers or error handling) directly enables this vulnerability when combined with the unvalidated division operation.

### Citations

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/sources/volo_vault.move (L814-814)
```text
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

**File:** volo-vault/sources/volo_vault.move (L848-848)
```text
    assert!(user_shares > 0, ERR_ZERO_SHARE);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
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
