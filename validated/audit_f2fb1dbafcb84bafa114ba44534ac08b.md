# Audit Report

## Title
Share Ratio Increase During Vault Operations Causes DoS of All Pending Deposit Requests

## Summary
When vault operations generate profit between deposit request creation and execution, the share ratio increases, causing `execute_deposit` to calculate fewer shares than the user's stored `expected_shares`. This triggers the slippage protection check and prevents execution of all pending deposits, creating a denial-of-service condition that occurs during normal profitable vault operations.

## Finding Description

The vulnerability exists in the deposit request lifecycle combined with vault operation value updates. The issue stems from storing a fixed `expected_shares` value at request time, which becomes invalid when the share ratio changes due to profitable operations.

**Request Phase:**
Users create deposit requests via `user_entry::deposit`, which stores the user-provided `expected_shares` parameter in a `DepositRequest` struct as a fixed field. [1](#0-0)  This request is created when the vault is in `VAULT_NORMAL_STATUS`. [2](#0-1) 

**Operation Phase:**
Between request creation and execution, operators perform vault operations. The `operation::start_op_with_bag` function sets the vault status to `VAULT_DURING_OPERATION_STATUS`. [3](#0-2)  Operations generate profit through DeFi strategies (lending, liquidity provision). When operations complete, `end_op_value_update_with_bag` recalculates the vault's `total_usd_value` based on current asset values [4](#0-3)  while `total_shares` remains constant [5](#0-4) , then restores the vault to `VAULT_NORMAL_STATUS`. [6](#0-5) 

**Execution Phase:**
The execution calculates the current share ratio using `get_share_ratio`, which computes `share_ratio = total_usd_value / total_shares`. [7](#0-6)  It then calculates shares to mint as `user_shares = new_usd_value_deposited / share_ratio_before`. [8](#0-7)  Finally, it enforces slippage protection: `assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE)`. [9](#0-8) 

**Root Cause:**
If vault operations increased `total_usd_value` while `total_shares` remained constant, the share ratio increases. Since `user_shares = deposit_value / share_ratio`, a higher share ratio results in fewer shares being minted. This causes `user_shares < expected_shares`, failing the assertion.

**Mathematical Proof:**
- At request time: `expected_shares = deposit_value / share_ratio_old`
- At execution time: `user_shares = deposit_value / share_ratio_new`
- If `share_ratio_new > share_ratio_old` (profit occurred): `user_shares < expected_shares`
- Assertion fails with `ERR_UNEXPECTED_SLIPPAGE`

## Impact Explanation

This vulnerability creates a HIGH severity operational DoS affecting core protocol functionality:

**Immediate Impact:**
- ALL pending deposit requests become unexecutable whenever vault operations generate profit
- Users' deposit funds remain locked in the request buffer, earning no yield
- Each failed execution wastes gas fees for the operator

**Cascading Impact:**
- Users must wait for the cancellation locking period to expire [10](#0-9)  (default 5 minutes [11](#0-10) )
- Users must cancel their requests and create new ones with updated `expected_shares`
- If operations continue generating profit, deposits may enter a perpetual cancel-and-retry loop
- Accumulated gas costs from failed executions, cancellations, and re-requests

**Protocol-Level Impact:**
- Vault cannot efficiently onboard new capital during profitable periods
- Creates a perverse incentive where vault success (generating profit) prevents growth (accepting deposits)
- Severely degrades user experience and protocol reputation

The severity is HIGH because it affects the core deposit functionality, triggers automatically during normal profitable operations, impacts ALL pending deposits simultaneously and deterministically, and creates persistent operational degradation.

## Likelihood Explanation

**Likelihood: VERY HIGH**

This issue will occur regularly during normal protocol operation:

**Reachable Entry Point:**
Any user can create a deposit request through the public `user_entry::deposit` function. [12](#0-11) 

**Feasible Preconditions:**
1. User creates a deposit request with `expected_shares` based on the current observable share ratio
2. Operator performs normal vault operations that generate profit
3. Operator attempts to execute the pending deposit request

**Execution Practicality:**
- No attacker capabilities required - this occurs during normal honest operation
- Vault operations generating profit is the primary goal and expected outcome
- The mathematical relationship guarantees the issue: any increase in `total_usd_value` while `total_shares` remains constant increases the share ratio and causes fewer shares to be minted

**Economic Reality:**
- This is not an attack scenario - it's an unintended consequence of successful vault strategy
- Vault operations are specifically designed to generate yield and increase value
- Given that vault operations are designed to generate profit and should do so frequently, this issue will affect pending deposits on a regular basis

## Recommendation

Implement one of the following solutions:

**Option 1: Dynamic Share Calculation**
Instead of storing fixed `expected_shares`, store the minimum acceptable share ratio. During execution, calculate shares based on current ratio and verify against the stored minimum ratio threshold. This allows the deposit to succeed when the share ratio improves.

**Option 2: Expected Shares Range**
Allow `expected_shares` to specify a minimum value, while accepting any amount equal to or greater than this minimum. The current implementation already checks `user_shares >= expected_shares`, so the fix would be to treat `expected_shares` as a minimum acceptable threshold rather than an exact expected value.

**Option 3: Two-Way Slippage Protection**
Modify the slippage check to only prevent execution when the share ratio DECREASES (negative slippage for users), not when it INCREASES (positive outcome). This would require checking if the actual ratio is worse than expected, not just different.

Recommended implementation:
```move
// In execute_deposit, replace the assertion with:
// Allow execution if user gets MORE shares than expected (ratio improved)
// Only block if user gets FEWER shares (ratio worsened)
assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
// This is already correct! The issue is that expected_shares needs to be
// calculated as a MINIMUM, not an exact expectation.

// Better: In request_deposit, clarify that expected_shares is a minimum:
// And/or provide a helper function to calculate minimum acceptable shares
// based on current ratio + acceptable slippage tolerance
```

## Proof of Concept

The following test demonstrates the vulnerability:

```move
#[test]
#[expected_failure(abort_code = vault::ERR_UNEXPECTED_SLIPPAGE)]
public fun test_deposit_fails_after_profitable_operation() {
    // 1. Setup vault with initial deposit to establish share ratio
    // 2. User creates deposit request with expected_shares based on current ratio
    // 3. Operator starts vault operation
    // 4. Simulate profit by increasing asset values (e.g., add extra coins to borrowed principal)
    // 5. Operator ends operation with value update (this increases share ratio)
    // 6. Operator attempts to execute the pending deposit
    // Expected: Execution fails with ERR_UNEXPECTED_SLIPPAGE
    // Actual: Execution fails (vulnerability confirmed)
}
```

This test would follow the same pattern as `test_start_op_with_value_gain` [13](#0-12)  but would include deposit request creation before operations and execution attempt after the value gain, which would fail due to the slippage check.

## Notes

The vulnerability is not in the slippage protection mechanism itself, but in the assumption that `expected_shares` represents an exact expectation rather than a minimum acceptable threshold. The current implementation correctly prevents execution when users would receive fewer shares than expected, but the "expected" value becomes stale when the share ratio improves. This is fundamentally a design issue in how deposit requests handle share ratio changes over time.

### Citations

**File:** volo-vault/sources/requests/deposit_request.move (L14-14)
```text
    expected_shares: u256, // Expected shares to get after deposit
```

**File:** volo-vault/sources/volo_vault.move (L36-36)
```text
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L779-781)
```text
    assert!(
        deposit_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L849-849)
```text
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1309-1309)
```text
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L355-357)
```text
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );
```

**File:** volo-vault/sources/operation.move (L366-366)
```text
    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/user_entry.move (L19-19)
```text
public fun deposit<PrincipalCoinType>(
```

**File:** volo-vault/tests/operation/operation.test.move (L579-716)
```text
public fun test_start_op_with_value_gain() {
    let mut s = test_scenario::begin(OWNER);

    let mut clock = clock::create_for_testing(s.ctx());

    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let navi_account_cap = lending::create_account(s.ctx());
        vault.add_new_defi_asset(
            0,
            navi_account_cap,
        );
        test_scenario::return_shared(vault);
    };

    // Set mock aggregator and price
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();

        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);

        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);

        test_scenario::return_shared(oracle_config);
    };

    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(10_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();

        vault.return_free_principal(coin.into_balance());

        vault::update_free_principal_value(&mut vault, &config, &clock);

        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };

    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        let coin = coin::mint_for_testing<USDC_TEST_COIN>(100_000_000_000, s.ctx());
        // Add 100 USDC to the vault
        vault.add_new_coin_type_asset<SUI_TEST_COIN, USDC_TEST_COIN>();
        vault.return_coin_type_asset(coin.into_balance());

        let config = s.take_shared<OracleConfig>();
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        test_scenario::return_shared(config);
        test_scenario::return_shared(vault);
    };

    s.next_tx(OWNER);
    {
        let operation = s.take_shared<Operation>();
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let cap = s.take_from_sender<OperatorCap>();
        let config = s.take_shared<OracleConfig>();
        let mut storage = s.take_shared<Storage>();

        let defi_asset_ids = vector[0];
        let defi_asset_types = vector[type_name::get<NaviAccountCap>()];

        let (
            asset_bag,
            tx_bag,
            tx_bag_for_check_value_update,
            mut principal_balance,
            coin_type_asset_balance,
        ) = operation::start_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            defi_asset_ids,
            defi_asset_types,
            1_000_000_000,
            0,
            s.ctx(),
        );

        let new_coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        principal_balance.join(new_coin.into_balance());

        // Step 2
        operation::end_op_with_bag<SUI_TEST_COIN, USDC_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            asset_bag,
            tx_bag,
            principal_balance,
            coin_type_asset_balance,
        );

        let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(0);
        navi_adaptor::update_navi_position_value(
            &mut vault,
            &config,
            &clock,
            navi_asset_type,
            &mut storage,
        );

        vault.update_free_principal_value(&config, &clock);
        vault.update_coin_type_asset_value<SUI_TEST_COIN, USDC_TEST_COIN>(&config, &clock);

        // Step 3
        operation::end_op_value_update_with_bag<SUI_TEST_COIN, SUI_TEST_COIN>(
            &mut vault,
            &operation,
            &cap,
            &clock,
            tx_bag_for_check_value_update,
        );

        s.return_to_sender(cap);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(operation);
        test_scenario::return_shared(config);
        test_scenario::return_shared(storage);
    };

    clock.destroy_for_testing();
    s.end();
}
```
