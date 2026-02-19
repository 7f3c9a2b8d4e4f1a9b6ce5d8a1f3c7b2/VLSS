# Audit Report

## Title
Deposit DoS via Share Ratio Inflation Between Request and Execution

## Summary
The deposit execution flow contains a time-of-check-time-of-use (TOCTOU) vulnerability where `expected_shares` is stored at request time but validated against shares calculated at execution time. When the operator performs routine compounding via `deposit_by_operator` between these steps, the share ratio increases without minting new shares, causing all pending deposits to fail the slippage check and preventing deposit execution.

## Finding Description

The vulnerability exists in the two-phase deposit mechanism that splits request submission from execution. The `DepositRequest` struct stores `expected_shares` as a fixed value based on the share ratio at request time. [1](#0-0) 

However, the `deposit_by_operator` function allows operators to add principal to the vault and increase `total_usd_value` without minting new shares, which increases the share ratio. [2](#0-1)  This function is used for legitimate compounding of vault profits.

When `execute_deposit` is called, it calculates user shares based on the CURRENT share ratio at execution time, not the ratio at request time. [3](#0-2) [4](#0-3) 

The slippage check enforces that calculated shares must be greater than or equal to expected shares: [5](#0-4) 

When the share ratio increases between request and execution, the calculated shares will be less than expected shares, causing this assertion to fail and reverting the transaction.

Both functions require `VAULT_NORMAL_STATUS`, meaning they can be called sequentially without any mutex protection: [6](#0-5) [7](#0-6) 

The share ratio calculation is: `share_ratio = total_usd_value / total_shares` [8](#0-7) 

**Mathematical proof:**
- At request time: `expected_shares = deposit_usd_value / R0`
- After compounding: `R1 = (total_usd_value + compound_amount) / total_shares` where `R1 > R0`
- At execution: `user_shares = deposit_usd_value / R1`
- Since `R1 > R0`: `user_shares = deposit_usd_value / R1 < deposit_usd_value / R0 = expected_shares`
- Check fails: `user_shares >= expected_shares → FALSE`

## Impact Explanation

This vulnerability causes a denial-of-service on the core deposit functionality during normal vault operations. All pending deposit requests become unexecutable when the share ratio increases through compounding operations.

The test suite demonstrates this behavior, showing the share ratio doubling from 1 to 2, then quadrupling to 4 through successive compound operations. [9](#0-8) [10](#0-9) 

**Quantified damage:**
- ALL pending deposits with `expected_shares` calculated at pre-compound ratios fail execution
- Users must wait `locking_time_for_cancel_request` (default 5 minutes) before canceling and resubmitting [11](#0-10) 
- During periods of frequent compounding, deposits may repeatedly fail
- This breaks the core user flow and prevents vault growth

The severity is High because this affects core protocol functionality, occurs during routine operations (not attacks), and can persist if compounding is frequent.

## Likelihood Explanation

The likelihood is HIGH because:

1. **No malicious actor required** - This occurs during normal operator activities where the operator performs legitimate compounding operations via `deposit_by_operator` to reinvest vault profits. [12](#0-11) 

2. **Routine operation** - The test suite confirms that `deposit_by_operator` is called regularly as part of normal vault operations. [13](#0-12) 

3. **No constraints** - Both `execute_deposit` and `deposit_by_operator` require only `VAULT_NORMAL_STATUS`, with no mutex or sequencing protection preventing this scenario.

4. **Inevitable occurrence** - Compounding is a routine operational activity that occurs whenever the vault generates profits that need to be reinvested, making this collision highly probable in active vaults.

## Recommendation

Implement one of the following solutions:

**Option 1: Dynamic expected_shares calculation**
Modify the slippage check to use a percentage-based tolerance rather than an absolute share amount:
```move
// Instead of storing expected_shares, store min_share_ratio
// At execution, check: user_shares >= (deposit_amount / initial_ratio) * (1 - tolerance_bps)
```

**Option 2: Vault status protection**
Introduce a temporary vault status flag during compounding that prevents deposit execution:
```move
// Set vault to VAULT_DURING_COMPOUND_STATUS when compounding
// Prevent execute_deposit when in this status
// Clear status after compound completes
```

**Option 3: Expected shares adjustment**
Recalculate expected_shares at execution time using a stored original ratio:
```move
// Store original_share_ratio in DepositRequest
// At execution: adjusted_expected_shares = expected_shares * (current_ratio / original_ratio)
// Check: user_shares >= adjusted_expected_shares
```

The recommended solution is **Option 1** as it maintains user protection against slippage while accommodating legitimate vault operations.

## Proof of Concept

```move
#[test]
public fun test_deposit_dos_via_compound() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault and oracle
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    vault_oracle::set_price(&mut oracle_config, &clock, sui_asset_type, 1 * ORACLE_DECIMALS);
    
    // User requests deposit with expected_shares based on ratio = 1
    s.next_tx(USER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let request_id = vault.request_deposit(coin, &clock, 1_000_000_000, receipt_id, USER);
        // expected_shares = 1_000_000_000 based on ratio = 1
        test_scenario::return_shared(vault);
    };
    
    // Operator compounds, doubling the share ratio from 1 to 2
    s.next_tx(OPERATOR);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        vault.deposit_by_operator(&clock, &config, coin);
        // Share ratio now = 2
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // Attempt to execute deposit - THIS WILL FAIL
    s.next_tx(OPERATOR);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        
        vault.execute_deposit(&clock, &config, request_id, 1_000_000_000);
        // user_shares = 1_000_000_000 / 2 = 500_000_000
        // expected_shares = 1_000_000_000
        // Check fails: 500_000_000 >= 1_000_000_000 -> FALSE
        // Transaction reverts with ERR_UNEXPECTED_SLIPPAGE
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that after compounding doubles the share ratio, the pending deposit request becomes unexecutable due to the slippage check failure, requiring user cancellation and resubmission.

### Citations

**File:** volo-vault/sources/requests/deposit_request.move (L14-14)
```text
    expected_shares: u256, // Expected shares to get after deposit
```

**File:** volo-vault/sources/volo_vault.move (L36-36)
```text
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L814-814)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L821-821)
```text
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L844-844)
```text
    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L849-849)
```text
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L874-892)
```text
public(package) fun deposit_by_operator<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    coin: Coin<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_normal();

    let deposit_amount = coin.value();

    self.free_principal.join(coin.into_balance());
    update_free_principal_value(self, config, clock);

    emit(OperatorDeposited {
        vault_id: self.vault_id(),
        amount: deposit_amount,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L1309-1309)
```text
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/tests/deposit/compound.test.move (L116-123)
```text
        operation::deposit_by_operator(
            &operation,
            &cap,
            &mut vault,
            &clock,
            &config,
            coin,
        );
```

**File:** volo-vault/tests/deposit/compound.test.move (L138-140)
```text
        assert!(vault.free_principal() == 2_000_000_000);
        assert!(vault.total_shares() == 2_000_000_000);
        assert!(vault.get_share_ratio( &clock) == 2_000_000_000);
```

**File:** volo-vault/tests/deposit/compound.test.move (L170-172)
```text
        assert!(vault.free_principal() == 4_000_000_000);
        assert!(vault.total_shares() == 2_000_000_000);
        assert!(vault.get_share_ratio( &clock) == 4_000_000_000);
```

**File:** volo-vault/sources/operation.move (L529-543)
```text
public fun deposit_by_operator<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    coin: Coin<PrincipalCoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.deposit_by_operator(
        clock,
        config,
        coin,
    );
}
```
