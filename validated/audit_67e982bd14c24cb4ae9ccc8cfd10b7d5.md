# Audit Report

## Title
Deposit DoS via Share Ratio Inflation Between Request and Execution

## Summary
The vault's two-phase deposit mechanism contains a time-of-check-time-of-use (TOCTOU) vulnerability where `expected_shares` is fixed at request time but validated against execution-time share ratios. When operators perform legitimate compounding via `deposit_by_operator` between these steps, the share ratio increases without minting new shares, causing all pending deposits to fail slippage validation and preventing deposit execution.

## Finding Description

The vulnerability exists in the deposit flow's separation of request submission from execution. When users request deposits, the `DepositRequest` struct stores `expected_shares` as a fixed value based on the current share ratio. [1](#0-0) 

The `deposit_by_operator` function allows operators to add principal to the vault, increasing `total_usd_value` without minting new shares, which increases the share ratio. [2](#0-1)  This function is used for legitimate compounding of vault profits.

When `execute_deposit` is called, it calculates user shares using the CURRENT share ratio at execution time via `get_share_ratio(clock)`. [3](#0-2)  The calculated shares are then derived from the new USD value deposited divided by this execution-time ratio. [4](#0-3) 

The slippage check enforces that calculated shares must meet or exceed expected shares. [5](#0-4)  When the share ratio increases between request and execution, the calculated shares will be less than expected shares, causing this assertion to fail and reverting the transaction.

Both functions require only `VAULT_NORMAL_STATUS`, meaning they can be called sequentially without mutex protection. [6](#0-5) [7](#0-6) [8](#0-7) 

The share ratio calculation confirms: `share_ratio = total_usd_value / total_shares`. [9](#0-8) 

**Mathematical proof:**
- At request time: `expected_shares = deposit_usd_value / R0` where R0 is the initial share ratio
- After compounding via `deposit_by_operator`: total_usd_value increases while total_shares remains unchanged, so `R1 = (total_usd_value + compound_amount) / total_shares` where `R1 > R0`
- At execution: `user_shares = deposit_usd_value / R1`
- Since `R1 > R0`: `user_shares = deposit_usd_value / R1 < deposit_usd_value / R0 = expected_shares`
- Slippage check fails: `user_shares >= expected_shares → FALSE`

## Impact Explanation

This vulnerability causes denial-of-service on core deposit functionality during normal vault operations. All pending deposit requests become unexecutable when the share ratio increases through routine compounding.

The test suite demonstrates this behavior, showing the share ratio doubling from 1 to 2 after first compound. [10](#0-9)  Then quadrupling from 2 to 4 after second compound. [11](#0-10) 

**Quantified damage:**
- ALL pending deposits with `expected_shares` calculated at pre-compound ratios fail execution
- Users must wait `locking_time_for_cancel_request` (default 5 minutes) before canceling and resubmitting [12](#0-11) 
- During periods of frequent compounding, deposits may repeatedly fail
- This breaks core user flow and prevents vault growth

The severity is High because this affects core protocol functionality, occurs during routine operations (not attacks), and can persist if compounding is frequent.

## Likelihood Explanation

The likelihood is HIGH because:

1. **No malicious actor required** - This occurs during normal operator activities where operators perform legitimate compounding operations via `deposit_by_operator` to reinvest vault profits. [13](#0-12) 

2. **Routine operation** - The test suite demonstrates that `deposit_by_operator` is a standard compounding mechanism. [14](#0-13) 

3. **No constraints** - Both `execute_deposit` and `deposit_by_operator` require only `VAULT_NORMAL_STATUS`, with no mutex or sequencing protection preventing this scenario.

4. **Inevitable occurrence** - Compounding is a routine operational activity that occurs whenever the vault generates profits that need to be reinvested, making this collision highly probable in active vaults.

## Recommendation

Implement one of the following fixes:

**Option 1: Store share ratio at request time**
Store the share ratio in `DepositRequest` at request time and use it for share calculation during execution, ensuring consistent valuation.

**Option 2: Recalculate expected_shares at execution**
Remove the `expected_shares` slippage check and instead use `max_shares_received` (which is already passed to `execute_deposit`) to protect against positive slippage only.

**Option 3: Add operation sequencing**
Prevent `deposit_by_operator` from being called when there are pending deposit requests, or batch process all pending deposits before allowing compounding.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = vault::ERR_UNEXPECTED_SLIPPAGE)]
public fun test_deposit_dos_via_compound() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and set SUI price to 2U
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    setup_oracle(&mut s, &mut clock);
    
    // User requests deposit: 1 SUI at ratio 1:1, expects 2 shares
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin,
            1_000_000_000, 2_000_000_000, // expected_shares = 2B
            option::none(), &clock, s.ctx()
        );
        
        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Operator compounds, doubling share ratio from 1 to 2
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        
        vault.deposit_by_operator(&clock, &config, coin);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // Execute deposit - FAILS with ERR_UNEXPECTED_SLIPPAGE
    // user_shares = 1 SUI * 2U / ratio(2) = 1 share < expected 2 shares
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        
        vault.execute_deposit(&clock, &config, 0, 2_000_000_000);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This is a design-level vulnerability in the two-phase deposit mechanism, not a malicious attack scenario. The operator is performing legitimate, expected operations (compounding vault profits), but the fixed `expected_shares` value becomes incompatible with the execution-time share ratio. The slippage protection mechanism intended to protect users actually creates a denial-of-service condition during normal vault operations.

### Citations

**File:** volo-vault/sources/requests/deposit_request.move (L5-17)
```text
public struct DepositRequest has copy, drop, store {
    request_id: u64, // Self incremented id (start from 0)
    // ---- Receipt Info ---- //
    receipt_id: address, // Receipt object address
    recipient: address, // Recipient address (only used for check when "with_lock" is true)
    // ---- Vault Info ---- //
    vault_id: address, // Vault address
    // ---- Deposit Info ---- //
    amount: u64, // Amount (of principal) to deposit
    expected_shares: u256, // Expected shares to get after deposit
    // ---- Request Status ---- //
    request_time: u64, // Time when the request is created
}
```

**File:** volo-vault/sources/volo_vault.move (L36-36)
```text
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L813-814)
```text
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L818-821)
```text
    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L841-844)
```text
    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

**File:** volo-vault/sources/volo_vault.move (L848-850)
```text
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
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

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```

**File:** volo-vault/tests/deposit/compound.test.move (L24-26)
```text
#[test]
// [TEST-CASE: Should compound deposit by operator.] @test-case COMPOUND-001
public fun test_compound_deposit_by_operator() {
```

**File:** volo-vault/tests/deposit/compound.test.move (L131-143)
```text
    // Check vault info
    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        // Free principal = 2 SUI = 4U
        // Share ratio = 4U / 2shares = 2
        assert!(vault.free_principal() == 2_000_000_000);
        assert!(vault.total_shares() == 2_000_000_000);
        assert!(vault.get_share_ratio( &clock) == 2_000_000_000);

        test_scenario::return_shared(vault);
    };
```

**File:** volo-vault/tests/deposit/compound.test.move (L163-175)
```text
    // Check vault info
    s.next_tx(OWNER);
    {
        let vault = s.take_shared<Vault<SUI_TEST_COIN>>();

        // Free principal = 4 SUI = 8U
        // Share ratio = 8U / 2shares = 4
        assert!(vault.free_principal() == 4_000_000_000);
        assert!(vault.total_shares() == 2_000_000_000);
        assert!(vault.get_share_ratio( &clock) == 4_000_000_000);

        test_scenario::return_shared(vault);
    };
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
