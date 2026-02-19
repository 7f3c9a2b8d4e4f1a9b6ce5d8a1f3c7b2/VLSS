# Audit Report

## Title
Withdrawal Fee Manipulation Bypasses User Slippage Protection Due to Post-Check Fee Deduction

## Summary
The `expected_amount` slippage protection in withdrawal execution validates the gross withdrawal amount before fee deduction rather than the net amount users receive. This allows admin to increase withdrawal fees after users submit requests, causing users to receive significantly less than their protected expected amount without triggering slippage failures. The issue represents a mis-scoped admin privilege combined with a broken user protection mechanism.

## Finding Description

The vulnerability exists in the withdrawal execution flow due to an ordering issue where fee deduction occurs after the `expected_amount` validation check.

In `execute_withdraw`, the withdrawal amount is calculated from shares and validated against user's `expected_amount` BEFORE fees are applied: [1](#0-0) 

However, the withdrawal fee is then deducted AFTER this validation passes, and users receive the net amount: [2](#0-1) 

The admin can change withdrawal fees at any time without restrictions beyond the fee cap, using only AdminCap authorization: [3](#0-2) [4](#0-3) 

The maximum withdrawal fee is capped at 5% (500 basis points): [5](#0-4) 

Users cannot immediately cancel their withdrawal requests due to a configurable locking period (default 5 minutes): [6](#0-5) [7](#0-6) 

Meanwhile, operators can execute withdrawal requests immediately with no time constraints: [8](#0-7) 

This contrasts sharply with the deposit flow, which correctly protects users by deducting fees BEFORE calculating shares and validating against `expected_shares`: [9](#0-8) 

In deposits, fees are deducted first (lines 830-836), then shares are calculated from the net value (line 844), then validated (lines 849-850). This ensures `expected_shares` protection works correctly even if fees change.

## Impact Explanation

This vulnerability breaks a critical user protection invariant and enables direct financial loss:

**Quantified Impact Scenario:**
- User submits withdrawal request expecting default 0.1% fee (10 bps)
- User sets `expected_amount = 990` tokens (allowing for price slippage)
- Admin increases fee to maximum 5% (500 bps) before execution
- Withdrawal calculation: `amount_to_withdraw = 1000` tokens
- Validation passes: `1000 >= 990` ✓
- Fee deduction: `1000 × 5% = 50` tokens
- User receives: `950` tokens instead of expected ~`999` tokens

The user loses approximately 49 tokens (4.9% of expected value) with no slippage protection triggering. With the 5% fee cap, this represents systematic extraction of up to 4.9% additional value from any pending withdrawal.

The impact is direct fund loss to users through a broken protection mechanism. Users reasonably expect `expected_amount` to protect the net amount they receive, but it only validates the gross pre-fee amount.

## Likelihood Explanation

**High Likelihood** - This vulnerability is trivially exploitable through normal protocol operations:

**Attack Preconditions:**
- Pending withdrawal requests exist (normal protocol state)
- Admin has access to AdminCap (normal operational role)

**Execution Path:**
1. Users submit withdrawal requests via `user_entry::withdraw` with `expected_amount` based on current ~0.1% fees
2. Admin calls `vault_manage::set_withdraw_fee` to increase fees (up to 500 bps)
3. Operator immediately calls `operation::execute_withdraw` 
4. Users receive significantly less than expected without protection triggering
5. Users cannot cancel due to 5-minute locking period

**Realistic Scenarios:**
- Accidental: Admin changes global fee policy without realizing impact on pending requests
- Opportunistic: Admin increases fees when large withdrawal requests are pending
- No technical barriers or complex setup required

The vulnerability stems from mis-scoped admin privileges: admins can change fees affecting pending user requests while users have no effective recourse due to the cancellation lock and immediate operator execution capability.

## Recommendation

**Primary Fix:** Validate `expected_amount` against the NET withdrawal amount after fee deduction:

```move
// In execute_withdraw function, reorder to:

// 1. Calculate gross amount
let amount_to_withdraw = /* existing calculation */;

// 2. Deduct fee FIRST
let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
let net_amount = amount_to_withdraw - fee_amount;

// 3. Validate NET amount against expected_amount
let expected_amount = withdraw_request.expected_amount();
assert!(net_amount >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
assert!(net_amount <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

// 4. Continue with balance splits using net_amount
```

**Alternative/Additional Mitigations:**
1. **Freeze fees for pending requests:** Store the fee rate in the withdrawal request and use that rate during execution
2. **Add timelock to fee changes:** Prevent immediate fee changes, giving users time to cancel
3. **Remove cancellation lock:** Allow immediate cancellation so users can react to fee changes

The primary fix ensures consistency with the deposit flow and makes the `expected_amount` protection work as users reasonably expect.

## Proof of Concept

```move
#[test]
fun test_withdraw_fee_manipulation_bypasses_slippage_protection() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Setup vault with oracle at 2:1 price ratio
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        clock::set_for_testing(&mut clock, 1000);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        test_scenario::return_shared(oracle_config);
    };
    
    // User deposits 1 SUI (gets ~1.998 shares after 0.1% fee)
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin,
            1_000_000_000, 2_000_000_000, option::none(), &clock, s.ctx()
        );
        transfer::public_transfer(coin, OWNER);
        transfer::public_transfer(receipt, OWNER);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(reward_manager);
    };
    
    // Execute deposit
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        vault::update_free_principal_value(&mut vault, &config, &clock);
        vault.execute_deposit(&clock, &config, 0, 2_000_000_000);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    // User requests withdrawal expecting 0.1% fee: expects to receive ~499.5M tokens
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut config = s.take_shared<OracleConfig>();
        let mut receipt = s.take_from_sender<Receipt>();
        clock::set_for_testing(&mut clock, 1000 + 12 * 3600_000);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut config, prices);
        vault.update_free_principal_value(&config, &clock);
        
        // User sets expected_amount=475M (allowing 5% slippage on NET amount)
        user_entry::withdraw(&mut vault, 1_000_000_000, 475_000_000, &mut receipt, &clock, s.ctx());
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        s.return_to_sender(receipt);
    };
    
    // ATTACK: Admin increases fee to 5% (500 bps) before execution
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let admin_cap = s.take_from_sender<AdminCap>();
        vault_manage::set_withdraw_fee(&admin_cap, &mut vault, 500); // 5% fee
        test_scenario::return_shared(vault);
        s.return_to_sender(admin_cap);
    };
    
    // Execute withdrawal with increased fee
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let operation = s.take_shared<Operation>();
        let cap = s.take_from_sender<OperatorCap>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        
        // Execute passes: gross amount 500M >= expected 475M ✓
        operation::execute_withdraw(
            &operation, &cap, &mut vault, &mut reward_manager,
            &clock, &config, 0, 500_000_000, s.ctx()
        );
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        test_scenario::return_shared(operation);
        s.return_to_sender(cap);
        test_scenario::return_shared(reward_manager);
    };
    
    // VERIFY: User receives only 475M instead of expected ~499.5M
    // Net received = 500M - (500M * 5%) = 475M
    // Loss = 499.5M - 475M = 24.5M (~4.9% of expected value)
    s.next_tx(OWNER);
    {
        let received_coin = s.take_from_sender<Coin<SUI_TEST_COIN>>();
        assert!(received_coin.value() == 475_000_000); // User receives only 475M
        // But user expected ~499.5M (with 0.1% fee) - lost ~24.5M to fee increase
        s.return_to_sender(received_coin);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that slippage protection fails when fees change between request and execution, allowing users to receive significantly less than expected without triggering the `ERR_UNEXPECTED_SLIPPAGE` assertion.

### Citations

**File:** volo-vault/sources/volo_vault.move (L30-33)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L35-36)
```text
const DEFAULT_LOCKING_TIME_FOR_WITHDRAW: u64 = 12 * 3600 * 1_000; // 12 hours to withdraw after a deposit
const DEFAULT_LOCKING_TIME_FOR_CANCEL_REQUEST: u64 = 5 * 60 * 1_000; // 5 minutes to cancel a submitted request
```

**File:** volo-vault/sources/volo_vault.move (L508-516)
```text
public(package) fun set_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    fee: u64,
) {
    self.check_version();
    assert!(fee <= MAX_WITHDRAW_FEE_RATE, ERR_EXCEED_LIMIT);
    self.withdraw_fee_rate = fee;
    emit(WithdrawFeeChanged { vault_id: self.vault_id(), fee: fee })
}
```

**File:** volo-vault/sources/volo_vault.move (L828-850)
```text
    let coin_amount = deposit_request.amount();

    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);

    self.free_principal.join(coin_balance);
    update_free_principal_value(self, config, clock);

    let total_usd_value_after = self.get_total_usd_value(clock);
    let new_usd_value_deposited = total_usd_value_after - total_usd_value_before;

    let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
    let expected_shares = deposit_request.expected_shares();
    // Negative slippage is determined by the "expected_shares"
    // Positive slippage is determined by the "max_shares_received"
    assert!(user_shares > 0, ERR_ZERO_SHARE);
    assert!(user_shares >= expected_shares, ERR_UNEXPECTED_SLIPPAGE);
    assert!(user_shares <= max_shares_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L964-967)
```text
    assert!(
        withdraw_request.request_time() + self.locking_time_for_cancel_request <= clock.timestamp_ms(),
        ERR_REQUEST_CANCEL_TIME_NOT_REACHED,
    );
```

**File:** volo-vault/sources/volo_vault.move (L1012-1030)
```text
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;

    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1039-1051)
```text
    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);

    emit(WithdrawExecuted {
        request_id: request_id,
        receipt_id: withdraw_request.receipt_id(),
        recipient: withdraw_request.recipient(),
        vault_id: self.id.to_address(),
        shares: shares_to_withdraw,
        amount: amount_to_withdraw - fee_amount,
    });
```

**File:** volo-vault/sources/manage.move (L50-56)
```text
public fun set_withdraw_fee<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    withdraw_fee: u64,
) {
    vault.set_withdraw_fee(withdraw_fee);
}
```

**File:** volo-vault/sources/operation.move (L449-479)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let withdraw_request = vault.withdraw_request(request_id);
    reward_manager.update_receipt_reward(vault, withdraw_request.receipt_id());

    let (withdraw_balance, recipient) = vault.execute_withdraw(
        clock,
        config,
        request_id,
        max_amount_received,
    );

    if (recipient != address::from_u256(0)) {
        transfer::public_transfer(withdraw_balance.into_coin(ctx), recipient);
    } else {
        vault.add_claimable_principal(withdraw_balance);
    }
}
```
