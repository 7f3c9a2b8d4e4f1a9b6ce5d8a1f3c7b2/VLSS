# Audit Report

## Title
Withdraw Fee Deduction After Slippage Check Breaks User Protection

## Summary
The `execute_withdraw()` function in the Volo vault validates slippage protection against the pre-fee withdrawal amount, then deducts fees afterward. This causes users to systematically receive less than their specified `expected_amount`, breaking the fundamental slippage protection mechanism on every withdrawal when fees are non-zero.

## Finding Description

The vulnerability exists in the withdrawal execution flow where the order of operations incorrectly validates slippage protection before deducting fees.

**Vulnerable Flow in `execute_withdraw()`:**

The function first calculates `amount_to_withdraw` based on shares and the current oracle price. [1](#0-0) 

The slippage check then validates this PRE-FEE amount against the user's `expected_amount`. [2](#0-1) 

Only AFTER the slippage check passes are withdrawal fees deducted from the withdrawal amount. [3](#0-2) 

The function returns the POST-FEE balance to the user, which is less than the `expected_amount` that passed the slippage check. [4](#0-3) 

**Fee Configuration:**

Withdrawal fees have a default of 10 basis points (0.1%) and a maximum of 500 basis points (5%). [5](#0-4) 

**Critical Asymmetry with Deposit Flow:**

The deposit flow correctly handles this by deducting fees BEFORE the slippage-protected calculation. In `execute_deposit()`, fees are deducted first from the incoming coin balance. [6](#0-5) 

The POST-FEE balance is then added to the vault's principal. [7](#0-6) 

USD value is calculated from this POST-FEE amount, shares are derived from it, and the slippage check validates these POST-FEE shares. [8](#0-7) 

This asymmetry confirms the withdrawal flow is incorrectly implemented.

**Test Masking:**

The standard test initialization function sets both deposit and withdrawal fees to zero, completely masking this vulnerability during testing. [9](#0-8) 

## Impact Explanation

**Direct Financial Impact:**
- With default 10bp fee: Users receive 99.9% of their `expected_amount` (0.1% systematic loss)
- With maximum 500bp fee: Users receive 95% of their `expected_amount` (5% systematic loss)

**Concrete Example:**
- User sets `expected_amount = 1,000,000` tokens as their minimum acceptable withdrawal
- `amount_to_withdraw` calculates to 1,000,000 tokens
- Slippage check passes: `1,000,000 >= 1,000,000` ✓
- Fee deducted (at 10bp): `fee_amount = 1,000,000 × 10 / 10,000 = 1,000` tokens
- User receives: `1,000,000 - 1,000 = 999,000` tokens
- **User expected minimum 1,000,000 but received 999,000**

**Who is Affected:**
All vault users performing withdrawals in production environments where fees are non-zero (which is the default configuration). The slippage protection parameter becomes misleading as users consistently receive less than their specified minimum.

## Likelihood Explanation

**Probability: 100% (Certain)**

This vulnerability triggers on every single withdrawal execution in production:

- **Reachable Entry Point**: Users call public functions that create withdrawal requests, which are then executed by operators
- **No Special Preconditions**: Only requires normal vault operation with non-zero fees, which is the production default configuration (10bp)
- **No Attack Complexity**: This is not an adversarial exploit but affects all legitimate user withdrawals
- **Guaranteed Occurrence**: Production vaults will use non-zero fees by default, making this certain to impact every user withdrawal

The issue occurs naturally during normal protocol operation and does not require any attacker action or special conditions.

## Recommendation

Modify `execute_withdraw()` to follow the same pattern as `execute_deposit()`: deduct fees BEFORE the slippage check, or validate slippage against the post-fee amount.

**Option 1 (Recommended)**: Calculate the post-fee amount and validate slippage against it:

```move
// Calculate pre-fee amount
let amount_to_withdraw = ... // existing calculation

// Calculate and deduct fee FIRST
let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
let post_fee_amount = amount_to_withdraw - fee_amount;

// Validate slippage against POST-FEE amount
assert!(post_fee_amount >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
assert!(post_fee_amount <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);

// Continue with withdrawal using post_fee_amount
```

**Option 2**: Adjust `expected_amount` upward to account for fees before the comparison (less recommended as it changes the semantic meaning of the parameter).

## Proof of Concept

```move
#[test]
public fun test_withdraw_fee_breaks_slippage_protection() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    init_vault::init_create_reward_manager<SUI_TEST_COIN>(&mut s);
    
    // Set non-zero withdraw fee (100bp = 1%)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let admin_cap = s.take_from_sender<AdminCap>();
        vault_manage::set_withdraw_fee(&admin_cap, &mut vault, 100); // 1% fee
        test_scenario::return_shared(vault);
        s.return_to_sender(admin_cap);
    };
    
    // Setup oracle prices
    s.next_tx(OWNER);
    {
        let mut oracle_config = s.take_shared<OracleConfig>();
        test_helpers::set_aggregators(&mut s, &mut clock, &mut oracle_config);
        clock::set_for_testing(&mut clock, 1000);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut oracle_config, prices);
        test_scenario::return_shared(oracle_config);
    };
    
    // Deposit 1,000,000,000 tokens
    s.next_tx(OWNER);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut reward_manager = s.take_shared<RewardManager<SUI_TEST_COIN>>();
        let (_request_id, receipt, coin) = user_entry::deposit(
            &mut vault, &mut reward_manager, coin,
            1_000_000_000, 2_000_000_000, option::none(),
            &clock, s.ctx()
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
    
    // Request withdrawal with expected_amount = 1,000,000,000 (user expects minimum 1B tokens)
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let mut config = s.take_shared<OracleConfig>();
        let mut receipt = s.take_from_sender<Receipt>();
        clock::set_for_testing(&mut clock, 1000 + 12 * 3600_000);
        let prices = vector[2 * ORACLE_DECIMALS, 1 * ORACLE_DECIMALS, 100_000 * ORACLE_DECIMALS];
        test_helpers::set_prices(&mut s, &mut clock, &mut config, prices);
        vault.update_free_principal_value(&config, &clock);
        user_entry::withdraw(&mut vault, 1_000_000_000, 1_000_000_000, &mut receipt, &clock, s.ctx());
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
        s.return_to_sender(receipt);
    };
    
    // Execute withdrawal - slippage check passes but user receives less than expected
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        let (withdraw_balance, _recipient) = vault.execute_withdraw(&clock, &config, 0, 1_000_000_000);
        
        // VULNERABILITY: User specified expected_amount = 1,000,000,000
        // But receives only 990,000,000 (1% fee deducted)
        let received_amount = withdraw_balance.value();
        assert!(received_amount == 990_000_000, 0); // User receives 99% due to 1% fee
        assert!(received_amount < 1_000_000_000, 1); // User receives LESS than expected_amount!
        
        transfer::public_transfer(withdraw_balance.into_coin(s.ctx()), _recipient);
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

This test demonstrates that when a user sets `expected_amount = 1,000,000,000` as their minimum acceptable withdrawal, they actually receive only `990,000,000` tokens (with 1% fee), breaking the slippage protection guarantee.

## Notes

This vulnerability represents a fundamental breach of the slippage protection mechanism. While the impact per transaction may seem small with the default 10bp fee, it represents a systematic violation of user expectations and trust in the protocol's protection mechanisms. With the maximum 500bp fee, users could receive 5% less than their specified minimum, which is highly significant.

The vulnerability is particularly insidious because:
1. It's masked in the test suite (fees set to zero)
2. It affects 100% of withdrawals in production (default 10bp fee)
3. It breaks a core security guarantee (slippage protection)
4. Users have no way to protect themselves (cannot set `expected_amount` higher to compensate)

### Citations

**File:** volo-vault/sources/volo_vault.move (L30-33)
```text
const DEPOSIT_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const WITHDRAW_FEE_RATE: u64 = 10; // default 10bp (0.1%)
const MAX_DEPOSIT_FEE_RATE: u64 = 500; // max 500bp (5%)
const MAX_WITHDRAW_FEE_RATE: u64 = 500; // max 500bp (5%)
```

**File:** volo-vault/sources/volo_vault.move (L830-836)
```text
    let deposit_fee = coin_amount * self.deposit_fee_rate / RATE_SCALING;

    // let actual_deposit_amount = coin_amount - deposit_fee;
    let mut coin_balance = coin.into_balance();
    // Split the deposit fee to the fee collected
    let deposit_fee_balance = coin_balance.split(deposit_fee as u64);
    self.deposit_withdraw_fee_collected.join(deposit_fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L838-838)
```text
    self.free_principal.join(coin_balance);
```

**File:** volo-vault/sources/volo_vault.move (L841-850)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1012-1022)
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
```

**File:** volo-vault/sources/volo_vault.move (L1024-1030)
```text
    // Check the slippage (less than 100bps)
    let expected_amount = withdraw_request.expected_amount();

    // Negative slippage is determined by the "expected_amount"
    // Positive slippage is determined by the "max_amount_received"
    assert!(amount_to_withdraw >= expected_amount, ERR_UNEXPECTED_SLIPPAGE);
    assert!(amount_to_withdraw <= max_amount_received, ERR_UNEXPECTED_SLIPPAGE);
```

**File:** volo-vault/sources/volo_vault.move (L1039-1042)
```text
    // Protocol fee
    let fee_amount = amount_to_withdraw * self.withdraw_fee_rate / RATE_SCALING;
    let fee_balance = withdraw_balance.split(fee_amount as u64);
    self.deposit_withdraw_fee_collected.join(fee_balance);
```

**File:** volo-vault/sources/volo_vault.move (L1076-1076)
```text
    (withdraw_balance, recipient)
```

**File:** volo-vault/tests/init_vault.move (L55-56)
```text
        vault.set_deposit_fee(0);
        vault.set_withdraw_fee(0);
```
