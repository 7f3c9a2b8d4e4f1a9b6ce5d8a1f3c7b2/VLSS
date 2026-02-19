# Audit Report

## Title
Division by Zero in Deposit Execution Due to Zero Share Ratio After Total Vault Loss

## Summary
When the vault experiences a complete loss of asset value (within the configured loss tolerance), the share ratio becomes zero while shares remain outstanding. This causes a division by zero error when attempting to execute pending deposits, creating a permanent denial-of-service condition where user funds become stuck in the deposit request buffer.

## Finding Description

The vulnerability exists in the interaction between share ratio calculation and deposit execution logic:

**Root Cause - Zero Share Ratio Calculation:**

In `get_share_ratio()`, when `total_shares > 0` but `total_usd_value = 0`, the function returns zero [1](#0-0) . The calculation at line 1309 evaluates to `vault_utils::div_d(0, total_shares) = 0 * DECIMALS / total_shares = 0`.

**Division by Zero Location:**

In `execute_deposit()`, the zero share ratio is used as a divisor [2](#0-1) . The `vault_utils::div_d()` function performs `value * DECIMALS / divisor` [3](#0-2) , which becomes `new_usd_value_deposited * DECIMALS / 0`, causing a transaction abort.

**How Total Value Can Reach Zero:**

The vault's loss tolerance mechanism allows assets to reach zero value. The loss tolerance check only validates that cumulative losses don't exceed a configured limit per epoch [4](#0-3) . When `loss_tolerance` is set to the maximum value of 10,000 basis points (100%) [5](#0-4) , the calculation `loss_limit = cur_epoch_loss_base_usd_value * 10_000 / 10_000` permits complete value loss.

During operation completion, if the total value reaches zero within the loss tolerance, the vault returns to NORMAL status [6](#0-5) . Additionally, asset values can be set to zero without any validation in `finish_update_asset_value()` [7](#0-6) .

**Why Existing Protections Fail:**

The `execute_deposit()` function requires the vault to be in NORMAL status but does not validate that the share ratio is non-zero before using it as a divisor [8](#0-7) . While line 848 asserts `user_shares > 0`, this check never executes because the division by zero abort occurs first at line 844.

## Impact Explanation

**Denial of Service:**
- All pending deposit requests become permanently unexecutable due to the division by zero abort
- Users cannot retrieve their deposited funds from the `deposit_coin_buffer`
- The vault becomes effectively frozen for deposit operations
- New deposits can be created but never executed, accumulating stuck funds

**Affected Parties:**
- Users with pending deposit requests have their funds locked in the buffer
- The protocol cannot process any deposits until the vault's total value is somehow restored
- This affects all users attempting to deposit during this state

**Value at Risk:**
- All coins held in `deposit_coin_buffer` become inaccessible
- The amount at risk depends on the volume of pending deposits when the condition occurs

**Severity Justification (Medium-High):**
- Requires an extreme precondition (100% value loss) but this is realistic in DeFi given historical exploits
- Impact is severe (permanent DoS) affecting all deposit operations
- Recovery requires external intervention (e.g., admin depositing value to restore share ratio)
- Withdrawals may remain functional if implemented differently

## Likelihood Explanation

**Feasibility Conditions:**
1. Vault must have outstanding shares (`total_shares > 0`)
2. All vault assets must reach zero USD value
3. The loss must be within the configured `loss_tolerance` limit
4. At least one pending deposit request must exist

**Realistic Scenarios:**
- External protocol exploit causing 100% loss (e.g., Navi, Suilend, or Cetus position compromise)
- Oracle failure reporting zero prices for all vault assets
- Liquidation cascade in integrated lending protocols
- Smart contract vulnerability in an external DeFi protocol

**Probability Assessment:**
- Medium probability given DeFi's history of protocol exploits and failures
- The vault's integration with multiple external protocols (Navi, Suilend, Cetus, Momentum) increases the attack surface
- Loss tolerance configuration explicitly permits up to 100% loss (MAX_LOSS_TOLERANCE = 10,000 basis points)
- Not directly attackable by malicious users, but can occur through operational risks

## Recommendation

Add a validation check in `execute_deposit()` to ensure the share ratio is non-zero before using it as a divisor:

```move
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    // ... existing code ...
    
    let share_ratio_before = self.get_share_ratio(clock);
    
    // Add this validation
    assert!(share_ratio_before > 0, ERR_ZERO_SHARE_RATIO);
    
    // ... rest of function ...
}
```

Additionally, consider:
1. Adding a minimum total USD value requirement before allowing vault to return to NORMAL status
2. Implementing a more conservative maximum loss tolerance (e.g., 50% instead of 100%)
3. Adding validation in `finish_update_asset_value()` to prevent setting asset values to zero when shares are outstanding

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = sui::types::EArithmeticError)]
public fun test_division_by_zero_after_total_loss() {
    let mut s = test_scenario::begin(OWNER);
    let mut clock = clock::create_for_testing(s.ctx());
    
    // Initialize vault and create initial deposit
    init_vault::init_vault(&mut s, &mut clock);
    init_vault::init_create_vault<SUI_TEST_COIN>(&mut s);
    
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        // Set loss tolerance to maximum (100%)
        vault.set_loss_tolerance(10_000);
        
        // Execute initial deposit to create shares
        // ... (initial deposit execution code)
        
        // Simulate 100% loss by setting all asset values to 0
        // This is within the 100% loss tolerance
        vault.finish_update_asset_value(
            string::utf8(b"free_principal"),
            0, // zero USD value
            clock.timestamp_ms()
        );
        
        // Now total_shares > 0 but total_usd_value = 0
        assert!(vault.total_shares() > 0);
        assert!(vault.get_total_usd_value(&clock) == 0);
        
        test_scenario::return_shared(vault);
    };
    
    // Create a new deposit request
    s.next_tx(ALICE);
    {
        let coin = coin::mint_for_testing<SUI_TEST_COIN>(1_000_000_000, s.ctx());
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        
        let (_request_id, receipt, _) = user_entry::deposit(
            &mut vault,
            coin,
            1_000_000_000,
            1,
            option::none(),
            &clock,
            s.ctx(),
        );
        
        transfer::public_transfer(receipt, ALICE);
        test_scenario::return_shared(vault);
    };
    
    // Attempt to execute deposit - should fail with division by zero
    s.next_tx(OWNER);
    {
        let mut vault = s.take_shared<Vault<SUI_TEST_COIN>>();
        let config = s.take_shared<OracleConfig>();
        
        // This will abort with division by zero (EArithmeticError)
        vault.execute_deposit(&clock, &config, 0, 10_000_000_000);
        
        test_scenario::return_shared(vault);
        test_scenario::return_shared(config);
    };
    
    clock.destroy_for_testing();
    s.end();
}
```

## Notes

This vulnerability demonstrates a critical edge case in the vault's accounting system where extreme loss scenarios (permitted by the loss tolerance configuration) can lead to operational failures. The division by zero is a direct consequence of allowing `total_usd_value` to reach zero while `total_shares` remains positive. While the precondition is extreme, the explicit allowance of 100% loss tolerance and the vault's integration with multiple external DeFi protocols make this scenario realistic in practice. The fix is straightforward: add validation to prevent operations when the share ratio is zero, and consider implementing additional safeguards to prevent the vault from reaching this state.

### Citations

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```

**File:** volo-vault/sources/volo_vault.move (L806-872)
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

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);

    let deposit_request = *self.request_buffer.deposit_requests.borrow(request_id);
    assert!(deposit_request.vault_id() == self.id.to_address(), ERR_VAULT_ID_MISMATCH);

    // Get the coin from the buffer
    let coin = self.request_buffer.deposit_coin_buffer.remove(request_id);
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

    // Update total shares in the vault
    self.total_shares = self.total_shares + user_shares;

    emit(DepositExecuted {
        request_id: request_id,
        receipt_id: deposit_request.receipt_id(),
        recipient: deposit_request.recipient(),
        vault_id: self.id.to_address(),
        amount: coin_amount,
        shares: user_shares,
    });

    let vault_receipt = &mut self.receipts[deposit_request.receipt_id()];
    vault_receipt.update_after_execute_deposit(
        deposit_request.amount(),
        user_shares,
        clock.timestamp_ms(),
    );

    self.delete_deposit_request(request_id);
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
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

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
```

**File:** volo-vault/tests/tolerance.test.move (L17-17)
```text
const MAX_LOSS_TOLERANCE: u256 = 10_000;
```

**File:** volo-vault/sources/operation.move (L359-376)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```
