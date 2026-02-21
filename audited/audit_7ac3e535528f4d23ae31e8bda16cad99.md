# Audit Report

## Title
Division by Zero in Deposit Execution Due to Zero Share Ratio After Total Vault Loss

## Summary
When the vault experiences a complete loss of asset value within the configured loss tolerance, the share ratio becomes zero while shares remain outstanding. This causes a division by zero error when attempting to execute pending deposits, creating a permanent denial-of-service condition where user funds become stuck in the deposit request buffer.

## Finding Description

The vulnerability exists in the interaction between share ratio calculation and deposit execution logic:

**Root Cause - Zero Share Ratio Calculation:**

In `get_share_ratio()`, when `total_shares > 0` but `total_usd_value = 0`, the function calculates the share ratio which evaluates to zero [1](#0-0) .

**Division by Zero Location:**

The `vault_utils::div_d()` function performs decimal division as `v1 * DECIMALS / v2` [2](#0-1) . 

In `execute_deposit()`, this zero share ratio is used as a divisor [3](#0-2) , which becomes `new_usd_value_deposited * DECIMALS / 0`, causing a transaction abort due to division by zero.

**How Total Value Can Reach Zero:**

The vault's loss tolerance mechanism allows assets to reach zero value. The loss tolerance check validates that cumulative losses don't exceed a configured limit per epoch [4](#0-3) . When `loss_tolerance` is set to the maximum value, the validation allows it to equal `RATE_SCALING` which is 10,000 basis points (100%) [5](#0-4) .

During operation completion, if the total value reaches zero within the loss tolerance, the vault returns to NORMAL status [6](#0-5) . Additionally, asset values can be set to zero without any validation in `finish_update_asset_value()` [7](#0-6) .

**Why Existing Protections Fail:**

The `execute_deposit()` function only validates that the vault is in NORMAL status [8](#0-7)  but does not validate that the share ratio is non-zero before using it as a divisor. The check at line 848 that asserts `user_shares > 0` never executes because the division by zero abort occurs first at line 844 [9](#0-8) .

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

**Severity Justification (High):**
- Impact is severe: permanent DoS affecting all deposit operations with fund lockup
- Recovery requires external intervention (e.g., admin must restore vault value)
- Breaks core protocol functionality (deposit execution)

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
- Medium probability given DeFi's history of protocol exploits and failures (e.g., Euler, Cream Finance, Venus Protocol)
- The vault's integration with multiple external protocols (Navi, Suilend, Cetus, Momentum) increases the attack surface
- Loss tolerance configuration explicitly permits up to 100% loss
- Not directly attackable by malicious users, but can occur through operational/external risks

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
    self.check_version();
    self.assert_normal();
    
    // ... existing code ...
    
    let share_ratio_before = self.get_share_ratio(clock);
    
    // Add this check:
    assert!(share_ratio_before > 0, ERR_ZERO_SHARE_RATIO);
    
    // ... rest of the function ...
}
```

Alternatively, add a state check that prevents the vault from transitioning to NORMAL status when `total_usd_value = 0` and `total_shares > 0`, requiring administrative intervention to resolve the state.

## Proof of Concept

```move
#[test]
fun test_division_by_zero_on_deposit_after_total_loss() {
    // Setup: Create vault with initial deposits
    let mut scenario = test_scenario::begin(ADMIN);
    
    // 1. Initialize vault and deposit to create shares
    vault::create_vault<SUI>(&mut scenario);
    deposit_funds(&mut scenario, USER1, 1000);
    
    // 2. Set loss tolerance to 100%
    set_loss_tolerance(&mut scenario, 10_000); // 100%
    
    // 3. Simulate operation that causes 100% value loss
    start_operation(&mut scenario);
    // ... perform operations that lose all value ...
    // Update all asset values to 0
    update_asset_values_to_zero(&mut scenario);
    end_operation(&mut scenario); // Passes loss tolerance check, returns to NORMAL
    
    // 4. User creates new deposit request
    create_deposit_request(&mut scenario, USER2, 500);
    
    // 5. Attempt to execute deposit - THIS WILL ABORT with division by zero
    // share_ratio = 0 (total_usd_value=0, total_shares>0)
    // user_shares = div_d(new_value, 0) = new_value * DECIMALS / 0 -> ABORT
    execute_deposit(&mut scenario); // Expected: Division by zero abort
    
    test_scenario::end(scenario);
}
```

## Notes

- This vulnerability demonstrates a critical edge case in the vault's share accounting when total value reaches zero
- While 100% loss is extreme, it's within the configured parameters and has historical precedent in DeFi
- The issue specifically affects deposits; withdrawals would fail differently (not division by zero, but would calculate zero withdrawal amounts)
- Recovery would require administrative action to inject value back into the vault to restore a non-zero share ratio

### Citations

**File:** volo-vault/sources/volo_vault.move (L486-492)
```text
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
```

**File:** volo-vault/sources/volo_vault.move (L626-635)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
```

**File:** volo-vault/sources/volo_vault.move (L813-821)
```text
    self.check_version();
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
    let total_usd_value_before = self.get_total_usd_value(clock);
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

**File:** volo-vault/sources/volo_vault.move (L1186-1187)
```text
    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1304-1309)
```text
    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
```

**File:** volo-vault/sources/utils.move (L28-30)
```text
public fun div_d(v1: u256, v2: u256): u256 {
    v1 * DECIMALS / v2
}
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
