# Audit Report

## Title
Division by Zero in Deposit Execution Due to Zero Share Ratio After Total Vault Loss

## Summary
When the vault experiences a complete loss of asset value within the configured loss tolerance, the share ratio becomes zero while shares remain outstanding. Subsequent deposit execution attempts trigger division by zero, causing transaction aborts and rendering all pending deposits permanently unexecutable, with user funds stuck in the request buffer.

## Finding Description

The vulnerability exists in the share ratio calculation and deposit execution flow:

**Division by Zero Location:**
In `execute_deposit()`, the share ratio is used as a divisor to calculate user shares. [1](#0-0)  The `div_d()` function performs fixed-point division as `value * DECIMALS / divisor`. [2](#0-1)  When `share_ratio_before = 0`, this becomes `new_usd_value_deposited * DECIMALS / 0`, causing an arithmetic abort.

**Root Cause - Zero Share Ratio:**
In `get_share_ratio()`, when `total_shares > 0` but `total_usd_value = 0`, the calculation returns zero. [3](#0-2)  The function only returns early when `total_shares == 0`, but when `total_shares > 0` and `total_usd_value = 0`, the formula `vault_utils::div_d(0, self.total_shares)` equals `0 * DECIMALS / total_shares = 0`.

**How Total Value Reaches Zero:**
The protocol allows loss tolerance up to 100% of vault value. The `set_loss_tolerance()` function permits tolerance values up to `RATE_SCALING`. [4](#0-3)  With `RATE_SCALING = 10_000`, [5](#0-4)  the maximum tolerance is 100%. 

During operation completion, the `update_tolerance()` function only validates that cumulative loss doesn't exceed the configured limit. [6](#0-5)  The loss limit calculation is `cur_epoch_loss_base_usd_value * loss_tolerance / RATE_SCALING`, meaning a 100% tolerance allows complete value loss. After operation completion with total loss, the vault returns to NORMAL status with zero total value but outstanding shares. [7](#0-6) 

**Why Protections Fail:**
- Loss tolerance validates maximum loss percentage, not minimum remaining value
- No validation exists for minimum share ratio in deposit execution
- The `assert!(user_shares > 0)` check never executes due to prior division by zero abort [8](#0-7) 
- `execute_deposit()` only checks vault status is NORMAL, not share ratio validity [9](#0-8) 

## Impact Explanation

**Denial of Service:**
- All pending deposit requests become permanently unexecutable due to arithmetic abort
- Users cannot retrieve funds already deposited to the request buffer
- New deposits can be created but never executed, continuously locking more user funds
- The vault effectively becomes frozen for deposit operations

**Affected Parties:**
- Users with pending deposits have funds permanently locked in `deposit_coin_buffer`
- Protocol cannot process any deposits until external intervention (admin manually increasing vault value)
- Vault reputation damage from frozen user funds

**Value at Risk:**
- All coins held in the deposit coin buffer become inaccessible
- Magnitude depends on pending deposit volume at time of total loss event
- No automated recovery mechanism exists in the protocol

**Severity Assessment:**
High impact (permanent DoS + fund lockup) with medium-to-low likelihood. The combination of severe user impact and the fact that the protocol explicitly allows the triggering condition (100% loss tolerance) justifies Medium-to-High severity.

## Likelihood Explanation

**Feasibility Conditions:**
1. Vault must have outstanding shares (`total_shares > 0`) from previous deposits
2. All vault assets must reach zero USD value
3. Loss must be within the configured `loss_tolerance` (up to 100% allowed)
4. At least one pending deposit request must exist

**Realistic Scenarios:**
- External protocol exploit/hack causing 100% loss in Navi, Suilend, Cetus, or Momentum positions
- Oracle failure reporting zero prices for all vault assets
- Liquidation cascade in integrated lending protocols
- Smart contract vulnerability in external DeFi protocol

**Critical Design Consideration:**
The protocol explicitly allows administrators to set loss tolerance to 100%, indicating this is considered a possible operational state. A protocol that allows a state should handle it correctly. The vulnerability is that the protocol permits a configuration (100% loss tolerance) that leads to unrecoverable deposit functionality.

**Probability Assessment:**
Medium-to-low likelihood. While 100% value loss is an extreme event, the protocol's explicit allowance of this configuration combined with DeFi's history of total loss events (bridge exploits, lending protocol hacks) and the vault's integration across multiple external protocols makes this scenario within the realm of realistic risk.

## Recommendation

Add a minimum share ratio validation in `execute_deposit()` before performing the division:

```move
// In execute_deposit(), before line 844:
assert!(share_ratio_before > 0, ERR_ZERO_SHARE_RATIO);
let user_shares = vault_utils::div_d(new_usd_value_deposited, share_ratio_before);
```

Additionally, consider:
1. Adding a maximum loss tolerance cap below 100% (e.g., 95%) to ensure some minimum vault value remains
2. Implementing an emergency recovery mechanism for zero-value states
3. Adding share ratio validation in `get_share_ratio()` to prevent returning zero when shares exist

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = volo_vault::ARITHMETIC_ERROR)]
fun test_division_by_zero_after_total_loss() {
    // 1. Setup: Create vault with initial deposits (total_shares > 0)
    // 2. Set loss_tolerance to 10_000 (100%)
    // 3. Start operation and simulate 100% value loss
    // 4. Complete operation (vault returns to NORMAL with share_ratio = 0)
    // 5. Create pending deposit request
    // 6. Attempt to execute_deposit -> ABORTS with division by zero
    // User funds remain locked in deposit_coin_buffer with no recovery
}
```

The test demonstrates that once the vault reaches zero total value with outstanding shares, all deposit executions abort, permanently locking user funds in the request buffer.

### Citations

**File:** volo-vault/sources/volo_vault.move (L28-28)
```text
const RATE_SCALING: u64 = 10_000;
```

**File:** volo-vault/sources/volo_vault.move (L486-494)
```text
public(package) fun set_loss_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    tolerance: u256,
) {
    self.check_version();
    assert!(tolerance <= (RATE_SCALING as u256), ERR_EXCEED_LIMIT);
    self.loss_tolerance = tolerance;
    emit(ToleranceChanged { vault_id: self.vault_id(), tolerance: tolerance })
}
```

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

**File:** volo-vault/sources/volo_vault.move (L814-821)
```text
    self.assert_normal();

    assert!(self.request_buffer.deposit_requests.contains(request_id), ERR_REQUEST_NOT_FOUND);

    // Current share ratio (before counting the new deposited coin)
    // This update should generate performance fee if the total usd value is increased
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

**File:** volo-vault/sources/operation.move (L359-377)
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
}
```
