# Audit Report

## Title
Navi Position Valuation Fails Completely on Single Reserve Oracle Failure, Causing Vault Operation Deadlock

## Summary
The `calculate_navi_position_value()` function uses assert-based oracle price fetching without error handling, causing complete transaction abort if any single reserve's oracle fails. This prevents the Navi asset from being marked as updated, permanently blocking vault operations until the oracle issue is resolved. Since admin recovery functions also require the vault to not be in operation status, there is no emergency recovery mechanism.

## Finding Description

The vulnerability exists in the loop structure where oracle price fetching lacks graceful degradation. The function iterates through all Navi reserves and calls `vault_oracle::get_asset_price()` for each non-zero balance. [1](#0-0) 

The oracle call contains two critical abort conditions that halt the entire transaction: [2](#0-1) 

Since Move does not support try-catch error handling, when any assertion fails, the transaction aborts immediately with no recovery path. The critical issue is that `finish_update_asset_value()` is only called after successful completion of the calculation, meaning if the oracle fails, the asset is never marked as updated. [3](#0-2) 

**The deadlock mechanism occurs as follows:**

During vault operations, the status is set to `VAULT_DURING_OPERATION_STATUS` and borrowed assets are tracked. [4](#0-3) 

When attempting to complete the operation, the system validates that ALL borrowed assets have been updated. [5](#0-4) 

This check is enforced before the vault status can be reset to normal. [6](#0-5) 

Since the oracle failure prevents the asset from being marked as updated, this check will always fail, and the vault status is never reset to `VAULT_NORMAL_STATUS`.

**Why existing protections fail:**

The admin's `set_enabled()` function explicitly blocks execution when the vault is in operation status, preventing emergency recovery. [7](#0-6) 

Critical user operations require normal vault status and are therefore blocked. [8](#0-7) 

## Impact Explanation

**HIGH Severity - Protocol-wide Denial of Service:**

This vulnerability causes complete operational deadlock with the following impacts:

1. **All user deposits blocked** - `request_deposit()` requires `assert_normal()` which fails when vault is stuck in `VAULT_DURING_OPERATION_STATUS`

2. **All user withdrawals blocked** - `request_withdraw()` similarly requires normal vault status

3. **No new operations possible** - `start_op_with_bag()` calls `pre_vault_check()` which requires normal status

4. **Cancel operations blocked** - Even request cancellations require `assert_not_during_operation()`

5. **No admin recovery** - The admin's `set_enabled()` function explicitly checks that vault is NOT in operation status

**Real-world scenario**: A Navi position with balances in 5 reserves (SUI, USDC, USDT, WETH, CETUS) where the CETUS oracle experiences staleness. Even though 99.5% of the position value can be priced, the entire vault is blocked until the CETUS oracle recovers. During this time, all vault users lose access to deposits and withdrawals.

## Likelihood Explanation

**HIGH Likelihood:**

1. **Reachable Entry Point**: `update_navi_position_value()` is a standard function called by operators during the value update phase after `end_op_with_bag()`. This is routine operational flow, not an edge case.

2. **Realistic Preconditions**:
   - Oracle failures occur naturally in production DeFi (network congestion, validator downtime, sparse updates for low-liquidity assets, Switchboard configuration issues)
   - Multi-reserve Navi positions are common for yield optimization strategies
   - Only requires one reserve's oracle to fail among potentially many

3. **No Special Privileges Required**: Natural oracle failures require no attacker action. However, a sophisticated attacker could deliberately trigger this by depositing a small amount in a reserve with a manipulatable or unreliable oracle.

4. **Economic Rationality**:
   - Natural occurrence: Zero cost, medium-to-high probability given oracle infrastructure dependencies
   - Malicious exploitation: Low cost (gas + minimal position), very high impact (entire vault operations blocked)

5. **No Prevention**: Oracle monitoring cannot prevent brief staleness windows, and even transient failures cause permanent vault lockup until resolved.

## Recommendation

Implement graceful degradation for oracle failures in Navi position valuation:

**Option 1: Skip reserves with oracle failures**
Modify the loop to continue when oracle price fetching fails, potentially using a last-known-good price or excluding that reserve from the calculation. Add a warning event to alert operators.

**Option 2: Add emergency admin recovery**
Create an admin-only function that can force-reset vault status with appropriate safeguards and audit logging.

**Option 3: Use non-aborting oracle queries**
Implement a variant of `get_asset_price()` that returns an Option or Result type instead of aborting, allowing the caller to handle failures gracefully.

**Recommended fix** (Option 1 + Option 2 combined):
- Modify the reserve loop to track which reserves failed oracle checks and skip them
- Calculate position value using only successfully-priced reserves
- Emit an event listing skipped reserves for monitoring
- Add an emergency admin function `force_complete_operation()` that can reset vault status after manual verification

## Proof of Concept

```move
#[test]
fun test_navi_oracle_failure_deadlock() {
    // Setup: Create vault, add Navi position with multiple reserves
    // 1. Start operation with start_op_with_bag() - vault enters VAULT_DURING_OPERATION_STATUS
    // 2. Complete operation with end_op_with_bag() - assets returned, value_update_enabled = true
    // 3. Simulate oracle failure for one reserve (e.g., by not updating its price within update_interval)
    // 4. Call update_navi_position_value() - this will ABORT due to ERR_PRICE_NOT_UPDATED
    // 5. Attempt to call end_op_value_update_with_bag() - will fail because asset not marked as updated
    // 6. Verify vault is stuck: request_deposit() should abort with ERR_VAULT_NOT_NORMAL
    // 7. Verify admin cannot recover: set_vault_enabled() should abort with ERR_VAULT_DURING_OPERATION
    // Result: Vault is permanently locked until oracle is manually fixed
}
```

The test would demonstrate that once the oracle fails during `update_navi_position_value()`, there is no code path to recover the vault to normal status without first fixing the underlying oracle issue.

## Notes

- This vulnerability affects any vault with Navi positions across multiple reserves
- The likelihood increases proportionally with the number of reserves in the position
- Similar vulnerabilities may exist in other adaptor value update functions (Cetus, Suilend, Momentum) that also call `vault_oracle::get_asset_price()`
- The issue is exacerbated by the lack of emergency recovery mechanisms in the current design
- Even brief oracle staleness (beyond `update_interval` of 1 minute) triggers the deadlock

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L43-72)
```text
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/sources/operation.move (L68-76)
```text
public(package) fun pre_vault_check<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    ctx: &TxContext,
) {
    // vault.assert_enabled();
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
}
```

**File:** volo-vault/sources/operation.move (L354-376)
```text
    vault.check_op_value_update_record();
    let total_usd_value_after = vault.get_total_usd_value(
        clock,
    );

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

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L707-717)
```text
public(package) fun request_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    coin: Coin<PrincipalCoinType>,
    clock: &Clock,
    expected_shares: u256,
    receipt_id: address,
    recipient: address,
): u64 {
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/sources/volo_vault.move (L1206-1219)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
}
```
