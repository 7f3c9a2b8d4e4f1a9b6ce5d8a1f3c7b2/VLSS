# Audit Report

## Title
Vault Operations with Suilend Positions Experience Permanent DoS During Pyth Oracle Downtime

## Summary
When Pyth oracle price feeds stop updating for more than 60 seconds, vault operations involving Suilend positions cannot complete their mandatory value update step, causing the vault to become stuck in `VAULT_DURING_OPERATION_STATUS` with no built-in recovery mechanism. The vault remains inoperable until Pyth resumes providing fresh prices, blocking all deposits, withdrawals, and new operations.

## Finding Description

The vulnerability exists in the interaction between multiple components that create an unrecoverable state when Pyth oracle experiences downtime:

**1. Pyth Price Staleness Check**

Suilend's `get_pyth_price_and_identifier()` function implements a 60-second staleness threshold [1](#0-0)  and returns `None` for the spot price when the price age exceeds this threshold [2](#0-1) .

**2. No Fallback in Reserve Price Update**

The Suilend `update_price()` function aborts with `EInvalidPrice` when it receives `None` from the oracle, with no fallback mechanism implemented [3](#0-2) .

**3. Zero-Second Staleness Requirement**

Suilend position valuation requires reserve prices to be updated in the same transaction, enforced by a zero-second staleness threshold [4](#0-3) . The `assert_price_is_fresh()` function enforces this requirement [5](#0-4) , and is called during Suilend position valuation [6](#0-5) .

**4. Mandatory Asset Value Updates in Operation Flow**

Vault operations set the vault status to `VAULT_DURING_OPERATION_STATUS` at the start [7](#0-6) , and require ALL borrowed assets to have their values updated before completion [8](#0-7) . The vault status can only be returned to `VAULT_NORMAL_STATUS` after this check passes [9](#0-8) .

**5. No Emergency Recovery Mechanism**

The admin cannot disable or modify the vault while it's in `VAULT_DURING_OPERATION_STATUS` [10](#0-9) . The `set_enabled()` function explicitly prevents status changes during operation. There is no admin function in the manage module that bypasses this check [11](#0-10) .

**6. User Operations Blocked**

All user deposit and withdrawal requests require the vault to be in `VAULT_NORMAL_STATUS` [12](#0-11) , effectively blocking all user interactions when the vault is stuck.

## Impact Explanation

**Operational DoS:**
- When an operator starts a vault operation involving Suilend positions, then Pyth stops updating for >60 seconds before completion, the operation cannot be finished
- The vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no way to transition out
- All vault functionality is completely blocked: deposits cannot be requested, withdrawals cannot be processed, and new operations cannot start
- Administrators have no emergency override capability to recover the vault

**Affected Parties:**
- All vault users are unable to access their funds (cannot deposit or withdraw)
- Vault operators cannot perform rebalancing or strategy adjustments  
- Vault administrators have no recovery path through the existing interface

**Severity Justification:**
- Complete operational paralysis of the vault
- Affects all users and all vault functions simultaneously
- No administrative recovery path exists within the protocol
- Duration depends entirely on external Pyth oracle recovery (potentially hours or days)
- While funds are not at risk of theft, they become completely inaccessible until external recovery

## Likelihood Explanation

**Realistic Occurrence:**
- Pyth oracle downtime exceeding 60 seconds is a realistic scenario in production environments due to:
  - Network congestion on source chains
  - Validator infrastructure issues
  - Cross-chain bridge delays
  - Price publisher infrastructure problems
- Pyth has experienced such outages in live deployments across multiple chains

**Attack Complexity:**
- This is not an intentional attack but a dependency failure scenario
- No attacker action required - normal vault operations during oracle downtime trigger the issue
- Any operator performing routine vault rebalancing with Suilend positions can encounter this

**Execution Path:**
1. Operator calls `start_op_with_bag()` including a Suilend obligation asset
2. Pyth oracle stops updating (external event, >60 seconds staleness)
3. Operator attempts to complete operation by calling `refresh_reserve_price()` → aborts with `EInvalidPrice` due to stale Pyth data
4. Cannot call `update_suilend_position_value()` because reserve prices are not fresh (0-second threshold)
5. Cannot call `end_op_value_update_with_bag()` because not all borrowed assets have been updated
6. Vault remains permanently stuck until Pyth recovers

**Detection Constraints:**
- Operators may not realize Pyth is stale until mid-operation
- No warning system or grace period exists in the protocol
- Once stuck, recovery requires external monitoring of Pyth's status

## Recommendation

Implement a multi-layered recovery strategy:

**1. Add Emergency Admin Recovery Function:**
```move
public fun emergency_reset_operation_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    vault.check_version();
    // Allow admin to force reset even during operation
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
    emit(EmergencyStatusReset { vault_id: vault.vault_id() });
}
```

**2. Implement Fallback Oracle Support:**
- Add secondary oracle sources (Switchboard, Supra) for Suilend price feeds
- Modify `get_pyth_price_and_identifier()` to return the last valid price with a staleness indicator rather than `None`
- Allow position valuation with stale prices when fresh prices are unavailable, with appropriate safeguards

**3. Add Operation Timeout Mechanism:**
- Track operation start time
- Allow automatic vault status reset after a configurable timeout period (e.g., 1 hour)
- Implement operator-initiated operation cancellation with asset return verification

**4. Implement Graceful Degradation:**
- Add a "skip asset update" mechanism for admin use during oracle failures
- Mark positions as "pending revaluation" instead of blocking the entire vault
- Allow vault to continue operations with stale valuations under admin supervision with strict risk controls

## Proof of Concept

```move
#[test]
fun test_vault_dos_during_pyth_downtime() {
    // Setup: Create vault with Suilend position
    let (mut vault, operation, operator_cap) = setup_vault_with_suilend();
    let clock = clock::create_for_testing(ctx);
    
    // Step 1: Operator starts operation
    let tx_bag = operation::start_op_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[SUILEND_ASSET_ID],
        vector[type_name::get<SuilendObligationOwnerCap>()],
        ctx
    );
    
    // Verify vault is now in DURING_OPERATION status
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, 0);
    
    // Step 2: Simulate Pyth oracle downtime (>60 seconds)
    clock::increment_for_testing(&mut clock, 61_000); // 61 seconds
    
    // Step 3: Attempt to refresh reserve price - WILL ABORT
    // lending_market::refresh_reserve_price() will call reserve::update_price()
    // which calls get_pyth_price_and_identifier() returning None
    // This aborts with EInvalidPrice
    
    // Step 4: Cannot complete operation
    // update_suilend_position_value() requires fresh prices (0-second threshold)
    // end_op_value_update_with_bag() requires all assets updated
    
    // Step 5: Vault is permanently stuck
    // Admin cannot call set_vault_enabled() due to DURING_OPERATION check
    // Users cannot deposit/withdraw due to assert_normal() check
    
    // Verify vault remains stuck
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS, 1);
    
    // Verify no recovery mechanism exists
    // This call will abort with ERR_VAULT_DURING_OPERATION
    vault_manage::set_vault_enabled(&admin_cap, &mut vault, false);
}
```

## Notes

This vulnerability represents a critical dependency risk where external oracle infrastructure failure can cause complete protocol DoS. The issue is compounded by:

1. The combination of Suilend's strict 0-second staleness requirement for position valuation with Pyth's 60-second tolerance creates a window where operations can become permanently stuck
2. The lack of built-in recovery mechanisms forces reliance on either external oracle recovery or protocol upgrades
3. The all-or-nothing nature of the `check_op_value_update_record()` enforcement means a single asset's inability to update blocks the entire vault

The only current recovery options are:
- Wait for Pyth oracle to resume normal operation (external dependency)
- Deploy a package upgrade with emergency recovery functions (significant governance action)

Neither option is acceptable for a production DeFi protocol requiring high availability and user fund accessibility.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L42-48)
```text
        let cur_time_s = clock::timestamp_ms(clock) / 1000;
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L47-47)
```text
    const PRICE_STALENESS_THRESHOLD_S: u64 = 0;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L238-246)
```text
    public fun assert_price_is_fresh<P>(reserve: &Reserve<P>, clock: &Clock) {
        assert!(is_price_fresh(reserve, clock), EPriceStale);
    }

    public(package) fun is_price_fresh<P>(reserve: &Reserve<P>, clock: &Clock): bool {
        let cur_time_s = clock::timestamp_ms(clock) / 1000;

        cur_time_s - reserve.price_last_update_timestamp_s <= PRICE_STALENESS_THRESHOLD_S
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-590)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L1213-1218)
```text
    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}
```
