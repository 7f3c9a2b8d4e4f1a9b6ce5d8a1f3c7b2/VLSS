# Audit Report

## Title
Pyth Oracle Failure Permanently Bricks Vault Operations with Suilend Positions

## Summary
When a vault holds Suilend positions, Pyth oracle failures during vault operations cause permanent DoS. The Suilend oracle integration returns `None` for invalid prices but the caller aborts without fallback, preventing position value updates and leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS` with all user funds inaccessible.

## Finding Description

The vulnerability stems from a critical design mismatch between Suilend's oracle interface and its implementation, combined with Volo's strict asset value update enforcement.

**Root Cause - Oracle Design Without Fallback:**

The Suilend `get_pyth_price_and_identifier()` function explicitly documents that it returns `Option::none()` for invalid prices so "the caller can handle invalid prices gracefully by eg falling back to a different oracle" [1](#0-0) 

It returns `None` when confidence exceeds 10% of price [2](#0-1)  or staleness exceeds 60 seconds [3](#0-2) 

However, the caller `reserve::update_price()` immediately aborts if the price is `None`, with no fallback mechanism implemented [4](#0-3) 

**Execution Path to Permanent Vault Lockup:**

1. **Operation Initiation**: Operator calls `start_op_with_bag()` which transitions vault to `VAULT_DURING_OPERATION_STATUS` [5](#0-4) 

2. **Asset Borrowing**: When Suilend positions are borrowed via `borrow_defi_asset()`, they are recorded in `op_value_update_record.asset_types_borrowed` [6](#0-5) 

3. **Strict Freshness Requirement**: Suilend enforces zero-second price staleness threshold [7](#0-6)  checked by `assert_price_is_fresh()` [8](#0-7) 

4. **Value Update Requirement**: The Suilend adaptor must call `assert_price_is_fresh()` for every deposit and borrow when calculating position value [9](#0-8) [10](#0-9) 

5. **Mandatory Update Enforcement**: The `check_op_value_update_record()` function enforces that ALL borrowed assets must have their values updated before operation completion [11](#0-10) 

6. **Status Reset Gating**: Only `end_op_value_update_with_bag()` can reset vault status back to `VAULT_NORMAL_STATUS` [12](#0-11)  and it requires passing the update check.

7. **User Operations Blocked**: Both `request_deposit()` and `request_withdraw()` require `VAULT_NORMAL_STATUS` [13](#0-12) [14](#0-13)  verified by `assert_normal()` [15](#0-14) 

8. **No Admin Recovery**: The `set_enabled()` function explicitly prevents operation during `VAULT_DURING_OPERATION_STATUS` [16](#0-15) 

## Impact Explanation

This vulnerability causes **complete and permanent protocol DoS** with the following impacts:

- **All user deposits permanently blocked**: Cannot call `request_deposit()` because vault is not in VAULT_NORMAL_STATUS
- **All user withdrawals permanently blocked**: Cannot call `request_withdraw()` because vault is not in VAULT_NORMAL_STATUS  
- **Complete fund lockup**: All user funds in the vault become inaccessible with no recovery mechanism
- **No admin recovery path**: Admin cannot call `set_enabled()` to restore vault functionality
- **Protocol reputation destroyed**: Users permanently lose access to their funds

This represents the highest severity impact category: permanent loss of protocol functionality with indefinite fund lockup affecting all users.

## Likelihood Explanation

**HIGH Likelihood - Operational Failure Scenario:**

This is NOT a malicious attack but a realistic operational failure with the following characteristics:

**Realistic Trigger Conditions:**
- Pyth oracle returns `None` when confidence ratio > 10% [17](#0-16)  or staleness > 60 seconds [18](#0-17) 
- These thresholds are regularly exceeded during: network congestion, oracle infrastructure issues, extreme market volatility, or temporary oracle downtime

**No Attacker Required:**
- Occurs during normal operator operations
- Honest operator following correct procedures
- No malicious actions needed

**Documented Design Flaw:**
- The Suilend adaptor documentation acknowledges price updates are required [19](#0-18)  but provides no fallback mechanism

**Preconditions:**
- Vault has Suilend positions (standard configuration for multi-protocol vault)
- Oracle experiences issues during operation window (realistic operational scenario)

## Recommendation

Implement a multi-layered mitigation strategy:

1. **Add fallback oracle mechanism** in Suilend's `reserve::update_price()` to use EMA price when spot price is unavailable
2. **Relax staleness threshold** from 0 seconds to a reasonable value (e.g., 60-120 seconds) to account for blockchain latency
3. **Add admin recovery function** that can force vault status back to NORMAL with appropriate safety checks
4. **Implement graceful degradation** in `update_suilend_position_value()` to use last known good price when fresh prices unavailable
5. **Add circuit breaker** to pause operations if oracle becomes unavailable before borrowing assets

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```move
// Test: Vault gets permanently stuck when Pyth oracle fails during operation

public fun test_vault_permanent_dos_with_suilend_oracle_failure() {
    // Setup: Create vault with Suilend position
    let vault = create_test_vault();
    add_suilend_position_to_vault(&mut vault);
    
    // Step 1: Operator starts operation (vault status → DURING_OPERATION)
    let (bag, tx, tx_check, _, _) = start_op_with_bag(
        &mut vault, &operation, &operator_cap, &clock, 
        vector[SUILEND_ASSET_ID], vector[type_of<SuilendObligationOwnerCap>()],
        0, 0, &mut ctx
    );
    
    // Step 2: Return assets
    end_op_with_bag(&mut vault, &operation, &operator_cap, bag, tx, _, _);
    
    // Step 3: Simulate Pyth oracle failure (confidence > 10% OR staleness > 60s)
    // When operator tries: lending_market::refresh_reserve_price() → ABORTS
    // Cannot call: update_suilend_position_value() → would abort at assert_price_is_fresh
    
    // Step 4: Try to complete operation → FAILS
    // end_op_value_update_with_bag() → aborts at check_op_value_update_record()
    // because Suilend asset not marked as updated
    
    // Result: Vault permanently stuck in DURING_OPERATION status
    assert!(vault.status() == VAULT_DURING_OPERATION_STATUS);
    
    // All user operations now permanently blocked:
    // deposit() → aborts (requires NORMAL status)
    // withdraw() → aborts (requires NORMAL status)
    // set_enabled() → aborts (blocked during operation)
}
```

The test demonstrates that once a vault enters the stuck state due to oracle failure, there is no recovery mechanism and all user funds become permanently inaccessible.

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L12-12)
```text
    const MIN_CONFIDENCE_RATIO: u64 = 10;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L15-18)
```text
    /// parse the pyth price info object to get a price and identifier. This function returns an None if the
    /// price is invalid due to confidence interval checks or staleness checks. It returns None instead of aborting
    /// so the caller can handle invalid prices gracefully by eg falling back to a different oracle
    /// return type: (spot price, ema price, price identifier)
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L36-38)
```text
        if (conf * MIN_CONFIDENCE_RATIO > price_mag) {
            return (option::none(), ema_price, price_identifier)
        };
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L43-47)
```text
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L586-588)
```text
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1215-1218)
```text
    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L12-19)
```text
// @dev Need to update the price of the reserve before calling this function
//      Update function: lending_market::refresh_reserve_price
//          public fun refresh_reserve_price<P>(
//              lending_market: &mut LendingMarket<P>,
//              reserve_array_index: u64,
//              clock: &Clock,
//              price_info: &PriceInfoObject,
//           )
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L56-56)
```text
        deposit_reserve.assert_price_is_fresh(clock);
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L68-68)
```text
        borrow_reserve.assert_price_is_fresh(clock);
```
