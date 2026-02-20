# Audit Report

## Title
Insufficient Pyth Price Staleness Threshold Causes Vault Operation DoS During Network Congestion

## Summary
The Suilend oracle module enforces a hardcoded 60-second staleness threshold for Pyth prices. When operators attempt to complete vault operations involving Suilend positions during network congestion or oracle delays, transactions abort due to stale prices, locking the vault in DURING_OPERATION status with no admin recovery mechanism available until Pyth prices become fresh again.

## Finding Description

**Root Cause:**

The Suilend oracle module hardcodes `MAX_STALENESS_SECONDS` to 60 seconds. [1](#0-0)  When Pyth price timestamps exceed this threshold, the `get_pyth_price_and_identifier()` function returns `option::none()` for the spot price. [2](#0-1) 

**Attack Path:**

1. **Operation Initiation**: Operator calls `start_op_with_bag()` which invokes `pre_vault_check()`, setting the vault status to `VAULT_DURING_OPERATION_STATUS`. [3](#0-2) 

2. **Price Update Requirement**: To complete operations with Suilend positions, operators must call `refresh_reserve_price()` on the lending market, which calls `reserve::update_price()`. [4](#0-3) 

3. **Abort on Stale Price**: The `reserve::update_price()` function calls `oracles::get_pyth_price_and_identifier()` and asserts the result is `Some`, aborting with `EInvalidPrice` if the price is stale. [5](#0-4) 

4. **Position Value Check**: The Suilend adaptor's `parse_suilend_obligation()` function requires fresh prices when parsing obligations, calling `assert_price_is_fresh()` on each reserve. [6](#0-5) 

5. **Operation Completion Blocked**: The `end_op_value_update_with_bag()` function calls `check_op_value_update_record()`, which requires all borrowed assets to have updated values. [7](#0-6) [8](#0-7) 

6. **Vault Lock**: The vault status can only be reset to `VAULT_NORMAL_STATUS` by completing `end_op_value_update_with_bag()`. [9](#0-8) 

**Why Protections Fail:**

The admin `set_enabled()` function explicitly prevents status changes when the vault is in `DURING_OPERATION` status. [10](#0-9)  All new operations are blocked because `pre_vault_check()` requires `VAULT_NORMAL_STATUS`. [11](#0-10) 

The oracle module acknowledges potential timing issues in code comments but provides no fallback mechanism. [12](#0-11) 

## Impact Explanation

**HIGH Severity** - This vulnerability causes complete operational failure affecting all vault users:

- **Complete DoS**: All vault operations (deposits, withdrawals, rebalancing) are blocked during the DoS period
- **Fund Inaccessibility**: All depositors cannot access funds until Pyth prices become fresh again
- **No Recovery Mechanism**: No admin function can bypass the DURING_OPERATION status when prices are stale
- **Cascading Impact**: All pending deposit/withdrawal requests are frozen, operators cannot perform any operations

While funds are not directly stolen, they become completely inaccessible during the DoS period, which could last for an extended duration during sustained network congestion or oracle infrastructure issues.

## Likelihood Explanation

**HIGH Likelihood** - This is not a theoretical edge case but a realistic operational scenario:

- **No Attacker Required**: Natural occurrence during adverse network conditions
- **Realistic Threshold**: 60 seconds is an extremely tight window for production blockchain systems where cross-chain oracle updates can experience legitimate delays
- **Common Scenarios**: Sui network congestion, Pyth oracle infrastructure maintenance or delays, cross-chain timing desynchronization between Sui and Pythnet timestamps, validator performance degradation

The condition automatically triggers during normal operations when price staleness occurs, making this a HIGH probability event during mainnet congestion.

## Recommendation

Implement an emergency admin recovery mechanism that allows resetting vault status when the vault has been stuck in DURING_OPERATION for an extended period. Additionally, consider:

1. Adding an admin-only function to force-reset vault status after a time threshold
2. Implementing a fallback price oracle mechanism for Suilend positions
3. Increasing the staleness threshold or making it configurable
4. Adding a grace period mechanism where slightly stale prices can be accepted with appropriate safeguards

## Proof of Concept

A test demonstrating this vulnerability would:
1. Start a vault operation with Suilend positions
2. Simulate time passage > 60 seconds without Pyth price updates
3. Attempt to refresh reserve prices (fails with EInvalidPrice)
4. Attempt to complete the operation (fails because asset values cannot be updated)
5. Verify vault is stuck in DURING_OPERATION status
6. Verify admin cannot recover via `set_enabled()` (blocked by status check)

### Citations

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L13-13)
```text
    const MAX_STALENESS_SECONDS: u64 = 60;
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L40-41)
```text
        // check current sui time against pythnet publish time. there can be some issues that arise because the
        // timestamps are from different sources and may get out of sync, but that's why we have a fallback oracle
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/oracles.move (L43-48)
```text
        if (
            cur_time_s > price::get_timestamp(&price) && // this is technically possible!
            cur_time_s - price::get_timestamp(&price) > MAX_STALENESS_SECONDS
        ) {
            return (option::none(), ema_price, price_identifier)
        };
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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L375-377)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/lending_market.move (L201-211)
```text
    public fun refresh_reserve_price<P>(
        lending_market: &mut LendingMarket<P>,
        reserve_array_index: u64,
        clock: &Clock,
        price_info: &PriceInfoObject,
    ) {
        assert!(lending_market.version == CURRENT_VERSION, EIncorrectVersion);

        let reserve = vector::borrow_mut(&mut lending_market.reserves, reserve_array_index);
        reserve::update_price<P>(reserve, clock, price_info);
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/reserve.move (L581-593)
```text
    public(package) fun update_price<P>(
        reserve: &mut Reserve<P>, 
        clock: &Clock,
        price_info_obj: &PriceInfoObject
    ) {
        let (mut price_decimal, ema_price_decimal, price_identifier) = oracles::get_pyth_price_and_identifier(price_info_obj, clock);
        assert!(price_identifier == reserve.price_identifier, EPriceIdentifierMismatch);
        assert!(option::is_some(&price_decimal), EInvalidPrice);

        reserve.price = option::extract(&mut price_decimal);
        reserve.smoothed_price = ema_price_decimal;
        reserve.price_last_update_timestamp_s = clock::timestamp_ms(clock) / 1000;
    }
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L53-68)
```text
    obligation.deposits().do_ref!(|deposit| {
        let deposit_reserve = &reserves[deposit.reserve_array_index()];

        deposit_reserve.assert_price_is_fresh(clock);

        let market_value = reserve::ctoken_market_value(
            deposit_reserve,
            deposit.deposited_ctoken_amount(),
        );
        total_deposited_value_usd = total_deposited_value_usd + market_value.to_scaled_val();
    });

    obligation.borrows().do_ref!(|borrow| {
        let borrow_reserve = &reserves[borrow.reserve_array_index()];

        borrow_reserve.assert_price_is_fresh(clock);
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
