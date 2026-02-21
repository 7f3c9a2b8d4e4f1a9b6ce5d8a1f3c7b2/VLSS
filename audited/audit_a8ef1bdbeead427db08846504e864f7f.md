# Audit Report

## Title
Division by Zero in Cetus Position Valuation Due to Unchecked Oracle Price

## Summary
The Volo vault's Cetus adaptor performs division operations using oracle prices without validating they are non-zero. When the Switchboard oracle returns a zero price value, the `calculate_cetus_position_value()` function aborts with a division-by-zero error. This creates a critical DoS condition where the vault becomes permanently stuck in `VAULT_DURING_OPERATION_STATUS`, blocking all user deposits, withdrawals, and future operations until the admin manually replaces the oracle aggregator.

## Finding Description

The vulnerability exists in the oracle price retrieval and Cetus position valuation flow, creating a complete protocol DoS when combined with the vault's operation lifecycle.

**Root Cause - Missing Oracle Price Validation:**

The oracle module's `get_current_price()` function retrieves prices from the Switchboard aggregator and directly returns the value without any non-zero validation. [1](#0-0)  The Switchboard Decimal type can legitimately hold a zero value, making this a realistic failure condition.

The `get_asset_price()` function stores and returns this unchecked price directly. [2](#0-1) 

**Division by Zero in Cetus Adaptor:**

The `calculate_cetus_position_value()` function retrieves oracle prices for both tokens in a Cetus pool and performs two critical division operations. [3](#0-2)  If `price_b` is zero, the first division `price_a * DECIMAL / price_b` causes an immediate transaction abort. Additionally, the second division operation will fail if `relative_price_from_oracle` becomes zero when `price_a` is zero. [4](#0-3) 

**Vault Lock-In Mechanism:**

During vault operations, the `pre_vault_check()` function sets the vault status to `VAULT_DURING_OPERATION_STATUS`. [5](#0-4) 

After the operator returns borrowed assets via `end_op_with_bag()`, the function enables value updates but does not change the vault status. [6](#0-5) 

The operation can only be finalized by calling `end_op_value_update_with_bag()`, which is the ONLY function that returns the vault to `VAULT_NORMAL_STATUS`. [7](#0-6) 

However, this function first calls `check_op_value_update_record()` which validates that ALL borrowed assets have been successfully updated. [8](#0-7)  If `update_cetus_position_value()` aborts due to division by zero, this check cannot pass, and the operation cannot be completed.

**Admin Cannot Override During Operations:**

The admin's `set_enabled()` function explicitly prevents status changes while the vault is in `VAULT_DURING_OPERATION_STATUS`. [9](#0-8) 

**User Operations Blocked:**

Both `request_deposit()` and `request_withdraw()` require the vault to be in `VAULT_NORMAL_STATUS` via the `assert_normal()` check. [10](#0-9) [11](#0-10) [12](#0-11) 

## Impact Explanation

**Critical Operational DoS:**

When the oracle returns zero and the operator attempts to update Cetus position values, the entire vault becomes frozen:

1. **Vault Stuck in Operation Mode:** The vault remains in `VAULT_DURING_OPERATION_STATUS` (status = 1) with no way for the operator to complete or abort the operation.

2. **All User Operations Blocked:** Users cannot request deposits or withdrawals because both functions require `VAULT_NORMAL_STATUS`. The protocol becomes completely non-functional for all vault users.

3. **Admin Limited Powers:** Even the admin cannot disable the vault or change its status while it's stuck in operation mode, as enforced by the status check.

4. **Protocol Unavailability:** The vault instance becomes completely unusable until the admin performs a multi-step recovery: (1) change the Switchboard aggregator to a working one via `change_switchboard_aggregator()`, (2) ensure the new oracle has non-zero prices, (3) operator retries the value update, (4) operation can finally complete.

**Severity Justification:**

While the condition is recoverable through admin intervention, it represents a critical operational failure. All user funds remain locked in the vault (cannot withdraw), new deposits are rejected, and the protocol is completely non-functional. The impact extends to all vault users simultaneously, making this a high-severity DoS vulnerability affecting protocol availability and user fund accessibility.

## Likelihood Explanation

**Preconditions:**

The vulnerability triggers when the Switchboard oracle returns a zero value for any token in a Cetus pool that the vault is managing. This can occur due to:

1. **Oracle Misconfiguration:** During initial deployment, the oracle aggregator might be incorrectly configured or pointed at a non-existent data feed
2. **Uninitialized Feed:** A newly created aggregator that hasn't received any price updates yet will have a zero value
3. **Oracle Malfunction:** Temporary failures in the Switchboard network or specific oracle feeds
4. **Edge Cases:** Genuinely zero or near-zero price values during extreme market conditions or for test tokens

**Feasibility:**

This is not an attacker-exploitable vulnerability but rather an operational risk. The scenario is realistic:
- Oracle systems in DeFi have historically experienced failures and misconfigurations
- Zero values from price feeds are a known failure mode across various oracle providers
- The protocol provides no safeguards against this failure condition

**Probability Assessment:**

**MODERATE** - While quality oracle systems should prevent zero prices through proper configuration and monitoring, misconfigurations during deployment and temporary oracle failures are realistic operational risks that have occurred in production DeFi systems. The likelihood is moderate because it depends on external oracle reliability rather than protocol logic flaws.

## Recommendation

Add zero-price validation in the oracle module to prevent division-by-zero errors:

```move
public fun get_current_price(config: &OracleConfig, clock: &Clock, aggregator: &Aggregator): u256 {
    config.check_version();
    
    let now = clock.timestamp_ms();
    let current_result = aggregator.current_result();
    
    let max_timestamp = current_result.max_timestamp_ms();
    
    if (now >= max_timestamp) {
        assert!(now - max_timestamp < config.update_interval, ERR_PRICE_NOT_UPDATED);
    };
    
    let price = current_result.result().value() as u256;
    assert!(price > 0, ERR_ZERO_PRICE); // Add zero-price validation
    price
}
```

Additionally, consider adding a more graceful recovery mechanism that allows the admin to force-reset the vault status in emergency situations, with appropriate governance controls.

## Proof of Concept

A complete test demonstrating this vulnerability would require:

1. Setting up a vault with a Cetus position
2. Configuring an oracle that returns zero price
3. Starting an operation that borrows the Cetus position
4. Attempting to update the Cetus position value, which aborts on division by zero
5. Verifying the vault is stuck in `VAULT_DURING_OPERATION_STATUS`
6. Demonstrating that user deposit/withdrawal requests fail

The test would show that the vault remains unusable until the admin changes the oracle aggregator to one with valid non-zero prices.

### Citations

**File:** volo-vault/sources/oracle.move (L137-137)
```text
    price_info.price
```

**File:** volo-vault/sources/oracle.move (L261-261)
```text
    current_result.result().value() as u256
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L50-52)
```text
    let price_a = vault_oracle::get_asset_price(config, clock, type_name_a);
    let price_b = vault_oracle::get_asset_price(config, clock, type_name_b);
    let relative_price_from_oracle = price_a * DECIMAL / price_b;
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L63-66)
```text
    assert!(
        (pool_price.diff(relative_price_from_oracle) * DECIMAL  / relative_price_from_oracle) < (DECIMAL  * slippage / SLIPPAGE_BASE),
        ERR_INVALID_POOL_PRICE,
    );
```

**File:** volo-vault/sources/operation.move (L74-74)
```text
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
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
