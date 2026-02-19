# Audit Report

## Title
Momentum Adaptor Permanently Locks Vault Operations Due to Stub Implementation Dependencies

## Summary
The Momentum adaptor integration depends on the mmt_v3 library which contains only stub implementations where all functions unconditionally abort with code 0. Any vault operation that borrows a MomentumPosition will fail when attempting to update its value, causing the vault to become permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism. This represents a complete denial-of-service for vault operations involving Momentum positions, resulting in permanent fund lockup for all depositors.

## Finding Description

The vulnerability exists in the compilation configuration and execution flow of vault operations with Momentum positions.

**Root Cause - Stub Dependencies:**

The mmt_v3 dependency is configured to use local stub implementations. [1](#0-0) 

All critical mmt_v3 functions are stub implementations that immediately abort with code 0:
- The `pool::sqrt_price` function unconditionally aborts [2](#0-1) 
- The `tick_math::get_sqrt_price_at_tick` function unconditionally aborts [3](#0-2) 
- The `liquidity_math::get_amounts_for_liquidity` function unconditionally aborts [4](#0-3) 
- The i32 module functions all unconditionally abort [5](#0-4) 

These stub implementations are published on-chain. [6](#0-5) 

**Execution Path:**

When an operator starts a vault operation borrowing a MomentumPosition, the vault status changes to `VAULT_DURING_OPERATION_STATUS` and the asset type is recorded in `asset_types_borrowed`. [7](#0-6) 

The Momentum adaptor's `update_momentum_position_value` function calls `get_position_token_amounts`. [8](#0-7) 

This function invokes the stub implementations which abort, causing the transaction to fail. [9](#0-8) 

**Why Protections Fail:**

After returning borrowed assets, `end_op_with_bag` enables value updates. [10](#0-9) 

When `finish_update_asset_value` is called successfully, it marks the asset as updated in `op_value_update_record`. [11](#0-10) 

However, the `end_op_value_update_with_bag` function requires all borrowed assets to be marked as updated before completing the operation. [12](#0-11) 

Since the Momentum value update always aborts, `finish_update_asset_value` never executes, so the asset can never be marked as updated. The check in `end_op_value_update_with_bag` will always fail, preventing the vault from returning to `VAULT_NORMAL_STATUS`. [13](#0-12) 

**No Recovery Mechanism:**

Even the admin cannot bypass this stuck state. The `set_enabled` function explicitly checks that the vault status is not `VAULT_DURING_OPERATION_STATUS`. [14](#0-13) 

The only function that can change the status from `VAULT_DURING_OPERATION_STATUS` to `VAULT_NORMAL_STATUS` is `end_op_value_update_with_bag`, which requires passing the impossible value update check. [15](#0-14) 

## Impact Explanation

**Direct Operational Impact:**
- Any vault operation that borrows a MomentumPosition becomes permanently frozen in `VAULT_DURING_OPERATION_STATUS`
- The vault cannot execute any deposit or withdrawal requests while in operation status
- All depositors' funds remain locked in the vault with no way to withdraw
- The entire vault becomes non-functional and requires migration to a new vault to recover user funds

**Affected Parties:**
- All vault depositors whose funds become locked during a failed Momentum operation
- Vault operators who cannot complete legitimate operations
- The protocol's reputation and operational viability

**Severity Justification:**
This is CRITICAL because:
1. It causes permanent fund lockup with zero recovery mechanisms
2. It affects core vault functionality (the operation lifecycle management)
3. The failure is deterministic - any Momentum operation will fail 100% of the time due to the stub implementations
4. There is no administrative override to bypass the stuck state
5. The stub implementations are published on-chain, making this a production issue

## Likelihood Explanation

**Trigger Conditions:**
- The vault must have a MomentumPosition asset added to it
- An operator must attempt to use it in any vault operation
- No special timing, network conditions, or attack complexity required

**Probability:**
CERTAIN (100%) - This is guaranteed to occur on the first attempted use of any Momentum position. The transaction will fail with an abort error code 0, and the vault will remain permanently stuck in operation status.

**Attacker Capabilities:**
No attacker is required. This occurs through normal protocol operations by authorized operators performing their legitimate duties. The issue manifests immediately upon attempting to use the Momentum integration.

## Recommendation

**Immediate Fix:**
1. Replace the stub implementations with actual mmt_v3 protocol implementations or point the dependency to the real deployed Momentum V3 contracts
2. If Momentum integration is not yet ready for production, remove MomentumPosition support from the operation flow entirely
3. Add emergency admin functions that can force-reset vault status in edge cases (with appropriate safeguards)

**Long-term Fix:**
1. Implement comprehensive integration tests that exercise all external protocol adaptors end-to-end
2. Add circuit breaker mechanisms that can safely abort stuck operations
3. Implement admin emergency recovery functions with appropriate access controls and safeguards

**Code Changes Required:**

Update the Move.toml dependency to point to the actual Momentum V3 implementation:
```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
```

Or add an emergency admin function to reset vault status (with extreme caution and proper validation).

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a vault with a MomentumPosition asset
2. Calling `start_op_with_bag` with the MomentumPosition in the asset list
3. Vault status transitions to `VAULT_DURING_OPERATION_STATUS`
4. Calling `end_op_with_bag` to return the position
5. Attempting to call `update_momentum_position_value` → Transaction aborts with code 0 at the stub function call
6. Attempting to call `end_op_value_update_with_bag` → Transaction fails with `ERR_USD_VALUE_NOT_UPDATED` because the MomentumPosition was never marked as updated
7. Vault is now permanently stuck; all subsequent operations fail

The stub implementation evidence is directly observable in the source code where every function body is `abort 0`. The Move.toml shows these stubs are what gets compiled and published.

### Citations

**File:** volo-vault/Move.toml (L80-86)
```text
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/mmt_v3"
rev = "main"
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-6)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L19-27)
```text
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L15-16)
```text
    public fun zero(): I32 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/Move.toml (L4-4)
```text
published-at = "0xc84b1ef2ac2ba5c3018e2b8c956ba5d0391e0e46d1daa1926d5a99a6a42526b4"
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
```

**File:** volo-vault/sources/volo_vault.move (L1189-1195)
```text
    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L69-91)
```text
public fun get_position_token_amounts<CoinA, CoinB>(
    pool: &MomentumPool<CoinA, CoinB>,
    position: &MomentumPosition,
): (u64, u64, u128) {
    let sqrt_price = pool.sqrt_price();

    let lower_tick = position.tick_lower_index();
    let upper_tick = position.tick_upper_index();

    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);

    let liquidity = position.liquidity();

    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
    (amount_a, amount_b, sqrt_price)
}
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-375)
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
```
