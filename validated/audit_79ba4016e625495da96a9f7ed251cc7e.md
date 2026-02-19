# Audit Report

## Title
Momentum Adaptor Permanently Locks Vault Operations Due to Stub Implementation Dependencies

## Summary
The Volo vault's Momentum adaptor depends on the mmt_v3 library which is compiled from local stub implementations where all functions unconditionally abort. Any vault operation that borrows a MomentumPosition will fail when attempting to update its value, causing the vault to become permanently stuck in VAULT_DURING_OPERATION_STATUS with no recovery mechanism.

## Finding Description

The vulnerability exists in the compilation configuration and execution flow of vault operations with Momentum positions:

**Root Cause - Stub Dependencies:**

The Move.toml configuration uses a local mmt_v3 dependency path rather than the actual deployed contract. [1](#0-0) 

This local dependency contains only interface stubs where every function immediately aborts. For example, the pool module's `sqrt_price` function: [2](#0-1) 

The tick_math module's `get_sqrt_price_at_tick` function: [3](#0-2) 

The i32 module and liquidity_math module follow the same pattern: [4](#0-3) [5](#0-4) 

**Execution Path:**

When a vault operation borrows a MomentumPosition, the operator must update its value before completing the operation. The momentum adaptor's update function calls helper functions that depend on the stub implementations: [6](#0-5) 

These calls invoke the stub functions which always abort, making value updates impossible.

**Why Protections Fail:**

The vault operation flow requires tracking and validating all borrowed assets. When assets are borrowed, they are recorded: [7](#0-6) 

After returning borrowed assets, the operator must call value update functions. Only successfully updated assets are marked in the tracking record: [8](#0-7) 

Before completing the operation, the vault enforces that ALL borrowed assets have been updated: [9](#0-8) 

Since the Momentum value update always aborts, this check can never pass. The vault remains stuck in VAULT_DURING_OPERATION_STATUS: [10](#0-9) 

Furthermore, the admin's `set_enabled` function explicitly prevents status changes when the vault is during operation: [11](#0-10) 

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Permanent Fund Lockup**: Once triggered, all vault funds become inaccessible as the vault cannot complete operations or execute new deposit/withdrawal requests while stuck in VAULT_DURING_OPERATION_STATUS.

2. **No Recovery Mechanism**: There is no administrative function to override or bypass the stuck state, as `set_enabled` explicitly forbids status changes during operations.

3. **Deterministic Failure**: The issue is not probabilistic - 100% of Momentum operations will fail due to the hardcoded abort statements.

4. **Protocol Reputation Damage**: The vault becomes permanently disabled, requiring full migration to recover user funds.

This breaks the core security guarantee that vault operations can be completed successfully and that funds remain accessible to legitimate users.

## Likelihood Explanation

**Certainty: GUARANTEED** if preconditions are met:

**Preconditions**:
- Vault contains a MomentumPosition asset (which the protocol explicitly supports)
- An operator attempts to use it in a vault operation (normal protocol usage)

**Attack Path**:
No malicious actor is required - this occurs through normal operational flow:
1. Operator calls `start_op_with_bag` requesting a MomentumPosition
2. Operation proceeds normally
3. Operator calls `end_op_with_bag` to return the position
4. Operator calls `update_momentum_position_value` (required step)
5. Transaction aborts with code 0
6. Vault is now permanently stuck

The vulnerability is deterministic because the stub implementations are compiled into the published package code, not runtime dependencies that could be swapped.

## Recommendation

**Immediate Fix**: Update Move.toml to use the actual deployed mmt_v3 contract instead of local stubs:

```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
```

**Additional Safeguards**:
1. Add a circuit breaker function that allows admin to force-reset vault status in emergency situations
2. Implement integration tests that verify all adaptor value update functions execute successfully
3. Add compile-time checks or deployment scripts to ensure external dependencies resolve to actual deployed contracts, not stubs

## Proof of Concept

A test demonstrating this vulnerability would:

1. Create a vault with a MomentumPosition asset
2. Call `start_op_with_bag` to borrow the MomentumPosition
3. Call `end_op_with_bag` to return it
4. Attempt to call `update_momentum_position_value` → Transaction aborts
5. Attempt to call `end_op_value_update_with_bag` → Fails because value not updated
6. Verify vault is stuck in VAULT_DURING_OPERATION_STATUS
7. Attempt admin recovery via `set_vault_enabled` → Fails with ERR_VAULT_DURING_OPERATION

The abort at step 4 is guaranteed by the stub implementation, making the vault permanently stuck.

## Notes

This is a deployment/configuration vulnerability rather than a logic vulnerability. The protocol code correctly enforces value update requirements, but the dependency configuration makes it impossible to satisfy those requirements for Momentum positions. The comment in Move.toml stating "we need to remove some test functions with errors" suggests the stub was meant as a temporary workaround, but it resulted in completely non-functional code being deployed.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L15-17)
```text
    public fun zero(): I32 {
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

**File:** volo-vault/sources/volo_vault.move (L1206-1218)
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
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

    let total_usd_value_before = total_usd_value;
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
}
```
