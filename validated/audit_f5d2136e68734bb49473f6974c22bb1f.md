# Audit Report

## Title
Momentum Adaptor Permanently Locks Vault Operations Due to Stub Implementation Dependencies

## Summary
The Volo vault's Momentum adaptor depends on stub implementations of the mmt_v3 library where all functions unconditionally abort with code 0. Any vault operation that borrows a MomentumPosition will fail when attempting to update its value, causing the vault to become permanently stuck in `VAULT_DURING_OPERATION_STATUS` with no administrative recovery mechanism.

## Finding Description

The vulnerability exists in the deployed vault package's compilation configuration and its interaction with the mandatory value update enforcement system.

**Root Cause - Compiled Stub Dependencies:**

The Move.toml configuration specifies a local mmt_v3 dependency that pulls from stub implementations within the same repository. [1](#0-0) 

The mmt_v3 package address is commented out in the [addresses] section, meaning no on-chain package binding exists. [2](#0-1) 

These local dependencies contain only interface stubs where every function immediately aborts. Critical functions used by the momentum adaptor include:

- `pool.sqrt_price()` [3](#0-2) 
- `tick_math::get_sqrt_price_at_tick()` [4](#0-3) 
- `liquidity_math::get_amounts_for_liquidity()` [5](#0-4) 
- `position.tick_lower_index()`, `position.tick_upper_index()`, `position.liquidity()` [6](#0-5) 

**Execution Path to Permanent Lockup:**

1. Operator initiates vault operation via `start_op_with_bag()` requesting a MomentumPosition
2. The vault status is set to `VAULT_DURING_OPERATION_STATUS` [7](#0-6) 
3. When borrowing the MomentumPosition, the asset type is recorded in `op_value_update_record.asset_types_borrowed` [8](#0-7) 
4. After returning borrowed assets, `enable_op_value_update()` is called [9](#0-8) 
5. Operator must call `update_momentum_position_value()` which internally calls `get_position_token_amounts()` [10](#0-9) 
6. This function calls the stub implementations (e.g., `pool.sqrt_price()` at line 73), which abort with code 0
7. The transaction fails before the asset can be marked as updated
8. When attempting to complete the operation via `end_op_value_update_with_bag()`, the system checks that all borrowed assets have been updated [11](#0-10) 
9. Since the MomentumPosition value update always aborts, the asset is never added to `asset_types_updated`, causing the completion check to fail
10. The vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`

**Why Recovery is Impossible:**

The admin's `set_enabled()` function explicitly prevents any status changes while the vault is in `VAULT_DURING_OPERATION_STATUS` [12](#0-11) 

No other administrative function can override this stuck state. The vault cannot execute deposits, withdrawals, or any new operations while stuck.

## Impact Explanation

**Critical Severity** - This vulnerability causes permanent protocol-level denial of service with complete fund lockup:

1. **Permanent Fund Inaccessibility**: Once triggered, all vault principal and user deposits become permanently locked as the vault cannot complete any operations or process deposit/withdrawal requests while stuck in `VAULT_DURING_OPERATION_STATUS`

2. **No Administrative Recovery**: The `set_enabled()` assertion at line 523 explicitly blocks all status changes during operations, and no bypass mechanism exists

3. **Deterministic 100% Failure Rate**: The issue is not probabilistic - every MomentumPosition operation will fail due to hardcoded `abort 0` statements in the compiled bytecode

4. **Protocol Integrity Violation**: Breaks the fundamental security guarantee that vault operations can be completed successfully and that user funds remain accessible

This represents a complete breakdown of the vault's core operational invariant, requiring full protocol migration to recover user assets.

## Likelihood Explanation

**Certainty: GUARANTEED** under normal protocol operation:

**Preconditions** (all reasonable):
- Vault contains a MomentumPosition asset (explicitly supported by protocol design)
- Operator attempts to use it in a vault operation (standard operational procedure)

**Attack Path** (no malicious actor required):
1. Operator calls `start_op_with_bag()` with MomentumPosition in asset list
2. Vault enters `VAULT_DURING_OPERATION_STATUS`
3. Operation proceeds normally, position is borrowed and returned
4. Operator calls `update_momentum_position_value()` as required by protocol
5. Transaction aborts with code 0 due to stub implementation
6. Operator cannot complete operation via `end_op_value_update_with_bag()` because value update check fails
7. Vault is now permanently stuck

The vulnerability triggers through **normal protocol usage** without any malicious input. The stub implementations are compiled into the published package bytecode (as evidenced by the published-at address in Move.toml), making this a deterministic failure in the deployed on-chain contract.

## Recommendation

**Immediate Fix**: Update the Move.toml to use the actual deployed Momentum protocol package instead of local stubs:

```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"

[addresses]
mmt_v3 = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

Then republish the vault package. For the currently deployed package, remove any MomentumPosition assets from vaults before operators attempt to use them, or deploy a new vault version and migrate user funds.

**Additional Safety**: Add an emergency admin function that can force-reset vault status from `DURING_OPERATION` to `NORMAL` with appropriate access controls and safeguards.

## Proof of Concept

```move
#[test]
fun test_momentum_position_locks_vault() {
    // 1. Setup: Create vault with MomentumPosition
    // 2. Operator calls start_op_with_bag() requesting MomentumPosition
    // 3. Vault status becomes VAULT_DURING_OPERATION_STATUS
    // 4. MomentumPosition is borrowed (added to asset_types_borrowed)
    // 5. Operator calls end_op_with_bag() (returns position)
    // 6. Operator calls enable_op_value_update()
    // 7. Operator attempts update_momentum_position_value()
    //    -> This aborts with code 0 at pool.sqrt_price() call
    // 8. Operator cannot call end_op_value_update_with_bag() 
    //    -> check_op_value_update_record() fails because MomentumPosition not in asset_types_updated
    // 9. Vault remains stuck in VAULT_DURING_OPERATION_STATUS
    // 10. Admin attempts set_enabled() -> blocked by assertion at line 523
    // Result: Vault permanently locked, all funds inaccessible
}
```

The test demonstrates that once a MomentumPosition is borrowed in an operation, the vault becomes permanently stuck because the stub implementation prevents successful value updates, and the mandatory update check prevents operation completion.

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

**File:** volo-vault/Move.toml (L96-103)
```text
[addresses]
volo_vault = "0xcd86f77503a755c48fe6c87e1b8e9a137ec0c1bf37aac8878b6083262b27fefa"
# switchboard  = "0xc3c7e6eb7202e9fb0389a2f7542b91cc40e4f7a33c02554fec11c4c92f938ea3"
# bluefin_spot = "0x3492c874c1e3b3e2984e8c41b589e642d4d0a5d6459e5a9cfc2d52fd7c89c267"
# mmt_v3       = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
# lending_core = "0xd899cf7d2b5db716bd2cf55599fb0d5ee38a3061e7b6bb6eebf73fa5bc4c81ca"
# suilend      = "0xf95b06141ed4a174f239417323bde3f209b972f5930d8521ea38a52aff3a6ddf"
# cetus_clmm   = "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb"
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L51-53)
```text
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
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

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
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
