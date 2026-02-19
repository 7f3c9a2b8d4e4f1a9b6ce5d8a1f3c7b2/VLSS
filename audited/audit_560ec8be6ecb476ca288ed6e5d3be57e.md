# Audit Report

## Title
Momentum Adaptor DoS Due to Stub Implementation Dependencies

## Summary
The Momentum adaptor depends on stub implementations of the mmt_v3 library where all functions unconditionally `abort 0`. Any vault operation borrowing a MomentumPosition will abort when attempting to update its value, permanently locking the vault in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism.

## Finding Description

The vulnerability exists in the mmt_v3 dependency configuration and its integration with vault operations.

**Root Cause - Stub Dependencies:**
The mmt_v3 dependency is configured to use local stub implementations [1](#0-0)  where all functions immediately abort [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

**Execution Path:**
When an operator borrows a MomentumPosition during vault operations, the asset type is tracked [7](#0-6) . The Momentum adaptor's `update_momentum_position_value` function calls `get_position_token_amounts` [8](#0-7)  which invokes multiple stub functions that abort.

**Why Protections Fail:**
After returning borrowed assets, `end_op_with_bag` enables value updates [9](#0-8) . Then `end_op_value_update_with_bag` checks that all borrowed assets have updated values [10](#0-9)  via `check_op_value_update_record` [11](#0-10) . Since the Momentum value update aborts, the asset cannot be marked as updated, and the operation cannot complete. The vault remains stuck in `VAULT_DURING_OPERATION_STATUS`, and the admin's `set_enabled` function explicitly prevents status changes while in this state [12](#0-11) .

## Impact Explanation

**Critical Protocol DoS:**
- Any vault operation borrowing a MomentumPosition becomes permanently frozen
- The vault cannot return to `VAULT_NORMAL_STATUS`, blocking all deposit/withdrawal executions
- Users' funds remain locked with no administrative recovery function  
- The entire vault must be abandoned and migrated

This violates the core vault operation invariant that operations can be completed after returning borrowed assets. The vault status mechanism becomes irrecoverably corrupted.

## Likelihood Explanation

**High Likelihood Given Preconditions:**
- Requires vault to have stored a MomentumPosition (operator must have added one)
- Any authorized operator performing normal vault operations with that position will trigger the issue
- The failure is deterministic - stub functions always abort
- No special network conditions or timing requirements
- The README confirms these are "function definitions only and is not a complete implementation" [13](#0-12) 

The mmt_v3 stubs are published at address specified in the package configuration [14](#0-13) , making this vulnerability active if any vault has integrated Momentum positions.

## Recommendation

**Immediate Actions:**
1. Do not add MomentumPosition assets to any vault until the integration is complete
2. If any vault has MomentumPosition assets, remove them immediately before any operation uses them

**Long-term Fix:**
Replace the stub mmt_v3 dependency with the actual Momentum protocol implementation:
- Update Move.toml to point to the real mmt_v3 contract at the mainnet package address `0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860` [15](#0-14) 
- Test all Momentum adaptor functions with real pool and position objects
- Add comprehensive integration tests for Momentum operations

## Proof of Concept

The vulnerability requires on-chain testing with deployed contracts, as it depends on the runtime linking of the mmt_v3 dependency. The stub implementations are published and linked based on the `published-at` configuration. A PoC would:

1. Deploy a vault with a MomentumPosition asset
2. Call `start_op_with_bag` borrowing the MomentumPosition
3. Call `end_op_with_bag` to return assets
4. Call `update_momentum_position_value` → Transaction aborts due to stub
5. Call `end_op_value_update_with_bag` → Fails because asset not marked as updated
6. Vault is now permanently stuck in `VAULT_DURING_OPERATION_STATUS`
7. Attempting `set_enabled` fails with `ERR_VAULT_DURING_OPERATION`

**Notes:**
The vulnerability's activation depends on whether the deployed volo_vault package links to the stub implementations at `0xc84b1ef2ac2ba5c3018e2b8c956ba5d0391e0e46d1daa1926d5a99a6a42526b4` or resolves to actual Momentum contract functions. The codebase evidence (README documentation, stub implementations, and published-at configuration) strongly indicates the stubs are what's deployed.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-5)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/i32.move (L15-16)
```text
    public fun zero(): I32 {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L25-26)
```text
    ) : (u64, u64) {
        abort 0
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L51-53)
```text
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
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

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L8-8)
```markdown
| mainnet-v1.1.3 | mainnet package id   | 0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860 |  
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L30-30)
```markdown
The MMT V3 interface provides function definitions only and is not a complete implementation. As a result, the Sui client may flag version inconsistencies when verifying the code. However, this does not impact the contract's functionality.
```

**File:** volo-vault/local_dependencies/mmt_v3/Move.toml (L4-4)
```text
published-at = "0xc84b1ef2ac2ba5c3018e2b8c956ba5d0391e0e46d1daa1926d5a99a6a42526b4"
```
