# Audit Report

## Title
Vault Permanent DoS via Stub MMT v3 Implementation in Momentum Adaptor

## Summary
The volo-vault integrates a local stub implementation of MMT v3 containing only function signatures with `abort 0` statements. When a MomentumPosition asset is added to the vault and used in an operation, the required value update will always abort, permanently locking the vault in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism available to admins.

## Finding Description

The codebase has a critical integration failure where MMT v3 dependency uses stub implementations instead of the actual protocol. The README explicitly confirms this is an interface-only package that provides "function definitions only and is not a complete implementation". [1](#0-0) 

All critical functions contain only `abort 0` statements:
- `pool.sqrt_price()` [2](#0-1) 
- `position.tick_lower_index()` [3](#0-2) 
- `position.tick_upper_index()` [4](#0-3) 
- `position.liquidity()` [5](#0-4) 
- `tick_math::get_sqrt_price_at_tick()` [6](#0-5) 
- `liquidity_math::get_amounts_for_liquidity()` [7](#0-6) 

However, the momentum adaptor attempts to call these functions to calculate position value. [8](#0-7) 

The vault operation system explicitly supports MomentumPosition assets in the operation flow, allowing them to be borrowed during operations. [9](#0-8) 

When an operation borrows a DeFi asset during `VAULT_DURING_OPERATION_STATUS`, it tracks it in `op_value_update_record.asset_types_borrowed`. [10](#0-9) 

After returning assets via `end_op_with_bag()`, the vault enables value updates. [11](#0-10) 

The system then requires all borrowed assets to have updated values through `check_op_value_update_record()`. [12](#0-11)  This check asserts that every borrowed asset type appears in the `asset_types_updated` table with a `true` value, otherwise aborting with `ERR_USD_VALUE_NOT_UPDATED`.

If the value update fails (which it will due to stub aborts), the vault cannot complete the operation. The only function that sets status back to `VAULT_NORMAL_STATUS` is `end_op_value_update_with_bag()` at the end of a successful operation. [13](#0-12) 

There is no admin recovery function because `set_enabled()` explicitly prevents use during operations: [14](#0-13) 

## Impact Explanation

**Operational DoS - Permanent Vault Bricking:**

Once any MomentumPosition is added and included in an operation:
1. Calling `update_momentum_position_value()` will abort due to stub implementations
2. Without successful value updates, `check_op_value_update_record()` will abort with `ERR_USD_VALUE_NOT_UPDATED`
3. The operation cannot be completed via `end_op_value_update_with_bag()`
4. The vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS` (status = 1)
5. No further operations can be started (requires `VAULT_NORMAL_STATUS`)
6. No deposits/withdrawals can be executed (requires normal operation status)
7. All user funds and assets in the vault become permanently inaccessible
8. No admin function can recover from this state

**Who is affected:**
- All vault users lose access to their deposited funds
- Protocol operations completely halt
- Operators cannot perform any vault management

This is a **HIGH severity** issue because it results in permanent loss of access to all vault funds if the broken feature is used.

## Likelihood Explanation

**Reachable Entry Point:**
Operators can add MomentumPosition via the public operator function `add_new_defi_asset()`. [15](#0-14) 

**Feasibility:**
While operators are trusted roles, this is not a compromise scenario. The system is explicitly designed to support MomentumPosition assets alongside Navi, Cetus, and Suilend positions. An operator legitimately attempting to:
1. Add MomentumPosition integration (seeing it's implemented like other adaptors)
2. Use it in operations as the code design suggests
3. Update its value as required by the protocol

Will trigger this DoS. This could happen through:
- Operator misunderstanding that MMT v3 is stub-only
- Following patterns from other working adaptors (Cetus, Navi, Suilend)
- Testing/development configuration accidentally deployed to production

**Probability:** Medium-High

The code structure explicitly includes MomentumPosition in the operation system, suggesting it's intended functionality. Operators following standard integration patterns for other adaptors would naturally attempt to use it.

## Recommendation

**Option 1: Remove Non-Functional Integration**
Remove MomentumPosition support from the codebase entirely until the actual MMT v3 protocol implementation is available:
- Remove MomentumPosition handling from `operation.move`
- Remove or mark the momentum adaptor as deprecated
- Document that Momentum integration is not yet supported

**Option 2: Implement Actual MMT v3 Integration**
Replace the stub implementation with the actual MMT v3 protocol:
- Update `Move.toml` dependencies to point to the real MMT v3 deployment
- Verify all adaptor functions work with the actual implementation
- Add integration tests

**Option 3: Add Emergency Recovery**
Implement an emergency admin function that can force vault status changes:
```move
public fun emergency_reset_status<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
) {
    // Clear operation state without checks
    vault.clear_op_value_update_record();
    vault.set_status(VAULT_NORMAL_STATUS);
}
```

## Proof of Concept

```move
#[test]
fun test_momentum_position_dos() {
    let mut scenario = test_scenario::begin(OPERATOR);
    
    // Setup vault with MomentumPosition
    let momentum_position = /* create stub position */;
    let operation = scenario.take_shared<Operation>();
    let mut vault = scenario.take_shared<Vault<SUI>>();
    let operator_cap = scenario.take_from_sender<OperatorCap>();
    
    // Add MomentumPosition to vault
    operation::add_new_defi_asset<SUI, MomentumPosition>(
        &operation,
        &operator_cap,
        &mut vault,
        0,
        momentum_position
    );
    
    // Start operation with MomentumPosition
    let (assets, tx_bag, tx_update_bag, principal, coins) = 
        operation::start_op_with_bag<SUI, SUI, SUI>(
            &mut vault,
            &operation,
            &operator_cap,
            &clock,
            vector[0],
            vector[type_name::get<MomentumPosition>()],
            0,
            0,
            scenario.ctx()
        );
    
    // Return assets
    operation::end_op_with_bag<SUI, SUI, SUI>(
        &mut vault,
        &operation,
        &operator_cap,
        assets,
        tx_bag,
        principal,
        coins
    );
    
    // Try to update MomentumPosition value - THIS WILL ABORT
    momentum_adaptor::update_momentum_position_value<SUI, TokenA, TokenB>(
        &mut vault,
        &config,
        &clock,
        vault_utils::parse_key<MomentumPosition>(0),
        &mut pool
    ); // Aborts with error code 0
    
    // Cannot complete operation
    // operation::end_op_value_update_with_bag() will fail with ERR_USD_VALUE_NOT_UPDATED
    // Vault is now permanently stuck in VAULT_DURING_OPERATION_STATUS
}
```

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L28-30)
```markdown
## Usage

The MMT V3 interface provides function definitions only and is not a complete implementation. As a result, the Sui client may flag version inconsistencies when verifying the code. However, this does not impact the contract's functionality.
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L51-51)
```text
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L52-52)
```text
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L53-53)
```text
    public fun liquidity(position: &Position) : u128 { abort 0 }
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

**File:** volo-vault/sources/operation.move (L147-153)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/operation.move (L565-574)
```text
public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.add_new_defi_asset(idx, asset);
}
```

**File:** volo-vault/sources/volo_vault.move (L523-523)
```text
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
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
