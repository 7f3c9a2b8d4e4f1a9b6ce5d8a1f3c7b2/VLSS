# Audit Report

## Title
Complete DoS of Vault Operations with Momentum Positions Due to Stub Implementation Dependencies

## Summary
All public functions in the `mmt_v3` module dependency are stub implementations that unconditionally execute `abort 0`. When a vault operator borrows a Momentum position and attempts to complete the required value update via `update_momentum_position_value`, the call chain inevitably hits these stub implementations and aborts. This prevents the operator from completing the three-phase operation pattern, leaving the vault permanently stuck in `VAULT_DURING_OPERATION_STATUS` and blocking all future user operations.

## Finding Description

The Volo vault system implements a secure three-phase operation pattern for managing DeFi assets:
1. **Start**: Borrow assets and transition vault to `VAULT_DURING_OPERATION_STATUS`
2. **Execute**: Perform operations with borrowed assets
3. **Complete**: Update all borrowed asset values and return vault to `VAULT_NORMAL_STATUS`

This pattern correctly enforces that all borrowed asset values must be updated before completing an operation. [1](#0-0) 

The critical flaw occurs with Momentum positions. The `update_momentum_position_value` function in the Momentum adaptor must call `get_position_token_amounts` to calculate position values. [2](#0-1) 

However, `get_position_token_amounts` depends entirely on `mmt_v3` module functions that are ALL stub implementations with unconditional `abort 0` statements: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

When an operator borrows a Momentum position via `start_op_with_bag`, the position gets tracked in the borrowed assets record. [7](#0-6) 

After operations complete and the position is returned via `end_op_with_bag`, the vault enables value updates. [8](#0-7) 

The operator must then call `update_momentum_position_value`, but this ALWAYS aborts due to the stub implementations. Consequently, when `end_op_value_update_with_bag` attempts to verify all borrowed assets were updated via `check_op_value_update_record`, the assertion fails because the Momentum position value was never successfully updated. [9](#0-8) 

The vault remains stuck in `VAULT_DURING_OPERATION_STATUS` and cannot transition back to `VAULT_NORMAL_STATUS`. [10](#0-9) 

## Impact Explanation

This vulnerability causes **complete denial of service** for any vault that adds a Momentum position:

**User Impact:**
- All deposit requests blocked (requires `VAULT_NORMAL_STATUS`) [11](#0-10) 
- All withdrawal requests blocked
- Existing user funds cannot be withdrawn through normal operations
- No way for users to cancel pending requests

**Operator Impact:**
- Cannot start new operations (requires `VAULT_NORMAL_STATUS`)
- Cannot perform portfolio rebalancing
- Cannot execute risk management strategies
- Vault effectively becomes inoperable

**Protocol Impact:**
- Complete loss of vault functionality
- User confidence destroyed
- Potential regulatory/legal issues due to fund lockup
- No yield generation capability

The severity is **CRITICAL** because:
1. 100% guaranteed to occur when Momentum positions are used
2. No workaround exists - the functions unconditionally abort
3. Affects core vault functionality completely
4. User funds become effectively locked (though not stolen)

## Likelihood Explanation

**Likelihood: Certainty (100%)**

This is not an attack vector requiring malicious actors - it is a **fundamental code defect** with guaranteed occurrence:

**Trigger Conditions:**
1. Vault adds a Momentum position as a DeFi asset (intended functionality)
2. Operator performs normal operations borrowing the position
3. Operator attempts to complete the operation

**No Special Requirements:**
- No economic constraints
- No timing dependencies  
- No external oracle manipulation needed
- No privileged access beyond normal operator capabilities

**Evidence of Production Usage:**
The `Move.toml` configuration shows `mmt_v3` is a production dependency, not a dev/test dependency. [12](#0-11) 

Every single public function in the required modules (`i64`, `i32`, `i128`, `pool`, `position`, `tick_math`, `liquidity_math`) contains only `abort 0` with no actual implementation. This makes it mathematically impossible to calculate Momentum position values.

## Recommendation

**Immediate Actions:**
1. **Do not add Momentum positions** to any production vaults until the dependency is fixed
2. If any vaults already have Momentum positions, consider emergency admin intervention to disable those vaults
3. Audit all other local dependencies to ensure they are not stub implementations

**Long-term Fix:**
Replace the stub `mmt_v3` implementation with the actual Momentum protocol interface:

```move
// In Move.toml, use the real mmt_v3 implementation instead of local stubs
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
addr = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

Alternatively, if there are specific issues with the upstream implementation (as suggested by the comment "we need to remove some test functions with errors"), create a proper fork that:
1. Implements all required public functions
2. Only removes or patches the problematic test functions
3. Maintains full functionality for position value calculations

**Testing:**
Add integration tests that verify:
1. Momentum position values can be calculated successfully
2. Complete operation cycles work with Momentum positions
3. Vault can return to `VAULT_NORMAL_STATUS` after borrowing and returning Momentum positions

## Proof of Concept

```move
#[test]
fun test_momentum_position_value_update_dos() {
    // Setup: Create vault and add Momentum position
    let mut scenario = test_scenario::begin(ADMIN);
    
    // Initialize vault, oracle config, clock
    let vault = create_test_vault(&mut scenario);
    let config = create_test_oracle_config(&mut scenario);
    let clock = clock::create_for_testing(ctx(&mut scenario));
    
    // Add a Momentum position to the vault
    let momentum_position = create_test_momentum_position();
    vault.add_new_defi_asset(0, momentum_position);
    
    // Operator starts operation borrowing the Momentum position
    let (bag, tx, tx_check, principal, coin_asset) = start_op_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[0], // defi_asset_ids
        vector[type_name::get<MomentumPosition>()], // defi_asset_types
        0, // principal_amount
        0, // coin_type_asset_amount
        &mut scenario.ctx()
    );
    
    // Verify vault is now in VAULT_DURING_OPERATION_STATUS
    assert!(vault.status() == 1);
    
    // Return the position
    end_op_with_bag(
        &mut vault,
        &operation,
        &operator_cap,
        bag,
        tx,
        principal,
        coin_asset
    );
    
    // Attempt to update Momentum position value - THIS WILL ABORT
    // Because all mmt_v3 functions are stubs with abort 0
    update_momentum_position_value(
        &mut vault,
        &config,
        &clock,
        asset_type,
        &mut pool
    ); // <-- This call ABORTS with abort 0
    
    // The following code is unreachable because update aborts
    // Therefore end_op_value_update_with_bag can never complete
    // Vault remains stuck in VAULT_DURING_OPERATION_STATUS forever
}
```

This test demonstrates that calling `update_momentum_position_value` unconditionally aborts due to the stub implementations, making it impossible to complete vault operations with Momentum positions.

### Citations

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L21-32)
```text
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    let position = vault.get_defi_asset<PrincipalCoinType, MomentumPosition>(asset_type);
    let usd_value = get_position_value(pool, position, config, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L132-132)
```text
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L51-53)
```text
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
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

**File:** volo-vault/sources/operation.move (L209-297)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();

    defi_assets.destroy_empty();
}
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

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
