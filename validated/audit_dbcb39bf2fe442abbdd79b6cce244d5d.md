# Audit Report

## Title
Momentum Adaptor DoS Due to Stub Implementation Dependencies

## Summary
The Momentum adaptor depends on stub implementations of the mmt_v3 library where all functions unconditionally abort. Any vault operation borrowing a MomentumPosition will abort when attempting to update its value, permanently locking the vault in `VAULT_DURING_OPERATION_STATUS` with no recovery mechanism.

## Finding Description

The vulnerability exists in the mmt_v3 dependency configuration and its integration with vault operations.

**Root Cause - Stub Dependencies:**

The mmt_v3 dependency is configured to use local stub implementations instead of the actual Momentum protocol deployment. [1](#0-0) 

All functions in these stub modules immediately abort:
- Position module functions [2](#0-1) 
- Pool module functions [3](#0-2) 
- Liquidity math functions [4](#0-3) 
- Tick math functions [5](#0-4) 

The README explicitly confirms: "The MMT V3 interface provides function definitions only and is not a complete implementation." [6](#0-5) 

**Execution Path:**

When an operator borrows a MomentumPosition during vault operations, the asset type is tracked. [7](#0-6) 

The Momentum adaptor's `update_momentum_position_value` function calls `get_position_token_amounts`, [8](#0-7)  which invokes multiple stub functions that will abort. [9](#0-8) 

**Why Protections Fail:**

After returning borrowed assets, `end_op_with_bag` enables value updates. [10](#0-9) 

Subsequently, `end_op_value_update_with_bag` checks that all borrowed assets have updated values [11](#0-10)  via `check_op_value_update_record`. [12](#0-11) 

Since the Momentum value update aborts before reaching `finish_update_asset_value`, [13](#0-12)  the asset cannot be marked as updated, and the operation cannot complete.

The vault remains stuck in `VAULT_DURING_OPERATION_STATUS`, and the admin's `set_enabled` function explicitly prevents status changes while in this state. [14](#0-13) 

## Impact Explanation

**Critical Protocol DoS:**

- Any vault operation borrowing a MomentumPosition becomes permanently frozen
- The vault cannot return to `VAULT_NORMAL_STATUS`, blocking all deposit/withdrawal executions which require normal status [15](#0-14) 
- Users' funds remain locked with no administrative recovery function
- The entire vault must be abandoned and migrated

This violates the core vault operation invariant that operations can be completed after returning borrowed assets. The vault status mechanism becomes irrecoverably corrupted, with no administrative function capable of forcing a status reset from `VAULT_DURING_OPERATION_STATUS`.

## Likelihood Explanation

**High Likelihood Given Preconditions:**

- Requires vault to have stored a MomentumPosition (operator must have added one via `add_new_defi_asset`) [16](#0-15) 
- Any authorized operator performing normal vault operations with that position will trigger the issue
- The failure is deterministic - stub functions always abort with no conditional logic
- No special network conditions or timing requirements
- The configuration explicitly uses local stubs rather than the deployed Momentum contract

The vulnerability is currently dormant but becomes active immediately if any vault integrates a MomentumPosition asset.

## Recommendation

Replace the local stub implementations with the actual Momentum protocol deployment by uncommenting and using the mainnet deployment configuration:

```toml
[dependencies.mmt_v3]
git    = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev    = "mainnet-v1.1.3"
subdir = "mmt_v3"
addr   = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

Additionally, implement an emergency recovery function that allows admins to force vault status reset under specific conditions, or add logic to allow vault operations to complete even if some asset value updates fail (with appropriate safeguards).

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a vault and adding a MomentumPosition via `add_new_defi_asset`
2. Calling `start_op_with_bag` with the MomentumPosition in `defi_asset_ids`/`defi_asset_types`
3. Attempting to call the Momentum adaptor's `update_momentum_position_value`
4. The transaction aborts due to stub function calls
5. The vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`
6. All attempts to call `set_enabled` or execute deposits/withdrawals fail

The deterministic nature of the stub aborts makes this vulnerability immediately exploitable under the stated preconditions.

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

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L50-59)
```text
    public fun reward_length(position: &Position) : u64 { abort 0 }
    public fun tick_lower_index(position: &Position) : I32 { abort 0 }
    public fun tick_upper_index(position: &Position) : I32 { abort 0 }
    public fun liquidity(position: &Position) : u128 { abort 0 }
    public fun owed_coin_x(position: &Position) : u64 { abort 0 }
    public fun owed_coin_y(position: &Position) : u64 { abort 0 }
    public fun fee_growth_inside_x_last(position: &Position) : u128 { abort 0 }
    public fun fee_growth_inside_y_last(position: &Position) : u128 { abort 0 }
    public fun fee_rate(position: &Position) : u64 { abort 0 }
    public fun pool_id(position: &Position) : ID { abort 0 }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L122-149)
```text
    public fun get_reserves<X, Y>(
        pool: &Pool<X, Y>
    ): (u64, u64) {
        abort 0
    }
    
    // pool getters
    public fun type_x<X, Y>(pool: &Pool<X, Y>): TypeName { abort 0 }
    public fun type_y<X, Y>(pool: &Pool<X, Y>): TypeName { abort 0 }
    public fun liquidity<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
    public fun sqrt_price<X, Y>(self: &Pool<X, Y>) : u128 { abort 0 }
    public fun tick_index_current<X, Y>(pool: &Pool<X, Y>) : I32 { abort 0 }
    public fun tick_spacing<X, Y>(pool: &Pool<X, Y>) : u32 { abort 0 }
    public fun max_liquidity_per_tick<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
    public fun observation_cardinality<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun observation_cardinality_next<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun observation_index<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun pool_id<X, Y>(pool: &Pool<X, Y>): ID { abort 0 }
    public fun swap_fee_rate<X, Y>(self: &Pool<X, Y>) : u64 { abort 0 }
    public fun flash_loan_fee_rate<X, Y>(self: &Pool<X, Y>) : u64 { abort 0 }
    public fun protocol_fee_share<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun protocol_flash_loan_fee_share<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun protocol_fee_x<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun protocol_fee_y<X, Y>(pool: &Pool<X, Y>): u64 { abort 0 }
    public fun reserves<X, Y>(pool: &Pool<X, Y>): (u64, u64) { abort 0 }
    public fun reward_coin_type<X, Y>(pool: &Pool<X, Y>, index: u64): TypeName { abort 0 }
    public fun fee_growth_global_x<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
    public fun fee_growth_global_y<X, Y>(pool: &Pool<X, Y>): u128 { abort 0 }
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-10)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/README.md (L30-30)
```markdown
The MMT V3 interface provides function definitions only and is not a complete implementation. As a result, the Sui client may flag version inconsistencies when verifying the code. However, this does not impact the contract's functionality.
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

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
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

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L1174-1203)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;

    if (
        self.status() == VAULT_DURING_OPERATION_STATUS 
        && self.op_value_update_record.value_update_enabled 
        && self.op_value_update_record.asset_types_borrowed.contains(&asset_type)
    ) {
        self.op_value_update_record.asset_types_updated.add(asset_type, true);
    };

    emit(AssetValueUpdated {
        vault_id: self.vault_id(),
        asset_type: asset_type,
        usd_value: usd_value,
        timestamp: now,
    });
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
