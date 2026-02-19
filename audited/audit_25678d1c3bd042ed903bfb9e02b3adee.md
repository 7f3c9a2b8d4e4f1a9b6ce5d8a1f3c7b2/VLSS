### Title
MMT V3 Stub Implementation Causes Permanent Vault Lockup When Momentum Positions Are Used

### Summary
All MMT v3 math functions contain only `abort 0` stub implementations, but the momentum adaptor attempts to call these functions when updating position values. Since the vault's operation system mandates that all borrowed assets must have their values updated before completing operations, any operation involving a MomentumPosition will permanently lock the vault in `VAULT_DURING_OPERATION_STATUS`, creating a complete denial of service.

### Finding Description

The MMT v3 local dependency contains only stub implementations with `abort 0` for all math functions: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The momentum adaptor calls these stub functions when calculating position values: [6](#0-5) 

Both Move.toml configurations use the local stub implementation instead of the actual on-chain MMT v3 package: [7](#0-6) [8](#0-7) 

The critical failure occurs in the vault's operation flow. When assets are borrowed during operations, they are tracked: [9](#0-8) 

After operations complete, the protocol MANDATES that all borrowed assets have their values updated: [10](#0-9) [11](#0-10) 

The MomentumPosition can be borrowed during operations: [12](#0-11) 

### Impact Explanation

When a MomentumPosition is added to the vault and used in operations:

1. The operation borrows the MomentumPosition, recording it in `op_value_update_record.asset_types_borrowed`
2. After returning assets, the operator must call `update_momentum_position_value` to mark it as updated
3. This function immediately aborts because it calls MMT v3 stub functions
4. Without the value update, `check_op_value_update_record` will abort with `ERR_USD_VALUE_NOT_UPDATED`
5. The vault remains permanently stuck in `VAULT_DURING_OPERATION_STATUS`
6. No further operations can be initiated, and all vault functionality is frozen
7. User deposits/withdrawals cannot be processed
8. The vault's total value cannot be updated, affecting share price calculations

This is a complete denial of service affecting all vault users and operations. All funds remain locked until a contract upgrade removes the MomentumPosition.

### Likelihood Explanation

Current likelihood is **Low** because no MomentumPosition assets appear to be actively used (no tests exist for momentum positions). However, likelihood becomes **High** immediately upon adding any MomentumPosition to the vault, as this is:

- A supported feature with dedicated adaptor code
- Normal administrative action to diversify vault assets  
- Not requiring any malicious intent or compromise
- Standard vault operations that borrow and value assets

The vulnerability activates through normal protocol usage once momentum positions are integrated. The adaptor's presence indicates this integration was planned or is planned.

### Recommendation

**Immediate Action:**
1. Remove or comment out the momentum adaptor module until MMT v3 implementation is available
2. Add validation in `add_new_defi_asset` to prevent adding MomentumPosition types
3. Update Move.toml to use the actual on-chain MMT v3 package when available:
   ```toml
   [dependencies.mmt_v3]
   git = "https://github.com/mmt-finance/mmt-contract-interface.git"
   rev = "mainnet-v1.1.3"
   subdir = "mmt_v3"
   addr = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
   ```

**Long-term Solution:**
1. Wait for MMT v3 interface to be properly integrated with actual implementation
2. Add comprehensive integration tests for momentum positions before enabling
3. Implement circuit breaker to allow emergency removal of problematic asset types

**Test Cases:**
- Test adding MomentumPosition and performing operation that borrows it
- Verify all MMT v3 math functions return valid values (not abort)
- Test complete operation cycle with momentum position value updates

### Proof of Concept

**Initial State:**
- Vault deployed and operational
- Oracle configured with price feeds

**Exploit Steps:**

1. Admin adds a MomentumPosition to the vault:
   ```
   vault.add_new_defi_asset<PrincipalCoin, MomentumPosition>(0, momentum_position)
   ```

2. Operator starts an operation borrowing the momentum position:
   ```
   start_op_with_bag(..., defi_asset_ids: [0], defi_asset_types: [MomentumPosition], ...)
   ```
   - Vault records MomentumPosition in `op_value_update_record.asset_types_borrowed`
   - Vault status set to `VAULT_DURING_OPERATION_STATUS`

3. Operator returns the position:
   ```
   end_op_with_bag(...) 
   ```
   - Position returned successfully

4. Operator attempts required value update:
   ```
   update_momentum_position_value(&mut vault, &config, &clock, asset_type, &mut pool)
   ```
   - **Transaction ABORTS** at line 78 or 83 when calling MMT v3 stub functions

5. Operator cannot complete operation:
   ```
   end_op_value_update_with_bag(...)
   ```
   - **Transaction ABORTS** with `ERR_USD_VALUE_NOT_UPDATED` because MomentumPosition not in `asset_types_updated`

**Result:** Vault permanently locked in `VAULT_DURING_OPERATION_STATUS`, all operations frozen, complete denial of service.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/sqrt_price_math.move (L1-32)
```text
module mmt_v3::sqrt_price_math {
    public fun get_amount_x_delta(
        sqrt_price_start: u128, 
        sqrt_price_end: u128, 
        liquidity: u128, 
        round_up: bool
    ) : u64 {
        abort 0
    }
    
    public fun get_amount_y_delta(sqrt_price_start: u128, sqrt_price_end: u128, liquidity: u128, round_up: bool) : u64 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_amount_x_rouding_up(current_price: u128, liquidity: u128, amount: u64, round_up: bool) : u128 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_amount_y_rouding_down(current_price: u128, liquidity: u128, amount: u64, round_up: bool) : u128 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_input(current_price: u128, liquidity: u128, amount: u64, is_token0: bool) : u128 {
        abort 0
    }
    
    public fun get_next_sqrt_price_from_output(current_price: u128, liquidity: u128, amount: u64, is_token0: bool) : u128 {
        abort 0
    }
    
    
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L1-53)
```text
module mmt_v3::liquidity_math {
    use mmt_v3::i128::{I128};

    public fun add_delta(current_liquidity: u128, delta_liquidity: I128) : u128 {
        abort 0
    }
    
    // get amount x for delta liquidity
    public fun get_amount_x_for_liquidity(sqrt_price_current: u128, sqrt_price_target: u128, liquidity: u128, round_up: bool) : u64 {
        abort 0
    }
    
    // get amount y for delta liquidity.
    public fun get_amount_y_for_liquidity(sqrt_price_current: u128, sqrt_price_target: u128, liquidity: u128, round_up: bool) : u64 {
        abort 0
    }
    
    // returns amounts of both assets as per delta liquidity.
    public fun get_amounts_for_liquidity(
        sqrt_price_current: u128, 
        sqrt_price_lower: u128, 
        sqrt_price_upper: u128, 
        liquidity: u128, 
        round_up: bool
    ) : (u64, u64) {
        abort 0
    }
    
    // get delta liquidity by amount x.
    public fun get_liquidity_for_amount_x(sqrt_price_current: u128, sqrt_price_target: u128, amount_x: u64) : u128 {
        abort 0
    }
    
    // get delta liquidity by amount y.
    public fun get_liquidity_for_amount_y(sqrt_price_current: u128, sqrt_price_target: u128, amount_y: u64) : u128 {
        abort 0
    }
    
    // returns liquidity from amounts x & y.
    public fun get_liquidity_for_amounts(sqrt_price_current: u128, sqrt_price_lower: u128, sqrt_price_upper: u128, amount_x: u64, amount_y: u64) : u128 {
        abort 0
    }

    public fun check_is_fix_coin_a(
        lower_sqrt_price: u128,
        upper_sqrt_price: u128,
        current_sqrt_price: u128,
        amount_a: u64,
        amount_b: u64
    ): (bool, u64, u64) {
        abort 0
    }
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L1-35)
```text
module mmt_v3::tick_math {
    use mmt_v3::i32::{I32};
    
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
    
    public fun get_tick_at_sqrt_price(arg0: u128) : I32 {
        abort 0
    }
    
    public fun is_valid_index(arg0: I32, arg1: u32) : bool {
        abort 0
    }
    
    public fun max_sqrt_price() : u128 {
        abort 0
    }
    
    public fun max_tick() : I32 {
        abort 0
    }
    
    public fun min_sqrt_price() : u128 {
        abort 0
    }
    
    public fun min_tick() : I32 {
        abort 0
    }
    
    public fun tick_bound() : u32 {
        abort 0
    }
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L98-192)
```text
    public fun initialize<X, Y>(
        pool: &mut Pool<X, Y>,
        sqrt_price: u128,
        clock: &Clock
    ) {
        abort 0
    }

    public fun verify_pool<X, Y>(
        pool: &Pool<X, Y>,
        id: ID,
    ) {
        abort 0
    }

    #[allow(lint(share_owned))]
    public fun transfer<X, Y>(self: Pool<X, Y>) {
        abort 0
    }

    public fun borrow_observations<X, Y>(pool: &Pool<X, Y>): &vector<Observation> { abort 0 }
    public fun borrow_tick_bitmap<X, Y>(pool: &Pool<X, Y>): &Table<I32, u256> { abort 0 }
    public fun borrow_ticks<X, Y>(pool: &Pool<X, Y>): &Table<I32, TickInfo> { abort 0 }

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

    // oracle public functions
    public fun observe<X, Y>(
        pool: &Pool<X, Y>,
        seconds_ago: vector<u64>,
        clock: &Clock
    ): (vector<i64::I64>, vector<u256>) {
        abort 0
    }

    // rewards getters
    public fun total_reward<X, Y>(pool: &Pool<X, Y>, reward_id: u64) : u64 { abort 0 }
    public fun total_reward_allocated<X, Y>(pool: &Pool<X, Y>, reward_id: u64) : u64 { abort 0 }
    public fun reward_ended_at<X, Y>(pool: &Pool<X, Y>, reward_index: u64): u64 { abort 0 }
    public fun reward_growth_global<X, Y>(pool: &Pool<X, Y>, timestamp: u64): u128 { abort 0 }
    public fun reward_last_update_at<X, Y>(pool: &Pool<X, Y>, reward_index: u64): u64 { abort 0 }
    public fun reward_per_seconds<X, Y>(pool: &Pool<X, Y>, timestamp: u64): u128 { abort 0 }
    public fun reward_length<X, Y>(pool: &Pool<X, Y>): u64 {abort 0}
    public fun reward_info_at<X, Y>(pool: &Pool<X, Y>, index: u64): &PoolRewardInfo {
        abort 0
    }

    // returns friendly ticks by adjusting tick spacing of the pool.
    public fun get_friendly_ticks<X, Y>(
        pool: &Pool<X, Y>, 
        lower_sqrt_price: u128, 
        upper_sqrt_price: u128
    ): (I32, I32) {
        abort 0
    }



    fun find_reward_info_index<X, Y, R>(
        pool: &Pool<X, Y>
    ): u64 {
        abort 0
    }

    fun safe_withdraw<X>(balance: &mut Balance<X>, amount: u64) : Balance<X> {
        abort 0
    }
}
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/position.move (L36-60)
```text
    public fun coins_owed_reward(position: &Position, reward_index: u64) : u64 {
        abort 0
    }

    // returns if position does not have claimable rewards.
    public fun is_empty(position: &Position) : bool {
        abort 0
    }
    
    public fun reward_growth_inside_last(position: &Position, reward_index: u64) : u128 {
        abort 0
    }
    
    // public getter functions
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

**File:** volo-vault/Move.toml (L79-86)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/mmt_v3"
rev = "main"
```

**File:** volo-vault/Move.mainnet.toml (L72-77)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
local = "./local_dependencies/mmt_v3"
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

**File:** volo-vault/sources/volo_vault.move (L1415-1426)
```text
public(package) fun borrow_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
): AssetType {
    self.check_version();
    self.assert_enabled();

    assert!(contains_asset_type(self, asset_type), ERR_ASSET_TYPE_NOT_FOUND);

    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
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
