### Title
Dead Code Dependency Renders Momentum Adaptor Non-Functional, Causing Denial of Service Risk

### Summary
The entire `mmt_v3` local dependency contains dead code with all functions aborting immediately. The `momentum_adaptor` module depends on these non-functional modules to value `MomentumPosition` assets. If any `MomentumPosition` is added to the vault, all value update operations will fail with abort, causing denial of service for vault operations.

### Finding Description

The `global_config` module is part of a broader issue - the entire `mmt_v3` local dependency has all functions stubbed out with `abort 0`: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The `momentum_adaptor` module directly depends on these dead code functions: [6](#0-5) 

The vault operation flow includes explicit support for `MomentumPosition` assets: [7](#0-6) 

**Root Cause:** The `Move.toml` indicates MMT v3 uses local dependencies "because we need to remove some test functions with errors", but all implementation functions were left as stubs that abort: [8](#0-7) 

**Why Protections Fail:** The `momentum_adaptor::update_momentum_position_value` is a public function callable via Programmable Transaction Blocks. When called, it invokes `pool.sqrt_price()`, `position.tick_lower_index()`, `position.tick_upper_index()`, `position.liquidity()`, `tick_math::get_sqrt_price_at_tick()`, and `liquidity_math::get_amounts_for_liquidity()` - all of which immediately abort.

### Impact Explanation

**Operational Impact - Denial of Service:**
- If any `MomentumPosition` asset is added to the vault using the supported infrastructure, value updates will fail
- The three-phase vault operation pattern requires asset value updates before completing operations
- Failed value updates prevent vault operations from completing, freezing vault functionality
- All vault operations involving Momentum positions would abort, blocking deposits, withdrawals, and strategy execution

**Who Is Affected:**
- Vault operators unable to execute operations
- Users with pending requests stuck indefinitely
- Protocol revenue generation halted

**Severity:** HIGH - Complete loss of vault functionality if Momentum integration is attempted.

### Likelihood Explanation

**Current State:** LOW likelihood because:
- No test files demonstrate `MomentumPosition` usage
- The dead code suggests this feature is not yet deployed

**Latent Risk:** MEDIUM to HIGH likelihood if:
- Operators attempt to integrate Momentum protocol positions in the future
- The infrastructure exists and is callable via public functions
- No validation prevents adding `MomentumPosition` assets

**Attack Complexity:** None required - simply using the intended functionality causes failure.

**Feasibility:** Any operator or user with appropriate permissions can trigger the DoS by:
1. Adding a `MomentumPosition` to the vault
2. Calling `update_momentum_position_value` via PTB [9](#0-8) 

### Recommendation

**Immediate Actions:**
1. Either implement the `mmt_v3` modules with functional code or completely remove the Momentum adaptor
2. Add compile-time checks or runtime assertions to prevent adding `MomentumPosition` assets until the dependency is functional
3. Document the non-functional state of Momentum integration in deployment documentation

**Code-Level Mitigation:**
```move
// Add to vault.move add_new_defi_asset function:
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    // Prevent adding MomentumPosition until mmt_v3 is functional
    assert!(
        type_name::get<AssetType>() != type_name::get<mmt_v3::position::Position>(),
        ERR_UNSUPPORTED_ASSET_TYPE
    );
    // ... existing code
}
```

**Testing:**
- Add integration tests attempting to use `MomentumPosition` that should explicitly fail
- Add tests for all mmt_v3 functions to verify they are operational before enabling Momentum adaptor

### Proof of Concept

**Initial State:**
- Vault deployed and operational
- Operator has `OperatorCap`
- Momentum pool exists with liquidity

**Exploitation Steps:**
1. Operator adds a `MomentumPosition` to vault via `add_new_defi_asset<PrincipalCoinType, MomentumPosition>(vault, idx, momentum_position)`
2. Operator initiates vault operation via `start_op_with_bag` with `MomentumPosition` in `defi_asset_types`
3. Operator attempts to update position value via PTB calling `momentum_adaptor::update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(vault, config, clock, asset_type, pool)`
4. Transaction aborts at `pool.sqrt_price()` call

**Expected Result:** Position value successfully updated, operation proceeds

**Actual Result:** Transaction aborts with code 0, vault operation stuck in `VAULT_DURING_OPERATION_STATUS`, all subsequent operations blocked

**Success Condition:** Vault becomes non-operational for all operations involving the Momentum position, requiring manual intervention to remove the position or revert vault state.

### Notes

The question specifically asks about `global_config` being abandoned/deprecated. Investigation confirms this is accurate, but the scope is much broader - the **entire mmt_v3 dependency is dead code**. This indicates either:
1. An incomplete integration where placeholder code was committed
2. Intentional removal of functionality but retention of module structure
3. Future planned integration not yet implemented

The comment in `Move.toml` stating "we need to remove some test functions with errors" suggests intentional modification, but leaving all implementations as stubs creates a latent vulnerability whenever the Momentum adaptor is used.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/global_config.move (L16-24)
```text
    fun init(tx_context: &mut TxContext) {
        abort 0
    }

    public fun contains_fee_rate(self: &GlobalConfig, fee_rate: u64): bool { abort 0 }

    public fun get_tick_spacing(self: &GlobalConfig, fee_rate: u64): u32 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/pool.move (L98-150)
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L4-27)
```text
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
