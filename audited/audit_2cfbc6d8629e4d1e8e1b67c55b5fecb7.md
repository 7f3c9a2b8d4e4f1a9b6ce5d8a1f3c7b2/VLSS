### Title
Critical Vault DoS and Fund Lockup via Stub MMT v3 Dependency with No Runtime Validation

### Summary
The MMT v3 dependency consists entirely of stub modules that immediately abort on any function call. If a MomentumPosition is added to the vault, all critical vault operations (deposits, withdrawals, operations) become permanently unusable because position value updates abort before completion. No runtime checks exist to detect or gracefully handle stub dependencies, causing complete vault lockup with all user funds trapped.

### Finding Description

The MMT v3 dependency at `volo-vault/local_dependencies/mmt_v3/` contains only stub implementations where every function immediately aborts: [1](#0-0) [2](#0-1) [3](#0-2) 

The momentum adaptor calls these stub functions to calculate position values: [4](#0-3) 

When `update_momentum_position_value` is called, it invokes `get_position_token_amounts`, which immediately aborts at line 78 when calling `tick_math::get_sqrt_price_at_tick`.

The critical failure path occurs because:

1. When a MomentumPosition defi asset is added, its value is initialized to 0 with update timestamp 0: [5](#0-4) 

2. All vault operations require `get_total_usd_value`, which enforces MAX_UPDATE_INTERVAL of 0 (same-transaction update requirement): [6](#0-5) [7](#0-6) 

3. Operations call `get_total_usd_value` to establish baseline valuation: [8](#0-7) 

4. Deposits require total USD value calculation: [9](#0-8) 

5. Withdrawals require share ratio calculation (which calls `get_total_usd_value`): [10](#0-9) 

With a MomentumPosition asset present, the operator must update its value before any vault operation. However, attempting to update causes immediate abort in stub functions, making `get_total_usd_value` permanently fail with `ERR_USD_VALUE_NOT_UPDATED`.

**Root Cause**: No runtime validation exists to detect stub/non-functional dependencies. The momentum adaptor functions are public and callable, but fail catastrophically rather than gracefully degrading or detecting the misconfiguration.

### Impact Explanation

**Complete Vault Operational Failure:**
- All deposit executions fail when calculating share ratios
- All withdrawal executions fail when calculating amounts  
- All vault operations fail when establishing baseline valuation
- User funds become permanently locked in the vault

**Direct User Fund Impact:**
- Existing depositors cannot withdraw their principal or rewards
- Pending withdrawal requests cannot be executed
- New deposits cannot be processed
- No recovery mechanism exists without removing the MomentumPosition asset

**Removal Restrictions:**
Asset removal requires NORMAL vault status: [11](#0-10) 

Once any operation begins and fails, the vault remains in failed state. Even though transaction abort reverts status changes, the vault cannot function with the MomentumPosition present.

**Severity**: Critical - Complete protocol lockup affecting all user funds with no automatic recovery path.

### Likelihood Explanation

**Preconditions:**
1. Operator adds MomentumPosition via `add_new_defi_asset` (requires OperatorCap): [12](#0-11) 

2. Stub MMT v3 modules deployed to production environment

**Realistic Scenario:**
An operator legitimately attempting to integrate Momentum protocol support would add a MomentumPosition asset, reasonably expecting it to function. The stub nature of MMT v3 modules is not obviously detectable without code inspection. The first indication of failure would be when operations abort, at which point user funds are already locked.

**Detection Difficulty:**
- No compile-time warnings about stub implementations
- No runtime checks for functional dependencies
- Failure manifests only when position value update is attempted
- Momentum adaptor interface appears complete and functional

**Likelihood**: Medium-High if stub modules are deployed. The question's framing ("if this stub module was intended for testing but accidentally deployed to production") assumes this deployment error has occurred, making the impact inevitable.

### Recommendation

**Immediate Mitigation:**
1. Remove all MMT v3 stub modules from production deployments
2. Implement either functional MMT v3 integration or remove momentum adaptor entirely
3. Add runtime validation in adaptors to detect and reject stub implementations

**Code-Level Fixes:**

1. Add version/capability checks in momentum adaptor:
```move
public fun update_momentum_position_value<PrincipalCoinType, CoinA, CoinB>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    pool: &mut MomentumPool<CoinA, CoinB>,
) {
    // Add runtime check for functional implementation
    assert!(is_mmt_v3_functional(), E_STUB_DEPENDENCY_DETECTED);
    // ... rest of implementation
}
```

2. Add graceful degradation in `get_total_usd_value` to skip assets that cannot be valued:
```move
// Attempt to get asset value with error handling
// If asset value cannot be updated, emit warning and skip
```

3. Add deployment validation tests that verify all dependencies are functional, not stubs

4. Implement emergency admin function to force-remove misconfigured assets without normal status requirements

### Proof of Concept

**Initial State:**
- Vault deployed and operational with SUI principal
- Users have deposited funds
- Operator has OperatorCap

**Attack Steps:**

1. Operator adds MomentumPosition to vault:
```
operation::add_new_defi_asset<SUI, MomentumPosition>(
    &operation, &cap, &mut vault, 0, momentum_position
)
```

2. Asset added with value=0, updated=0

3. Operator attempts any operation requiring total USD value:
```
operation::start_op_with_bag<SUI, USDC, T>(...)
// OR
operation::execute_deposit<SUI>(...)  
// OR
operation::execute_withdraw<SUI>(...)
```

4. **Expected**: Operation proceeds normally
5. **Actual**: Transaction aborts when attempting to call `tick_math::get_sqrt_price_at_tick` or `liquidity_math::get_amounts_for_liquidity` (both stub functions that immediately `abort 0`)

6. **Result**: 
   - All vault operations fail permanently
   - User funds locked
   - No recovery path without admin intervention to force-remove the asset

**Success Condition**: Vault becomes unusable and all user funds are trapped until MomentumPosition can be removed.

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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
```

**File:** volo-vault/sources/volo_vault.move (L820-821)
```text
    let total_usd_value_before = self.get_total_usd_value(clock);
    let share_ratio_before = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1006-1006)
```text
    let ratio = self.get_share_ratio(clock);
```

**File:** volo-vault/sources/volo_vault.move (L1264-1270)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
    });
```

**File:** volo-vault/sources/volo_vault.move (L1365-1366)
```text
    self.assets_value.add(asset_type, 0);
    self.assets_value_updated.add(asset_type, 0);
```

**File:** volo-vault/sources/volo_vault.move (L1395-1395)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/operation.move (L178-178)
```text
    let total_usd_value = vault.get_total_usd_value(clock);
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
