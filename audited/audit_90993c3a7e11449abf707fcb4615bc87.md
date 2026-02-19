### Title
Complete Momentum Adaptor Failure Due to Stub Implementation Causing Vault DoS

### Summary
The entire mmt_v3 dependency consists of stub implementations where all functions call `abort 0`, yet the production momentum_adaptor depends on these functions to calculate position values. When a vault contains a MomentumPosition, any attempt to update its value will abort the transaction, blocking all deposits and withdrawals due to mandatory asset value update requirements.

### Finding Description
The mmt_v3 local dependency was created to "remove some test functions with errors" [1](#0-0)  but instead contains complete stub implementations where every function simply aborts.

All critical functions are stubs:
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

The momentum_adaptor's core functionality depends on these stub functions: [5](#0-4) 

MomentumPosition is explicitly supported in vault operations: [6](#0-5) 

The vault requires all asset values to be updated within MAX_UPDATE_INTERVAL (set to 0) before calculating total USD value: [7](#0-6)  and [8](#0-7) 

### Impact Explanation
**Severity: CRITICAL - Vault Denial of Service**

When a MomentumPosition exists in a vault:
1. The `update_momentum_position_value` function will abort when calling stub implementations
2. Without updated position value, `get_total_usd_value` will abort due to staleness check
3. Deposits and withdrawals require `get_total_usd_value` to calculate share ratios
4. The vault becomes completely non-functional for all users
5. The vault may become stuck in "during operation" status if position value update is attempted during an operation

All depositors and withdrawers are blocked from accessing their funds. The protocol cannot function with Momentum positions despite explicit support in the codebase.

### Likelihood Explanation
**Likelihood: HIGH**

- **Precondition**: Admin/operator adds a MomentumPosition using `add_new_defi_asset` [9](#0-8) 
- **Trigger**: Any operation requiring total USD value calculation (deposits, withdrawals, operations)
- **Complexity**: No complex attack required - normal protocol usage triggers the bug
- **Detection**: Would be immediately evident once a MomentumPosition is added
- **Cost**: Zero cost attack - happens through normal operations

The vulnerability is guaranteed to manifest if MomentumPosition support is used, as the code is deployed with stub implementations.

### Recommendation
**Immediate Actions:**
1. Replace the local mmt_v3 dependency stub implementations with the real mainnet implementations from the original source: [10](#0-9) 

2. Remove or properly implement the momentum_adaptor module - do not leave it in a non-functional state

3. Add integration tests that verify momentum adaptor functionality end-to-end before deployment

4. Implement CI/CD checks that run all tests including those in dependencies to catch stub implementations

**Code-Level Fix:**
Replace the entire `volo-vault/local_dependencies/mmt_v3` directory with actual implementations from `https://github.com/mmt-finance/mmt-contract-interface.git` at `mainnet-v1.1.3` or remove MomentumPosition support entirely.

**Test Requirements:**
Add integration tests that:
- Create a vault with a MomentumPosition
- Call `update_momentum_position_value`
- Execute deposits and withdrawals
- Verify all operations complete successfully

### Proof of Concept
**Setup:**
1. Deploy vault with published-at address [11](#0-10) 
2. Admin calls `add_new_defi_asset` with a MomentumPosition [9](#0-8) 

**Exploit:**
1. User initiates deposit request
2. Operator attempts to execute deposit [12](#0-11) 
3. System calls `get_total_usd_value` which requires updated asset values
4. Operator calls `update_momentum_position_value` [13](#0-12) 
5. Function calls `tick_math::get_sqrt_price_at_tick` which aborts [14](#0-13) 

**Result:**
Transaction aborts with error code 0. Deposit cannot be executed. All vault operations blocked.

**Expected vs Actual:**
- Expected: Position value calculated, deposit executed successfully
- Actual: Transaction aborts, vault becomes non-functional

### Citations

**File:** volo-vault/Move.toml (L4-4)
```text
published-at = "0x4da7b643d0e7bfa5ec6f10e0dc28e562068114e913864a84f61be0cb26b684e0"
```

**File:** volo-vault/Move.toml (L45-49)
```text
# [dependencies.mmt_v3]
# git    = "https://github.com/mmt-finance/mmt-contract-interface.git"
# rev    = "mainnet-v1.1.3"
# subdir = "mmt_v3"
# addr   = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
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

**File:** volo-vault/local_dependencies/mmt_v3/sources/i64.move (L15-125)
```text
    public fun zero(): I64 {
        abort 0
    }

    public fun from_u64(v: u64): I64 {
        abort 0
    }

    public fun from(v: u64): I64 {
        abort 0
    }

    public fun neg_from(v: u64): I64 {
        abort 0
    }

    public fun wrapping_add(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun add(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun wrapping_sub(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun sub(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun mul(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun div(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun abs(v: I64): I64 {
        abort 0
    }

    public fun abs_u64(v: I64): u64 {
        abort 0
    }

    public fun shl(v: I64, shift: u8): I64 {
        abort 0
    }

    public fun shr(v: I64, shift: u8): I64 {
        abort 0
    }

    public fun mod(v: I64, n: I64): I64 {
        abort 0
    }

    public fun as_u64(v: I64): u64 {
        abort 0
    }

    public fun sign(v: I64): u8 {
        abort 0
    }

    public fun is_neg(v: I64): bool {
        abort 0
    }

    public fun cmp(num1: I64, num2: I64): u8 {
        abort 0
    }

    public fun eq(num1: I64, num2: I64): bool {
        abort 0
    }

    public fun gt(num1: I64, num2: I64): bool {
        abort 0
    }

    public fun gte(num1: I64, num2: I64): bool {
        abort 0
    }

    public fun lt(num1: I64, num2: I64): bool {
        abort 0
    }

    public fun lte(num1: I64, num2: I64): bool {
        abort 0
    }

    public fun or(num1: I64, num2: I64): I64 {
        abort 0
    }

    public fun and(num1: I64, num2: I64): I64 {
        abort 0
    }

    fun u64_neg(v: u64): u64 {
        abort 0
    }

    fun u8_neg(v: u8): u8 {
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L78-89)
```text
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

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
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

**File:** volo-vault/sources/volo_vault.move (L40-40)
```text
const MAX_UPDATE_INTERVAL: u64 = 0; // max update interval 0
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
