### Title
Critical Missing Dependency: MMT v3 Stub Implementation Causes Vault Operation Failure with Momentum Positions

### Summary
The `mmt_v3::tick_math` and `mmt_v3::liquidity_math` modules contain only stub implementations that abort execution, yet are invoked in production code paths when processing Momentum protocol positions. When operators add MomentumPosition assets to vaults and perform operations, all transactions abort with error code 0, permanently locking the vault in DURING_OPERATION status and preventing user deposits/withdrawals.

### Finding Description

The `mmt_v3::tick_math` module contains stub implementations where all functions immediately abort: [1](#0-0) 

Similarly, the `mmt_v3::liquidity_math` module also contains stub implementations: [2](#0-1) 

These stub functions ARE called in production code paths. The momentum adaptor invokes `tick_math::get_sqrt_price_at_tick` to calculate position values: [3](#0-2) 

And invokes `liquidity_math::get_amounts_for_liquidity`: [4](#0-3) 

This function chain is triggered during vault operations when `update_momentum_position_value` is called: [5](#0-4) 

The code path is reachable because:
1. Operators can add MomentumPosition assets to vaults via the public operation interface: [6](#0-5) 

2. MomentumPosition assets are explicitly supported in vault operations (borrowing phase): [7](#0-6) 

3. After borrowing and returning assets, operators MUST update asset values during the three-phase operation lifecycle. The vault transitions to DURING_OPERATION status and requires value updates before completion: [8](#0-7) [9](#0-8) 

There are no tests validating momentum adaptor functionality, allowing this critical missing dependency to remain undetected.

### Impact Explanation

**Operational DoS Impact:**
- When operators add MomentumPosition assets and perform vault operations, the `update_momentum_position_value` call aborts with error 0
- The vault becomes permanently stuck in DURING_OPERATION status (status = 1)
- All vault operations are blocked (deposits, withdrawals, subsequent operations) because the vault cannot return to NORMAL status
- User funds remain locked in the vault
- The three-phase operation cannot be completed, violating the critical invariant that "operation start/end status toggles" must function correctly

**Affected Users:**
- All users with deposits in vaults containing MomentumPosition assets
- Operators unable to complete legitimate operations
- Protocol reputation damage from locked vaults

**Severity: CRITICAL** - Complete vault lockup affecting all depositors when supported DeFi asset types are used as designed.

### Likelihood Explanation

**Reachability:** The code path is directly reachable through legitimate operator actions:
1. Operator adds MomentumPosition to vault (supported asset type)
2. Operator initiates vault operation including the momentum position
3. During value update phase, operator calls `update_momentum_position_value`
4. Transaction aborts immediately

**Preconditions:**
- Operator has valid OperatorCap (normal operational requirement)
- Vault contains at least one MomentumPosition asset
- Operator performs standard three-phase operation workflow

**Execution Practicality:** The bug triggers during normal protocol usage without requiring any malicious behavior or edge cases. The stub implementations will abort 100% of the time when called.

**Detection:** No runtime checks exist to prevent adding momentum positions or warn about the stub implementations. The code compiles and deploys successfully, making the issue invisible until triggered in production.

**Probability: HIGH** if momentum positions are ever added to vaults. Currently MEDIUM overall since no tests suggest momentum positions have been deployed in production yet.

### Recommendation

**Immediate Actions:**
1. Remove support for MomentumPosition assets until proper MMT v3 implementations are integrated
2. Add explicit checks preventing addition of MomentumPosition to vaults:

```move
// In operation::add_new_defi_asset
assert!(
    type_name::get<AssetType>() != type_name::get<MomentumPosition>(),
    ERR_UNSUPPORTED_ASSET_TYPE
);
```

**Long-term Fix:**
1. Replace stub implementations in `mmt_v3::tick_math` and `mmt_v3::liquidity_math` with functional implementations OR import the complete MMT v3 dependency
2. Add comprehensive integration tests for momentum adaptor:
   - Test adding momentum positions to vaults
   - Test full operation lifecycle with momentum positions
   - Validate position value calculations

**Invariant Checks:**
1. Add pre-deployment verification that all imported modules have functional implementations (no `abort 0` stubs)
2. Add CI/CD checks to prevent deployment of stub dependencies
3. Document all supported DeFi asset types with integration test requirements

### Proof of Concept

**Initial State:**
- Vault deployed with NORMAL status
- Operator has valid OperatorCap
- Oracle configured with price feeds

**Exploitation Steps:**

1. Operator adds MomentumPosition to vault:
```move
operation::add_new_defi_asset<SUI, MomentumPosition>(
    &operation,
    &operator_cap,
    &mut vault,
    0,  // idx
    momentum_position
);
```

2. Operator starts vault operation:
```move
let (bag, tx, tx_check, principal, coin) = 
    operation::start_op_with_bag<SUI, USDC, SUI>(
        &mut vault,
        &operation,
        &operator_cap,
        &clock,
        vector[0],  // momentum position id
        vector[type_name::get<MomentumPosition>()],
        0, 0,
        ctx
    );
// Vault status now = DURING_OPERATION
```

3. Operator ends operation:
```move
operation::end_op_with_bag<SUI, USDC, SUI>(
    &mut vault, &operation, &operator_cap,
    bag, tx, principal, coin
);
// Vault status still = DURING_OPERATION, value update enabled
```

4. Operator attempts to update momentum position value:
```move
momentum_adaptor::update_momentum_position_value<SUI, TokenA, TokenB>(
    &mut vault,
    &config,
    &clock,
    momentum_asset_type,
    &mut pool
);
// ABORTS with error code 0 at tick_math.move:5
```

**Expected Result:** Value update completes, vault returns to NORMAL status

**Actual Result:** Transaction aborts with error 0, vault permanently stuck in DURING_OPERATION status, all further operations blocked

**Success Condition for Exploit:** Vault status = DURING_OPERATION with no path to recovery

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-34)
```text
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
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L4-52)
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

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L78-79)
```text
    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L83-89)
```text
    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
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

**File:** volo-vault/sources/operation.move (L294-296)
```text
    vault.enable_op_value_update();

    defi_assets.destroy_empty();
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
