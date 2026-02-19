### Title
Complete Denial of Service for Vault Operations Using MomentumPosition Due to Stub Function Implementation

### Summary
The Volo Vault integrates MomentumPosition as a supported DeFi asset type, but the entire mmt_v3 local dependency consists of stub functions that always abort. Any vault operation borrowing a MomentumPosition will fail when attempting to update the position's value, causing the vault to be permanently stuck in operation status and unable to complete any further operations.

### Finding Description

The vulnerability stems from the complete stub implementation of the mmt_v3 module. All functions in `liquidity_math.move` are stubs that immediately abort: [1](#0-0) [2](#0-1) 

The Volo Vault production code explicitly supports MomentumPosition as a DeFi asset type in its operation flow: [3](#0-2) [4](#0-3) 

The `momentum_adaptor` module provides a public function to update position values that is called during vault operations: [5](#0-4) 

This function calls `get_position_token_amounts`, which attempts to use multiple stub functions: [6](#0-5) 

The critical call to the stub function occurs here: [7](#0-6) 

Additional stub functions that will abort include:
- `pool.sqrt_price()`: [8](#0-7) 
- `position.tick_lower_index()`: [9](#0-8) 
- `position.tick_upper_index()`: [10](#0-9) 
- `position.liquidity()`: [11](#0-10) 
- `tick_math::get_sqrt_price_at_tick()`: [12](#0-11) 

After a vault operation returns borrowed assets, the protocol enforces that all borrowed asset values must be updated: [13](#0-12) [14](#0-13) 

The check function ensures all borrowed assets have been updated: [15](#0-14) 

**Execution Path:**
1. Vault operation borrows MomentumPosition → vault enters VAULT_DURING_OPERATION_STATUS
2. Operator executes operation and returns MomentumPosition
3. Operator attempts to call `update_momentum_position_value` to complete operation
4. Function calls `get_position_token_amounts` 
5. Any of the mmt_v3 stub functions (sqrt_price, tick_lower_index, tick_upper_index, liquidity, get_sqrt_price_at_tick, or get_amounts_for_liquidity) gets called
6. Transaction aborts with `abort 0`
7. Without successful update, `check_op_value_update_record` will fail with ERR_USD_VALUE_NOT_UPDATED
8. Vault remains stuck in VAULT_DURING_OPERATION_STATUS permanently
9. All future operations are blocked

### Impact Explanation

**Concrete Harm:**
- Any vault that adds a MomentumPosition as a DeFi asset will be permanently bricked
- Once a vault operation borrows the MomentumPosition, the vault becomes stuck in VAULT_DURING_OPERATION_STATUS
- The vault cannot complete the operation because position value update always aborts
- All vault functions requiring VAULT_NORMAL_STATUS (deposits, withdrawals, new operations) are permanently blocked
- User funds remain locked in the vault with no recovery mechanism

**Who Is Affected:**
- Vault users with deposits (cannot withdraw)
- Vault operators (cannot execute operations)
- Protocol (loss of TVL and reputation)

**Severity Justification:**
This is CRITICAL because:
1. Complete denial of service - vault becomes permanently unusable
2. Funds are locked with no emergency recovery
3. 100% reproducibility - will always occur if MomentumPosition is used
4. No workaround exists without code changes to mmt_v3
5. Affects critical invariant: "All borrowed DeFi assets returned" cannot be verified

### Likelihood Explanation

**Reachable Entry Point:** 
The `update_momentum_position_value` function is public and must be called by operators during vault operations. The `start_op_with_bag` function is also public and allows borrowing MomentumPosition. [16](#0-15) 

**Attacker Capabilities:**
- No attacker needed - this is an inherent code defect
- Any legitimate use of MomentumPosition triggers the vulnerability
- Vault administrators who add MomentumPosition assets inadvertently trigger the DoS

**Execution Practicality:**
100% certain to occur because:
- All mmt_v3 functions are hard-coded stubs with `abort 0`
- No conditional logic or parameters can prevent the abort
- Sui Move execution model guarantees abort terminates transaction

**Feasibility Conditions:**
Only requires:
1. Vault has MomentumPosition asset added via `add_new_defi_asset`
2. Any operation borrows that MomentumPosition
3. Operator attempts required value update to complete operation

**Probability:** 
100% if MomentumPosition is used. Currently 0% if no vaults have added MomentumPosition assets yet (making this a latent critical vulnerability).

### Recommendation

**Immediate Mitigation:**
1. Remove MomentumPosition support from all production vaults
2. Add package-level documentation warning that mmt_v3 integration is incomplete
3. Prevent `add_new_defi_asset` from accepting MomentumPosition type until mmt_v3 is implemented

**Long-term Fix:**
1. Either implement actual mmt_v3 functionality or remove the stub dependency entirely
2. If Momentum integration is intended, replace stub functions with working implementations
3. Add integration tests that verify full operation cycle with MomentumPosition before deployment

**Code-level Changes:**
```move
// In operation.move or vault initialization
public fun is_supported_defi_asset<AssetType>(): bool {
    let asset_type = type_name::get<AssetType>();
    // Block MomentumPosition until mmt_v3 is implemented
    assert!(asset_type != type_name::get<MomentumPosition>(), ERR_UNSUPPORTED_ASSET_TYPE);
    true
}
```

**Invariant Checks:**
Add runtime check in `add_new_defi_asset`: [17](#0-16) 

Add assertion that MomentumPosition is not allowed until mmt_v3 is fully implemented.

**Test Cases:**
1. Test that attempts to add MomentumPosition fail with clear error
2. Test full operation cycle (borrow → execute → return → update → complete) for each supported DeFi asset type
3. Integration test calling all adaptor update functions to verify they don't abort

### Proof of Concept

**Initial State:**
- Vault deployed with SUI as principal coin
- OracleConfig configured with price feeds
- OperatorCap and Operation objects created

**Transaction Sequence:**

**Step 1:** Add MomentumPosition to vault
```move
// Admin adds a MomentumPosition asset
let momentum_position = /* create or obtain MomentumPosition */;
operation::add_new_defi_asset<SUI, MomentumPosition>(
    &operation,
    &operator_cap,
    &mut vault,
    0, // idx
    momentum_position
);
// SUCCESS: Position added to vault
```

**Step 2:** Start vault operation borrowing MomentumPosition
```move
let (bag, tx, tx_check, principal, coin_asset) = operation::start_op_with_bag<SUI, USDC, ObligationType>(
    &mut vault,
    &operation,
    &operator_cap,
    &clock,
    vector[0], // defi_asset_ids - borrow position at idx 0
    vector[type_name::get<MomentumPosition>()], // defi_asset_types
    0, // principal_amount
    0, // coin_type_asset_amount
    ctx
);
// SUCCESS: Vault status changed to VAULT_DURING_OPERATION_STATUS
```

**Step 3:** Return position and attempt to complete operation
```move
operation::end_op_with_bag<SUI, USDC, ObligationType>(
    &mut vault,
    &operation,
    &operator_cap,
    bag,
    tx,
    principal,
    coin_asset
);
// SUCCESS: Position returned, value_update_enabled = true
```

**Step 4:** Attempt to update position value
```move
let asset_type = vault_utils::parse_key<MomentumPosition>(0);
momentum_adaptor::update_momentum_position_value<SUI, TokenA, TokenB>(
    &mut vault,
    &config,
    &clock,
    asset_type,
    &mut pool
);
// ABORTS: Transaction fails with abort 0 from liquidity_math::get_amounts_for_liquidity
```

**Step 5:** Attempt to complete operation
```move
operation::end_op_value_update_with_bag<SUI, ObligationType>(
    &mut vault,
    &operation,
    &operator_cap,
    &clock,
    tx_check
);
// FAILS: check_op_value_update_record asserts ERR_USD_VALUE_NOT_UPDATED
```

**Expected Result:** 
Operations complete successfully, vault returns to VAULT_NORMAL_STATUS

**Actual Result:** 
- Step 4 aborts immediately, transaction reverts
- Vault stuck in VAULT_DURING_OPERATION_STATUS forever
- Step 5 cannot proceed because position value was never updated
- All future vault operations blocked

**Success Condition for Exploit:**
Vault is permanently bricked - cannot execute deposits, withdrawals, or any operations requiring normal status.

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L4-6)
```text
    public fun add_delta(current_liquidity: u128, delta_liquidity: I128) : u128 {
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

**File:** volo-vault/sources/operation.move (L94-104)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
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

**File:** volo-vault/sources/operation.move (L259-265)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };
```

**File:** volo-vault/sources/operation.move (L345-348)
```text
        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };
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
