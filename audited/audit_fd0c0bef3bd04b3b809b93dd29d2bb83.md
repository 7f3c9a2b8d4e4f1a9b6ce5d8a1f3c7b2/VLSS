### Title
Stub Implementation of MMT v3 in Production Configuration Causes Complete DoS of Vault Operations with Momentum Positions

### Summary
The mainnet configuration (`Move.mainnet.toml`) uses local dependencies for MMT v3 that contain only stub implementations with `abort 0` in all functions. If a `MomentumPosition` is added to a vault and any operation attempts to update its value, the transaction will abort immediately, causing the vault to become permanently stuck in `DURING_OPERATION` status and blocking all subsequent operations including deposits and withdrawals.

### Finding Description

The MMT v3 dependency is configured to use local stub implementations in the production configuration: [1](#0-0) 

All MMT v3 modules in `local_dependencies/mmt_v3/sources/` contain only stub implementations that immediately abort: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The momentum adaptor directly calls these stub functions during value updates: [6](#0-5) 

When `update_momentum_position_value()` is called during vault operations, it invokes `get_position_token_amounts()` which calls `pool.sqrt_price()` at line 73. This immediately aborts with error code 0, terminating the entire transaction.

**Execution Path:**
1. Operator starts vault operation with `start_op_with_bag()` - vault status set to `DURING_OPERATION` (status = 1) [7](#0-6) 

2. During the operation, `update_momentum_position_value()` is called to update the position's USD value [8](#0-7) 

3. Transaction aborts at `pool.sqrt_price()` call with code 0

4. Vault remains stuck in `DURING_OPERATION` status

5. All subsequent operations fail because vault cannot be used in `DURING_OPERATION` status: [9](#0-8) 

### Impact Explanation

**Severity: CRITICAL**

**Concrete Impact:**
- Complete operational DoS for any vault containing a `MomentumPosition`
- Vault permanently stuck in `DURING_OPERATION` status (cannot revert to `NORMAL` status)
- All user deposits and withdrawals blocked indefinitely
- Funds locked in vault become inaccessible
- No recovery mechanism exists without contract upgrade

**Affected Parties:**
- All users with deposits in affected vault
- Vault operators unable to execute any operations
- Protocol reputation damage

**Quantified Damage:**
- 100% of vault funds (potentially millions of dollars) become locked
- Complete service disruption for affected vaults
- Requires emergency contract upgrade and complex migration to recover

### Likelihood Explanation

**Likelihood: MEDIUM-HIGH (Conditional)**

**Preconditions:**
1. ✓ Mainnet configuration uses local stub dependencies (currently configured) [10](#0-9) 

2. Operator adds `MomentumPosition` to vault using `add_new_defi_asset()` [11](#0-10) 

3. Any operation attempts to update the position's value

**Execution Practicality:**
- 100% reproducible if MomentumPosition is used
- No special attack privileges required
- Normal vault operation flow triggers the abort
- No bypasses or workarounds exist

**Detection/Operational Constraints:**
- Would be immediately detected on first operation attempt
- Cannot be detected until MomentumPosition is actively used
- Comment in `Move.toml` indicates stubs are intentional for removing "test functions with errors," suggesting incomplete integration

**Probability Reasoning:**
- If MMT v3 integration is not yet active (no MomentumPosition deployed), no current impact
- If integration is activated with current configuration, 100% failure rate
- Risk escalates from LOW to CRITICAL when MomentumPosition is first added to any vault

### Recommendation

**Immediate Actions:**

1. **Verify Production Configuration:** 
   - Confirm whether production deployment uses local stubs or actual MMT v3 git dependency
   - If stubs are deployed, immediately block adding MomentumPosition to any vault

2. **Update Configuration:**
   Replace local stub dependency with actual MMT v3 implementation:
   ```toml
   [dependencies.mmt_v3]
   git    = "https://github.com/mmt-finance/mmt-contract-interface.git"
   rev    = "mainnet-v1.1.3"
   subdir = "mmt_v3"
   addr   = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
   ```

3. **Add Pre-Deployment Validation:**
   - Add CI/CD checks to verify all dependency modules have functional implementations
   - Test integration with actual protocol dependencies before mainnet deployment

4. **Add Safety Checks:**
   Add validation in `add_new_defi_asset()` to verify asset type compatibility before allowing addition to vault:
   ```move
   // Verify asset type is supported and functional
   public fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
       operation: &Operation,
       cap: &OperatorCap,
       vault: &mut Vault<PrincipalCoinType>,
       idx: u8,
       asset: AssetType,
   ) {
       vault::assert_operator_not_freezed(operation, cap);
       // Add check: verify asset type has working implementation
       vault.add_new_defi_asset(idx, asset);
   }
   ```

5. **Documentation:**
   - Document that MMT v3 integration requires actual dependency, not stubs
   - Add warnings about deployment configuration requirements

### Proof of Concept

**Initial State:**
- Vault deployed with mainnet configuration using local MMT v3 stubs
- Operator has valid OperatorCap
- MomentumPosition added to vault via `add_new_defi_asset()`

**Exploit Steps:**

1. Operator initiates vault operation:
   ```move
   operation::start_op_with_bag<SUI, USDC, SuilendObligation>(
       vault,
       operation,
       operator_cap,
       clock,
       vector[MOMENTUM_POSITION_ID],
       vector[type_name::get<MomentumPosition>()],
       principal_amount,
       coin_amount,
       ctx
   );
   // Vault status now = DURING_OPERATION (1)
   ```

2. Operator attempts to update position value:
   ```move
   momentum_adaptor::update_momentum_position_value<SUI, TokenA, TokenB>(
       vault,
       oracle_config,
       clock,
       momentum_asset_type,
       momentum_pool
   );
   // Transaction ABORTS with code 0 at pool.sqrt_price() call
   ```

**Expected vs Actual Result:**
- **Expected:** Position value updated, operation continues normally
- **Actual:** Transaction aborts immediately, vault stuck in DURING_OPERATION status

**Success Condition (for exploit):**
- Vault status remains `DURING_OPERATION` (value = 1)
- All subsequent operations fail with `assert_normal()` check
- Users cannot deposit or withdraw
- Funds effectively locked until contract upgrade

**Notes**

This finding represents a critical deployment configuration issue rather than a code vulnerability. The stub implementations are intentionally included as local dependencies with a comment indicating they're used "because we need to remove some test functions with errors." This suggests the MMT v3 integration may be incomplete or in development.

However, the mainnet configuration file (`Move.mainnet.toml`) actively points to these stubs, creating a severe risk if MomentumPosition functionality is activated without switching to the actual implementation. The commented-out git dependency shows the intended production configuration, but it is not currently active.

The severity is CRITICAL if MomentumPosition is used with the current configuration, but the actual risk depends on deployment practices and whether the MMT v3 integration is operationally active in production.

### Citations

**File:** volo-vault/Move.mainnet.toml (L72-77)
```text
# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
local = "./local_dependencies/mmt_v3"
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
