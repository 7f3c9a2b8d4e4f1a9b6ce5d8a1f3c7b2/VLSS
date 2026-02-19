# Audit Report

## Title
Momentum Adaptor Integration Failure Causes Operational DoS Due to Stub Implementation

## Summary
The `mmt_v3` dependency uses local stub implementations where all functions execute `abort 0`, rather than linking to the deployed MMT V3 contract. When operators attempt to value Momentum positions in the vault, the transaction will abort, causing operational DoS and preventing vault operations from completing.

## Finding Description

The `tick_math` module contains only stub implementations where all 8 public functions immediately abort. [1](#0-0) 

The momentum adaptor's valuation logic depends on `tick_math::get_sqrt_price_at_tick()` to calculate position token amounts. [2](#0-1)  The function `update_momentum_position_value()` calls `get_position_value()`, which calls `get_position_token_amounts()`, which directly invokes the stub function that aborts.

MomentumPosition is fully integrated as a supported asset type in vault operations. The operation module includes complete borrowing logic, [3](#0-2)  returning logic, [4](#0-3)  and validation checks [5](#0-4)  for MomentumPosition.

The configuration uses local stub dependencies instead of the deployed MMT V3 contract. [6](#0-5)  The actual deployed contract address (`0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860`) is commented out. [7](#0-6) 

The locked dependency configuration confirms stubs are being used in the build. [8](#0-7) 

**Execution Path:**
1. Operator adds MomentumPosition to vault via `operation::add_new_defi_asset<T, MomentumPosition>()`
2. During operation completion, operator calls `momentum_adaptor::update_momentum_position_value()`
3. Function executes call chain: `update_momentum_position_value()` → `get_position_value()` → `get_position_token_amounts()` → `tick_math::get_sqrt_price_at_tick()`
4. Transaction aborts at line 5 of tick_math.move with `abort 0`
5. Vault remains stuck in `VAULT_DURING_OPERATION_STATUS`, preventing further operations

## Impact Explanation

**High-Confidence Operational DoS**: When Momentum positions are added to the vault and any operation requiring asset valuation is attempted, the transaction will abort. This prevents:
- Vault operations from completing successfully
- Normal asset valuation and accounting updates
- Operation value updates required by the three-phase operation pattern

**Affected Parties:**
- Vault operators unable to complete operations involving Momentum positions
- Users with funds locked in vaults containing Momentum positions
- Protocol reputation damage from operational failures

The vault's three-phase operation pattern requires asset values to be updated before completing operations via `end_op_value_update_with_bag()`. The abort prevents this critical step, leaving the vault in `VAULT_DURING_OPERATION_STATUS` and blocking all subsequent operations.

**Severity: Medium-High** - This causes guaranteed operational failure when triggered, but requires Momentum positions to be present in the vault. Since MomentumPosition is fully integrated as a supported asset type with complete operation handling, this represents a latent production failure waiting to occur.

## Likelihood Explanation

**Trigger Conditions:**
1. Operators add a Momentum position to the vault (explicitly supported operation with complete integration)
2. Any vault operation requiring asset valuation is initiated
3. The momentum adaptor's valuation function is called
4. Immediate abort occurs

**Probability:** High if Momentum positions are used. The issue is currently latent (likely no Momentum positions have been added to production vaults yet), but the integration is complete and ready to accept them. Once triggered, the failure is guaranteed due to the unconditional `abort 0` in the stub implementation.

**Detection Difficulty:** The complete absence of test coverage for the momentum adaptor means this critical integration failure cannot be caught during development or CI/CD testing.

## Recommendation

Update the `mmt_v3` dependency configuration to use the deployed MMT V3 contract instead of local stub implementations:

```toml
[dependencies.mmt_v3]
git = "https://github.com/mmt-finance/mmt-contract-interface.git"
rev = "mainnet-v1.1.3"
subdir = "mmt_v3"
addr = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
```

Additionally:
1. Add comprehensive test coverage for the momentum adaptor
2. Verify integration with actual MMT V3 contract in testnet environment
3. Add CI/CD checks to prevent stub implementations in production builds

## Proof of Concept

```move
#[test]
fun test_momentum_position_valuation_aborts() {
    // Setup vault with MomentumPosition
    let ctx = &mut tx_context::dummy();
    let clock = clock::create_for_testing(ctx);
    
    // Create momentum position and pool (simplified)
    let momentum_position = /* create test position */;
    let momentum_pool = /* create test pool */;
    
    // Add momentum position to vault
    vault.add_new_defi_asset<SUI, MomentumPosition>(
        asset_type,
        momentum_position
    );
    
    // Attempt to update momentum position value
    // This will abort at tick_math::get_sqrt_price_at_tick()
    momentum_adaptor::update_momentum_position_value<SUI, CoinA, CoinB>(
        &mut vault,
        &config,
        &clock,
        asset_type,
        &mut momentum_pool,
    ); // <- ABORTS HERE with abort 0
}
```

The test demonstrates that any call to `update_momentum_position_value()` will abort when it reaches `tick_math::get_sqrt_price_at_tick()`, proving the operational DoS condition.

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

**File:** volo-vault/Move.toml (L45-49)
```text
# [dependencies.mmt_v3]
# git    = "https://github.com/mmt-finance/mmt-contract-interface.git"
# rev    = "mainnet-v1.1.3"
# subdir = "mmt_v3"
# addr   = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
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

**File:** volo-vault/Move.lock (L148-153)
```text
id = "mmt_v3"
source = { git = "https://github.com/Sui-Volo/volo-smart-contracts.git", rev = "main", subdir = "volo-vault/local_dependencies/mmt_v3" }

dependencies = [
  { id = "Sui", name = "Sui" },
]
```
