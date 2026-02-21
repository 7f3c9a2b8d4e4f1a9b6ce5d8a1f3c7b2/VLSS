# Audit Report

## Title
Vault Lacks Health Factor Enforcement for Navi Positions Despite Having Dedicated Health Limiter Module

## Summary
The vault's Navi adaptor only calculates net position value (supply minus borrow) without validating health factors. A dedicated health limiter module with `verify_navi_position_healthy()` exists but is not integrated as a dependency in the main vault package. This allows operators to create Navi lending positions with dangerously low health factors that pass all vault checks but face high liquidation risk, causing losses that far exceed the vault's 0.1% loss tolerance.

## Finding Description

The vulnerability exists in the vault's three-phase operation flow for Navi positions, which performs no health factor validation at any stage.

**Phase 1 - Asset Borrowing**: Operators borrow Navi AccountCap from the vault via `start_op_with_bag()`. [1](#0-0) 

**Phase 2 - External Operations**: Operators interact with Navi's lending protocol to create leveraged positions. Navi's native `execute_borrow()` only ensures the health factor remains above the protocol's minimum threshold (typically ~1.0) at the moment of borrowing. [2](#0-1)  This check prevents immediate insolvency but does not enforce a safe margin.

**Phase 3 - Value Update & Solvency Check**: After returning the AccountCap via `end_op_with_bag()` [3](#0-2) , operators update the position value using `calculate_navi_position_value()`, which only calculates net USD value (total supply minus total borrow) without any health factor validation. [4](#0-3) 

The final solvency check in `end_op_value_update_with_bag()` only validates that losses don't exceed the vault's loss tolerance based on USD value changes, with no health factor consideration. [5](#0-4) 

**The Missing Protection**: A dedicated health limiter module exists with a `verify_navi_position_healthy()` function that can enforce minimum health factors. [6](#0-5)  However, this module is defined in a separate package named "limiter" [7](#0-6)  and is not listed as a dependency in the main vault package's dependencies. [8](#0-7)  The function is never called anywhere in the vault codebase.

## Impact Explanation

**Direct Financial Impact:**
- Operators can create Navi positions with minimal health factor buffers (e.g., 1.05-1.10) during normal operations that pass all vault checks (positive net value, within loss tolerance)
- Market volatility causing 5-10% price movements can push the health factor below 1.0, triggering liquidation
- Liquidation penalties in lending protocols typically range from 5-10% of liquidated collateral
- The vault's default loss tolerance is 0.1% (10 basis points) per epoch [9](#0-8) 
- Loss tolerance enforcement calculates: `loss_limit = base_usd_value * tolerance / 10000` and asserts losses stay within this limit [10](#0-9) 
- A single liquidation event causing 5-10% loss is 50-100x the 0.1% loss tolerance, completely bypassing the vault's risk management system

**Security Invariant Violation:**
The vault's solvency protection relies on loss tolerance enforcement, which assumes losses are gradual and controlled. Liquidation events bypass this protection by causing discrete, large losses that exceed the tolerance limit in a single transaction, violating the fundamental risk management invariant.

**Affected Parties:**
- Vault depositors bear liquidation losses through share dilution
- Protocol reputation damaged if positions are liquidated
- Risk compounds with multiple Navi positions across different assets

## Likelihood Explanation

**High Likelihood:**

1. **Normal Operation Path**: Creating leveraged Navi positions is a standard vault operation that operators perform regularly to generate yield. The execution flow through `start_op_with_bag()` → external Navi calls → `end_op_with_bag()` → value update is the expected operational pattern. No malicious intent is required.

2. **Lack of Awareness**: Well-intentioned operators may create positions with health factors of 1.1-1.2 believing they have adequate safety margin, unaware the vault has no health factor visibility or enforcement mechanisms beyond Navi's native minimum threshold check.

3. **Market Conditions**: Cryptocurrency markets regularly experience 5-10% intraday price swings. Positions with health factors below 1.15 face constant liquidation risk under normal market volatility, making this scenario highly probable.

4. **No Detection Mechanism**: The vault has no on-chain visibility into Navi position health factors. While the health limiter module was explicitly designed for this purpose, its complete absence from the dependency chain means no protection exists.

5. **Observable Execution**: Navi's `execute_borrow()` ensures `health_factor >= health_factor_in_borrow`, but this only prevents health factor < 1.0 at the moment of borrowing, not dangerously low values that become unhealthy from subsequent price movements.

## Recommendation

**Immediate Fix:**
1. Add the health limiter package as a dependency in the main vault's `Move.toml`:
```toml
[dependencies.limiter]
local = "./health-limiter"
```

2. Import and call `verify_navi_position_healthy()` in the operation flow, specifically:
   - After `end_op_with_bag()` but before `end_op_value_update_with_bag()`
   - Set a safe minimum health factor threshold (e.g., 1.5 or 150% collateralization)

3. Add health factor validation to `update_navi_position_value()`:
```move
use limiter::navi_adaptor;

public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
    oracle: &PriceOracle,  // Add oracle parameter
    min_health_factor: u256,  // Add minimum threshold parameter
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    
    // Verify health factor before accepting position
    navi_adaptor::verify_navi_position_healthy(
        clock,
        storage,
        oracle,
        account_cap.account_owner(),
        min_health_factor
    );
    
    let usd_value = calculate_navi_position_value(/* ... */);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**Long-term Solution:**
- Implement continuous health factor monitoring for all leveraged positions
- Add operator warnings when positions approach liquidation thresholds
- Consider implementing automatic position adjustment or deleveraging when health factors drop below safe levels

## Proof of Concept

```move
#[test]
fun test_navi_position_liquidation_bypasses_loss_tolerance() {
    // Setup: Create vault with 0.1% loss tolerance (default)
    let mut scenario = test_scenario::begin(ADMIN);
    let vault = create_test_vault(&mut scenario);
    
    // Operator creates Navi position with 1.05 health factor
    // This passes Navi's minimum check (HF >= 1.0) but is dangerous
    test_scenario::next_tx(&mut scenario, OPERATOR);
    {
        let (defi_assets, tx_bag, check_bag, principal, coin_asset) = 
            start_op_with_bag(/* borrow Navi AccountCap */);
        
        // External: Operator deposits $100K collateral, borrows $95K (HF = 1.05)
        // This passes Navi's execute_borrow() check since HF > 1.0
        navi_lending::deposit(/* $100K collateral */);
        navi_lending::borrow(/* $95K assets */);
        
        // Return assets - NO health factor check occurs
        end_op_with_bag(vault, defi_assets, tx_bag, principal, coin_asset);
    };
    
    // Update position value - only calculates net value ($5K), no HF check
    test_scenario::next_tx(&mut scenario, OPERATOR);
    {
        update_navi_position_value(vault, config, clock, asset_type, storage);
        // Net value = $100K - $95K = $5K (positive, passes check)
    };
    
    // Market moves 10% down - collateral now worth $90K, borrow still $95K
    // Health factor drops below 1.0, position gets liquidated
    // Liquidation penalty: 8% of $100K = $8K loss
    
    // Final check - Loss tolerance exceeded!
    test_scenario::next_tx(&mut scenario, OPERATOR);
    {
        end_op_value_update_with_bag(vault, check_bag, clock);
        // Expected: vault loss tolerance = 0.1% of $100K = $100
        // Actual loss: $8,000
        // Ratio: 80x the loss tolerance limit
        // Transaction should revert but position already liquidated
    };
    
    // Assert: Depositors lost $8K through share dilution
    // This is 80x the intended maximum loss per epoch
    assert!(actual_loss > loss_tolerance * 50, E_LOSS_TOLERANCE_BYPASSED);
}
```

**Notes:**
- This vulnerability requires the health limiter module to be integrated into the main vault package dependencies
- The fix should enforce health factor checks as part of the standard operation flow, not as an optional external validation
- The 0.1% loss tolerance is well-documented but becomes meaningless if single liquidation events can cause 5-10% losses

### Citations

**File:** volo-vault/sources/operation.move (L118-123)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
```

**File:** volo-vault/sources/operation.move (L235-239)
```text
        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };
```

**File:** volo-vault/sources/operation.move (L359-364)
```text
    // Update tolerance if there is a loss (there is a max loss limit each epoch)
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L150-155)
```text
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-78)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-49)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);

    emit(NaviHealthFactorVerified {
        account,
        health_factor,
        safe_check_hf: min_health_factor,
    });

    let is_healthy = health_factor > min_health_factor;

    // hf_normalized has 9 decimals
    // e.g. hf = 123456 (123456 * 1e27)
    //      hf_normalized = 123456 * 1e9
    //      hf = 0.5 (5 * 1e26)
    //      hf_normalized = 5 * 1e8 = 0.5 * 1e9
    //      hf = 1.356 (1.356 * 1e27)
    //      hf_normalized = 1.356 * 1e9
    let mut hf_normalized = health_factor / DECIMAL_E18;

    if (hf_normalized > DECIMAL_E9) {
        hf_normalized = DECIMAL_E9;
    };

    assert!(is_healthy, hf_normalized as u64);
}
```

**File:** volo-vault/health-limiter/Move.toml (L2-2)
```text
name    = "limiter"
```

**File:** volo-vault/Move.toml (L1-127)
```text
[package]
name    = "volo_vault"
edition = "2024.beta"  # edition = "legacy" to use legacy (pre-2024) Move
published-at = "0x4da7b643d0e7bfa5ec6f10e0dc28e562068114e913864a84f61be0cb26b684e0"

# navi lending core and suilend uses different pyth code repo
[dependencies.Pyth]
git      = "https://github.com/solendprotocol/pyth-crosschain.git"
rev      = "mainnet"
subdir   = "target_chains/sui/contracts"
override = true

# [dependencies.lending_core]
# git    = "https://github.com/naviprotocol/protocol-interface"
# rev    = "main"
# subdir = "lending_core"
# # addr   = "0x81c408448d0d57b3e371ea94de1d40bf852784d3e225de1e74acab3e8395c18f"

# [dependencies.Switchboard]
# git    = "https://github.com/switchboard-xyz/sui.git"
# subdir = "on_demand"
# rev    = "main"
# # addr   = "0xe6717fb7c9d44706bf8ce8a651e25c0a7902d32cb0ff40c0976251ce8ac25655"

[dependencies.CetusClmm]
git    = "https://github.com/CetusProtocol/cetus-clmm-interface.git"
subdir = "sui/cetus_clmm"
rev    = "mainnet-v1.48.4"
# rev = "mainnet-v1.25.0"
# addr     = "0xc6faf3703b0e8ba9ed06b7851134bbbe7565eb35ff823fd78432baa4cbeaa12e"
override = true

# [dependencies.suilend]
# git    = "https://github.com/solendprotocol/suilend"
# rev    = "mainnet"
# subdir = "contracts/suilend"
# addr   = "0x21f544aff826a48e6bd5364498454d8487c4a90f84995604cd5c947c06b596c3"

# [dependencies.BluefinSpot]
# git    = "https://github.com/fireflyprotocol/bluefin-spot-contract-interface.git"
# subdir = ""
# rev    = "main"
# # addr   = "0x6c796c3ab3421a68158e0df18e4657b2827b1f8fed5ed4b82dba9c935988711b"

# [dependencies.mmt_v3]
# git    = "https://github.com/mmt-finance/mmt-contract-interface.git"
# rev    = "mainnet-v1.1.3"
# subdir = "mmt_v3"
# addr   = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"

[dependencies.lending_core]
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/protocol/lending_core"
rev = "main"

[dependencies.Switchboard]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "on_demand"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/switchboard_sui/on_demand"
rev = "main"


[dependencies.suilend]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "suilend_d/suilend"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/suilend_d/suilend"
rev = "main"

# [dependencies.CetusClmm]
# local = "./local_dependencies/cetus-clmm-interface/sui/cetus_clmm"

# [dependencies.BluefinSpot]
# local = "./local_dependencies/bluefin-spot-contract-interface"

# MMT V3 uses local dependencies because we need to remove some test functions with errors
[dependencies.mmt_v3]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "mmt_v3"
git = "https://github.com/Sui-Volo/volo-smart-contracts.git"
subdir = "volo-vault/local_dependencies/mmt_v3"
rev = "main"

# [dev-dependencies.CetusClmm]
# git      = "https://github.com/CetusProtocol/cetus-clmm-interface.git"
# subdir   = "sui/cetus_clmm"
# rev      = "mainnet-v1.25.0"
# # addr     = "0xc6faf3703b0e8ba9ed06b7851134bbbe7565eb35ff823fd78432baa4cbeaa12e"
# override = true


[addresses]
volo_vault = "0xcd86f77503a755c48fe6c87e1b8e9a137ec0c1bf37aac8878b6083262b27fefa"
# switchboard  = "0xc3c7e6eb7202e9fb0389a2f7542b91cc40e4f7a33c02554fec11c4c92f938ea3"
# bluefin_spot = "0x3492c874c1e3b3e2984e8c41b589e642d4d0a5d6459e5a9cfc2d52fd7c89c267"
# mmt_v3       = "0x70285592c97965e811e0c6f98dccc3a9c2b4ad854b3594faab9597ada267b860"
# lending_core = "0xd899cf7d2b5db716bd2cf55599fb0d5ee38a3061e7b6bb6eebf73fa5bc4c81ca"
# suilend      = "0xf95b06141ed4a174f239417323bde3f209b972f5930d8521ea38a52aff3a6ddf"
# cetus_clmm   = "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb"


# Named addresses will be accessible in Move as `@name`. They're also exported:
# for example, `std = "0x1"` is exported by the Standard Library.
# alice = "0xA11CE"


# override = true
# The dev-dependencies section allows overriding dependencies for `--test` and
# `--dev` modes. You can introduce test-only dependencies here.
# Local = { local = "../path/to/dev-build" }

[dev-addresses]
# The dev-addresses section allows overwriting named addresses for the `--test`
# and `--dev` modes.
# alice = "0xB0B"


# Sui and Suilend have conflicts in "MoveStdLib" and "Pyth"
# [dependencies.MoveStdlib]
# git      = "https://github.com/MystenLabs/sui.git"
# rev      = "mainnet"
# subdir   = "crates/sui-framework/packages/move-stdlib"
# override = true
```

**File:** volo-vault/sources/volo_vault.move (L38-38)
```text
const DEFAULT_TOLERANCE: u256 = 10; // principal loss tolerance at every epoch (0.1%)
```

**File:** volo-vault/sources/volo_vault.move (L626-641)
```text
public(package) fun update_tolerance<T0>(self: &mut Vault<T0>, loss: u256) {
    self.check_version();

    self.cur_epoch_loss = self.cur_epoch_loss + loss;

    // let loss_limit = usd_value_before * (self.loss_tolerance as u256) / (RATE_SCALING as u256);
    let loss_limit =
        self.cur_epoch_loss_base_usd_value * (self.loss_tolerance as u256) / (RATE_SCALING as u256);

    assert!(loss_limit >= self.cur_epoch_loss, ERR_EXCEED_LOSS_LIMIT);
    emit(LossToleranceUpdated {
        vault_id: self.vault_id(),
        current_loss: self.cur_epoch_loss,
        loss_limit: loss_limit,
    });
}
```
