### Title
Missing Navi Position Health Factor Verification Exposes Vault to Liquidation Risk

### Summary
The vault system includes a health-limiter module with `verify_navi_position_healthy()` function designed to ensure Navi lending positions maintain safe health factors, but this function is never integrated or called during vault operations. Operators can borrow maximum amounts from Navi protocol, leaving positions with minimal health factor buffers (e.g., HF ≈ 1.06), exposing the vault to liquidation risk from minor price movements and resulting in 5% collateral loss penalties.

### Finding Description

The health-limiter module exists as a standalone package at [1](#0-0)  with functionality to verify Navi position health factors against configurable minimum thresholds. However, the main vault package does not depend on this limiter package [2](#0-1)  and never imports or calls the verification function.

During vault operations, when operators borrow NaviAccountCap assets [3](#0-2) , they can interact with Navi protocol to modify position collateral and debt. After returning the NaviAccountCap [4](#0-3) , the vault only updates the position's USD value [5](#0-4)  and checks loss tolerance [6](#0-5) , but never verifies the health factor.

While Navi protocol itself prevents withdrawing collateral that would make positions unhealthy [7](#0-6) , it allows borrowing up to the minimum required health factor threshold [8](#0-7) . For typical parameters (LTV=80%, liquidation_threshold=85%), the minimum health factor is threshold/LTV = 1.0625, providing only 6.25% buffer before liquidation.

**Root Cause:** The vault relies solely on total USD value change checks and never validates that Navi positions maintain adequate safety margins above the liquidation threshold. The designed health verification function exists but is architecturally disconnected from the operation flow.

**Note on the specific attack:** The flash loan attack described in the original question (flash deposit collateral → borrow → immediately withdraw collateral) is NOT possible because Navi's own health checks prevent step 4 (withdrawing collateral would fail the health assertion). However, the missing health factor verification creates a different but related vulnerability.

### Impact Explanation

**Direct Fund Impact:** When a Navi position with minimal health factor buffer (HF ≈ 1.06) experiences adverse conditions, liquidation results in 5% collateral loss [9](#0-8) . For a $100,000 position, this represents $5,000 loss to vault depositors.

**Exposure Scenarios:**
- Small price movements (6% decline) trigger liquidation
- Interest accrual on debt positions
- Oracle price updates during market volatility
- Combined multi-asset position effects

The vault's 0.1% per-epoch loss tolerance is designed for normal operational losses, not 5% liquidation penalties. A single liquidation event consumes 50 epochs worth of tolerance, or could exceed the limit entirely if vault value is insufficient.

**Affected Parties:**
- Vault share holders bear liquidation losses
- Protocol reputation damage from preventable liquidations
- Loss of productive capital during liquidation recovery

**Severity:** Critical - the vulnerability creates systemic risk across all Navi-integrated vault operations, with quantifiable 5% loss magnitude and high probability given minimal health factor buffers against normal market volatility.

### Likelihood Explanation

**Reachable Entry Point:** Standard operator workflow [10](#0-9)  provides legitimate access to borrow and modify Navi positions.

**Feasibility:** Operators with OperatorCap can:
1. Execute authorized operations borrowing NaviAccountCap
2. Interact with Navi protocol following all of Navi's own health checks
3. Return positions that pass vault's loss tolerance but have minimal liquidation buffer
4. This is not malicious operator behavior - even honest strategies maximizing capital efficiency would naturally approach maximum leverage ratios

**Execution Practicality:** 
- No special conditions required beyond normal operations
- Navi protocol's own constraints allow HF ≥ 1.0625
- No flash loan complexity needed
- Vault's value-only checks insufficient to detect risk

**Economic Rationality:** 
- 6% price movements occur regularly in crypto markets
- Interest accrual continuously reduces health factor
- Multiple positions compound risk exposure
- Liquidation is automatic and economically incentivized for liquidators

**Probability:** HIGH - given that:
- Operators naturally maximize capital efficiency
- No mechanism prevents minimum-HF positions
- Normal market volatility frequently exceeds 6% buffer
- Verification function exists but is architecturally unused

### Recommendation

**Immediate Fix:**

1. Add limiter package dependency to vault's Move.toml
2. Import and call `verify_navi_position_healthy()` in operation flow after position value updates:

```
// In operation.move, after navi_adaptor::update_navi_position_value
limiter::navi_adaptor::verify_navi_position_healthy(
    clock,
    storage,
    oracle,
    account_cap.account_owner(),
    MINIMUM_SAFE_HEALTH_FACTOR  // e.g., 1.5e27 for 50% buffer
);
```

3. Add minimum health factor configuration to vault parameters (recommended: 1.3-1.5 minimum)

**Invariant to Enforce:**
After any operation modifying Navi positions, assert: `health_factor ≥ configured_minimum` where minimum provides adequate buffer above 1.0 for price volatility, interest accrual, and multi-asset correlation risks.

**Test Cases:**
- Test operation rejection when resulting HF < minimum threshold
- Test position remains healthy under simulated 10% price movements
- Test recovery from near-minimum HF positions
- Test liquidation scenario impact on vault value

### Proof of Concept

**Initial State:**
- Vault owns NaviAccountCap controlling position with 1,000 SUI collateral ($2,000 at $2/SUI), 0 debt
- Navi parameters: LTV=80%, liquidation_threshold=85%

**Transaction Sequence:**

1. Operator calls `start_op_with_bag` borrowing NaviAccountCap
2. Operator uses NaviAccountCap to borrow $1,600 USDC from Navi (maximum allowed: $2,000 × 0.80)
   - Navi calculates HF = ($2,000 × 0.85) / $1,600 = 1.0625
   - Passes Navi's requirement: HF ≥ threshold/LTV = 1.0625 ✓
3. Operator returns NaviAccountCap via `end_op_with_bag`
4. Vault calls `navi_adaptor::update_navi_position_value`:
   - Calculates position value: $2,000 collateral - $1,600 debt = $400
   - Operator returns $1,600 USDC to vault as coin asset
   - Total vault value unchanged: $400 (Navi) + $1,600 (coins) = $2,000
5. `end_op_value_update_with_bag` checks loss tolerance:
   - Loss = $0 (total value unchanged)
   - Passes tolerance check ✓
6. **No health factor verification occurs** - operation completes successfully

**Expected Result:** Operation should fail with health factor too low error

**Actual Result:** Operation succeeds, leaving position at HF=1.0625 with only 6.25% buffer before liquidation

**Success Condition for Exploit:** SUI price drops 6.25% to $1.875, triggering liquidation:
- New HF = (1,000 × $1.875 × 0.85) / $1,600 = 0.996 < 1.0
- Liquidator seizes collateral + 5% bonus
- Vault loses ~$100 (5% of ~$2,000 position) despite no operator malice

### Citations

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

**File:** volo-vault/sources/operation.move (L94-207)
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
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);

    let mut defi_assets = bag::new(ctx);

    let defi_assets_length = defi_asset_ids.length();
    assert!(defi_assets_length == defi_asset_types.length(), ERR_ASSETS_LENGTH_MISMATCH);

    let mut i = 0;
    while (i < defi_assets_length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = vault.borrow_defi_asset<T, NaviAccountCap>(
                vault_utils::parse_key<NaviAccountCap>(defi_asset_id),
            );
            defi_assets.add<String, NaviAccountCap>(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = vault.borrow_defi_asset<T, CetusPosition>(cetus_asset_type);
            defi_assets.add<String, CetusPosition>(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let obligation_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = vault.borrow_defi_asset<T, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
            );
            defi_assets.add<String, SuilendObligationOwnerCap<ObligationType>>(
                obligation_asset_type,
                obligation,
            );
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = vault.borrow_defi_asset<T, MomentumPosition>(
                momentum_asset_type,
            );
            defi_assets.add<String, MomentumPosition>(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = vault.borrow_defi_asset<T, Receipt>(receipt_asset_type);
            defi_assets.add<String, Receipt>(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    let principal_balance = if (principal_amount > 0) {
        vault.borrow_free_principal(principal_amount)
    } else {
        balance::zero<T>()
    };

    let coin_type_asset_balance = if (coin_type_asset_amount > 0) {
        vault.borrow_coin_type_asset<T, CoinType>(
            coin_type_asset_amount,
        )
    } else {
        balance::zero<CoinType>()
    };

    let total_usd_value = vault.get_total_usd_value(clock);
    let total_shares = vault.total_shares();

    let tx = TxBag {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
    };

    let tx_for_check_value_update = TxBagForCheckValueUpdate {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    };

    emit(OperationStarted {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount,
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount,
        total_usd_value,
    });

    (defi_assets, tx, tx_for_check_value_update, principal_balance, coin_type_asset_balance)
}
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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L13-29)
```text
public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L88-91)
```text
        let token_amount = user_collateral_balance(storage, asset, user);
        let actual_amount = safe_math::min(amount, token_amount);
        decrease_supply_balance(storage, asset, user, actual_amount);
        assert!(is_health(clock, oracle, storage, user), error::user_is_unhealthy());
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L150-156)
```text
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L531-534)
```text
                liquidation_ratio = 35%, liquidation_bonus = 5%
                treasury_factor = 10%
        */
        let (liquidation_ratio, liquidation_bonus, _) = storage::get_liquidation_factors(storage, collateral_asset);
```
