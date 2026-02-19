# Audit Report

## Title
Vault Lacks Health Factor Enforcement for Navi Positions Despite Having Dedicated Health Limiter Module

## Summary
The vault's Navi adaptor calculates only net position value (supply - borrow) without validating health factors, and the vault's operation flow performs no health factor checks before or after Navi operations. A dedicated health limiter module with `verify_navi_position_healthy()` exists but is not integrated as a dependency. This allows operators to create Navi lending positions with dangerously low health factors (e.g., 1.05-1.10) that pass all vault checks but face high liquidation risk from minor price movements, causing losses that far exceed the vault's loss tolerance.

## Finding Description

The vulnerability exists in the three-phase vault operation flow for Navi positions:

**Phase 1 - Asset Borrowing:** Operators borrow Navi AccountCap from the vault via `start_op_with_bag()`. [1](#0-0) 

**Phase 2 - External Operations:** Operators interact directly with Navi's lending protocol to deposit collateral and borrow assets. Navi's native health checks in `execute_borrow()` only ensure health factor remains above the protocol's minimum threshold (typically ~1.0). [2](#0-1) 

**Phase 3 - Value Update & Solvency Check:** After returning the AccountCap via `end_op_with_bag()` [3](#0-2) , operators update the position value using `calculate_navi_position_value()`, which only calculates net USD value (supply - borrow) without any health factor validation. [4](#0-3) 

The final solvency check in `end_op_value_update_with_bag()` only validates that losses don't exceed the vault's loss tolerance based on total USD value changes, with no health factor consideration. [5](#0-4) 

**The Missing Protection:** A dedicated health limiter module exists with `verify_navi_position_healthy()` that can enforce minimum health factors. [6](#0-5)  However, this module is defined in a separate package named "limiter" [7](#0-6)  and is not listed as a dependency in the main vault package. [8](#0-7) 

This breaks the security invariant for External Integrations requiring "Health-factor enforcement for Navi" - the vault has no visibility into or enforcement of health factors for Navi positions.

## Impact Explanation

**Direct Financial Impact:**
- Operators can create Navi positions with minimal health factor buffers (e.g., 1.05-1.10) during normal operations
- These positions pass all vault checks (positive net value, within loss tolerance)
- Market volatility causing 5-10% price movements can push health factor below 1.0, triggering liquidation
- Liquidation penalties in lending protocols typically range from 5-10% of liquidated collateral
- Example: $100K position with 1.05 health factor liquidated → $5-10K loss
- The vault's default loss tolerance is 0.1% (10 basis points) [9](#0-8) , meaning the tolerance on a $100K vault would be ~$100
- A single liquidation event causes losses 50-100x the loss tolerance, violating the vault's risk management invariant

**Security Invariant Violation:**
The vault's solvency protection relies on loss tolerance enforcement [10](#0-9) , which assumes losses are gradual and controlled. Liquidation events bypass this protection entirely by causing discrete, large losses that exceed the tolerance limit in a single transaction.

**Affected Parties:**
- Vault depositors bear liquidation losses through share dilution
- Protocol reputation damaged if positions are liquidated
- Risk compounds with multiple Navi positions across different assets

## Likelihood Explanation

**High Likelihood:**

1. **Normal Operation Path:** Creating leveraged Navi positions is a standard vault operation that operators perform regularly to generate yield. No malicious intent is required.

2. **Lack of Awareness:** Well-intentioned operators may create positions with health factors of 1.1-1.2 believing they have adequate safety margin, unaware the vault has no health factor visibility or enforcement mechanisms beyond Navi's native checks.

3. **Market Conditions:** Cryptocurrency markets regularly experience 5-10% intraday price swings. Positions with health factors below 1.15 face constant liquidation risk under normal market volatility.

4. **No Detection Mechanism:** The vault has no on-chain visibility into Navi position health factors. Off-chain monitoring would require direct queries to Navi's protocol, but on-chain protections should exist as the protocol explicitly designed a health limiter module for this purpose.

5. **Observable Execution:** Navi's `execute_borrow()` checks ensure `health_factor >= health_factor_in_borrow` [11](#0-10) , but this only prevents health factor < 1.0 at the moment of borrowing, not dangerously low values that become unhealthy from subsequent price movements.

## Recommendation

Integrate the health limiter module into vault operations:

1. **Add Dependency:** Add the `limiter` package as a dependency in `volo-vault/Move.toml`

2. **Enforce Health Checks:** Call `limiter::navi_adaptor::verify_navi_position_healthy()` after Navi operations and before completing the value update phase:

```move
// In operation.move, after end_op_with_bag() and before end_op_value_update_with_bag()
public fun verify_navi_health_factors<T>(
    vault: &Vault<T>,
    storage: &mut Storage,
    oracle: &PriceOracle,
    clock: &Clock,
    navi_asset_types: vector<String>,
    min_health_factor: u256, // e.g., 1.2e27 for 1.2 health factor
) {
    // For each Navi position, verify health factor
    navi_asset_types.do!(|asset_type| {
        let account_cap = vault.get_defi_asset<T, NaviAccountCap>(asset_type);
        limiter::navi_adaptor::verify_navi_position_healthy(
            clock,
            storage,
            oracle,
            account_cap.account_owner(),
            min_health_factor,
        );
    });
}
```

3. **Configuration:** Allow vault administrators to configure the minimum health factor threshold (e.g., 1.2 for 20% safety buffer) as part of vault initialization or admin functions.

4. **Update Operation Flow:** Require operators to call the health verification function as part of the standard operation flow before finalizing value updates.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploying a test vault with Navi integration
2. Creating a Navi position with health factor = 1.05 through normal operator flow:
   - Call `start_op_with_bag()` to borrow Navi AccountCap
   - Deposit minimal collateral to Navi
   - Borrow maximum amount allowed (health factor ~1.05)
   - Return AccountCap via `end_op_with_bag()`
   - Update value via `update_navi_position_value()` (passes with no error)
   - Complete operation via `end_op_value_update_with_bag()` (passes all checks)
3. Simulate a 5% price drop in collateral asset
4. Show that the position is now liquidatable (health factor < 1.0)
5. Execute liquidation, demonstrating 5-10% loss
6. Verify that loss exceeds vault's 0.1% loss tolerance by 50-100x

The test would confirm that no health factor checks exist in the vault operation flow despite the availability of the health limiter module.

### Citations

**File:** volo-vault/sources/operation.move (L94-123)
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
```

**File:** volo-vault/sources/operation.move (L209-297)
```text
public fun end_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    mut defi_assets: Bag,
    tx: TxBag,
    principal_balance: Balance<T>,
    coin_type_asset_balance: Balance<CoinType>,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBag {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            let navi_account_cap = defi_assets.remove<String, NaviAccountCap>(navi_asset_type);
            vault.return_defi_asset(navi_asset_type, navi_account_cap);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            let cetus_position = defi_assets.remove<String, CetusPosition>(cetus_asset_type);
            vault.return_defi_asset(cetus_asset_type, cetus_position);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            let obligation = defi_assets.remove<String, SuilendObligationOwnerCap<ObligationType>>(
                suilend_asset_type,
            );
            vault.return_defi_asset(suilend_asset_type, obligation);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            let momentum_position = defi_assets.remove<String, MomentumPosition>(
                momentum_asset_type,
            );
            vault.return_defi_asset(momentum_asset_type, momentum_position);
        };

        if (defi_asset_type == type_name::get<Receipt>()) {
            let receipt_asset_type = vault_utils::parse_key<Receipt>(defi_asset_id);
            let receipt = defi_assets.remove<String, Receipt>(receipt_asset_type);
            vault.return_defi_asset(receipt_asset_type, receipt);
        };

        i = i + 1;
    };

    emit(OperationEnded {
        vault_id: vault.vault_id(),
        defi_asset_ids,
        defi_asset_types,
        principal_coin_type: type_name::get<T>(),
        principal_amount: principal_balance.value(),
        coin_type_asset_type: type_name::get<CoinType>(),
        coin_type_asset_amount: coin_type_asset_balance.value(),
    });

    vault.return_free_principal(principal_balance);

    if (coin_type_asset_balance.value() > 0) {
        vault.return_coin_type_asset<T, CoinType>(coin_type_asset_balance);
    } else {
        coin_type_asset_balance.destroy_zero();
    };

    vault.enable_op_value_update();

    defi_assets.destroy_empty();
}
```

**File:** volo-vault/sources/operation.move (L353-364)
```text
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
```

**File:** volo-vault/local_dependencies/protocol/lending_core/sources/logic.move (L127-159)
```text
    public(friend) fun execute_borrow<CoinType>(clock: &Clock, oracle: &PriceOracle, storage: &mut Storage, asset: u8, user: address, amount: u256) {
        //////////////////////////////////////////////////////////////////
        // Update borrow_index, supply_index, last_timestamp, treasury  //
        //////////////////////////////////////////////////////////////////
        update_state_of_all(clock, storage);

        validation::validate_borrow<CoinType>(storage, asset, amount);

        /////////////////////////////////////////////////////////////////////////
        // Convert balances to actual balances using the latest exchange rates //
        /////////////////////////////////////////////////////////////////////////
        increase_borrow_balance(storage, asset, user, amount);
        
        /////////////////////////////////////////////////////
        // Add the asset to the user's list of loan assets //
        /////////////////////////////////////////////////////
        if (!is_loan(storage, asset, user)) {
            storage::update_user_loans(storage, asset, user)
        };

        //////////////////////////////////
        // Checking user health factors //
        //////////////////////////////////
        let avg_ltv = calculate_avg_ltv(clock, oracle, storage, user);
        let avg_threshold = calculate_avg_threshold(clock, oracle, storage, user);
        assert!(avg_ltv > 0 && avg_threshold > 0, error::ltv_is_not_enough());
        let health_factor_in_borrow = ray_math::ray_div(avg_threshold, avg_ltv);
        let health_factor = user_health_factor(clock, storage, oracle, user);
        assert!(health_factor >= health_factor_in_borrow, error::user_is_unhealthy());

        update_interest_rate(storage, asset);
        emit_state_updated_event(storage, asset, user);
    }
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L31-79)
```text
public fun calculate_navi_position_value(
    account: address,
    storage: &mut Storage,
    config: &OracleConfig,
    clock: &Clock,
): u256 {
    let mut i = storage.get_reserves_count();

    let mut total_supply_usd_value: u256 = 0;
    let mut total_borrow_usd_value: u256 = 0;

    // i: asset id
    while (i > 0) {
        let (supply, borrow) = storage.get_user_balance(i - 1, account);

        // TODO: to use dynamic index or not
        // let (supply_index, borrow_index) = storage.get_index(i - 1);
        let (supply_index, borrow_index) = dynamic_calculator::calculate_current_index(
            clock,
            storage,
            i - 1,
        );
        let supply_scaled = ray_math::ray_mul(supply, supply_index);
        let borrow_scaled = ray_math::ray_mul(borrow, borrow_index);

        let coin_type = storage.get_coin_type(i - 1);

        if (supply == 0 && borrow == 0) {
            i = i - 1;
            continue
        };

        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);

        total_supply_usd_value = total_supply_usd_value + supply_usd_value;
        total_borrow_usd_value = total_borrow_usd_value + borrow_usd_value;

        i = i - 1;
    };

    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };

    total_supply_usd_value - total_borrow_usd_value
}
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

**File:** volo-vault/Move.toml (L51-86)
```text
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
