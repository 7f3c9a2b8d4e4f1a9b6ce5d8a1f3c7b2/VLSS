### Title
Missing Suilend Obligation Health Check When Borrowing ObligationOwnerCap Enables Unhealthy Position Operations

### Summary
When the vault borrows `SuilendObligationOwnerCap` during operations, no health check is performed on the underlying Suilend obligation's debt/collateral ratio. This allows operators to perform actions on already-unhealthy obligations, potentially leading to liquidations and vault losses. While a health limiter exists for Navi positions, no equivalent protection exists for Suilend.

### Finding Description

In `volo-vault/sources/operation.move`, the `start_op_with_bag` function borrows `SuilendObligationOwnerCap` from the vault without any health verification: [1](#0-0) 

The borrowing is delegated to `vault.borrow_defi_asset()`, which performs no health checks: [2](#0-1) 

This function only verifies version, enabled status, and asset type existence. There is no check of the underlying Suilend obligation's health state.

In contrast, the codebase includes a health limiter module for Navi that verifies positions meet minimum health factor requirements: [3](#0-2) 

**No equivalent health limiter exists for Suilend.** The only directory in the health-limiter adaptors contains solely the Navi implementation: [4](#0-3) 

While Suilend's internal `borrow()` function does check health AFTER adding debt, this check only applies when actually borrowing from Suilend, not when the vault hands the cap to the operator: [5](#0-4) 

The root cause is the absence of pre-operation health verification when borrowing the capability from the vault, creating a gap where operators can manipulate unhealthy positions.

### Impact Explanation

**Direct Fund Impact:** If an operator borrows a `SuilendObligationOwnerCap` controlling an unhealthy obligation (where `weighted_borrowed_value_upper_bound_usd > allowed_borrow_value_usd`), subsequent operations can trigger liquidation. Suilend liquidations extract value through liquidation bonuses and protocol fees, directly reducing vault assets.

**Security Integrity Impact:** This violates the stated invariant under External Integrations: "Health-factor enforcement for Navi; adaptors for Cetus/Suilend/Momentum handle assets safely." The asymmetric protection (Navi has health enforcement, Suilend lacks it) creates systemic risk.

**Quantified Damage:** Suilend obligations define health as: [6](#0-5) 

And liquidatability as: [7](#0-6) 

When liquidated, the vault loses collateral value to liquidators and protocol fees. Even a 5% liquidation bonus on a $100K obligation costs the vault $5K in direct losses.

### Likelihood Explanation

**Reachable Entry Point:** The `start_op_with_bag` function is called by operators holding `OperatorCap` during normal vault operations, making this code path frequently executed.

**Feasible Preconditions:** No malicious operator is required. Market volatility can cause previously-healthy obligations to become unhealthy between operations. An honest operator might unknowingly borrow an unhealthy cap if:
- Oracle price updates make the obligation unhealthy
- Interest accrual increases debt to unhealthy levels
- Previous operations by other protocols affected the position

**Execution Practicality:** The exploit path is the normal operation flow itself:
1. Obligation becomes unhealthy due to market conditions
2. Operator calls `start_op_with_bag` (no health check performed)
3. Operator performs operations that further stress the position
4. Position gets liquidated, vault incurs losses

**Detection Constraints:** Without health checks, there is no automated prevention mechanism. The vault only checks total USD value changes via loss tolerance, which may not catch individual obligation liquidations until after they occur: [8](#0-7) 

### Recommendation

**Immediate Fix:** Implement a Suilend health limiter module parallel to the existing Navi implementation:

1. Create `volo-vault/health-limiter/sources/adaptors/suilend_limiter.move`
2. Implement `verify_suilend_obligation_healthy()` that checks:
   - Calls Suilend's `obligation::is_healthy()` function
   - Verifies `weighted_borrowed_value_upper_bound_usd <= allowed_borrow_value_usd`
   - Asserts health factor meets minimum threshold before operations

3. Modify `start_op_with_bag` to call health verification before borrowing Suilend caps:
```move
if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
    // Add health check here before borrowing
    suilend_limiter::verify_suilend_obligation_healthy(
        lending_market,
        obligation_cap,
        clock,
        min_health_factor
    );
    let obligation = vault.borrow_defi_asset<...>(...);
    ...
}
```

4. Add similar verification in `end_op_with_bag` before returning the cap to ensure operations didn't degrade health below acceptable thresholds.

**Invariant Enforcement:** Add assertion that all borrowed DeFi assets (including Suilend) meet minimum health requirements as defined in vault configuration, consistent with the Navi health limiter pattern.

**Test Cases:**
- Attempt to borrow SuilendObligationOwnerCap with unhealthy obligation (should abort)
- Verify operations that would make obligation unhealthy are prevented
- Confirm health checks are enforced symmetrically for both Navi and Suilend

### Proof of Concept

**Initial State:**
- Vault owns `SuilendObligationOwnerCap` for obligation with ID `0xABC`
- Obligation has:
  - `deposited_value_usd`: 100,000 USD
  - `allowed_borrow_value_usd`: 75,000 USD (75% LTV)
  - `weighted_borrowed_value_upper_bound_usd`: 76,000 USD (UNHEALTHY)

**Transaction Sequence:**
1. Operator calls `start_op_with_bag` specifying the unhealthy Suilend obligation
2. Function executes without health check, borrowing the cap: [1](#0-0) 
3. Operator uses cap to interact with Suilend (any operation that requires the cap)
4. Market movement or interest accrual increases `weighted_borrowed_value_usd` above `unhealthy_borrow_value_usd`
5. Obligation becomes liquidatable per Suilend's definition: [7](#0-6) 
6. External liquidator liquidates the position
7. Vault loses collateral to liquidation bonus + protocol fees

**Expected Result:** Transaction should abort at step 2 with health check failure

**Actual Result:** Transaction succeeds, allowing operations on unhealthy obligation, leading to liquidation and vault losses

**Success Condition:** The vulnerability is confirmed by the absence of health verification in the borrow path and the asymmetric implementation (Navi protected, Suilend unprotected).

### Citations

**File:** volo-vault/sources/operation.move (L132-145)
```text
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

**File:** volo-vault/sources/volo_vault.move (L1415-1434)
```text
public(package) fun borrow_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
): AssetType {
    self.check_version();
    self.assert_enabled();

    assert!(contains_asset_type(self, asset_type), ERR_ASSET_TYPE_NOT_FOUND);

    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };

    emit(DefiAssetBorrowed {
        vault_id: self.vault_id(),
        asset_type: asset_type,
    });

    self.assets.remove<String, AssetType>(asset_type)
}
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L1-1)
```text
module limiter::navi_adaptor;
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L402-402)
```text
        assert!(is_healthy(obligation), EObligationIsNotHealthy);
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L790-792)
```text
    public fun is_healthy<P>(obligation: &Obligation<P>): bool {
        le(obligation.weighted_borrowed_value_upper_bound_usd, obligation.allowed_borrow_value_usd)
    }
```

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L794-796)
```text
    public fun is_liquidatable<P>(obligation: &Obligation<P>): bool {
        gt(obligation.weighted_borrowed_value_usd, obligation.unhealthy_borrow_value_usd)
    }
```
