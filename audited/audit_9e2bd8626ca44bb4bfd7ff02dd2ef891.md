### Title
Navi Adaptor Uses Non-Normalized Oracle Prices Causing Systematic Asset Misvaluation

### Summary
The Navi adaptor uses `get_asset_price()` to retrieve raw oracle prices instead of `get_normalized_asset_price()` like all other adaptors, causing systematic misvaluation of Navi positions. For assets with decimals ≠ 9 (e.g., USDC with 6 decimals), this creates valuation errors of up to 1000x, corrupting vault accounting, share ratios, and loss tolerance checks.

### Finding Description

The Navi adaptor's `calculate_navi_position_value()` function retrieves oracle prices using `vault_oracle::get_asset_price()` which returns raw prices without decimal normalization: [1](#0-0) 

In contrast, all other adaptors (Cetus, Momentum) follow the correct pattern of using `get_normalized_asset_price()` for value calculations: [2](#0-1) [3](#0-2) 

The normalization function adjusts prices based on the `decimals` field stored in `PriceInfo`: [4](#0-3) 

Test configurations show different assets use different decimal values (SUI=9, USDC=6, BTC=8): [5](#0-4) 

**Root Cause**: The Navi adaptor skips the normalization step that accounts for different decimal configurations across assets. When `mul_with_oracle_price()` is called with raw prices, it assumes all prices have 18 decimals and divides by 10^18: [6](#0-5) 

**Why Existing Protections Fail**: There is no validation that all adaptors use consistent price retrieval methods. The type system doesn't enforce which oracle getter function should be used.

### Impact Explanation

**Concrete Valuation Errors**:
- For USDC (decimals=6): Borrowed amounts undervalued by 10^(9-6) = 1000x
- For BTC (decimals=8): Borrowed amounts undervalued by 10^(9-8) = 10x
- For assets with decimals > 9: Overvaluation occurs

**Example**: A $1000 USDC borrow in Navi is calculated as only $1 by the vault.

**Vault-Level Impact**:
1. **Share Ratio Corruption**: Vault's `total_usd_value` is incorrect, causing wrong share prices. Users depositing when Navi positions are undervalued receive excessive shares.

2. **Loss Tolerance Bypass**: If borrowed assets are undervalued, actual losses may exceed the epoch `loss_tolerance` without detection: [7](#0-6) 

3. **Vault Insolvency**: Vault accounting shows higher net worth than reality, enabling excessive leverage and potential insolvency during redemptions.

4. **Unfair Value Distribution**: Users withdrawing during misvaluation periods extract more/less value than their fair share.

**Who Is Affected**: All vault depositors whose shares are minted/burned based on corrupted valuations.

**Severity**: Critical - systematic accounting errors affecting core vault operations.

### Likelihood Explanation

**Reachable Entry Point**: The bug triggers whenever operators update Navi position values during vault operations: [8](#0-7) 

**Feasible Preconditions**:
- Vault has Navi positions with non-9-decimal assets (USDC, USDT common)
- Operators call `update_navi_position_value()` during operation value updates
- No special permissions or state manipulation required

**Execution Practicality**: Occurs automatically in normal vault operation flow. The three-phase operation lifecycle mandates value updates for all borrowed assets: [9](#0-8) 

**Detection Constraints**: Error is systematic and affects all Navi positions with non-9-decimal assets. Likely already present in production if vault uses USDC/USDT.

**Economic Rationality**: No additional cost to trigger - happens during normal operations.

**Probability**: High - occurs every operation cycle involving Navi positions with affected assets.

### Recommendation

**Immediate Fix**: Change Navi adaptor to use normalized prices:

```move
// In navi_adaptor.move, replace line 63:
- let price = vault_oracle::get_asset_price(config, clock, coin_type);
+ let price = vault_oracle::get_normalized_asset_price(config, clock, coin_type);
```

**Validation Enhancement**: Add internal documentation/assertions that all value calculation adaptors must use `get_normalized_asset_price()` for consistency.

**Test Cases**:
1. Test Navi position value calculation with USDC (6 decimals), verify result matches expected USD value
2. Test vault share ratio calculation with mixed-decimal Navi positions
3. Test loss tolerance detection with undervalued Navi borrows

**Audit All Adaptors**: Verify Suilend and any other adaptors follow the correct pattern.

### Proof of Concept

**Initial State**:
- Vault configured with USDC oracle (decimals=6, price=1e18 for $1)
- NaviAccountCap with 1000 USDC borrowed (1,000,000,000 scaled units)
- Operator performing operation value update

**Transaction Steps**:
1. Operator calls `update_navi_position_value()` for Navi position
2. Adaptor calls `calculate_navi_position_value()`
3. For USDC borrow:
   - Raw price retrieved: 1e18
   - Calculation: `1_000_000_000 * 1e18 / 1e18 = 1_000_000_000` (9 decimal precision)
   - **Result: $1 instead of $1000**

**Expected vs Actual**:
- Expected (with normalization): `1_000_000_000 * (1e18 * 1000) / 1e18 = 1_000_000_000_000` (representing $1000)
- Actual (current bug): `1_000_000_000` (representing $1)
- **Error magnitude: 1000x undervaluation**

**Impact Verification**:
- Vault's `assets_value` table shows Navi position value 1000x lower than reality
- `total_usd_value` calculated incorrectly
- Share ratio computed from wrong total leads to unfair share distribution

### Notes

While the security question mentions `to_target_decimal_value()`, this function is only used in the Pyth oracle adaptor and not in the Navi adaptor flow. The vault uses Switchboard oracles. However, the Navi adaptor has an analogous decimal handling bug using raw vs. normalized prices.

The bug does NOT directly enable over-borrowing in Navi protocol itself, as Navi's health factor calculations use Navi's own oracle system independently of the vault's oracle. The health limiter module also uses Navi's oracle: [10](#0-9) 

The vulnerability's primary impact is vault-level accounting corruption affecting share ratios, loss tolerance, and vault solvency - not direct Navi protocol health factor bypass.

### Citations

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L63-66)
```text
        let price = vault_oracle::get_asset_price(config, clock, coin_type);

        let supply_usd_value = vault_utils::mul_with_oracle_price(supply_scaled as u256, price);
        let borrow_usd_value = vault_utils::mul_with_oracle_price(borrow_scaled as u256, price);
```

**File:** volo-vault/sources/adaptors/cetus_adaptor.move (L68-72)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L60-64)
```text
    let normalized_price_a = vault_oracle::get_normalized_asset_price(config, clock, type_name_a);
    let normalized_price_b = vault_oracle::get_normalized_asset_price(config, clock, type_name_b);

    let value_a = vault_utils::mul_with_oracle_price(amount_a as u256, normalized_price_a);
    let value_b = vault_utils::mul_with_oracle_price(amount_b as u256, normalized_price_b);
```

**File:** volo-vault/sources/oracle.move (L140-154)
```text
public fun get_normalized_asset_price(
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
): u256 {
    let price = get_asset_price(config, clock, asset_type);
    let decimals = config.aggregators[asset_type].decimals;

    // Normalize price to 9 decimals
    if (decimals < 9) {
        price * (pow(10, 9 - decimals) as u256)
    } else {
        price / (pow(10, decimals - 9) as u256)
    }
}
```

**File:** volo-vault/tests/test_helpers.move (L27-47)
```text
        vault_oracle::set_aggregator(
            config,
            clock,
            sui_asset_type,
            9,
            MOCK_AGGREGATOR_SUI,
        );
        vault_oracle::set_aggregator(
            config,
            clock,
            usdc_asset_type,
            6,
            MOCK_AGGREGATOR_USDC,
        );
        vault_oracle::set_aggregator(
            config,
            clock,
            btc_asset_type,
            8,
            MOCK_AGGREGATOR_BTC,
        );
```

**File:** volo-vault/sources/utils.move (L69-71)
```text
public fun mul_with_oracle_price(v1: u256, v2: u256): u256 {
    v1 * v2 / ORACLE_DECIMALS
}
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

**File:** volo-vault/sources/operation.move (L299-377)
```text
public fun end_op_value_update_with_bag<T, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    tx: TxBagForCheckValueUpdate,
) {
    vault::assert_operator_not_freezed(operation, cap);
    vault.assert_during_operation();

    let TxBagForCheckValueUpdate {
        vault_id,
        defi_asset_ids,
        defi_asset_types,
        total_usd_value,
        total_shares,
    } = tx;

    assert!(vault.vault_id() == vault_id, ERR_VAULT_ID_MISMATCH);

    // First check if all assets has been returned
    let length = defi_asset_ids.length();
    let mut i = 0;
    while (i < length) {
        let defi_asset_id = defi_asset_ids[i];
        let defi_asset_type = defi_asset_types[i];

        if (defi_asset_type == type_name::get<NaviAccountCap>()) {
            let navi_asset_type = vault_utils::parse_key<NaviAccountCap>(defi_asset_id);
            assert!(vault.contains_asset_type(navi_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<CetusPosition>()) {
            let cetus_asset_type = vault_utils::parse_key<CetusPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(cetus_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        if (defi_asset_type == type_name::get<MomentumPosition>()) {
            let momentum_asset_type = vault_utils::parse_key<MomentumPosition>(defi_asset_id);
            assert!(vault.contains_asset_type(momentum_asset_type), ERR_ASSETS_NOT_RETURNED);
        };

        i = i + 1;
    };

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

    assert!(vault.total_shares() == total_shares, ERR_VERIFY_SHARE);

    emit(OperationValueUpdateChecked {
        vault_id: vault.vault_id(),
        total_usd_value_before,
        total_usd_value_after,
        loss,
    });

    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

**File:** volo-vault/health-limiter/sources/adaptors/navi_limiter.move (L18-25)
```text
public fun verify_navi_position_healthy(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    let health_factor = logic::user_health_factor(clock, storage, oracle, account);
```
