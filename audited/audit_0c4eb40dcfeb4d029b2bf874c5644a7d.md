# Audit Report

## Title
Underwater Navi Positions Reported as Zero Value Enable Excess Withdrawals and Socialized Losses

## Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position is underwater (debt exceeds collateral), instead of accounting for the negative net value. This inflates the vault's total USD value and share ratio, allowing users to withdraw more principal than their fair share while remaining shareholders absorb the underwater debt.

## Finding Description

When a Navi position becomes underwater (total debt exceeds total collateral), the valuation logic returns 0 instead of representing the negative economic position: [1](#0-0) 

This 0 value is then stored in the vault's asset value tracking and used for total USD value calculations: [2](#0-1) [3](#0-2) 

The vault's total USD value calculation sums all asset values, treating the 0 as "no position" rather than "underwater position with debt obligation": [4](#0-3) 

This inflated total value directly affects share ratio calculations used for withdrawals: [5](#0-4) 

Withdrawal execution uses this inflated share ratio to determine payout amounts: [6](#0-5) 

**Why Existing Protections Fail:**

1. **Health Limiter Not Enforced**: The health limiter module exists with functions `verify_navi_position_healthy` and `is_navi_position_healthy`: [7](#0-6) 

However, these functions are never invoked in the vault's operational code, leaving positions unchecked.

2. **Loss Tolerance Timing Weakness**: The loss tolerance mechanism resets the base value at the start of each operation or epoch: [8](#0-7) [9](#0-8) 

If a position is already underwater when the base value is set, the base incorporates the inflated 0 value. Subsequent loss comparisons are between inflated values, masking the hidden debt: [10](#0-9) 

3. **Asset Return Check Insufficient**: Operation completion only verifies that borrowed assets are returned, not their health or solvency: [11](#0-10) 

## Impact Explanation

**Critical Severity - Direct Financial Harm:**

When a Navi position becomes underwater (e.g., $1,200 collateral vs $1,500 debt = -$300 true net value), it reports $0 instead. If the vault has:
- $2,000 in free principal
- $0 reported for underwater Navi position (should be -$300)
- Reported total value: $2,000
- True total value: $1,700

The share ratio becomes `$2,000 / total_shares` instead of the correct `$1,700 / total_shares`, inflating by approximately 17.6%.

**Affected Parties:**
- **Remaining vault shareholders** absorb the socialized losses from underwater positions
- **Early withdrawers** extract excess value at the expense of later withdrawers
- **Protocol reputation** damaged as users discover unfair value distribution

The vulnerability enables direct value extraction from the vault through inflated share valuations, with losses systematically transferred to remaining participants.

## Likelihood Explanation

**High Likelihood - No Attacker Capabilities Required:**

This is a protocol design flaw affecting all users during normal operations. Any user can submit withdrawal requests—no special privileges or attack sophistication needed.

**Feasible Trigger Conditions:**
1. Vault operates normally with Navi leveraged position
2. Market volatility causes borrowed asset price increase or collateral price decrease
3. Navi position becomes underwater (health factor < 1.0)
4. Next operation calls `update_navi_position_value()` which returns 0
5. Withdrawal executions proceed with inflated share ratio
6. Early withdrawers extract excess value

**Realistic Scenario:**
DeFi lending positions frequently approach liquidation thresholds during market volatility. Underwater positions can occur when:
- Liquidation delays during high network congestion
- Oracle price updates lag behind market movements
- Flash crashes cause rapid price movements
- Accumulated bad debt from insufficient liquidation incentives

These conditions are common in DeFi protocols rather than exceptional edge cases.

## Recommendation

**1. Implement Health Factor Enforcement:**
Invoke the existing health limiter functions before allowing operations to proceed with risky positions:

```move
// In operation.move or navi_adaptor.move
use limiter::navi_adaptor as navi_limiter;

public fun verify_navi_position_before_operation(
    clock: &Clock,
    storage: &mut Storage,
    oracle: &PriceOracle,
    account: address,
    min_health_factor: u256,
) {
    navi_limiter::verify_navi_position_healthy(
        clock,
        storage,
        oracle,
        account,
        min_health_factor
    );
}
```

**2. Account for Underwater Positions:**
Modify the vault's total value calculation to properly account for negative positions. Since Move doesn't support negative u256, consider:
- Maintaining a separate "underwater debt" tracking field
- Preventing operations when any position is underwater
- Implementing emergency liquidation or debt restructuring mechanisms

**3. Enhanced Loss Tolerance:**
Add explicit checks for underwater positions in the loss tolerance mechanism, not just epoch-to-epoch deltas:

```move
// Check if any position is underwater
public fun check_all_positions_healthy<T>(
    vault: &Vault<T>,
    // ... health check parameters
): bool {
    // Verify all DeFi positions meet minimum health factors
    // Return false if any position is underwater
}
```

## Proof of Concept

The vulnerability can be demonstrated by:
1. Creating a vault with a Navi position that has collateral and debt
2. Simulating market conditions that cause the position to become underwater (debt > collateral)
3. Calling `update_navi_position_value()` which returns 0
4. Executing withdrawals that receive inflated amounts based on the inflated share ratio
5. Observing that remaining shareholders are left with the underwater debt obligation

The core issue is mathematically demonstrated: if true vault value is $1,700 but reported as $2,000 due to underwater position reporting 0 instead of -$300, the share ratio is inflated by 17.6%, causing direct fund loss to remaining shareholders.

## Notes

This vulnerability represents a fundamental accounting flaw where negative economic positions (underwater debt) are not properly reflected in the vault's valuation system. The health limiter infrastructure exists but remains dormant, and the loss tolerance mechanism has a timing weakness that allows already-underwater positions to persist undetected. Market volatility making positions underwater is a realistic and frequent occurrence in DeFi lending protocols, making this a high-probability, critical-impact vulnerability.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L28-28)
```text
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
```

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/volo_vault.move (L608-624)
```text
public(package) fun try_reset_tolerance<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    by_admin: bool,
    ctx: &TxContext,
) {
    self.check_version();

    if (by_admin || self.cur_epoch < tx_context::epoch(ctx)) {
        self.cur_epoch_loss = 0;
        self.cur_epoch = tx_context::epoch(ctx);
        self.cur_epoch_loss_base_usd_value = self.get_total_usd_value_without_update();
        emit(LossToleranceReset {
            vault_id: self.vault_id(),
            epoch: self.cur_epoch,
        });
    };
}
```

**File:** volo-vault/sources/volo_vault.move (L626-640)
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
```

**File:** volo-vault/sources/volo_vault.move (L1006-1022)
```text
    let ratio = self.get_share_ratio(clock);

    // Get the corresponding withdraw request from the vault
    let withdraw_request = self.request_buffer.withdraw_requests[request_id];

    // Shares and amount to withdraw
    let shares_to_withdraw = withdraw_request.shares();
    let usd_value_to_withdraw = vault_utils::mul_d(shares_to_withdraw, ratio);
    let amount_to_withdraw =
        vault_utils::div_with_oracle_price(
            usd_value_to_withdraw,
            vault_oracle::get_normalized_asset_price(
                config,
                clock,
                type_name::get<PrincipalCoinType>().into_string(),
            ),
        ) as u64;
```

**File:** volo-vault/sources/volo_vault.move (L1174-1187)
```text
public(package) fun finish_update_asset_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    asset_type: String,
    usd_value: u256,
    now: u64,
) {
    self.check_version();
    self.assert_enabled();

    let last_update_time = &mut self.assets_value_updated[asset_type];
    *last_update_time = now;

    let position_value = &mut self.assets_value[asset_type];
    *position_value = usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1264-1269)
```text
    self.asset_types.do_ref!(|asset_type| {
        let last_update_time = *self.assets_value_updated.borrow(*asset_type);
        assert!(now - last_update_time <= MAX_UPDATE_INTERVAL, ERR_USD_VALUE_NOT_UPDATED);

        let usd_value = *self.assets_value.borrow(*asset_type);
        total_usd_value = total_usd_value + usd_value;
```

**File:** volo-vault/sources/volo_vault.move (L1297-1309)
```text
public(package) fun get_share_ratio<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
    clock: &Clock,
): u256 {
    self.check_version();
    self.assert_enabled();

    if (self.total_shares == 0) {
        return vault_utils::to_decimals(1)
    };

    let total_usd_value = self.get_total_usd_value(clock);
    let share_ratio = vault_utils::div_d(total_usd_value, self.total_shares);
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

**File:** volo-vault/sources/operation.move (L319-351)
```text
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
```
