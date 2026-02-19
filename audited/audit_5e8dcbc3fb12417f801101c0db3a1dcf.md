### Title
Underwater Navi Positions Return Zero Value Masking Insolvency and Enabling Value Extraction

### Summary
The `calculate_navi_position_value()` function returns 0 when a Navi lending position is underwater (borrows exceed collateral), completely hiding both the collateral assets and debt obligations from the vault's accounting. This masks insolvency, bypasses loss tolerance mechanisms, and allows continued operations with incorrect share valuations, enabling users to extract value at the expense of remaining depositors.

### Finding Description

**Location**: [1](#0-0) 

When a Navi position becomes underwater (total borrows > total collateral), the function returns 0 instead of accurately representing the position's state or rejecting the update. The vault then stores this 0 value in its asset tracking: [2](#0-1) 

**Root Cause**: The function treats negative net positions as having zero value rather than:
1. Enforcing health factor requirements before accepting the valuation
2. Rejecting underwater positions that violate protocol safety
3. Triggering liquidation or emergency protocols

**Why Protections Fail**:

1. **Health Limiter Not Integrated**: A health limiter module exists at `health-limiter/sources/adaptors/navi_limiter.move` with `verify_navi_position_healthy()`, but grep searches confirm it is never imported or called in the actual vault operation flow. The navi adaptor has no health checks: [3](#0-2) 

2. **Loss Tolerance Bypass**: The operation end checks only detect the change from previous recorded value to 0, not the full extent of underwater status. If a position goes from +$500 to -$200 net value (returned as 0), only $500 loss is counted: [4](#0-3) 

3. **Share Ratio Corruption**: The vault calculates share ratios using total USD value which now excludes the underwater position entirely: [5](#0-4) 

**Execution Path**:
- During operation value updates, `update_navi_position_value()` is called
- For underwater positions, returns 0 to `finish_update_asset_value()`
- Vault's `assets_value[navi_asset_type]` set to 0
- `get_total_usd_value()` sums all asset values, excluding the underwater position's actual state
- Share ratio calculated as `total_usd_value / total_shares` is artificially inflated
- Users withdraw based on incorrect valuation

### Impact Explanation

**Concrete Harm**:

1. **Masked Insolvency**: Vault reports positive net value while actually insolvent. Example:
   - Vault has $10,000 total value, 10,000 shares
   - Navi position: $1,000 collateral, $1,200 debt (net -$200)
   - Function returns 0, vault reports $9,800 instead of true $9,800 - $200 = $9,600
   - Vault appears solvent but is actually underwater

2. **Value Extraction via Withdrawals**: Users withdrawing shares receive more principal than their fair share:
   - Share ratio calculated as $9,800 / 10,000 = $0.98 per share
   - True ratio should be $9,600 / 10,000 = $0.96 per share  
   - Withdrawing 1,000 shares: receives $980 instead of $960
   - $20 excess extracted from remaining depositors per 1,000 shares

3. **Loss Tolerance Evasion**: Hidden debt doesn't count toward epoch loss limits. A position going from +$500 to -$200 (actual $700 loss) only registers $500 loss against the tolerance threshold.

4. **Continued Operations**: Vault accepts new deposits and processes withdrawals based on false valuations until enough withdrawals expose the insolvency.

**Affected Parties**: All vault depositors, with early withdrawers extracting value and late withdrawers/remaining depositors bearing the full loss.

**Severity Justification**: CRITICAL - Enables silent insolvency, direct fund loss through value extraction, and complete breakdown of the vault's risk management and accounting systems.

### Likelihood Explanation

**Attacker Capabilities**: No special capabilities required. Any user with existing vault shares can benefit by withdrawing when positions are underwater but not yet reflected in valuations.

**Attack Complexity**: LOW - Happens automatically through normal market movements:
- Navi lending positions naturally fluctuate with asset prices and interest rates
- Volatile markets can push leveraged positions underwater
- Operators update values during regular operations, triggering the vulnerability

**Feasibility Conditions**:
- Navi position exists in vault (operator-managed)
- Market moves against the position (normal occurrence)
- Value update happens via `update_navi_position_value()` (standard operation flow)
- User withdraws before full extent of losses is realized

**Detection Constraints**: External observers monitoring Navi protocol state can detect underwater positions before the vault reflects them, creating information asymmetry and frontrunning opportunities.

**Probability**: HIGH - In volatile DeFi markets, leveraged lending positions regularly approach and breach liquidation thresholds. The vulnerability triggers on every value update for any underwater position.

### Recommendation

**Immediate Fix**:

1. **Integrate Health Factor Checks**: Before accepting any Navi position valuation, verify it meets minimum health requirements:

```move
// In update_navi_position_value(), before finish_update_asset_value()
use limiter::navi_adaptor as navi_limiter;

public fun update_navi_position_value<PrincipalCoinType>(
    vault: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
    storage: &mut Storage,
    oracle: &PriceOracle,
    min_health_factor: u256,
) {
    let account_cap = vault.get_defi_asset<PrincipalCoinType, NaviAccountCap>(asset_type);
    
    // CRITICAL: Verify position is healthy before accepting value
    navi_limiter::verify_navi_position_healthy(
        clock,
        storage,
        oracle,
        account_cap.account_owner(),
        min_health_factor
    );
    
    let usd_value = calculate_navi_position_value(
        account_cap.account_owner(),
        storage,
        config,
        clock,
    );

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

2. **Reject Underwater Positions**: Modify `calculate_navi_position_value()` to abort instead of returning 0:

```move
if (total_supply_usd_value < total_borrow_usd_value) {
    abort ERR_NAVI_POSITION_UNDERWATER  // Force operator intervention
};
```

3. **Add Invariant Checks**: In `end_op_value_update_with_bag()`, verify no positions have become unhealthy.

**Test Cases**:
- Position starts healthy, becomes underwater during operation → operation should fail
- Attempt to add underwater position to vault → should abort
- Position at exactly liquidation threshold → should abort or require safety margin
- Gradual degradation across multiple operations → cumulative loss should be tracked accurately

### Proof of Concept

**Initial State**:
- Vault created with 10,000 SUI principal
- Operator adds Navi position with 1,000 SUI supply, 500 SUI borrow (net +500 SUI = ~$500 value at $1/SUI)
- Total vault value: $10,500, total shares: 10,000
- Share ratio: $1.05 per share

**Transaction Sequence**:

1. **Market Movement**: SUI price drops, or borrowed asset appreciates
   - Navi position now: 1,000 SUI supply ($800 at $0.80/SUI), 500 borrowed asset ($1,200 at new price)
   - Net value: $800 - $1,200 = -$400 (underwater)

2. **Operator Updates Position Value**: Calls `update_navi_position_value()`
   - `calculate_navi_position_value()` executes
   - Calculates: total_supply = $800, total_borrow = $1,200
   - Returns 0 (lines 74-76)
   - `finish_update_asset_value()` stores 0 in `assets_value[navi]`

3. **Value Check in Operation End**: `end_op_value_update_with_bag()`
   - Previous total_usd_value: $10,500
   - Current total_usd_value: $10,100 (principal $9,600 + navi $0 + other assets $500)
   - Detected loss: $400 (from previous navi value $500 to $0)
   - **Hidden loss: additional $400 of debt not accounted for**
   - True vault value: $10,100 - $400 debt = $9,700

4. **User Withdrawal**: User withdraws 1,000 shares
   - Calculated amount: 1,000 shares × ($10,100 / 10,000) = $1,010
   - Should receive: 1,000 shares × ($9,700 / 10,000) = $970
   - **Excess extracted: $40**

**Expected Result**: Operation should fail with health factor violation, preventing acceptance of underwater position valuation.

**Actual Result**: Operation completes successfully, vault operates with masked $400 debt, user extracts $40 excess value.

**Success Condition**: After multiple such withdrawals, remaining depositors discover vault cannot fulfill all withdrawal requests at reported share ratio, revealing the hidden insolvency.

### Citations

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L1-29)
```text
module volo_vault::navi_adaptor;

use lending_core::account::AccountCap as NaviAccountCap;
use lending_core::dynamic_calculator;
use lending_core::storage::Storage;
use math::ray_math;
use std::ascii::String;
use sui::clock::Clock;
use volo_vault::vault::Vault;
use volo_vault::vault_oracle::{Self, OracleConfig};
use volo_vault::vault_utils;

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

**File:** volo-vault/sources/adaptors/navi_adaptor.move (L74-76)
```text
    if (total_supply_usd_value < total_borrow_usd_value) {
        return 0
    };
```

**File:** volo-vault/sources/operation.move (L360-364)
```text
    let mut loss = 0;
    if (total_usd_value_after < total_usd_value_before) {
        loss = total_usd_value_before - total_usd_value_after;
        vault.update_tolerance(loss);
    };
```

**File:** volo-vault/sources/volo_vault.move (L1297-1318)
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

    emit(ShareRatioUpdated {
        vault_id: self.vault_id(),
        share_ratio: share_ratio,
        timestamp: clock.timestamp_ms(),
    });

    share_ratio
}
```
