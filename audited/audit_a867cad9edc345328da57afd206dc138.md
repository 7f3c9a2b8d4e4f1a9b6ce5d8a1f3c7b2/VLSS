### Title
Missing Health Factor Verification for Suilend Positions Allows Continued Operations with Underwater Assets

### Summary
The Suilend adaptor reports 0 USD value for underwater positions (debt exceeds collateral) without enforcing health factor checks, allowing vault operations to continue with liquidatable Suilend obligations. Unlike Navi positions which have explicit health factor verification through the `navi_limiter` module, Suilend positions lack equivalent protection, violating the critical invariant requiring health-factor enforcement for external integrations. [1](#0-0) 

### Finding Description

**Root Cause:**

The `parse_suilend_obligation()` function in the Suilend adaptor returns 0 when a position is underwater: [2](#0-1) 

This 0 value is then passed to `finish_update_asset_value()` which simply records it in the vault's asset valuation table: [3](#0-2) 

**Missing Protection:**

The health-limiter package contains only `navi_limiter.move` for Navi position health verification: [4](#0-3) 

No equivalent Suilend health limiter exists, despite the health-limiter package depending on both protocols: [5](#0-4) 

**Operation Flow Without Health Checks:**

During the three-step operation pattern, `end_op_value_update_with_bag()` only verifies that Suilend assets were returned to the vault, but does NOT check if they are healthy: [6](#0-5) 

The operation completes successfully as long as the total loss doesn't exceed `loss_tolerance`: [7](#0-6) 

**Why Existing Protections Fail:**

While Suilend's internal protocol enforces health checks when borrowing or withdrawing: [8](#0-7) 

These checks only apply during direct Suilend operations. A Suilend obligation held by the vault can become unhealthy due to market price movements between operations, and the vault's operation flow has no mechanism to detect or prevent continued use of such underwater positions.

### Impact Explanation

**Direct Fund Impact:**

When a Suilend position is underwater (total_deposited_value_usd < total_borrowed_value_usd), the collateral value is insufficient to cover the debt. By reporting this as 0 value, the vault:

1. Masks the true risk exposure from the position
2. Allows operators to continue deploying funds through liquidatable obligations
3. Exposes the position to liquidation where liquidators can seize collateral at a discount (liquidation bonus), causing permanent loss to vault depositors

**Security Integrity Violation:**

The protocol explicitly requires "Health-factor enforcement for Navi; adaptors for Cetus/Suilend/Momentum handle assets safely" as a critical invariant. The asymmetric protection (Navi has health checks, Suilend does not) creates a security gap where:

- Underwater Suilend positions can report 0 value
- Operations bypass health-factor gates that should prevent further deployment
- Loss tolerance checks alone are insufficient, as they only verify the loss doesn't exceed a percentage threshold, not whether positions are at imminent risk of liquidation

**Severity Justification:**

This is Critical because:
- Vault continues operations with liquidatable positions
- No operator intervention required - market volatility alone triggers the condition
- Permanent loss of vault funds through liquidation
- Violates stated security invariants for external protocol integration

### Likelihood Explanation

**Market-Driven Trigger:**

This vulnerability activates through normal market conditions without any attacker action:
1. Vault holds a Suilend obligation with deposits and borrows
2. Market prices move adversely (collateral value decreases OR debt value increases)
3. Position becomes underwater: `total_deposited_value_usd < total_borrowed_value_usd`
4. Next operator update reports 0 value, operation proceeds

**Execution Path:**

The operator calls the standard three-step operation pattern:
1. `start_op_with_bag()` - borrows Suilend obligation from vault
2. `end_op_with_bag()` - returns obligation to vault
3. `update_suilend_position_value()` - reports 0 for underwater position
4. `end_op_value_update_with_bag()` - completes without health check [9](#0-8) 

**No Barriers:**

- No special permissions needed beyond normal operator capabilities
- No reliance on compromised trusted roles
- Common in volatile crypto markets (flash crashes, depegs, liquidation cascades)
- Detection difficulty: 0 value appears as a position exit rather than underwater exposure

**Probability:**

HIGH - DeFi lending markets regularly experience:
- 10-20% daily volatility in collateral assets
- Liquidation waves during market stress
- Oracle price updates causing sudden health factor changes

### Recommendation

**Immediate Fix:**

Create `suilend_limiter.move` in the health-limiter module with equivalent health verification:

```move
module limiter::suilend_limiter;

use suilend::lending_market::LendingMarket;
use suilend::obligation;
use sui::clock::Clock;

public fun verify_suilend_position_healthy<ObligationType>(
    lending_market: &mut LendingMarket<ObligationType>,
    obligation_cap: &ObligationOwnerCap<ObligationType>,
    clock: &Clock,
) {
    let obligation = lending_market.obligation(obligation_cap.obligation_id());
    assert!(obligation::is_healthy(obligation), /* appropriate error code */);
}
```

**Integration Point:**

Call health verification in the operation flow after updating Suilend position values, similar to Navi verification pattern. The check should occur in `end_op_value_update_with_bag()` before accepting the 0 value: [6](#0-5) 

**Alternative Approach:**

Modify `parse_suilend_obligation()` to abort when a position is underwater rather than silently returning 0:

```move
if (total_deposited_value_usd < total_borrowed_value_usd) {
    abort EUnderwaterSuilendPosition
};
```

**Test Cases:**

1. Create Suilend position with healthy health factor
2. Simulate adverse price movement making position underwater
3. Attempt `update_suilend_position_value()` - should abort
4. Verify operations cannot proceed with unhealthy Suilend positions
5. Test recovery path when position becomes healthy again

### Proof of Concept

**Initial State:**
1. Vault holds SuilendObligationOwnerCap with:
   - Deposited SUI collateral: $10,000 USD
   - Borrowed USDC: $8,000 USD
   - Position value: $2,000 USD (healthy)

**Market Event:**
2. SUI price drops 30%
   - Deposited SUI collateral: $7,000 USD
   - Borrowed USDC: $8,000 USD
   - Position is now underwater by -$1,000 USD

**Exploitation:**
3. Operator executes normal operation:
```move
operation::start_op_with_bag(vault, ...);
operation::end_op_with_bag(vault, ...);
suilend_adaptor::update_suilend_position_value(vault, lending_market, clock, asset_type);
// Returns 0 instead of aborting for underwater position
operation::end_op_value_update_with_bag(vault, ...);
```

**Expected Result:**
Operation should abort with health factor violation error

**Actual Result:**
- `parse_suilend_obligation()` returns 0 at line 86
- Operation completes successfully
- Vault continues operating with liquidatable position
- Position subject to liquidation, causing permanent loss

**Success Condition:**
The vulnerability is confirmed if operations complete without error despite the Suilend position being underwater and at risk of immediate liquidation.

### Citations

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L23-40)
```text
public fun update_suilend_position_value<PrincipalCoinType, ObligationType>(
    vault: &mut Vault<PrincipalCoinType>,
    lending_market: &mut LendingMarket<ObligationType>,
    clock: &Clock,
    asset_type: String,
) {
    let obligation_cap = vault.get_defi_asset<
        PrincipalCoinType,
        SuilendObligationOwnerCap<ObligationType>,
    >(
        asset_type,
    );

    suilend_compound_interest(obligation_cap, lending_market, clock);
    let usd_value = parse_suilend_obligation(obligation_cap, lending_market, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/adaptors/suilend_adaptor.move (L85-88)
```text
    if (total_deposited_value_usd < total_borrowed_value_usd) {
        return 0
    };
    (total_deposited_value_usd - total_borrowed_value_usd) / DECIMAL
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

**File:** volo-vault/health-limiter/Move.toml (L50-63)
```text
[dependencies.lending_core]
local = "../local_dependencies/protocol/lending_core"

[dependencies.Switchboard]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "on_demand"
local = "../local_dependencies/switchboard_sui/on_demand"

[dependencies.suilend]
# git = "https://github.com/Sui-Volo/vault-dependencies"
# rev = "main"
# subdir = "suilend_d/suilend"
local = "../local_dependencies/suilend_d/suilend"
```

**File:** volo-vault/sources/operation.move (L336-343)
```text
        if (defi_asset_type == type_name::get<SuilendObligationOwnerCap<ObligationType>>()) {
            let suilend_asset_type = vault_utils::parse_key<
                SuilendObligationOwnerCap<ObligationType>,
            >(
                defi_asset_id,
            );
            assert!(vault.contains_asset_type(suilend_asset_type), ERR_ASSETS_NOT_RETURNED);
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

**File:** volo-vault/local_dependencies/suilend_d/suilend/sources/obligation.move (L790-796)
```text
    public fun is_healthy<P>(obligation: &Obligation<P>): bool {
        le(obligation.weighted_borrowed_value_upper_bound_usd, obligation.allowed_borrow_value_usd)
    }

    public fun is_liquidatable<P>(obligation: &Obligation<P>): bool {
        gt(obligation.weighted_borrowed_value_usd, obligation.unhealthy_borrow_value_usd)
    }
```
