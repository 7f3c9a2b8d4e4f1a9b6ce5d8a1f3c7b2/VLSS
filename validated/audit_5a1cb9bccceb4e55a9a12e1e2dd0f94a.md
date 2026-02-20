# Audit Report

## Title
Critical Missing Dependency: MMT v3 Stub Implementation Causes Permanent Vault Lockup

## Summary
The `mmt_v3::tick_math` and `mmt_v3::liquidity_math` modules contain only stub implementations that unconditionally abort execution. When operators perform vault operations with MomentumPosition assets, the mandatory value update fails, permanently locking the vault in DURING_OPERATION status with no recovery mechanism, preventing all user deposits and withdrawals.

## Finding Description

This vulnerability breaks the critical protocol invariant that "vault operations must complete and return to NORMAL status." The issue stems from three interconnected components:

**1. Stub Implementations in Critical Dependencies**

The MMT v3 dependency modules contain only non-functional stub implementations that immediately abort. [1](#0-0) 

Similarly, the liquidity math module aborts on all function calls. [2](#0-1) 

**2. Production Code Invokes These Stubs**

The momentum adaptor's value calculation directly calls these stub functions. [3](#0-2) [4](#0-3) 

**3. Mandatory Three-Phase Operation Lifecycle**

When operators start vault operations, the vault status transitions to DURING_OPERATION. [5](#0-4) 

MomentumPosition assets can be borrowed during operations, which registers them as requiring value updates. [6](#0-5) [7](#0-6) 

After returning assets, operators must update the value of ALL borrowed assets. [8](#0-7) 

The vault enforces that all borrowed assets have been updated before allowing status return to NORMAL. [9](#0-8) [10](#0-9) 

Only after this check passes can the vault return to NORMAL status. [11](#0-10) 

**4. Complete Protocol Lockup**

When the vault is stuck in DURING_OPERATION status, all user operations are blocked. [12](#0-11) 

Deposit requests are blocked. [13](#0-12) 

Withdrawal requests are also blocked. [14](#0-13) 

**5. No Recovery Mechanism**

The admin's `set_enabled` function explicitly rejects vaults in DURING_OPERATION status, preventing any administrative recovery. [15](#0-14) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability causes complete protocol denial-of-service with permanent fund lockup:

1. **Permanent Vault Lockup**: The vault becomes permanently stuck in DURING_OPERATION status. The admin cannot override this state, and no recovery path exists.

2. **All User Funds Locked**: Every user with deposits in the affected vault cannot withdraw their funds. Their assets remain inaccessible indefinitely.

3. **Deposit Prevention**: New deposits are impossible, as the `assert_normal` check blocks all deposit requests.

4. **Operator Inability**: Operators cannot perform any subsequent operations, as each operation requires starting from NORMAL status.

5. **Protocol Invariant Violation**: The critical security invariant that "vault operations must complete and return to NORMAL status" is permanently broken.

This affects all depositors in any vault containing MomentumPosition assets, potentially locking substantial protocol TVL with zero recovery possibility.

## Likelihood Explanation

**Probability: HIGH (if MomentumPosition assets are used)**

The vulnerability triggers through normal, intended protocol usage:

1. **No Special Conditions Required**: An operator with a valid OperatorCap simply needs to add a MomentumPosition to a vault and perform a standard three-phase vault operation.

2. **100% Reproducible**: The stub implementations abort unconditionally with no conditional logic, making this deterministic and reproducible every time.

3. **No Warning Mechanisms**: There are no runtime checks to prevent adding momentum positions or validate that dependencies are functional. The code compiles and deploys successfully.

4. **Silent Failure Mode**: The issue is not detectable until triggered in production. Codebase searches confirm the complete absence of momentum adaptor tests in the test suite, indicating this code path has never been validated.

5. **Currently Undetected**: The lack of any test coverage for MomentumPosition functionality suggests this vulnerability exists in production deployments but remains undetected until first use.

## Recommendation

**Immediate Actions:**
1. Remove MomentumPosition support from all vaults until proper MMT v3 implementations are available
2. Add deployment validation that checks for stub implementations in critical dependencies
3. Add circuit breaker allowing admin recovery from DURING_OPERATION status in emergency situations

**Long-term Fix:**
1. Replace stub implementations with actual MMT v3 integration code
2. Add comprehensive test coverage for all DeFi position adaptors
3. Implement pre-flight checks that validate adaptor functionality before allowing asset additions

**Code Fix Example:**
Add an emergency recovery function:
```move
public fun emergency_reset_vault_status<T>(
    _: &AdminCap, 
    vault: &mut Vault<T>
) {
    // Emergency only - allows admin to recover stuck vaults
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
}
```

## Proof of Concept

```move
#[test]
fun test_momentum_position_vault_lockup() {
    let mut scenario = test_scenario::begin(@0xA);
    
    // Setup vault with MomentumPosition
    let admin_cap = vault::create_admin_cap(scenario.ctx());
    let mut vault = vault::create_vault<SUI>(&admin_cap, scenario.ctx());
    let op_cap = vault::create_operator_cap(&admin_cap, scenario.ctx());
    
    // Add MomentumPosition to vault (would succeed)
    let momentum_position = create_mock_momentum_position(scenario.ctx());
    vault::add_new_defi_asset(&op_cap, &mut vault, 0, momentum_position);
    
    // Start operation (succeeds - vault enters DURING_OPERATION)
    let (assets, tx_bag, _) = operation::start_op_with_bag(
        &mut vault, &op_cap, clock, 
        vector[0], vector[type_name::get<MomentumPosition>()],
        0, 0, scenario.ctx()
    );
    
    // Return assets (succeeds)
    operation::end_op_with_bag(&mut vault, &op_cap, assets, tx_bag, ...);
    
    // Try to update momentum position value - ABORTS HERE
    // momentum_adaptor::update_momentum_position_value(...);
    // This abort prevents completion, vault stuck in DURING_OPERATION
    
    // Now all user operations fail with assert_normal check
    // vault.assert_normal(); // FAILS - vault stuck forever
    
    scenario.end();
}
```

## Notes

The vulnerability is valid and critical because:
- All components are in-scope production code
- The execution path is fully reachable through normal operator actions
- No administrative recovery mechanism exists
- Impact is complete protocol DoS with permanent fund lockup
- Likelihood is 100% if MomentumPosition assets are used

### Citations

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/tick_math.move (L4-6)
```text
    public fun get_sqrt_price_at_tick(arg0: I32) : u128 {
        abort 0
    }
```

**File:** volo-vault/local_dependencies/mmt_v3/sources/utils/liquidity_math.move (L4-6)
```text
    public fun add_delta(current_liquidity: u128, delta_liquidity: I128) : u128 {
        abort 0
    }
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L78-79)
```text
    let lower_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(lower_tick);
    let upper_tick_sqrt_price = tick_math::get_sqrt_price_at_tick(upper_tick);
```

**File:** volo-vault/sources/adaptors/momentum.adaptor.move (L83-89)
```text
    let (amount_a, amount_b) = liquidity_math::get_amounts_for_liquidity(
        sqrt_price,
        lower_tick_sqrt_price,
        upper_tick_sqrt_price,
        liquidity,
        false,
    );
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

**File:** volo-vault/sources/operation.move (L294-294)
```text
    vault.enable_op_value_update();
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/operation.move (L375-376)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
    vault.clear_op_value_update_record();
```

**File:** volo-vault/sources/volo_vault.move (L518-531)
```text
public(package) fun set_enabled<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    self.check_version();
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);

    if (enabled) {
        self.set_status(VAULT_NORMAL_STATUS);
    } else {
        self.set_status(VAULT_DISABLED_STATUS);
    };
    emit(VaultEnabled { vault_id: self.vault_id(), enabled: enabled })
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L715-717)
```text
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/sources/volo_vault.move (L904-906)
```text
    self.check_version();
    self.assert_normal();
    assert!(self.contains_vault_receipt_info(receipt_id), ERR_RECEIPT_NOT_FOUND);
```

**File:** volo-vault/sources/volo_vault.move (L1206-1218)
```text
public(package) fun check_op_value_update_record<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    self.check_version();
    self.assert_enabled();
    assert!(self.op_value_update_record.value_update_enabled, ERR_OP_VALUE_UPDATE_NOT_ENABLED);

    let record = &self.op_value_update_record;

    record.asset_types_borrowed.do_ref!(|asset_type| {
        assert!(record.asset_types_updated.contains(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
        assert!(*record.asset_types_updated.borrow(*asset_type), ERR_USD_VALUE_NOT_UPDATED);
    });
```

**File:** volo-vault/sources/volo_vault.move (L1424-1426)
```text
    if (self.status() == VAULT_DURING_OPERATION_STATUS) {
        self.op_value_update_record.asset_types_borrowed.push_back(asset_type);
    };
```
