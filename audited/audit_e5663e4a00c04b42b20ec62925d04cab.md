# Audit Report

## Title
Partial Upgrade Causes Complete Vault DoS Due to Independent Component Version Checks

## Summary
The vault upgrade mechanism allows independent upgrades of three components (Vault, RewardManager, OracleConfig) through separate admin functions. When a protocol package upgrade bumps VERSION constants but only some components are upgraded, all vault operations fail because each component independently validates its version field against its VERSION constant. This design flaw creates complete denial of service until all three components are upgraded together, with no code-level safeguards preventing partial upgrade states.

## Finding Description

The upgrade mechanism exposes three independent functions in `volo-vault/sources/manage.move`: [1](#0-0) 

Each component maintains its own VERSION constant and performs independent version checking. The Vault component checks its version: [2](#0-1) [3](#0-2) [4](#0-3) 

The RewardManager component checks its version: [5](#0-4) [6](#0-5) [7](#0-6) 

The OracleConfig component checks its version: [8](#0-7) [9](#0-8) [10](#0-9) 

**Root Cause**: Critical vault operations require all three components but perform no cross-component version validation. When `execute_deposit()` is called: [11](#0-10) 

The execution flow triggers three independent version checks:
1. Line 393 calls `reward_manager.update_reward_buffers()`: [12](#0-11) 

2. Line 398 calls `vault.execute_deposit()`: [13](#0-12) 

3. Within vault.execute_deposit, line 839 calls `update_free_principal_value()` which uses OracleConfig: [14](#0-13) 

This ultimately triggers oracle version check: [15](#0-14) 

**Failure Scenario**: After a package upgrade where VERSION constants are bumped from 1→2, if admin calls `upgrade_vault()` but forgets `upgrade_reward_manager()` and `upgrade_oracle_config()`, any deposit/withdrawal will abort at the first mismatched version check with ERR_INVALID_VERSION.

## Impact Explanation

**Complete Operational DoS**:
- All deposits fail - users cannot add funds
- All withdrawals fail - users cannot retrieve funds  
- All reward claims fail - no rewards collection possible
- All operator operations fail - no rebalancing or strategy execution

**Funds Temporarily Locked**: User funds remain inaccessible until admin discovers the issue and completes remaining upgrades. This causes:
- Loss of liquidity access
- No yield generation during downtime
- Severe protocol reputation damage
- User panic and potential loss of confidence

**Severity: HIGH** - Complete loss of vault functionality affecting all users simultaneously with funds locked until manual admin intervention.

## Likelihood Explanation

**Realistic Operational Scenario**: This is not about malicious admin behavior but a **design flaw** that enables dangerous partial upgrade states with no safeguards.

**Execution Path**:
1. Protocol team deploys package upgrade via `sui move upgrade` with bumped VERSION constants
2. Admin calls upgrade functions sequentially
3. If any transaction fails, script errors, or runbook is incomplete, partial upgrade occurs
4. Next user transaction triggers immediate DoS

**Why This Is Valid**: The protocol design allows three independent upgrade functions with:
- No atomic upgrade mechanism
- No cross-component version validation
- No upgrade state management
- No warnings preventing partial upgrades

Well-designed upgrade systems prevent this through atomic operations or cross-component checks. The current implementation places unrealistic operational burden on admin with zero code-level safety rails.

**Probability: MEDIUM-HIGH** - Multi-step manual processes are inherently error-prone, and the lack of safeguards makes this a realistic operational failure mode.

## Recommendation

Implement one of the following solutions:

**Option 1: Atomic Upgrade Function**
```move
public fun upgrade_all(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    oracle_config: &mut OracleConfig,
) {
    vault.upgrade_vault();
    reward_manager.upgrade_reward_manager();
    oracle_config.upgrade_oracle_config();
}
```

**Option 2: Cross-Component Version Validation**
Add validation in critical operations:
```move
public fun execute_deposit<PrincipalCoinType>(...) {
    // Validate all components have matching versions
    assert!(
        vault.version() == reward_manager.version() && 
        vault.version() == oracle_config.version(),
        ERR_VERSION_MISMATCH
    );
    // ... rest of function
}
```

**Option 3: Upgrade State Management**
Track upgrade state to prevent partial upgrades:
```move
public struct UpgradeState has key {
    vault_upgraded: bool,
    reward_manager_upgraded: bool,
    oracle_config_upgraded: bool,
}
```

## Proof of Concept

```move
#[test]
fun test_partial_upgrade_causes_dos() {
    // Setup: Deploy vault system with VERSION=1 for all components
    let (vault, reward_manager, oracle_config, admin_cap) = setup_vault();
    
    // Simulate package upgrade: VERSION constants now = 2
    // Admin upgrades only vault
    upgrade_vault(&admin_cap, &mut vault);
    
    // Vault.version = 2, but RewardManager.version = 1, OracleConfig.version = 1
    
    // User attempts deposit - should fail with ERR_INVALID_VERSION
    let result = execute_deposit(
        &operation,
        &operator_cap,
        &mut vault,
        &mut reward_manager,
        &clock,
        &oracle_config,
        request_id,
        max_shares
    );
    
    // Transaction aborts when reward_manager.check_version() 
    // finds version mismatch (1 != 2)
    assert!(result.is_err(), 0);
}
```

## Notes

This vulnerability demonstrates a critical design flaw in the upgrade mechanism. While it requires admin action, it's not about malicious behavior but rather insufficient safeguards in the protocol design. The system should not allow dangerous partial upgrade states to exist. Modern DeFi protocols typically use atomic upgrades or state management to prevent such scenarios. The severity is HIGH due to complete vault DoS affecting all users with no recourse except admin intervention.

### Citations

**File:** volo-vault/sources/manage.move (L22-38)
```text
public fun upgrade_vault<PrincipalCoinType>(_: &AdminCap, vault: &mut Vault<PrincipalCoinType>) {
    vault.upgrade_vault();
}

public fun upgrade_reward_manager<PrincipalCoinType>(
    _: &AdminCap,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
) {
    reward_manager.upgrade_reward_manager();
}

public fun upgrade_oracle_config(
    _: &AdminCap,
    oracle_config: &mut OracleConfig,
) {
    oracle_config.upgrade_oracle_config();
}
```

**File:** volo-vault/sources/volo_vault.move (L21-21)
```text
const VERSION: u64 = 1;
```

**File:** volo-vault/sources/volo_vault.move (L464-469)
```text
public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
```

**File:** volo-vault/sources/volo_vault.move (L663-665)
```text
public(package) fun check_version<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.version == VERSION, ERR_INVALID_VERSION);
}
```

**File:** volo-vault/sources/volo_vault.move (L806-814)
```text
public(package) fun execute_deposit<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    self.check_version();
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1101-1113)
```text
public fun update_free_principal_value<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    config: &OracleConfig,
    clock: &Clock,
) {
    self.check_version();
    self.assert_enabled();

    let principal_price = vault_oracle::get_normalized_asset_price(
        config,
        clock,
        type_name::get<PrincipalCoinType>().into_string(),
    );
```

**File:** volo-vault/sources/reward_manager.move (L29-29)
```text
const VERSION: u64 = 1;
```

**File:** volo-vault/sources/reward_manager.move (L186-188)
```text
public(package) fun check_version<PrincipalCoinType>(self: &RewardManager<PrincipalCoinType>) {
    assert!(self.version == VERSION, ERR_INVALID_VERSION);
}
```

**File:** volo-vault/sources/reward_manager.move (L190-200)
```text
public(package) fun upgrade_reward_manager<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(RewardManagerUpgraded {
        reward_manager_id: self.id.to_address(),
        version: VERSION,
    });
}
```

**File:** volo-vault/sources/reward_manager.move (L449-462)
```text
public fun update_reward_buffers<PrincipalCoinType>(
    self: &mut RewardManager<PrincipalCoinType>,
    vault: &mut Vault<PrincipalCoinType>,
    clock: &Clock,
) {
    self.check_version();
    assert!(self.vault_id == vault.vault_id(), ERR_REWARD_MANAGER_VAULT_MISMATCH);

    let buffer_reward_types = self.reward_buffer.distributions.keys();

    buffer_reward_types.do_ref!(|reward_type| {
        self.update_reward_buffer<PrincipalCoinType>(vault, clock, *reward_type);
    });
}
```

**File:** volo-vault/sources/oracle.move (L11-11)
```text
const VERSION: u64 = 2;
```

**File:** volo-vault/sources/oracle.move (L96-98)
```text
public(package) fun check_version(self: &OracleConfig) {
    assert!(self.version == VERSION, ERR_INVALID_VERSION);
}
```

**File:** volo-vault/sources/oracle.move (L100-108)
```text
public(package) fun upgrade_oracle_config(self: &mut OracleConfig) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(OracleConfigUpgraded {
        oracle_config_id: self.id.to_address(),
        version: VERSION,
    });
}
```

**File:** volo-vault/sources/oracle.move (L126-138)
```text
public fun get_asset_price(config: &OracleConfig, clock: &Clock, asset_type: String): u256 {
    config.check_version();

    assert!(table::contains(&config.aggregators, asset_type), ERR_AGGREGATOR_NOT_FOUND);

    let price_info = &config.aggregators[asset_type];
    let now = clock.timestamp_ms();

    // Price must be updated within update_interval
    assert!(price_info.last_updated.diff(now) < config.update_interval, ERR_PRICE_NOT_UPDATED);

    price_info.price
}
```

**File:** volo-vault/sources/operation.move (L381-404)
```text
public fun execute_deposit<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_shares_received: u256,
) {
    vault::assert_operator_not_freezed(operation, cap);

    reward_manager.update_reward_buffers(vault, clock);

    let deposit_request = vault.deposit_request(request_id);
    reward_manager.update_receipt_reward(vault, deposit_request.receipt_id());

    vault.execute_deposit(
        clock,
        config,
        request_id,
        max_shares_received,
    );
}
```
