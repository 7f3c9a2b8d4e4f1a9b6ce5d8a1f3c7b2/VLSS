### Title
Partial Upgrade Causes Complete Vault DoS Due to Version Mismatch

### Summary
The vault upgrade mechanism allows independent upgrades of Vault, RewardManager, and OracleConfig components through separate admin functions. When a protocol upgrade bumps VERSION constants but only some components are upgraded, all vault operations fail because each component's check_version() requires matching its own VERSION constant. This creates a complete denial of service until all components are upgraded.

### Finding Description

The upgrade mechanism in `volo-vault/sources/manage.move` exposes three independent upgrade functions: [1](#0-0) 

Each component (Vault, RewardManager, OracleConfig) maintains its own VERSION constant and version field, with independent version checking:

**Vault version checking:** [2](#0-1) [3](#0-2) [4](#0-3) 

**RewardManager version checking:** [5](#0-4) [6](#0-5) [7](#0-6) 

**OracleConfig version checking:** [8](#0-7) [9](#0-8) [10](#0-9) 

**Root Cause:** Critical vault operations require multiple components working together but perform no cross-component version validation: [11](#0-10) 

When `execute_deposit()` is called:
1. Line 393 calls `reward_manager.update_reward_buffers()` which internally calls `self.check_version()` 
2. Line 398-403 calls `vault.execute_deposit()` which internally calls `self.check_version()`
3. The vault method uses OracleConfig which also calls its own `check_version()`

Each component only validates its own version matches its own VERSION constant. There is no validation that all interacting components have compatible versions.

**Failure Scenario:**
After a Sui package upgrade where VERSION constants are bumped from 1→2:
- Admin calls `upgrade_vault()` → Vault.version = 2 ✓
- Admin forgets `upgrade_reward_manager()` → RewardManager.version = 1 ✗
- Admin forgets `upgrade_oracle_config()` → OracleConfig.version = 1 ✗

Any deposit/withdrawal operation will abort at the first `check_version()` call on the non-upgraded component with `ERR_INVALID_VERSION`. [12](#0-11) 

### Impact Explanation

**Complete Operational DoS:**
- All deposits fail - users cannot add funds to vault
- All withdrawals fail - users cannot retrieve their funds  
- All reward claims fail - users cannot collect earned rewards
- All operator operations fail - no rebalancing or strategy execution possible

**Funds Locked:** User funds remain locked in the vault until admin completes the upgrade of all components. During this period:
- No liquidity access for users
- No yield generation
- Protocol reputation damage
- Potential panic if users cannot access funds

**Affected Parties:**
- All vault users with deposited funds
- Protocol operators unable to manage positions
- Protocol treasury unable to collect fees

**Severity Justification:** HIGH
- Impact: Complete loss of vault functionality, funds temporarily locked
- Duration: Until admin discovers issue and upgrades remaining components
- Scope: Affects all users and all vault operations simultaneously

### Likelihood Explanation

**Realistic Operational Error:** This is not a malicious attack but a realistic admin operational mistake during protocol upgrades.

**Execution Path:**
1. Protocol team deploys package upgrade via `sui move upgrade` with bumped VERSION constants
2. Admin holds AdminCap and calls upgrade functions
3. Admin successfully calls `upgrade_vault()` 
4. Due to operational error (e.g., transaction failure, script error, incomplete runbook), admin fails to call `upgrade_reward_manager()` and `upgrade_oracle_config()`
5. Next user transaction calling any vault operation triggers the DoS

**Feasibility Conditions:**
- Requires AdminCap (trusted role) - but this is about operational error, not malicious compromise
- No technical barriers - the three functions are independent and can be called separately
- No warnings or safeguards preventing partial upgrade
- No atomic upgrade mechanism forcing all three together

**Probability Assessment:** MEDIUM-HIGH
- Multi-step manual upgrade process increases error probability
- No code-level enforcement of atomic upgrades
- No validation that dependent components have compatible versions
- Historical precedent of partial upgrade issues in other protocols

**Detection:** Issue is immediately apparent when first user transaction fails, but damage (DoS) is already done.

### Recommendation

**1. Implement Atomic Upgrade Function:**

Create a single entry point in `manage.move` that upgrades all three components atomically:

```move
public fun upgrade_all<PrincipalCoinType>(
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

**2. Add Cross-Component Version Validation:**

Add version compatibility checks in critical operations. In `operation.move`, add validation before executing operations:

```move
public fun execute_deposit<PrincipalCoinType>(
    // ... existing parameters
) {
    // Add cross-version validation
    assert!(vault.version() == reward_manager.version(), ERR_VERSION_MISMATCH);
    assert!(vault.version() == oracle_config.version(), ERR_VERSION_MISMATCH);
    
    // ... existing logic
}
```

Expose version getters in each module and add assertions that all interconnected components have matching versions.

**3. Add Upgrade State Tracking:**

Track upgrade completion state to prevent partial upgrades:

```move
public struct UpgradeState has key {
    vault_version: u64,
    reward_manager_version: u64,
    oracle_config_version: u64,
    upgrade_in_progress: bool,
}
```

**4. Test Cases:**

Add regression tests:
- Test that partial upgrade causes operations to fail with expected error
- Test that atomic upgrade succeeds and allows operations to continue
- Test version mismatch detection in all critical operation paths

### Proof of Concept

**Initial State:**
- Vault deployed with VERSION = 1, version field = 1
- RewardManager deployed with VERSION = 1, version field = 1  
- OracleConfig deployed with VERSION = 1, version field = 1
- All operations working normally

**Step 1: Deploy Package Upgrade**
```bash
sui client upgrade --gas-budget 500000000
# New package deployed with:
# - volo_vault::VERSION = 2
# - reward_manager::VERSION = 2  
# - oracle_config::VERSION = 2
```

**Step 2: Partial Upgrade (Admin Error)**
```move
// Admin calls only vault upgrade
transaction {
    upgrade_vault(&admin_cap, &mut vault);
}
// Result: vault.version = 2
// But: reward_manager.version = 1, oracle_config.version = 1
```

**Step 3: User Attempts Deposit**
```move
transaction {
    operation::execute_deposit(
        &operation,
        &operator_cap,
        &mut vault,          // version = 2 ✓
        &mut reward_manager, // version = 1 ✗ 
        &clock,
        &oracle_config,      // version = 1 ✗
        request_id,
        max_shares,
    );
}
```

**Expected Result:** Transaction succeeds, deposit executed

**Actual Result:** Transaction ABORTS with error code 3_007 (ERR_INVALID_VERSION) at line 454 in reward_manager.move when `update_reward_buffers()` calls `self.check_version()` and finds self.version (1) != VERSION (2).

**Success Condition for Exploit:** Vault operations are completely blocked until admin calls `upgrade_reward_manager()` and `upgrade_oracle_config()` to complete the upgrade.

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
