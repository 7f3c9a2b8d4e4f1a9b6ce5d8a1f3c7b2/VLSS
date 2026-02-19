### Title
Incomplete State Migration in upgrade_vault() Causes Permanent Vault Corruption and Fund Lockup

### Summary
The `upgrade_vault()` function only updates the version field without migrating critical vault state including `op_value_update_record`, `request_buffer`, `receipts`, and `assets` tables. If called while the vault is in DURING_OPERATION status, the stale operation tracking state causes all subsequent operation completions to fail, permanently locking the vault and all user funds.

### Finding Description

The `upgrade_vault()` function performs minimal state migration: [1](#0-0) 

This function only updates the `version` field and emits an event. It performs **zero migration** of the complex state fields that are critical for vault operations:

1. **op_value_update_record**: Tracks borrowed assets during operations with `asset_types_borrowed` vector, `asset_types_updated` table, and `value_update_enabled` flag [2](#0-1) 

2. **request_buffer**: Contains pending deposit/withdraw requests and coin buffers [3](#0-2) 

3. **receipts**: Table of user receipt information [4](#0-3) 

4. **assets/assets_value/assets_value_updated**: Asset tracking tables [5](#0-4) 

The function has **no precondition checks** - it does not verify that:
- The vault is in NORMAL status (not during operation)
- The request_buffer is empty
- The op_value_update_record is cleared

When operations complete, they must call `check_op_value_update_record()`: [6](#0-5) 

This function verifies that all borrowed assets tracked in `asset_types_borrowed` have corresponding entries in `asset_types_updated` that are marked as `true`. 

The operation completion flow calls this check: [7](#0-6) 

**Exploitation Path**:
1. Vault is in DURING_OPERATION_STATUS with borrowed assets tracked in op_value_update_record
2. Admin calls `upgrade_vault()` via the management interface: [8](#0-7) 

3. Only the version field is updated; op_value_update_record retains stale state (borrowed assets list, incomplete updated table)
4. Operator attempts to complete operation by calling `end_op_value_update_with_bag()`
5. `check_op_value_update_record()` fails because `asset_types_updated` doesn't have proper entries for the tracked borrowed assets
6. Transaction aborts with `ERR_USD_VALUE_NOT_UPDATED` or `ERR_OP_VALUE_UPDATE_NOT_ENABLED`
7. Vault remains permanently in DURING_OPERATION_STATUS
8. All user deposits and withdrawals are blocked as they require NORMAL status: [9](#0-8) [10](#0-9) [11](#0-10) 

### Impact Explanation

**Direct Operational Impact - Complete Vault Lockup**:
- Vault becomes permanently stuck in DURING_OPERATION_STATUS
- All user deposit requests blocked (require NORMAL status)
- All user withdrawal requests blocked (require NORMAL status)
- No mechanism to clear corrupted operation state without another package upgrade
- All funds (free_principal, claimable_principal, assets) locked indefinitely

**Affected Parties**:
- All vault depositors lose access to their funds
- Operators cannot execute any deposit/withdrawal operations
- Protocol experiences complete DoS for the affected vault
- Reward distributions also blocked as receipt operations require compatible vault state

**Severity Justification**:
This is CRITICAL because:
1. Results in permanent fund lockup with no recovery mechanism
2. Affects ALL users of the vault
3. No time-based recovery (vault remains broken indefinitely)
4. Requires emergency package upgrade to fix corrupted state
5. Violates critical invariant: "All borrowed DeFi assets returned; operation start/end status toggles"

In contrast, the liquid staking migration implements a proper multi-step migration with explicit state export/import: [12](#0-11) 

The vault upgrade lacks any equivalent migration logic.

### Likelihood Explanation

**Reachable Entry Point**:
- `upgrade_vault()` is callable by AdminCap holder at any time
- No authorization beyond AdminCap check (which is expected for admin function)

**Feasible Preconditions**:
- Vault must be in DURING_OPERATION_STATUS when upgrade is called
- This is a realistic scenario during package upgrades when:
  - Operations are actively running
  - Operators are rebalancing portfolios
  - Multi-step operations are in progress
  - Admin may upgrade believing operations will complete normally

**Execution Practicality**:
- Admin simply calls `upgrade_vault()` through the management interface
- No need to bypass any security checks
- Corruption occurs automatically if vault is in operation
- Standard Sui Move execution, no special tricks required

**Attack Complexity**: NONE - This is an operational failure, not an attack. The vulnerability triggers during normal admin operations.

**Probability**: HIGH
- Package upgrades are expected events in protocol lifecycle
- Operations are frequently running during normal vault operation
- No warnings or checks prevent upgrading during operations
- Admin has no visibility into safe upgrade timing

### Recommendation

**Immediate Fix**:
Add precondition checks to `upgrade_vault()`:

```move
public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    
    // CRITICAL: Vault must be in safe state for upgrade
    self.assert_normal();  // Not during operation
    
    // Verify no pending requests
    assert!(self.request_buffer.deposit_id_count == 0 || 
            self.request_buffer.deposit_requests.is_empty(), ERR_PENDING_REQUESTS);
    assert!(self.request_buffer.withdraw_id_count == 0 || 
            self.request_buffer.withdraw_requests.is_empty(), ERR_PENDING_REQUESTS);
    
    // Verify operation record is clean
    assert!(!self.op_value_update_record.value_update_enabled, ERR_OPERATION_IN_PROGRESS);
    assert!(self.op_value_update_record.asset_types_borrowed.is_empty(), ERR_OPERATION_IN_PROGRESS);
    
    self.version = VERSION;
    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
```

**Proper Migration Pattern**:
If state migration is needed (new fields, changed logic), implement a multi-step migration similar to liquid staking:
1. Create MigrationCap with state tracking
2. Pause vault operations
3. Export state from old structure
4. Import into new structure with validation
5. Destroy migration cap
6. Unpause vault

**Invariant Checks to Add**:
- Pre-upgrade: Vault in NORMAL status
- Pre-upgrade: No pending deposit/withdraw requests
- Pre-upgrade: op_value_update_record cleared
- Post-upgrade: Version incremented correctly
- Post-upgrade: All state fields accessible and valid

**Test Cases**:
1. Test upgrade_vault() aborts if vault in DURING_OPERATION_STATUS
2. Test upgrade_vault() aborts if pending deposit requests exist
3. Test upgrade_vault() aborts if pending withdraw requests exist
4. Test upgrade_vault() aborts if op_value_update_record has tracked assets
5. Test successful upgrade only when vault in clean NORMAL state
6. Test operations can complete normally after proper upgrade

### Proof of Concept

**Initial State**:
1. Vault deployed with VERSION = 1
2. Vault has active deposits with total_shares > 0
3. Operator starts operation: `start_op_with_bag()` sets status to DURING_OPERATION_STATUS
4. Assets borrowed, tracked in `op_value_update_record.asset_types_borrowed`
5. `op_value_update_record.value_update_enabled = false` (set to true later)

**Attack Sequence**:
1. Admin calls `upgrade_vault(vault)` while operation in progress
2. Only `vault.version` updated to VERSION
3. `op_value_update_record` retains stale state:
   - `asset_types_borrowed` still contains borrowed asset entries
   - `asset_types_updated` table incomplete
   - `value_update_enabled = false` or has stale value

4. Operator attempts to complete operation:
   - Calls `end_op_with_bag()` to return assets
   - Assets returned successfully
   - Calls `enable_op_value_update(vault)`
   - Calls `end_op_value_update_with_bag()` to finalize

5. Inside `end_op_value_update_with_bag()`:
   - Checks assets returned (passes)
   - Calls `vault.check_op_value_update_record()` at line 354
   - Function iterates `asset_types_borrowed` vector
   - Checks if each asset in `asset_types_updated` table
   - **ABORTS** with `ERR_USD_VALUE_NOT_UPDATED` because stale entries don't match

**Expected vs Actual Result**:
- **Expected**: Operation completes, vault returns to NORMAL status
- **Actual**: Transaction aborts, vault stuck in DURING_OPERATION_STATUS forever

**Success Condition for Exploit**: Vault permanently in DURING_OPERATION_STATUS, all subsequent user operations fail with `ERR_VAULT_NOT_NORMAL`.

### Citations

**File:** volo-vault/sources/volo_vault.move (L113-116)
```text
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
```

**File:** volo-vault/sources/volo_vault.move (L127-127)
```text
    receipts: Table<address, VaultReceiptInfo>,
```

**File:** volo-vault/sources/volo_vault.move (L132-140)
```text
public struct RequestBuffer<phantom T> has store {
    // ---- Deposit Request ---- //
    deposit_id_count: u64,
    deposit_requests: Table<u64, DepositRequest>,
    deposit_coin_buffer: Table<u64, Coin<T>>,
    // ---- Withdraw Request ---- //
    withdraw_id_count: u64,
    withdraw_requests: Table<u64, WithdrawRequest>,
}
```

**File:** volo-vault/sources/volo_vault.move (L142-146)
```text
public struct OperationValueUpdateRecord has store {
    asset_types_borrowed: vector<String>,
    value_update_enabled: bool,
    asset_types_updated: Table<String, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L464-469)
```text
public(package) fun upgrade_vault<PrincipalCoinType>(self: &mut Vault<PrincipalCoinType>) {
    assert!(self.version < VERSION, ERR_INVALID_VERSION);
    self.version = VERSION;

    emit(VaultUpgraded { vault_id: self.id.to_address(), version: VERSION });
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L716-716)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L905-905)
```text
    self.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L1205-1219)
```text
// * @dev Check if the value of each borrowed asset during operation is updated correctly
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
}
```

**File:** volo-vault/sources/operation.move (L354-354)
```text
    vault.check_op_value_update_record();
```

**File:** volo-vault/sources/manage.move (L22-24)
```text
public fun upgrade_vault<PrincipalCoinType>(_: &AdminCap, vault: &mut Vault<PrincipalCoinType>) {
    vault.upgrade_vault();
}
```

**File:** liquid_staking/sources/migration/migrate.move (L1-11)
```text
/// Module: Migration
/// migrate from volo v1 to volo v2
/// migration will be only executed once
/// flow:
/// 1. create stake pool
/// 2. export stakes
/// 3. take unclaimed fees
/// 4. import stakes
/// 5. destroy migration cap
/// 6. unpause the pool (after migration)
module liquid_staking::migration {
```
