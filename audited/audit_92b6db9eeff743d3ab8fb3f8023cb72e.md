### Title
Circular Receipt Dependencies Cause Permanent Vault Operation Deadlock

### Summary
When Vault A holds a receipt from Vault B and Vault B holds a receipt from Vault A, both vaults cannot complete their operations concurrently due to the `assert_normal()` requirement in `update_receipt_value()`. This creates a mutual blocking scenario where whichever vault starts an operation first prevents the other from updating asset values and completing its operation, effectively causing permanent DoS on both vaults.

### Finding Description

The vulnerability exists in the receipt value update mechanism during vault operations. The three-phase operation flow requires:

**Phase 1**: `start_op_with_bag` sets vault status to `VAULT_DURING_OPERATION_STATUS` [1](#0-0) 

**Phase 2**: `end_op_with_bag` returns borrowed assets but keeps status as `VAULT_DURING_OPERATION_STATUS` [2](#0-1) 

**Phase 3**: Between phases 2 and 3, all asset values must be updated via adaptor-specific functions. For receipts, this requires calling `update_receipt_value()` [3](#0-2) 

The root cause is in `receipt_adaptor::update_receipt_value()` which enforces: [4](#0-3) 

This `assert_normal()` check verifies the receipt-issuing vault is in `VAULT_NORMAL_STATUS`: [5](#0-4) 

**Circular Dependency Creation**: No checks exist in `add_new_defi_asset()` to prevent circular receipt dependencies: [6](#0-5) 

**Execution Path Leading to Deadlock**:

1. Vault A (SUI) holds a receipt from Vault B (USDC)
2. Vault B (USDC) holds a receipt from Vault A (SUI) 
3. Vault A starts operation → `vault_a.status = VAULT_DURING_OPERATION_STATUS`
4. Vault B independently starts its own operation → `vault_b.status = VAULT_DURING_OPERATION_STATUS`
5. Vault A completes phase 2, must call `update_receipt_value<SUI, USDC>(vault_a, vault_b, ...)`
6. Line 29 executes `vault_b.assert_normal()` but Vault B is in `VAULT_DURING_OPERATION_STATUS` → **ABORT with `ERR_VAULT_NOT_NORMAL`**
7. Similarly, Vault B cannot complete because Vault A is in operation
8. Both vaults are permanently stuck in `VAULT_DURING_OPERATION_STATUS`

The commented-out check at lines 23-28 only prevented self-referencing (same vault), not circular cross-vault dependencies: [7](#0-6) 

### Impact Explanation

**Operational Impact - Vault Functions Completely Blocked**:

When circular dependencies exist and both vaults enter operations, neither can complete phase 3 (`end_op_value_update_with_bag`), leaving them permanently in `VAULT_DURING_OPERATION_STATUS`. This blocks:

1. **All Future Operations**: Cannot start new operations because `pre_vault_check()` requires `assert_normal()` [8](#0-7) 

2. **Status-Dependent Functions**: Cannot disable vault because `set_enabled()` requires `assert_not_during_operation()` [9](#0-8) 

3. **Normal User Flows**: Deposits/withdrawals may be blocked if they require vault to be in normal status

4. **Asset Management**: Cannot perform rebalancing, DeFi integrations, or risk management operations

**Affected Parties**:
- Vault operators unable to manage assets
- Users unable to interact with vaults stuck in operation
- Protocol accumulating stale asset valuations
- Loss of protocol utility and user funds effectively locked

**Severity Justification**: HIGH - This is a permanent DoS condition affecting core vault functionality with no recovery path except removing the circular dependency or upgrading the contract.

### Likelihood Explanation

**Attacker Capabilities**: No malicious actor required - occurs through normal operations.

**Feasible Preconditions**:
1. Circular receipt dependencies can be created through normal vault asset management
2. Both vault operators independently decide to run operations (normal maintenance activity)
3. Timing overlap where both vaults are in operation phase simultaneously

**Execution Practicality**: 
- Vault operations are regular occurrences for rebalancing, yield harvesting, risk management
- In a multi-vault ecosystem, operations frequently overlap
- No coordination mechanism exists between independent vault operators
- Even if coordinated, race conditions can occur in concurrent transactions

**Attack Complexity**: NONE - happens naturally without any attack

**Detection/Operational Constraints**: 
- Operators may not realize circular dependencies exist until DoS occurs
- No warnings or checks during receipt addition
- No mechanism to atomically coordinate operations across vaults

**Probability**: HIGH - In any system with multiple vaults holding cross-vault receipts and regular operations, collision is inevitable over time.

### Recommendation

**Immediate Fix - Add Circular Dependency Prevention**:

In `receipt_adaptor::update_receipt_value()`, replace the strict `assert_normal()` check with one that allows vault operations to proceed if the receipt vault is in operation:

```move
// Allow value update even if receipt_vault is in operation
// Use cached/stale value rather than blocking
if (receipt_vault.status() == VAULT_NORMAL_STATUS) {
    // Normal path - fresh valuation
    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);
    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
} else {
    // Receipt vault in operation - use last known value
    // Asset value already exists from previous update, no action needed
    // Or mark as stale and require re-validation later
}
```

**Alternative Fix - Detect Circular Dependencies on Addition**:

In `add_new_defi_asset()` when adding a Receipt type, check if the receipt's vault already holds a receipt from the current vault:

```move
if (type_name::get<AssetType>() == type_name::get<Receipt>()) {
    // Check receipt.vault_id() doesn't already hold a receipt from self.vault_id()
    // Abort if circular dependency detected
}
```

**Invariant to Enforce**:
- No circular receipt dependencies between vaults (A holds receipt from B → B must not hold receipt from A)
- OR vault operations must be non-blocking on cross-vault receipt valuations

**Test Cases**:
1. Create Vault A with receipt from Vault B, Vault B with receipt from Vault A
2. Start operation on Vault A
3. Start operation on Vault B  
4. Verify both can complete operations without blocking
5. Verify asset values are correctly updated or marked as stale

### Proof of Concept

**Initial State Setup**:
1. Create Vault A (SUI vault) and Vault B (USDC vault)
2. User deposits into both vaults and receives receipts
3. Vault A's operator calls `add_new_defi_asset(receipt_from_B)` - adds Vault B's receipt as asset
4. Vault B's operator calls `add_new_defi_asset(receipt_from_A)` - adds Vault A's receipt as asset
5. Circular dependency now exists: A holds receipt from B, B holds receipt from A

**Exploitation Steps**:

Transaction 1 (Vault A Operation):
```move
// Vault A starts operation
let (bag_a, tx_a, check_a, principal_a, coin_a) = operation::start_op_with_bag<SUI, _, _>(
    &mut vault_a, &operation, &cap_a, &clock, 
    defi_asset_ids, defi_asset_types, 0, 0, ctx
);
// vault_a.status = VAULT_DURING_OPERATION_STATUS

// ... perform some operation ...

// End operation phase 2
operation::end_op_with_bag(
    &mut vault_a, &operation, &cap_a, bag_a, tx_a, principal_a, coin_a
);
// vault_a.status still = VAULT_DURING_OPERATION_STATUS
```

Transaction 2 (Vault B Operation - concurrent):
```move
// Vault B starts operation (before A completes)
let (bag_b, tx_b, check_b, principal_b, coin_b) = operation::start_op_with_bag<USDC, _, _>(
    &mut vault_b, &operation, &cap_b, &clock,
    defi_asset_ids_b, defi_asset_types_b, 0, 0, ctx
);
// vault_b.status = VAULT_DURING_OPERATION_STATUS
```

Transaction 3 (Vault A tries to complete):
```move
// Vault A must update receipt value from Vault B
receipt_adaptor::update_receipt_value<SUI, USDC>(
    &mut vault_a, 
    &vault_b,  // Vault B is in VAULT_DURING_OPERATION_STATUS
    &config, &clock, receipt_asset_type
);
// ABORTS at line 29: vault_b.assert_normal() fails
// Error: ERR_VAULT_NOT_NORMAL (5_022)
```

**Expected Result**: Operation completes successfully with asset values updated

**Actual Result**: Transaction 3 aborts with `ERR_VAULT_NOT_NORMAL`, Vault A stuck in `VAULT_DURING_OPERATION_STATUS`, cannot complete operation or start new operations

**Success Condition for Exploit**: Both vaults remain in `VAULT_DURING_OPERATION_STATUS` with no recovery path, all vault operations permanently blocked.

### Citations

**File:** volo-vault/sources/operation.move (L73-75)
```text
    vault.assert_normal();
    vault.set_status(VAULT_DURING_OPERATION_STATUS);
    vault.try_reset_tolerance(false, ctx);
```

**File:** volo-vault/sources/operation.move (L219-219)
```text
    vault.assert_during_operation();
```

**File:** volo-vault/tests/operation/operation.test.move (L3281-3287)
```text
        receipt_adaptor::update_receipt_value<SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault,
            &usdc_vault,
            &config,
            &clock,
            receipt_asset_type,
        );
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L23-28)
```text
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
```

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L29-29)
```text
    receipt_vault.assert_normal();
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
}
```

**File:** volo-vault/sources/volo_vault.move (L657-661)
```text
public(package) fun assert_not_during_operation<PrincipalCoinType>(
    self: &Vault<PrincipalCoinType>,
) {
    assert!(self.status() != VAULT_DURING_OPERATION_STATUS, ERR_VAULT_DURING_OPERATION);
}
```

**File:** volo-vault/sources/volo_vault.move (L1374-1386)
```text
public(package) fun add_new_defi_asset<PrincipalCoinType, AssetType: key + store>(
    self: &mut Vault<PrincipalCoinType>,
    idx: u8,
    asset: AssetType,
) {
    self.check_version();
    // self.assert_normal();
    self.assert_enabled();

    let asset_type = vault_utils::parse_key<AssetType>(idx);
    set_new_asset_type(self, asset_type);
    self.assets.add<String, AssetType>(asset_type, asset);
}
```
