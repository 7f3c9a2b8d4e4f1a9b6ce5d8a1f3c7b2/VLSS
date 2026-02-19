### Title
Cross-Vault Receipt Valuation Dependency Creates Operational DoS Vector

### Summary
The `receipt_adaptor::update_receipt_value()` function requires the receipt-issuing vault to be in NORMAL status via `assert_normal()` check at line 29. When Vault A holds receipts from Vault B and attempts to update receipt values during its operation (phase 2.5), any concurrent operation on Vault B blocks this update, preventing Vault A from completing its operation and leaving it stuck in DURING_OPERATION status. This creates a cross-vault dependency that enables operational denial-of-service. [1](#0-0) 

### Finding Description

The vulnerability exists in the receipt valuation flow during vault operations. When a vault holds receipts from another vault as DeFi assets, it must call `update_receipt_value()` to update the USD value of those receipts during the operation's value update phase (between `end_op_with_bag` and `end_op_value_update_with_bag`). [2](#0-1) 

The `assert_normal()` check enforces that the receipt-issuing vault (receipt_vault parameter) must be in `VAULT_NORMAL_STATUS` (value 0). This check aborts with `ERR_VAULT_NOT_NORMAL` if the vault is in any other status. [3](#0-2) 

Vault status transitions occur during operations via the `set_status()` function, which is `public(package)` and called by the operation module: [4](#0-3) 

When an operator starts an operation on any vault, that vault transitions from `VAULT_NORMAL_STATUS` (0) to `VAULT_DURING_OPERATION_STATUS` (1). The vault remains in this status until the operation completes via `end_op_value_update_with_bag`. [5](#0-4) 

**Root Cause:** The design creates a hard dependency between vaults where Vault A's ability to complete operations depends on Vault B's status. OperatorCap objects are global (not vault-specific) and can operate on any vault. [6](#0-5) 

**Why Protections Fail:** 
- No timeout mechanism exists to force-complete or abort operations
- Admin cannot directly reset vault status from DURING_OPERATION to NORMAL (only enable/disable via `set_vault_enabled`)
- TxBag structures lack drop ability, forcing operations to complete, but completion is impossible if receipt_vault is locked [7](#0-6) 

### Impact Explanation

**Direct Harm:**
1. Vault A becomes stuck in `VAULT_DURING_OPERATION_STATUS` and cannot return to normal operations
2. All user-facing functions requiring NORMAL status are blocked: `request_deposit`, `request_withdraw`, `cancel_deposit_request`, etc.
3. Users cannot access their funds in Vault A until Vault B completes its operation

**Protocol Damage:**
- Vault A's operation cannot complete phase 3 validation, preventing proper loss tolerance checks
- Asset values remain stale, potentially violating the `assets_value_updated` timestamp invariant
- Request buffers become inaccessible, freezing pending deposits/withdrawals

**Affected Parties:**
- All Vault A receipt holders lose access to deposit/withdraw functionality
- Vault A operator cannot complete their operation flow
- Protocol reputation damage from operational freeze

**Severity Justification:**
This is a design-level operational DoS that can affect any vault holding receipts from other vaults. The attack surface includes all cross-vault receipt holdings, which is an intended use case for the receipt adaptor system.

### Likelihood Explanation

**Attacker Capabilities:**
An operator (malicious or coordinating with another operator) can:
1. Observe when Vault A starts an operation
2. Immediately start an operation on Vault B before Vault A reaches value update phase
3. Time the operations to maximize disruption

**Attack Complexity:**
- Low: Requires only calling `start_op_with_bag` on Vault B
- No special timing precision needed, as operation phases can take multiple transactions
- Works even with legitimate operations (no obviously malicious behavior)

**Feasibility Conditions:**
- Vault A must hold receipts from Vault B (documented use case in tests)
- Operator must have access to OperatorCap (granted by admin, but intended for multiple operators)
- Cross-vault dependencies exist in the system design [8](#0-7) 

**Detection Constraints:**
- Difficult to distinguish from normal operation timing
- No on-chain evidence of malicious intent vs. coincidental timing
- Admin cannot prevent or resolve the situation without waiting for Vault B to complete

**Probability:**
High probability in production with multiple vaults and operators, as race conditions are inherent to the design. Even non-malicious concurrent operations create this risk.

### Recommendation

**Code-Level Mitigation:**

1. **Remove the strict status check** and implement a read-only valuation path:
   - Create `assert_enabled()` check instead of `assert_normal()` to allow valuation during Vault B's operations
   - Add read-only getters that don't modify vault state
   - Ensure receipt valuation doesn't depend on vault operation status

2. **Add timeout mechanism:**
   - Store operation start timestamp in vault
   - Allow admin to force-complete stale operations after timeout
   - Implement emergency status reset with admin cap

3. **Add operation dependency tracking:**
   - Before starting operation on Vault A, check if any of its receipt vaults (Vault B) are in operation
   - Abort operation start or queue it for retry
   - Prevent circular dependencies

**Invariant Checks:**
- Add assertion: "Vault cannot enter DURING_OPERATION if it issues receipts held by other vaults currently in DURING_OPERATION"
- Monitor cross-vault operation timing in integration tests

**Test Cases:**
```
test_concurrent_receipt_vault_operations():
  - Vault A holds receipt from Vault B
  - Start operation on Vault B
  - Start operation on Vault A  
  - Attempt to update receipt value
  - Verify: Either succeeds with new design OR aborts with clear error
```

### Proof of Concept

**Required Initial State:**
1. Vault A (SUI principal) is deployed and operational
2. Vault B (USDC principal) is deployed and operational
3. User deposits into Vault B, receives Receipt
4. Receipt is added as DeFi asset to Vault A via `add_new_defi_asset`
5. Two operators exist with valid OperatorCap objects

**Transaction Sequence:**

**Tx 1 - Operator B starts operation on Vault B:**
```
operation::start_op_with_bag<USDC, ...>(vault_b, operation, operator_cap_b, ...)
→ vault_b.status transitions to VAULT_DURING_OPERATION_STATUS (1)
```

**Tx 2 - Operator A starts operation on Vault A:**
```
operation::start_op_with_bag<SUI, ...>(vault_a, operation, operator_cap_a, ...)
→ vault_a.status transitions to VAULT_DURING_OPERATION_STATUS (1)
```

**Tx 3 - Operator A returns assets and enables value updates:**
```
operation::end_op_with_bag(vault_a, tx_bag, asset_bag, principal_balance, coin_balance)
→ All assets returned, value update enabled
```

**Tx 4 - Operator A attempts to update receipt value:**
```
receipt_adaptor::update_receipt_value<SUI, USDC>(
    vault_a,
    vault_b,  // Still in DURING_OPERATION_STATUS
    config,
    clock,
    receipt_asset_type
)
→ ABORTS at line 29: ERR_VAULT_NOT_NORMAL (error 5_022)
```

**Expected vs Actual Result:**
- **Expected:** Receipt value updates successfully, allowing Vault A to complete operation
- **Actual:** Transaction aborts, Vault A stuck in DURING_OPERATION_STATUS

**Success Condition:**
Vault A remains in DURING_OPERATION_STATUS indefinitely until Vault B completes its operation. During this time, all user functions on Vault A abort with status check errors, demonstrating operational DoS.

### Citations

**File:** volo-vault/sources/adaptors/receipt_adaptor.move (L16-36)
```text
public fun update_receipt_value<PrincipalCoinType, PrincipalCoinTypeB>(
    vault: &mut Vault<PrincipalCoinType>,
    receipt_vault: &Vault<PrincipalCoinTypeB>,
    config: &OracleConfig,
    clock: &Clock,
    asset_type: String,
) {
    // Actually it seems no need to check this
    // "vault" and "receipt_vault" can not be passed in with the same vault object
    // assert!(
    //     type_name::get<PrincipalCoinType>() != type_name::get<PrincipalCoinTypeB>(),
    //     ERR_NO_SELF_VAULT,
    // );
    receipt_vault.assert_normal();

    let receipt = vault.get_defi_asset<PrincipalCoinType, Receipt>(asset_type);

    let usd_value = get_receipt_value(receipt_vault, config, receipt, clock);

    vault.finish_update_asset_value(asset_type, usd_value, clock.timestamp_ms());
}
```

**File:** volo-vault/sources/volo_vault.move (L84-86)
```text
public struct OperatorCap has key, store {
    id: UID,
}
```

**File:** volo-vault/sources/volo_vault.move (L649-651)
```text
public(package) fun assert_normal<PrincipalCoinType>(self: &Vault<PrincipalCoinType>) {
    assert!(self.status() == VAULT_NORMAL_STATUS, ERR_VAULT_NOT_NORMAL);
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

**File:** volo-vault/sources/operation.move (L375-375)
```text
    vault.set_status(VAULT_NORMAL_STATUS);
```

**File:** volo-vault/sources/manage.move (L13-19)
```text
public fun set_vault_enabled<PrincipalCoinType>(
    _: &AdminCap,
    vault: &mut Vault<PrincipalCoinType>,
    enabled: bool,
) {
    vault.set_enabled(enabled);
}
```

**File:** volo-vault/tests/operation/operation.test.move (L2222-2228)
```text
        receipt_adaptor::update_receipt_value<SUI_TEST_COIN, USDC_TEST_COIN>(
            &mut vault,
            &usdc_vault,
            &config,
            &clock,
            receipt_asset_type,
        );
```
