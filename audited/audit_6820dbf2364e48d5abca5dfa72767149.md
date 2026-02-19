### Title
Operator Freeze Mechanism Bypass via Unvalidated Operation Object

### Summary
The `set_operator_freezed()` function and all operation execution functions accept any `Operation` shared object without verifying it is the legitimate one created during deployment. A frozen operator can bypass the freeze control by passing an alternate `Operation` object (e.g., from their own deployment) to operation functions, completely circumventing the security mechanism.

### Finding Description

The vulnerability exists in the operator freeze mechanism across multiple locations:

**1. Admin sets freeze using any Operation object:** [1](#0-0) 

This function accepts an arbitrary `Operation` object without validation.

**2. Operation struct has no linkage to Vaults:** [2](#0-1) 

The `Operation` object is a standalone shared object with no ties to specific Vaults.

**3. Vault struct stores no Operation reference:** [3](#0-2) 

No field in the Vault struct stores which Operation object is authoritative.

**4. Operation functions accept any Operation object:** [4](#0-3) 

The `start_op_with_bag` function (and all other operation functions) accept the `Operation` object as a parameter from the caller and only verify the operator is not frozen in that specific Operation object: [5](#0-4) 

**5. Module init creates one Operation per deployment:** [6](#0-5) 

While init creates a single Operation object, nothing prevents operators from using a different one.

**Root Cause:** The system assumes a single Operation object exists and will be used, but provides no enforcement mechanism. The freeze check only queries the Operation object passed by the caller, not a canonical one stored in the Vault.

### Impact Explanation

**Security Integrity Bypass - Complete Operator Freeze Mechanism Failure:**

1. **Authorization Bypass**: The critical invariant "operator freeze respected" is completely violated. When admin freezes an operator, that operator can continue executing all operations.

2. **Affected Operations**: All operator functions are bypassable:
   - `execute_deposit` [7](#0-6) 
   - `execute_withdraw` [8](#0-7) 
   - `start_op_with_bag` and `end_op_with_bag` for all adaptor operations

3. **Governance Impact**: Admin loses the ability to protect the vault from malicious or compromised operators. The freeze mechanism is a critical emergency control that becomes useless.

4. **Severity**: HIGH - This is a complete bypass of a core security control designed to protect user funds from operator misbehavior.

### Likelihood Explanation

**Exploitation is trivial and requires no special privileges:**

1. **Reachable Entry Point**: All operation functions are public and callable with appropriate capability objects.

2. **Attack Prerequisites**:
   - Operator possesses an `OperatorCap` (normal operating condition)
   - Operator has access to a different `Operation` object (easily obtainable)

3. **Obtaining an alternate Operation object**:
   - Deploy their own instance of the volo_vault module (creates new Operation in init)
   - Use an Operation object from a different legitimate deployment
   - Any shared Operation object of the correct type works

4. **Execution Steps**:
   ```
   Step 1: Admin calls set_operator_freezed(admin_cap, legitimate_operation, attacker_cap_id, true)
   Step 2: Attacker calls operation::start_op_with_bag(vault, DIFFERENT_operation, attacker_cap, ...)
   Step 3: The freeze check passes because DIFFERENT_operation has no freeze for attacker_cap_id
   Step 4: Attacker executes operations normally despite being "frozen"
   ```

5. **Detection**: Extremely difficult to detect since the attacker uses normal operation functions with valid parameters.

6. **Probability**: Very High - requires minimal technical sophistication and no economic cost beyond normal transaction fees.

### Recommendation

**Primary Fix - Store and Validate Operation Object ID:**

1. Add `operation_id: address` field to Vault struct: [3](#0-2) 

2. Initialize during vault creation:
```move
public fun create_vault<PrincipalCoinType>(_: &AdminCap, operation: &Operation, ctx: &mut TxContext) {
    // ... existing code ...
    let mut vault = Vault<PrincipalCoinType> {
        // ... existing fields ...
        operation_id: object::id_address(operation),
    };
}
```

3. Add validation function:
```move
public(package) fun assert_correct_operation<T>(vault: &Vault<T>, operation: &Operation) {
    assert!(vault.operation_id == object::id_address(operation), ERR_WRONG_OPERATION_OBJECT);
}
```

4. Call validation in all operation functions before freeze check: [4](#0-3) 

Add `vault.assert_correct_operation(operation);` before line 105.

5. Repeat for all operation functions: `execute_deposit`, `execute_withdraw`, `end_op_with_bag`, `end_op_value_update_with_bag`, etc.

**Test Case:**
Create test verifying that passing wrong Operation object fails with ERR_WRONG_OPERATION_OBJECT.

### Proof of Concept

**Initial State:**
- Legitimate volo_vault deployment with `legitimate_operation` shared object
- Vault created and operational
- Operator has valid `OperatorCap`
- Admin has `AdminCap`

**Attack Sequence:**

**Transaction 1 - Admin freezes operator:**
```move
vault_manage::set_operator_freezed(
    admin_cap, 
    legitimate_operation, 
    object::id_address(operator_cap), 
    true
);
```
Expected: Operator frozen in legitimate_operation
Actual: Operator frozen in legitimate_operation only

**Transaction 2 - Attacker deploys their own instance:**
```move
// Attacker deploys volo_vault module under different package
// This creates attacker_operation in init()
```
Result: New `attacker_operation` shared object exists with empty freeze map

**Transaction 3 - Attacker executes operation with wrong Operation:**
```move
operation::start_op_with_bag<SUI, USDC, SUI>(
    vault,           // Legitimate vault
    attacker_operation,  // WRONG Operation object!
    operator_cap,    // Attacker's valid cap
    clock,
    defi_asset_ids,
    defi_asset_types,
    principal_amount,
    coin_type_asset_amount,
    ctx
);
```

**Expected Result:** Transaction should fail with ERR_OPERATOR_FREEZED
**Actual Result:** Transaction succeeds because `assert_operator_not_freezed(attacker_operation, cap)` checks attacker_operation's freeze map, which doesn't have the operator frozen

**Success Condition:** Frozen operator successfully executes vault operations, completely bypassing the freeze mechanism.

### Citations

**File:** volo-vault/sources/manage.move (L88-95)
```text
public fun set_operator_freezed(
    _: &AdminCap,
    operation: &mut Operation,
    op_cap_id: address,
    freezed: bool,
) {
    vault::set_operator_freezed(operation, op_cap_id, freezed);
}
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
}
```

**File:** volo-vault/sources/volo_vault.move (L96-130)
```text
public struct Vault<phantom T> has key, store {
    id: UID,
    version: u64,
    // ---- Pool Info ---- //
    status: u8,
    total_shares: u256,
    locking_time_for_withdraw: u64, // Locking time for withdraw (ms)
    locking_time_for_cancel_request: u64, // Time to cancel a request (ms)
    // ---- Fee ---- //
    deposit_withdraw_fee_collected: Balance<T>,
    // ---- Principal Info ---- //
    free_principal: Balance<T>,
    claimable_principal: Balance<T>,
    // ---- Config ---- //
    deposit_fee_rate: u64,
    withdraw_fee_rate: u64,
    // ---- Assets ---- //
    asset_types: vector<String>, // All assets types, used for looping
    assets: Bag, // <asset_type, asset_object>, asset_object can be balance or DeFi assets
    assets_value: Table<String, u256>, // Assets value in USD
    assets_value_updated: Table<String, u64>, // Last updated timestamp of assets value
    // ---- Loss Tolerance ---- //
    cur_epoch: u64,
    cur_epoch_loss_base_usd_value: u256,
    cur_epoch_loss: u256,
    loss_tolerance: u256,
    // ---- Request Buffer ---- //
    request_buffer: RequestBuffer<T>,
    // ---- Reward Info ---- //
    reward_manager: address,
    // ---- Receipt Info ---- //
    receipts: Table<address, VaultReceiptInfo>,
    // ---- Operation Value Update Record ---- //
    op_value_update_record: OperationValueUpdateRecord,
}
```

**File:** volo-vault/sources/volo_vault.move (L349-358)
```text
fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::public_transfer(admin_cap, ctx.sender());

    let operation = Operation {
        id: object::new(ctx),
        freezed_operators: table::new(ctx),
    };
    transfer::share_object(operation);
}
```

**File:** volo-vault/sources/volo_vault.move (L380-385)
```text
public(package) fun assert_operator_not_freezed(operation: &Operation, cap: &OperatorCap) {
    let cap_id = cap.operator_id();
    // If the operator has ever been freezed, it will be in the freezed_operator map, check its value
    // If the operator has never been freezed, no error will be emitted
    assert!(!operator_freezed(operation, cap_id), ERR_OPERATOR_FREEZED);
}
```

**File:** volo-vault/sources/operation.move (L94-106)
```text
public fun start_op_with_bag<T, CoinType, ObligationType>(
    vault: &mut Vault<T>,
    operation: &Operation,
    cap: &OperatorCap,
    clock: &Clock,
    defi_asset_ids: vector<u8>,
    defi_asset_types: vector<TypeName>,
    principal_amount: u64,
    coin_type_asset_amount: u64,
    ctx: &mut TxContext,
): (Bag, TxBag, TxBagForCheckValueUpdate, Balance<T>, Balance<CoinType>) {
    vault::assert_operator_not_freezed(operation, cap);
    pre_vault_check(vault, ctx);
```

**File:** volo-vault/sources/operation.move (L381-391)
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
```

**File:** volo-vault/sources/operation.move (L449-460)
```text
public fun execute_withdraw<PrincipalCoinType>(
    operation: &Operation,
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    reward_manager: &mut RewardManager<PrincipalCoinType>,
    clock: &Clock,
    config: &OracleConfig,
    request_id: u64,
    max_amount_received: u64,
    ctx: &mut TxContext,
) {
    vault::assert_operator_not_freezed(operation, cap);
```
