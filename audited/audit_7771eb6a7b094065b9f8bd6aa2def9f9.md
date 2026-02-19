### Title
Frozen Operators Can Bypass Security Controls to Retrieve Fees

### Summary
The `retrieve_deposit_withdraw_fee_operator()` function in `manage.move` does not verify if an operator is frozen before allowing fee retrieval. This allows frozen operators to continue extracting accumulated deposit and withdrawal fees from the vault, completely bypassing the operator freeze mechanism that is designed as a security control to restrict compromised or malicious operators.

### Finding Description

The function `retrieve_deposit_withdraw_fee_operator()` accepts only an `OperatorCap` and `Vault` parameter: [1](#0-0) 

This function directly calls the internal vault function without any freeze check: [2](#0-1) 

The protocol implements an operator freeze mechanism through the `Operation` shared object that maintains a `freezed_operators` table: [3](#0-2) 

The freeze check function `assert_operator_not_freezed()` verifies operator status and aborts with `ERR_OPERATOR_FREEZED` if the operator is frozen: [4](#0-3) 

However, `retrieve_deposit_withdraw_fee_operator()` does not accept the `Operation` object as a parameter, making it impossible to perform this critical security check. In contrast, all other operator functions correctly implement freeze checks. For example: [5](#0-4) [6](#0-5) [7](#0-6) 

The root cause is that `retrieve_deposit_withdraw_fee_operator()` lacks the `Operation` parameter required to verify freeze status, creating an authorization bypass in the fee retrieval path.

### Impact Explanation

**Security Integrity Impact - Authorization Bypass:**

When administrators freeze an operator (typically due to detected malicious behavior, key compromise, or security incidents), the expectation is that the operator loses all vault access immediately. The freeze mechanism is implemented via: [8](#0-7) 

However, a frozen operator retains the ability to extract all accumulated deposit and withdrawal fees using `retrieve_deposit_withdraw_fee_operator()`. This completely undermines the freeze mechanism's purpose as a security control.

**Concrete Impact:**
- Frozen operators can drain accumulated fees (potentially significant amounts depending on vault activity)
- Admin's security response (freezing the operator) is ineffective for protecting fee assets
- Violates the critical invariant: "operator freeze respected" 
- Creates a window of vulnerability between detecting malicious behavior and fully securing vault assets

**Affected Parties:**
- Vault users whose deposit/withdrawal fees are extracted by frozen operators
- Protocol administrators who rely on freeze as an emergency security measure

### Likelihood Explanation

**Attacker Capabilities:**
An operator who has been frozen (typically due to suspected compromise or malicious activity) still possesses their `OperatorCap` object. They can directly call the public function with no additional requirements.

**Attack Complexity:**
Minimal - single function call:
1. Operator is frozen by admin via `set_operator_freezed()`
2. Frozen operator calls `retrieve_deposit_withdraw_fee_operator(&operator_cap, &mut vault, amount)`
3. Fees are successfully extracted despite frozen status

**Feasibility Conditions:**
- Operator has their `OperatorCap` (always true until transfer/destruction)
- Vault has accumulated fees from user deposits/withdrawals (normal operation)
- No additional preconditions or complex state setup required

**Detection/Operational Constraints:**
- Transaction is valid and will succeed under normal conditions
- No error is thrown or event indicating security policy violation
- Admin may not detect the fee extraction until monitoring fee balances

**Probability:**
High - in any scenario where an operator needs to be frozen (the exact situation where this security control matters most), they can still extract fees before or after being frozen.

### Recommendation

**Code-Level Mitigation:**

Modify `retrieve_deposit_withdraw_fee_operator()` to accept the `Operation` object and perform freeze verification:

```move
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    operation: &Operation,  // Add this parameter
    cap: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault::assert_operator_not_freezed(operation, cap);  // Add this check
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

**Invariant Check:**
Ensure all operator functions (those accepting `OperatorCap`) also accept `Operation` and call `assert_operator_not_freezed()` before any state modifications.

**Test Cases:**
1. Test that frozen operator cannot retrieve fees (should abort with `ERR_OPERATOR_FREEZED`)
2. Test that unfrozen operator can retrieve fees normally
3. Test freeze → fee retrieval attempt → unfreeze → successful fee retrieval sequence

### Proof of Concept

**Initial State:**
- Vault exists with accumulated deposit/withdrawal fees (e.g., 1,000,000 units)
- Operator has valid `OperatorCap` 
- Admin has `AdminCap`
- Shared `Operation` object exists

**Attack Sequence:**

Transaction 1 (Admin freezes operator):
```
vault_manage::set_operator_freezed(
    &admin_cap,
    &mut operation,
    operator_cap_id,
    true  // freeze = true
)
```
Result: `operator_freezed(operation, operator_cap_id)` returns `true`

Transaction 2 (Frozen operator retrieves fees):
```
let fees = vault_manage::retrieve_deposit_withdraw_fee_operator(
    &operator_cap,  // Note: Operation not passed
    &mut vault,
    1_000_000
)
```

**Expected Result:** Transaction should abort with `ERR_OPERATOR_FREEZED` error code (5_015)

**Actual Result:** Transaction succeeds, frozen operator receives 1,000,000 units of fees

**Success Condition for Exploit:** 
- Frozen operator successfully extracts fees without authorization check failure
- Vault's `deposit_withdraw_fee_collected` balance decreases by requested amount
- Operator receives `Balance<PrincipalCoinType>` despite being frozen

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

**File:** volo-vault/sources/manage.move (L150-156)
```text
public fun retrieve_deposit_withdraw_fee_operator<PrincipalCoinType>(
    _: &OperatorCap,
    vault: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    vault.retrieve_deposit_withdraw_fee(amount)
}
```

**File:** volo-vault/sources/volo_vault.move (L89-92)
```text
public struct Operation has key, store {
    id: UID,
    freezed_operators: Table<address, bool>,
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

**File:** volo-vault/sources/volo_vault.move (L1544-1557)
```text
public(package) fun retrieve_deposit_withdraw_fee<PrincipalCoinType>(
    self: &mut Vault<PrincipalCoinType>,
    amount: u64,
): Balance<PrincipalCoinType> {
    self.check_version();
    self.assert_normal();

    emit(DepositWithdrawFeeRetrieved {
        vault_id: self.vault_id(),
        amount: amount,
    });

    self.deposit_withdraw_fee_collected.split(amount)
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
